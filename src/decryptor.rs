use std::{sync::Arc};

use async_trait::async_trait;
use prost::encoding::bool;
use crate::{prekey::Prekey, session::{Session, self}, mac::AxolotlMac, serializable::Deserializable, x448::KeyPairX448, ntru::{KeyPairNtru, NtruedKeys, self, PrivateKeyNtru, DecryptionMode::Double}, signed_key_pair::SignedKeyPair, message::Type};

/*

Session: { id, nid, blob, receive_only, restoring }

*/

// TODO: should this be async actually?
#[async_trait]
pub trait Sessions {
	// TODO: replace with `Nid`; should exclude receive_only session
	async fn get_active(&self, nid: &str) -> Option<Session>;
	// TODO: get_by_id() should be introduced instead where id = derive_id(eph.id, sender_identity)
	async fn get_for_kex(&self, key_id: u64) -> Option<Session>;

	// TODO: save_in_place(session, nid)?
	async fn clear_all(&self, nid: &str); // TODO: result?
	async fn save(&self, session: &Session); // TODO: introduce result
}

// TODO: should this be async actually?
#[async_trait]
pub trait Identities {
	async fn get_my_identity(&self) -> Option<KeyPairX448>; // TODO: Result with a custom error type?
	async fn get_my_ntru_identity(&self) -> Option<KeyPairNtru>; // TODO: result with a custom error type?
}

// TODO: should this be async actually?
#[async_trait]
pub trait Prekeys {
	async fn get(&self, id: u64) -> Option<Prekey>; // TODO: use Result instead; a separate consume?
	async fn get_signed(&self, id: u64) -> Option<SignedKeyPair>; // TODO: use Result instead and handle errors: locked vs not found
	/// deletes a Prekey where id = prekey.x448_key.id, if any
	async fn delete(&self, id: u64);
}

pub struct Decryptor {
	sessions: Arc<dyn Sessions>,
	prekeys: Arc<dyn Prekeys>,
	identities: Arc<dyn Identities>
}

impl Decryptor {
	pub fn new(sessions: Arc<dyn Sessions>, prekeys: Arc<dyn Prekeys>, identities: Arc<dyn Identities>) -> Self {
		Self {
			sessions: Arc::clone(&sessions),
			prekeys: Arc::clone(&prekeys),
			identities: Arc::clone(&identities)
		}
	}
}

pub enum Error {
	/// Protobuf encoding error; ignore the message
	BadMacFormat,	
	/// DB is locked/corrupted/not ready; try again later
	NoIdentityFound,
	/// DB is locked/corrupted/not ready; try again later
	NoNtruIdentityFound,
	/// A stale signed key is used; reset
	NoSignedPrekeyFound(u64),
	/// A prekey has already been used by someone else (quite impossible) or there was a crash previously; reset
	NoPrekeyFound(u64),
	/// ephemeral_key was encrypted only once or first_key/second_key order was not respected
	BadNtruEncryptedEphemeral,
	/// No session found for given nid; reset
	NoSessionFound,
	/// Current session is corrupted; reset
	// TODO: rename, make less generic
	WrongMac
}

pub struct Decrypted {
	msg: Vec<u8>,
	_type: Type
}

impl Decryptor {
	pub async fn decrypt(&mut self, mac: &[u8], nid: &str, my_nid: &str) -> Result<Decrypted, Error> {
		// all the state change should be saved here, not by the caller – should it?
		let mac = AxolotlMac::deserialize(mac).or(Err(Error::BadMacFormat))?;

		// a new session is being initiated (doesn't mean it's the first message though)
		if let Some(ref kex) = mac.body().key_exchange {
			if let Some(current) = self.sessions.get_for_kex(kex.ntru_encrypted_ephemeral.key_id).await {
				return self.decrypt_with_session(current, mac).await;
			} else {
				let identity = self.identities.get_my_identity().await.ok_or(Error::NoIdentityFound)?;
				let ntru_identity = self.identities.get_my_ntru_identity().await.ok_or(Error::NoNtruIdentityFound)?;

				// TODO: reset if failed (handle by an outer layer?)
				let signed_prekey = self.prekeys.get_signed(kex.signed_prekey_id).await.ok_or(Error::NoSignedPrekeyFound(kex.signed_prekey_id))?;
				// TODO: reset if failed (handle by an outer layer?)
				// TODO: consume later (before saving the session)
				let Prekey { key_x448, key_ntru, .. } = self.prekeys.get(kex.x448_prekey_id).await.ok_or(Error::NoPrekeyFound(kex.x448_prekey_id))?;
				let find_key = |_| -> Result<&PrivateKeyNtru, ntru::Error> {
					Ok(key_ntru.private_key())
				};
				let NtruedKeys { ephemeral: their_key_x448, ntru: their_key_ntru } = ntru::decrypt_ephemeral(
					&kex.ntru_encrypted_ephemeral,
					Double { second_key: ntru_identity.private_key(), first_key: Box::new(find_key) }).or(Err(Error::BadNtruEncryptedEphemeral))?;
				let their_identity = kex.x448_identity.clone(); 

				// TODO: make sure nid corresponds to the supplied identity by:
				// GET users/cid.{identity, identity_ntru, signing_identity} == kex.{identity, identity_ntru, signing_identity}
				// ^ if no match, ignore the message?
				// ^ if http error, try later?
				let session = Session::bob(identity, ntru_identity, signed_prekey, key_x448, key_ntru, their_identity, their_key_x448, their_key_ntru);

				// TODO: check current.has_receive only first? –if yes, clear as well
				if kex.force_reset {
					self.sessions.clear_all(nid).await;

					return self.decrypt_with_session(session, mac).await;
				} else {
					if let Some(_) = self.sessions.get_active(nid).await {
						if session.role() == session::Role::Alice {
							if Self::should_be_alice(my_nid, nid) {
								// the other side thought they should be Alice (they'll fix themselves), so keep this session for some time in receive_only mode
								// FIXME: save as READ_ONLY
								// session.set_read_only();
								return self.decrypt_with_session(session, mac).await;
							} else {
								// I was Alice, but at the same time some one initiated a session and I actually should be Bob
								// now, I'll delete my session and will use the new one
								self.sessions.clear_all(nid).await;

								return self.decrypt_with_session(session, mac).await;
							}
						} else {
							self.sessions.clear_all(nid).await;

							return self.decrypt_with_session(session, mac).await;
						}
					} else {
						return self.decrypt_with_session(session, mac).await;
					}
				}
			}
		} else {
			if let Some(current) = self.sessions.get_active(nid).await {
				return self.decrypt_with_session(current, mac).await;
			} else {
				return Err(Error::NoSessionFound)
			}
		}
	}

	// TODO: rename
	fn should_be_alice(my_nid: &str, nid: &str) -> bool {
		my_nid < nid
	}

	async fn decrypt_with_session(&self, mut session: Session, mac: AxolotlMac) -> Result<Decrypted, Error> {
		let _type = mac.body()._type;
		// if error reset?
		let msg = session.decrypt(&mac).or(Err(Error::WrongMac))?;
		// TODO: respect receive_only
		self.sessions.save(&session).await;

		if let Some(id) = mac.body().key_exchange.as_ref().and_then(|k| Some(k.x448_prekey_id)) {
			self.prekeys.delete(id).await;
		}

		Ok(Decrypted { msg, _type })
	}
}


#[cfg(test)]
mod tests {
	use super::Decryptor;

	// TODO: move to Nid instead
	#[test]
	fn test_role_by_nid() {
		assert!(Decryptor::should_be_alice("abcdef:1", "ghijkl:1"));
		assert!(Decryptor::should_be_alice("abcdef:1", "abcdef:2"));
		assert!(Decryptor::should_be_alice("1bcdef:1", "2bcdef:2"));
	}

	#[test]
	fn test_decrypt() {
		// match decryptor.decrypt(&frame, &nid).await {
		// 	case Ok(plain) => callback(plain),
		//	case Err(err) => match err {
		//		case BadMacFormat => ignore(),
		//		case NoIdentityFound => ignore(),
		//		case NoNtruIdentityFound => ignore(),
		//		case NoSignedPrekeyFound => send_reset(force_kex = true),
		//		case NoPrekeyFound => send_reset(force_kex = true)
		//  }
		// }
	}
}