use std::{sync::Arc};

use async_trait::async_trait;
use prost::encoding::bool;
use crate::{prekey::Prekey, session::{Session, self}, mac::AxolotlMac, serializable::Deserializable, x448::KeyPairX448, ntru::{KeyPairNtru, NtruedKeys, self, PrivateKeyNtru, DecryptionMode::Double}, signed_key_pair::SignedKeyPair, message::Type};

/*

Active: { nid(primary), session_id }
ReadOnly: { nid(primary), session_id }

Session: { id(primary), nid, blob, receive_only, restoring }

*/

// TODO: should this be async actually?
// db.get(id) -> Vec<u8>
// Session::deserialize()
#[async_trait]
pub trait Sessions {
	/// Should ignore receive_only sessions
	// TODO: replace with `Nid`; should exclude receive_only session
	async fn get_active(&self, nid: &str) -> Option<Session>;
	/// Returns any session, whether active or receive_only
	async fn get_by_id(&self, id: u64) -> Option<Session>;

	/// Clears active and receive_only sessions, if any
	async fn clear_all(&self, nid: &str); // TODO: result?
	async fn save(&self, session: &Session, nid: &str, id: u64, receive_only: bool); // TODO: introduce result
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

pub struct Cryptor {
	sessions: Arc<dyn Sessions>,
	prekeys: Arc<dyn Prekeys>,
	identities: Arc<dyn Identities>
}

impl Cryptor {
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

impl Cryptor {
	pub async fn decrypt(&mut self, mac: &[u8], nid: &str, my_nid: &str) -> Result<Decrypted, Error> {
		// all the state change should be saved here, not by the caller – should it?
		let mac = AxolotlMac::deserialize(mac).or(Err(Error::BadMacFormat))?;

		// a new session is being initiated (doesn't mean it's the first message though)
		if let Some(ref kex) = mac.body().key_exchange {
			// this can be both, active and readonly session – does not matter at this point
			if let Some(session) = self.sessions.get_by_id(kex.id()).await {
				return self.decrypt_with_session(session, mac, nid).await;
			} else {
				let identity = self.identities.get_my_identity().await.ok_or(Error::NoIdentityFound)?;
				let ntru_identity = self.identities.get_my_ntru_identity().await.ok_or(Error::NoNtruIdentityFound)?;

				let signed_prekey = self.prekeys.get_signed(kex.signed_prekey_id).await.ok_or(Error::NoSignedPrekeyFound(kex.signed_prekey_id))?;
				let Prekey { key_x448, key_ntru, .. } = self.prekeys.get(kex.x448_prekey_id).await.ok_or(Error::NoPrekeyFound(kex.x448_prekey_id))?;
				let find_key = |_| -> Result<&PrivateKeyNtru, ntru::Error> {
					Ok(key_ntru.private_key())
				};
				let NtruedKeys { ephemeral: their_key_x448, ntru: their_key_ntru } = ntru::decrypt_ephemeral(
					&kex.ntru_encrypted_ephemeral,
					Double { second_key: ntru_identity.private_key(), first_key: Box::new(find_key) }).or(Err(Error::BadNtruEncryptedEphemeral))?;
				let their_identity = kex.x448_identity.clone(); 
				// FIXME: should I save this new identity by DB?
				// TODO: make sure nid corresponds to the supplied identity by:
				// GET users/cid.{identity, identity_ntru, signing_identity} == kex.{identity, identity_ntru, signing_identity}
				// ^ if no match, ignore the message?
				// ^ if http error, try later?
				let mut session = Session::bob(identity, ntru_identity, signed_prekey, key_x448, key_ntru, their_identity, their_key_x448, their_key_ntru);

				// TODO: check current.has_receive only first? –if yes, clear as well
				if kex.force_reset {
					self.sessions.clear_all(nid).await;

					return self.decrypt_with_session(session, mac, nid).await;
				} else {
					// do I have any other session for this nid?
					if let Some(_) = self.sessions.get_active(nid).await {
						if session.role() == session::Role::Alice {
							if Self::should_be_alice(my_nid, nid) {
								// the sender is considering herself Alice (but they'll fix themselves eventually), so keep 
								// this session for some time in receive_only mode to decrypt their unacked (in terms of Axolotl) messages
								session.set_read_only();

								return self.decrypt_with_session(session, mac, nid).await;
							} else {
								// I was Alice, but at the same time some one initiated a session and I actually should be Bob
								// now, I'll delete my session and will use the new one
								self.sessions.clear_all(nid).await;

								return self.decrypt_with_session(session, mac, nid).await;
							}
						} else {
							// I'm bob already, but from now on, I should be using this new session only
							self.sessions.clear_all(nid).await;

							return self.decrypt_with_session(session, mac, nid).await;
						}
					} else {
						// this is a new and the only session, so proceed normally: decrypt, save, etc
						return self.decrypt_with_session(session, mac, nid).await;
					}
				}
			}
		} else {
			if let Some(current) = self.sessions.get_active(nid).await {
				// at this point, it could be save to delete any readonly sessions, if any
				return self.decrypt_with_session(current, mac, nid).await;
			} else {
				return Err(Error::NoSessionFound)
			}
		}
	}

	// TODO: rename
	fn should_be_alice(my_nid: &str, nid: &str) -> bool {
		my_nid < nid
	}

	async fn decrypt_with_session(&self, mut session: Session, mac: AxolotlMac, nid: &str) -> Result<Decrypted, Error> {
		if let Ok(msg) = session.decrypt(&mac) {
			// TODO: respect receive_only
			self.sessions.save(&session, nid, session.id(), session.receive_only()).await;

			// TODO: session itself could keep Option<prekey_id> and clear it per each decryption, if required
			if let Some(id) = mac.body().key_exchange.as_ref().and_then(|k| Some(k.x448_prekey_id)) {
				self.prekeys.delete(id).await;
			}

			Ok(Decrypted { msg, _type: mac.body()._type })
		} else {
			self.sessions.clear_all(nid).await;

			Err(Error::WrongMac)
		}
	}

	pub async fn encrypt(&self, plaintext: &[u8], nid: &str) -> Vec<u8> {
		if let Some(current) = self.sessions.get_active(nid).await {

		} else {
		}
		// get session
		// create a new one, if not found
		// encrypt
		// save
		// return
		todo!()
	}

	async fn encrypt_with_session(&self, session: Session, plaintext: &[u8], nid: &str) -> Vec<u8> {
		todo!()
	}
}


#[cfg(test)]
mod tests {
	use super::Cryptor;

	// TODO: move to Nid instead
	#[test]
	fn test_role_by_nid() {
		assert!(Cryptor::should_be_alice("abcdef:1", "ghijkl:1"));
		assert!(Cryptor::should_be_alice("abcdef:1", "abcdef:2"));
		assert!(Cryptor::should_be_alice("1bcdef:1", "2bcdef:2"));
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