use std::{sync::Arc};

use async_trait::async_trait;
use prost::encoding::bool;
use crate::{prekey::Prekey, session::{Session, self}, mac::AxolotlMac, serializable::{Deserializable, Serializable}, x448::{KeyPairX448, PublicKeyX448}, ntru::{KeyPairNtru, NtruedKeys, self, PrivateKeyNtru, DecryptionMode::Double, PublicKeyNtru}, signed_key_pair::SignedKeyPair, message::Type, ed448::{KeyPairEd448}, signed_public_key::SignedPublicKeyX448, identity_keys::IdentityKeys};

/*

Active: { nid(primary), session_id }
ReceiveOnly: { nid(primary), session_id }

Session: { id(primary), nid, blob, receive_only, restoring }

*/

pub trait Storage {
	/// Should ignore receive_only sessions
	// TODO: replace with `Nid`; should exclude receive_only session
	// TODO: should be result to include the "DB is locked" case
	fn get_active_session_for_nid(&self, nid: &str) -> Option<Session>;
	/// Returns any session, whether active or receive_only
	fn get_session_by_id(&self, id: u64) -> Option<Session>;

	/// Clears active and receive_only sessions, if any
	fn clear_all_sessions_for_nid(&self, nid: &str); // TODO: result?
	fn save_session(&self, session: &Session, nid: &str, id: u64, receive_only: bool); // TODO: introduce result

	// Identity
	fn get_my_x448_identity(&self) -> Option<KeyPairX448>; // TODO: Result with a custom error type?
	fn get_my_ed448_identity(&self) -> Option<KeyPairEd448>;
	fn get_my_ntru_identity(&self) -> Option<KeyPairNtru>; // TODO: result with a custom error type?
	
	fn get_identity_keys_for_nid(&self, nid: &str) -> Option<IdentityKeys>;
	fn save_identity_keys_for_nid(&self, identity: &IdentityKeys, nid: &str);

	// Prekeys
	fn get_prekey(&self, id: u64) -> Option<Prekey>; // TODO: use Result instead; a separate consume?
	/// deletes a Prekey where id = prekey.x448_key.id, if any
	fn delete_prekey(&self, id: u64);
	
	fn get_signed_prekey(&self, id: u64) -> Option<SignedKeyPair>; // TODO: use Result instead and handle errors: locked vs not found

}

#[async_trait]
pub trait Apis {
	async fn fetch_prekey(&self, nid: &str, auth_nid: &str, auth_token: &str) -> Result<FetchedPrekeyBundle, Error>;
}

pub struct Cryptor<S, A>
where
	S: Storage + Send,
	A: Apis + Send
{
	storage: Arc<S>,
	apis: Arc<A>
}

impl<S: Storage + Send, A: Apis + Send> Cryptor<S, A> {
	pub fn new(storage: Arc<S>, apis: Arc<A>) -> Self {
		Self {
			storage: Arc::clone(&storage),
			apis: Arc::clone(&apis)
		}
	}
}

#[derive(Debug)]
pub enum Error {
	/// Protobuf encoding error; ignore the message
	BadMacFormat,	
	/// DB is locked/corrupted/not ready; try again later
	NoIdentityFound,
	/// DB is locked/corrupted/not ready; try again later
	NoNtruIdentityFound,
	/// DB is locked/corrupted/not ready; try again later
	NoSigningIdentityFound,
	/// Previously saved identity does not match with the backend's response; reset?
	IdentityDoesNotMatch,
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

// TODO: rename
pub struct FetchedPrekeyBundle {
	prekey_x448: PublicKeyX448,
	prekey_ntru: PublicKeyNtru,
	signed_prekey_x448: SignedPublicKeyX448,
	identity: IdentityKeys
}

impl<S: Storage + Send, A: Apis + Send> Cryptor<S, A> {
	pub async fn decrypt(&mut self, mac: &[u8], nid: &str, my_nid: &str) -> Result<Decrypted, Error> {
		// all the state change should be saved here, not by the caller – should it?
		let mac = AxolotlMac::deserialize(mac).or(Err(Error::BadMacFormat))?;

		// a new session is being initiated (doesn't mean it's the first message though)
		if let Some(ref kex) = mac.body().key_exchange {
			// this can be both, active and receive_only session – does not matter at this point
			if let Some(session) = self.storage.get_session_by_id(kex.id()) {
				return self.decrypt_with_session(session, mac, nid);
			} else {
				let identity = self.storage.get_my_x448_identity().ok_or(Error::NoIdentityFound)?;
				let ntru_identity = self.storage.get_my_ntru_identity().ok_or(Error::NoNtruIdentityFound)?;

				let signed_prekey = self.storage.get_signed_prekey(kex.signed_prekey_id).ok_or(Error::NoSignedPrekeyFound(kex.signed_prekey_id))?;
				let Prekey { key_x448, key_ntru, .. } = self.storage.get_prekey(kex.x448_prekey_id).ok_or(Error::NoPrekeyFound(kex.x448_prekey_id))?;
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
					self.storage.clear_all_sessions_for_nid(nid);

					return self.decrypt_with_session(session, mac, nid);
				} else {
					// do I have any other session for this nid?
					if let Some(_) = self.storage.get_active_session_for_nid(nid) {
						if session.role() == session::Role::Alice {
							if should_be_alice(my_nid, nid) {
								// the sender is considering herself Alice (but they'll fix themselves eventually), so keep 
								// this session for some time in receive_only mode to decrypt their unacked (in terms of Axolotl) messages
								session.set_read_only();

								return self.decrypt_with_session(session, mac, nid);
							} else {
								// I was Alice, but at the same time some one initiated a session and I actually should be Bob
								// now, I'll delete my session and will use the new one
								self.storage.clear_all_sessions_for_nid(nid);

								return self.decrypt_with_session(session, mac, nid);
							}
						} else {
							// I'm bob already, but from now on, I should be using this new session only
							self.storage.clear_all_sessions_for_nid(nid);

							return self.decrypt_with_session(session, mac, nid);
						}
					} else {
						// this is a new and the only session, so proceed normally: decrypt, save, etc
						return self.decrypt_with_session(session, mac, nid);
					}
				}
			}
		} else {
			if let Some(current) = self.storage.get_active_session_for_nid(nid) {
				// at this point, it could be save to delete any receive_only sessions, if any
				return self.decrypt_with_session(current, mac, nid);
			} else {
				return Err(Error::NoSessionFound)
			}
		}
	}

	fn decrypt_with_session(&self, mut session: Session, mac: AxolotlMac, nid: &str) -> Result<Decrypted, Error> {
		if let Ok(msg) = session.decrypt(&mac) {
			self.storage.save_session(&session, nid, session.id(), session.receive_only());

			// TODO: session itself could keep Option<prekey_id> and clear it per each decryption, if required
			if let Some(id) = mac.body().key_exchange.as_ref().and_then(|k| Some(k.x448_prekey_id)) {
				self.storage.delete_prekey(id);
			}

			Ok(Decrypted { msg, _type: mac.body()._type })
		} else {
			self.storage.clear_all_sessions_for_nid(nid);

			Err(Error::WrongMac)
		}
	}

	// force_ntru, as is now implemented, is not what it might look like: it can ntru-encrypt my next ratchet when the time
	// to turn comes, but it can't turn it emmidiately because of Axolotl's strict ping-pong nature
	pub async fn encrypt(&self, plaintext: &[u8], _type: Type, nid: &str, my_nid: &str, auth_token: &str, force_reset: bool) -> Result<Vec<u8>, Error> {
		if force_reset {
			self.storage.clear_all_sessions_for_nid(nid);
		}

		if let Some(current) = self.storage.get_active_session_for_nid(nid) {
			return self.encrypt_with_session(current, plaintext, _type, nid);
		} else {
			let my_identity = self.storage.get_my_x448_identity().ok_or(Error::NoIdentityFound)?;
			let my_ntru_identity = self.storage.get_my_ntru_identity().ok_or(Error::NoNtruIdentityFound)?;
			let my_signing_identity = self.storage.get_my_ed448_identity().ok_or(Error::NoSigningIdentityFound)?;
			let my_ratchet = KeyPairX448::generate();
			let my_ntru_ratchet = KeyPairNtru::generate();
			let bundle = self.apis.fetch_prekey(nid, my_nid, auth_token).await?; // TODO: respect UserDoesNotExist + network errors

			if let Some(identity) = self.storage.get_identity_keys_for_nid(nid) {
				if identity.x448 != bundle.identity.x448 || identity.ntru != bundle.identity.ntru || identity.ed448 != bundle.identity.ed448 {
					return Err(Error::IdentityDoesNotMatch);
				}
			} else {
				self.storage.save_identity_keys_for_nid(&bundle.identity, nid);
			}

			let session = Session::alice(my_identity,
				my_ratchet,
				my_signing_identity,
				my_ntru_identity,
				my_ntru_ratchet, 
				bundle.identity.x448,
				bundle.signed_prekey_x448,
				bundle.prekey_x448,
				bundle.prekey_ntru,
				bundle.identity.ntru,
				force_reset);

				return self.encrypt_with_session(session, plaintext, _type, nid);
		}
	}

	// add_prekey
	// add_signed_prekey
	// is_signed_prekey_stale

	fn encrypt_with_session(&self, mut session: Session, plaintext: &[u8], _type: Type, nid: &str) -> Result<Vec<u8>, Error> {
		let ciphertext = session.encrypt(plaintext, _type);

		self.storage.save_session(&session, nid, session.id(), false);
		// Desktop keeps restarting indefinitely if encrypt throws, but can it can't fail now

		return Ok(ciphertext.serialize());
	}
}

// TODO: rename & move somewhere else
fn should_be_alice(my_nid: &str, nid: &str) -> bool {
	my_nid < nid
}
#[cfg(test)]
mod tests {
	use crate::cryptor::should_be_alice;

	// TODO: move to Nid instead
	#[test]
	fn test_role_by_nid() {
		assert!(should_be_alice("abcdef:1", "ghijkl:1"));
		assert!(should_be_alice("abcdef:1", "abcdef:2"));
		assert!(should_be_alice("1bcdef:1", "2bcdef:2"));
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