use std::{sync::Arc, fmt::Display};

use async_trait::async_trait;
use prost::encoding::bool;
use crate::{prekey::Prekey, session::{Session, self}, mac::AxolotlMac, serializable::{Deserializable, Serializable}, x448::{KeyPairX448, PublicKeyX448}, ntru::{KeyPairNtru, NtruedKeys, self, PrivateKeyNtru, DecryptionMode::Double, PublicKeyNtru}, signed_key_pair::SignedKeyPair, message::Type, ed448::{KeyPairEd448}, signed_public_key::SignedPublicKeyX448, identity_keys::IdentityKeys};

/*

Active: { nid(primary), session_id }
ReceiveOnly: { nid(primary), session_id }

Session: { id(primary), nid, blob, receive_only, restoring }

*/

#[async_trait]
pub trait Storage {
	/// Should ignore receive_only sessions
	// TODO: replace with `Nid`; should exclude receive_only session
	// TODO: should be result to include the "DB is locked" case
	async fn get_active_session_for_nid(&self, nid: &str) -> Option<Session>;
	/// Returns any session, whether active or receive_only
	async fn get_session_by_id(&self, id: u64) -> Option<Session>;

	/// Clears active and receive_only sessions, if any
	async fn clear_all_sessions_for_nid(&self, nid: &str); // TODO: result?
	async fn save_session(&self, session: Session, nid: &str, id: u64, receive_only: bool); // TODO: introduce result

	// Identity
	async fn get_my_x448_identity(&self) -> Option<KeyPairX448>; // TODO: Result with a custom error type?
	async fn get_my_ed448_identity(&self) -> Option<KeyPairEd448>;
	async fn get_my_ntru_identity(&self) -> Option<KeyPairNtru>; // TODO: result with a custom error type?
	
	async fn get_identity_keys_for_nid(&self, nid: &str) -> Option<IdentityKeys>;
	async fn save_identity_keys_for_nid(&self, identity: &IdentityKeys, nid: &str);

	// Prekeys
	async fn get_prekey(&self, id: u64) -> Option<Prekey>; // TODO: use Result instead; a separate consume?
	/// deletes a Prekey where id = prekey.x448_key.id, if any
	async fn delete_prekey(&self, id: u64);
	
	async fn get_signed_prekey(&self, id: u64) -> Option<SignedKeyPair>; // TODO: use Result instead and handle errors: locked vs not found

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

#[derive(Debug, Copy, Clone)]
pub enum Error {
	/// Protobuf encoding error; ignore the message
	BadMacFormat = 1,	
	/// DB is locked/corrupted/not ready; try again later
	NoIdentityFound = 2,
	/// DB is locked/corrupted/not ready; try again later
	NoNtruIdentityFound = 3,
	/// DB is locked/corrupted/not ready; try again later
	NoSigningIdentityFound = 4,
	/// Previously saved identity does not match with the backend's response; reset?
	IdentityDoesNotMatch = 5,
	/// A stale signed key is used; reset
	NoSignedPrekeyFound = 6,
	/// A prekey has already been used by someone else (quite impossible) or there was a crash previously; reset
	NoPrekeyFound = 7,
	/// ephemeral_key was encrypted only once or first_key/second_key order was not respected
	BadNtruEncryptedEphemeral = 8,
	/// No session found for given nid; reset
	NoSessionFound = 9,
	/// Current session is corrupted; reset
	// TODO: rename, make less generic
	WrongMac = 10,
	/// No user exists or authentication failure; fail, no recovery
	NoPrekeysForUser = 11,
	/// A prekey was fetched, but it's of unknown format; fail and ignore
	BadPrekeyFormat = 12,
	/// A generic network error; try again later
	NoNetwork = 13
}

impl Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{:?}", self)
	}
}

impl From<std::array::TryFromSliceError> for Error {
	fn from(_: std::array::TryFromSliceError) -> Self {
		Self::BadPrekeyFormat
	}
}

pub struct Decrypted {
	msg: Vec<u8>,
	_type: Type
}

// TODO: rename
pub struct FetchedPrekeyBundle {
	pub prekey_x448: PublicKeyX448,
	pub prekey_ntru: PublicKeyNtru,
	pub signed_prekey_x448: SignedPublicKeyX448,
	pub identity: IdentityKeys
}

impl<S: Storage + Send, A: Apis + Send> Cryptor<S, A> {
	pub async fn decrypt(&mut self, mac: &[u8], nid: &str, my_nid: &str) -> Result<Decrypted, Error> {
		// all the state change should be saved here, not by the caller – should it?
		let mac = AxolotlMac::deserialize(mac).or(Err(Error::BadMacFormat))?;

		// a new session is being initiated (doesn't mean it's the first message though)
		if let Some(ref kex) = mac.body().key_exchange {
			// this can be both, active and receive_only session – does not matter at this point
			if let Some(session) = self.storage.get_session_by_id(kex.id()).await {
				return self.decrypt_with_session(session, mac, nid).await;
			} else {
				let identity = self.storage.get_my_x448_identity().await.ok_or(Error::NoIdentityFound)?;
				let ntru_identity = self.storage.get_my_ntru_identity().await.ok_or(Error::NoNtruIdentityFound)?;
				let signed_prekey = self.storage.get_signed_prekey(kex.signed_prekey_id).await.ok_or(Error::NoSignedPrekeyFound)?;
				let Prekey { key_x448, key_ntru, .. } = self.storage.get_prekey(kex.x448_prekey_id).await.ok_or(Error::NoPrekeyFound)?;
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
					self.storage.clear_all_sessions_for_nid(nid).await;

					return self.decrypt_with_session(session, mac, nid).await;
				} else {
					// do I have any other session for this nid?
					if let Some(_) = self.storage.get_active_session_for_nid(nid).await {
						if session.role() == session::Role::Alice {
							if should_be_alice(my_nid, nid) {
								// the sender is considering herself Alice (but they'll fix themselves eventually), so keep 
								// this session for some time in receive_only mode to decrypt their unacked (in terms of Axolotl) messages
								session.set_read_only();

								return self.decrypt_with_session(session, mac, nid).await;
							} else {
								// I was Alice, but at the same time some one initiated a session and I actually should be Bob
								// now, I'll delete my session and will use the new one
								self.storage.clear_all_sessions_for_nid(nid).await;

								return self.decrypt_with_session(session, mac, nid).await;
							}
						} else {
							// I'm bob already, but from now on, I should be using this new session only
							self.storage.clear_all_sessions_for_nid(nid).await;

							return self.decrypt_with_session(session, mac, nid).await;
						}
					} else {
						// this is a new and the only session, so proceed normally: decrypt, save, etc
						return self.decrypt_with_session(session, mac, nid).await;
					}
				}
			}
		} else {
			if let Some(current) = self.storage.get_active_session_for_nid(nid).await {
				// at this point, it could be save to delete any receive_only sessions, if any
				return self.decrypt_with_session(current, mac, nid).await;
			} else {
				return Err(Error::NoSessionFound)
			}
		}
	}

	async fn decrypt_with_session(&self, mut session: Session, mac: AxolotlMac, nid: &str) -> Result<Decrypted, Error> {
		if let Ok(msg) = session.decrypt(&mac) {
			let id = session.id();
			let receive_only = session.receive_only();

			self.storage.save_session(session, nid, id, receive_only).await;

			// TODO: session itself could keep Option<prekey_id> and clear it per each decryption, if required
			if let Some(id) = mac.body().key_exchange.as_ref().and_then(|k| Some(k.x448_prekey_id)) {
				self.storage.delete_prekey(id).await;
			}

			Ok(Decrypted { msg, _type: mac.body()._type })
		} else {
			self.storage.clear_all_sessions_for_nid(nid).await;

			Err(Error::WrongMac)
		}
	}

	// force_ntru, as is now implemented, is not what it might look like: it can ntru-encrypt my next ratchet when the time
	// to turn comes, but it can't turn it emmidiately because of Axolotl's strict ping-pong nature
	pub async fn encrypt(&self, plaintext: &[u8], _type: Type, nid: &str, my_nid: &str, auth_token: &str, force_reset: bool) -> Result<Vec<u8>, Error> {
		if force_reset {
			self.storage.clear_all_sessions_for_nid(nid).await;
		}

		if let Some(current) = self.storage.get_active_session_for_nid(nid).await {
			return self.encrypt_with_session(current, plaintext, _type, nid).await;
		} else {
			let my_identity = self.storage.get_my_x448_identity().await.ok_or(Error::NoIdentityFound)?;
			let my_ntru_identity = self.storage.get_my_ntru_identity().await.ok_or(Error::NoNtruIdentityFound)?;
			let my_signing_identity = self.storage.get_my_ed448_identity().await.ok_or(Error::NoSigningIdentityFound)?;
			let my_ratchet = KeyPairX448::generate();
			let my_ntru_ratchet = KeyPairNtru::generate();
			let bundle = self.apis.fetch_prekey(nid, my_nid, auth_token).await?; // TODO: respect UserDoesNotExist + network errors

			if let Some(identity) = self.storage.get_identity_keys_for_nid(nid).await {
				if identity.x448 != bundle.identity.x448 || identity.ntru != bundle.identity.ntru || identity.ed448 != bundle.identity.ed448 {
					return Err(Error::IdentityDoesNotMatch);
				}
			} else {
				self.storage.save_identity_keys_for_nid(&bundle.identity, nid).await;
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

				return self.encrypt_with_session(session, plaintext, _type, nid).await;
		}
	}

	// add_prekey
	// add_signed_prekey
	// is_signed_prekey_stale

	async fn encrypt_with_session(&self, mut session: Session, plaintext: &[u8], _type: Type, nid: &str) -> Result<Vec<u8>, Error> {
		let ciphertext = session.encrypt(plaintext, _type);
		let id = session.id();

		self.storage.save_session(session, nid, id, false).await;
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