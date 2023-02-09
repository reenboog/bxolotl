use std::{fmt::Display, sync::Arc};

use crate::{
	ed448::KeyPairEd448,
	identity_keys::IdentityKeys,
	job_queue,
	kyber::{
		self, DecryptionMode::Double, KeyBundle, KeyPairKyber, PrivateKeyKyber, PublicKeyKyber,
	},
	mac::AxolotlMac,
	message::Type,
	prekey::Prekey,
	serializable::{Deserializable, Serializable},
	session::{self, Session},
	signed_key_pair::SignedKeyPair,
	signed_public_key::SignedPublicKeyX448,
	x448::{KeyPairX448, PublicKeyX448},
};
use async_trait::async_trait;
use prost::encoding::bool;

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
	/// `nid` parameter has to be checked otherwise it's possible to bypass identity checks.
	fn get_session_by_id(&self, nid: &str, id: u64) -> Option<Session>;

	/// Clears active and receive_only sessions, if any
	fn clear_all_sessions_for_nid(&self, nid: &str); // TODO: result?
	fn save_session(&self, session: Session, nid: &str, id: u64, receive_only: bool); // TODO: introduce result

	// Identity
	fn get_my_x448_identity(&self) -> Option<KeyPairX448>; // TODO: Result with a custom error type?
	fn get_my_ed448_identity(&self) -> Option<KeyPairEd448>;
	fn get_my_kyber_identity(&self) -> Option<KeyPairKyber>; // TODO: result with a custom error type?

	fn get_identity_keys_for_nid(&self, nid: &str) -> Option<IdentityKeys>;
	fn save_identity_keys_for_nid(&self, identity: &IdentityKeys, nid: &str);

	// Prekeys
	fn get_prekey(&self, id: u64) -> Option<Prekey>; // TODO: use Result instead; a separate consume?
	/// deletes a Prekey where id = prekey.x448_key.id, if any
	// IMPORTANT: make sure last_resort keys are not deleted
	fn delete_prekey(&self, id: u64);

	fn get_signed_prekey(&self, id: u64) -> Option<SignedKeyPair>; // TODO: use Result instead and handle errors: locked vs not found
}

#[async_trait]
pub trait AsyncStorage {
	async fn get_active_session_for_nid(&self, nid: &str) -> Option<Session>;
	async fn get_session_by_id(&self, nid: &str, id: u64) -> Option<Session>;

	async fn clear_all_sessions_for_nid(&self, nid: &str);
	async fn save_session(&self, session: Session, nid: &str, id: u64, receive_only: bool);

	async fn get_my_x448_identity(&self) -> Option<KeyPairX448>;
	async fn get_my_ed448_identity(&self) -> Option<KeyPairEd448>;
	async fn get_my_kyber_identity(&self) -> Option<KeyPairKyber>;

	async fn get_identity_keys_for_nid(&self, nid: &str) -> Option<IdentityKeys>;
	async fn save_identity_keys_for_nid(&self, identity: &IdentityKeys, nid: &str);

	async fn get_prekey(&self, id: u64) -> Option<Prekey>;
	async fn delete_prekey(&self, id: u64);

	async fn get_signed_prekey(&self, id: u64) -> Option<SignedKeyPair>;
}

#[async_trait]
impl<T> AsyncStorage for T
where
	T: Storage + Sync,
{
	async fn get_active_session_for_nid(&self, nid: &str) -> Option<Session> {
		self.get_active_session_for_nid(nid)
	}
	async fn get_session_by_id(&self, nid: &str, id: u64) -> Option<Session> {
		self.get_session_by_id(nid, id)
	}

	async fn clear_all_sessions_for_nid(&self, nid: &str) {
		self.clear_all_sessions_for_nid(nid)
	}
	async fn save_session(&self, session: Session, nid: &str, id: u64, receive_only: bool) {
		self.save_session(session, nid, id, receive_only)
	}

	async fn get_my_x448_identity(&self) -> Option<KeyPairX448> {
		self.get_my_x448_identity()
	}
	async fn get_my_ed448_identity(&self) -> Option<KeyPairEd448> {
		self.get_my_ed448_identity()
	}
	async fn get_my_kyber_identity(&self) -> Option<KeyPairKyber> {
		self.get_my_kyber_identity()
	}

	async fn get_identity_keys_for_nid(&self, nid: &str) -> Option<IdentityKeys> {
		self.get_identity_keys_for_nid(nid)
	}
	async fn save_identity_keys_for_nid(&self, identity: &IdentityKeys, nid: &str) {
		self.save_identity_keys_for_nid(identity, nid)
	}

	async fn get_prekey(&self, id: u64) -> Option<Prekey> {
		self.get_prekey(id)
	}
	async fn delete_prekey(&self, id: u64) {
		self.delete_prekey(id)
	}

	async fn get_signed_prekey(&self, id: u64) -> Option<SignedKeyPair> {
		self.get_signed_prekey(id)
	}
}

#[async_trait]
pub trait Apis {
	async fn fetch_prekey(
		&self,
		nid: &str,
		auth_nid: &str,
		auth_token: &str,
	) -> Result<FetchedPrekeyBundle, Error>;
}

pub struct Cryptor<S, A> {
	storage: Arc<S>,
	apis: Arc<A>,
	tasks: job_queue::Queue<String>,
}

impl<S: AsyncStorage + Sync, A: Apis + Sync> Cryptor<S, A> {
	pub fn new(storage: Arc<S>, apis: Arc<A>) -> Self {
		Self {
			storage,
			apis,
			tasks: job_queue::Queue::new(),
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
	NoKyberIdentityFound = 3,
	/// DB is locked/corrupted/not ready; try again later
	NoSigningIdentityFound = 4,
	/// Previously saved identity does not match with the backend's response; reset?
	IdentityDoesNotMatch = 5,
	/// A stale signed key is used; reset
	NoSignedPrekeyFound = 6,
	/// A prekey has already been used by someone else (quite impossible) or there was a crash previously; reset
	NoPrekeyFound = 7,
	/// ephemeral_key was encrypted only once or first_key/second_key order was not respected
	BadKyberEncryptedEphemeral = 8,
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
	NoNetwork = 13,
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
	pub msg: Vec<u8>,
	pub _type: Type,
}

// TODO: rename
pub struct FetchedPrekeyBundle {
	pub prekey_x448: PublicKeyX448,
	pub prekey_kyber: PublicKeyKyber,
	pub signed_prekey_x448: SignedPublicKeyX448,
	pub identity: IdentityKeys,
}

// TODO: reuse ccl's existing Nid type

impl<S: AsyncStorage + Sync, A: Apis + Sync> Cryptor<S, A> {
	pub async fn decrypt(&self, mac: &[u8], nid: &str, my_nid: &str) -> Result<Decrypted, Error> {
		self.tasks
			.push(nid.to_string(), || self.decrypt_msg(mac, nid, my_nid))
			.await
	}

	async fn decrypt_msg(&self, mac: &[u8], nid: &str, my_nid: &str) -> Result<Decrypted, Error> {
		// all the state change should be saved here, not by the caller – should it?
		let mac = AxolotlMac::deserialize(mac).or(Err(Error::BadMacFormat))?;

		// a new session is being initiated (doesn't mean it's the first message though)
		if let Some(ref kex) = mac.body().key_exchange {
			// this can be both, active and receive_only session – does not matter at this point
			if let Some(session) = self.storage.get_session_by_id(nid, kex.id()).await {
				self.decrypt_with_session(session, mac, nid).await
			} else {
				let identity = self
					.storage
					.get_my_x448_identity()
					.await
					.ok_or(Error::NoIdentityFound)?;
				let kyber_identity = self
					.storage
					.get_my_kyber_identity()
					.await
					.ok_or(Error::NoKyberIdentityFound)?;
				let signed_prekey = self
					.storage
					.get_signed_prekey(kex.signed_prekey_id)
					.await
					.ok_or(Error::NoSignedPrekeyFound)?;
				// TODO: mark as read_only if prekey is last_resort? it would freshen the session and make sure
				// unique prekeys are used. On the other hand, if the sender also has no prekeys left, the receiver might
				// use her last_resort prekey as well which might lead to a continous ping pong
				let Prekey {
					key_x448,
					key_kyber,
					..
				} = self
					.storage
					.get_prekey(kex.x448_prekey_id)
					.await
					.ok_or(Error::NoPrekeyFound)?;
				let find_key =
					|_| -> Result<&PrivateKeyKyber, kyber::Error> { Ok(key_kyber.private_key()) };
				let KeyBundle {
					ephemeral: their_key_x448,
					kyber: their_key_kyber,
				} = kyber::decrypt_keys(
					&kex.kyber_encrypted_ephemeral,
					Double {
						second_key: kyber_identity.private_key(),
						first_key: Box::new(find_key),
					},
				)
				.or(Err(Error::BadKyberEncryptedEphemeral))?;
				let their_identity = kex.x448_identity.clone();
				// FIXME: should I save this new identity by DB?
				// TODO: make sure nid corresponds to the supplied identity by:
				// GET users/cid.{identity, identity_kyber, signing_identity} == kex.{identity, identity_kyber, signing_identity}
				// ^ if no match, ignore the message?
				// ^ if http error, try later?
				// ^ if the sending account is deleted, ignore?
				let mut session = Session::bob(
					identity,
					kyber_identity,
					signed_prekey,
					key_x448,
					key_kyber,
					their_identity,
					their_key_x448,
					their_key_kyber,
				);

				// TODO: check current.has_receive only first? –if yes, clear as well
				if kex.force_reset {
					self.storage.clear_all_sessions_for_nid(nid).await;

					self.decrypt_with_session(session, mac, nid).await
				} else {
					// do I have any other session for this nid?
					if let Some(current) = self.storage.get_active_session_for_nid(nid).await {
						if current.role() == session::Role::Alice {
							if should_be_alice(my_nid, nid) {
								// the sender is considering herself Alice (but they'll fix themselves eventually), so keep
								// this session for some time in receive_only mode to decrypt their unacked (in terms of Axolotl) messages
								session.set_receive_only();

								self.decrypt_with_session(session, mac, nid).await
							} else {
								// I was Alice, but at the same time some one initiated a session and I actually should be Bob
								// now, I'll delete my session and will use the new one
								self.storage.clear_all_sessions_for_nid(nid).await;

								self.decrypt_with_session(session, mac, nid).await
							}
						} else {
							// I'm bob already, but from now on, I should be using this new session only
							self.storage.clear_all_sessions_for_nid(nid).await;

							self.decrypt_with_session(session, mac, nid).await
						}
					} else {
						// this is a new and the only session, so proceed normally: decrypt, save, etc
						self.decrypt_with_session(session, mac, nid).await
					}
				}
			}
		} else {
			if let Some(current) = self.storage.get_active_session_for_nid(nid).await {
				// at this point, it could be save to delete any receive_only sessions, if any
				self.decrypt_with_session(current, mac, nid).await
			} else {
				Err(Error::NoSessionFound)
			}
		}
	}

	async fn decrypt_with_session(
		&self,
		mut session: Session,
		mac: AxolotlMac,
		nid: &str,
	) -> Result<Decrypted, Error> {
		let res = session.decrypt(&mac);

		if let Ok(msg) = res {
			let id = session.id();
			// it could be either active or receive_only session
			let receive_only = session.receive_only();
			self.storage
				.save_session(session, nid, id, receive_only)
				.await;

			// TODO: session itself could keep Option<prekey_id> and clear it per each decryption, if required
			if let Some(id) = mac
				.body()
				.key_exchange
				.as_ref()
				.and_then(|k| Some(k.x448_prekey_id))
			{
				self.storage.delete_prekey(id).await;
			}

			Ok(Decrypted {
				msg,
				_type: mac.body()._type,
			})
		} else {
			self.storage.clear_all_sessions_for_nid(nid).await;

			Err(Error::WrongMac)
		}
	}

	pub async fn encrypt(
		&self,
		plaintext: &[u8],
		_type: Type,
		nid: &str,
		my_nid: &str,
		auth_token: &str,
		force_reset: bool,
	) -> Result<Vec<u8>, Error> {
		self.tasks
			.push(nid.to_string(), || {
				self.encrypt_msg(plaintext, _type, nid, my_nid, auth_token, force_reset)
			})
			.await
	}

	// force_kyber, as is now implemented, is not what it might look like: it can kyber-encrypt my next ratchet when the time
	// to turn comes, but it can't turn it emmidiately because of Axolotl's strict ping-pong nature
	async fn encrypt_msg(
		&self,
		plaintext: &[u8],
		_type: Type,
		nid: &str,
		my_nid: &str,
		auth_token: &str,
		force_reset: bool,
	) -> Result<Vec<u8>, Error> {
		if force_reset {
			self.storage.clear_all_sessions_for_nid(nid).await;
		}

		if let Some(current) = self.storage.get_active_session_for_nid(nid).await {
			self.encrypt_with_session(current, plaintext, _type, nid)
				.await
		} else {
			let my_identity = self
				.storage
				.get_my_x448_identity()
				.await
				.ok_or(Error::NoIdentityFound)?;
			let my_kyber_identity = self
				.storage
				.get_my_kyber_identity()
				.await
				.ok_or(Error::NoKyberIdentityFound)?;
			let my_signing_identity = self
				.storage
				.get_my_ed448_identity()
				.await
				.ok_or(Error::NoSigningIdentityFound)?;
			let my_ratchet = KeyPairX448::generate();
			let my_kyber_ratchet = KeyPairKyber::generate();
			let bundle = self.apis.fetch_prekey(nid, my_nid, auth_token).await?; // TODO: respect UserDoesNotExist + network errors

			if let Some(identity) = self.storage.get_identity_keys_for_nid(nid).await {
				if identity.x448 != bundle.identity.x448
					|| identity.kyber != bundle.identity.kyber
					|| identity.ed448 != bundle.identity.ed448
				{
					return Err(Error::IdentityDoesNotMatch);
				}
			} else {
				self.storage
					.save_identity_keys_for_nid(&bundle.identity, nid)
					.await;
			}

			let session = Session::alice(
				my_identity,
				my_ratchet,
				my_signing_identity,
				my_kyber_identity,
				my_kyber_ratchet,
				bundle.identity.x448,
				bundle.signed_prekey_x448,
				bundle.prekey_x448,
				bundle.prekey_kyber,
				bundle.identity.kyber,
				force_reset,
			);

			self.encrypt_with_session(session, plaintext, _type, nid)
				.await
		}
	}

	async fn encrypt_with_session(
		&self,
		mut session: Session,
		plaintext: &[u8],
		_type: Type,
		nid: &str,
	) -> Result<Vec<u8>, Error> {
		let ciphertext = session.encrypt(plaintext, _type);
		let id = session.id();
		let receive_only = session.receive_only();

		// can be session.receive_only instead of false (its guaranteed to be that way)
		self.storage
			.save_session(session, nid, id, receive_only)
			.await;
		// Desktop keeps restarting indefinitely if encrypt throws, but it can't fail now

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

	use super::*;
	use crate::prekey;
	use std::collections::{HashMap, HashSet, VecDeque};
	use std::sync::Mutex;

	struct NodeIdSecrets {
		x448_identity: KeyPairX448,
		ed448_identity: KeyPairEd448,
		kyber_identity: KeyPairKyber,

		prekeys: HashMap<u64, Prekey>,
		signed_prekey: SignedKeyPair,
	}

	type NodeIdData = (NodeIdSecrets, Vec<FetchedPrekeyBundle>);

	fn generate_node_id_data() -> NodeIdData {
		let ed448_identity = KeyPairEd448::generate();
		let secrets = NodeIdSecrets {
			x448_identity: KeyPairX448::generate(),
			ed448_identity: ed448_identity.clone(),
			kyber_identity: KeyPairKyber::generate(),

			prekeys: {
				let prekeys = prekey::generate(10, true);
				prekeys.into_iter().map(|x| (x.id(), x)).collect()
			},
			signed_prekey: {
				let key_pair = KeyPairX448::generate();
				let signature = ed448_identity
					.private_key()
					.sign(key_pair.public_key().as_bytes());

				SignedKeyPair::new(
					key_pair.private_key().clone(),
					SignedPublicKeyX448::new(key_pair.public_key().clone(), signature),
				)
			},
		};

		let prekey_bundles = secrets
			.prekeys
			.iter()
			.map(|(_, prekey)| {
				let bundle = FetchedPrekeyBundle {
					prekey_x448: prekey.key_x448.public_key().clone(),
					prekey_kyber: prekey.key_kyber.public_key().clone(),
					signed_prekey_x448: secrets.signed_prekey.public().clone(),
					identity: IdentityKeys {
						x448: secrets.x448_identity.public_key().clone(),
						ed448: secrets.ed448_identity.public_key().clone(),
						kyber: secrets.kyber_identity.public_key().clone(),
					},
				};
				bundle
			})
			.collect();

		(secrets, prekey_bundles)
	}

	struct TestStorageData {
		secrets: NodeIdSecrets,
		sessions_by_id: HashMap<u64, Session>,
		active_sessions: HashMap<String, u64>,
		receive_only_sessions: HashMap<String, HashSet<u64>>,
		identity_keys: HashMap<String, IdentityKeys>,
	}

	impl TestStorageData {
		pub fn new(secrets: NodeIdSecrets) -> Self {
			Self {
				secrets,
				sessions_by_id: HashMap::new(),
				active_sessions: HashMap::new(),
				receive_only_sessions: HashMap::new(),
				identity_keys: HashMap::new(),
			}
		}
	}

	struct TestStorage(Mutex<TestStorageData>);

	impl TestStorage {
		pub fn new(secrets: NodeIdSecrets) -> Self {
			Self(Mutex::new(TestStorageData::new(secrets)))
		}
	}

	impl super::Storage for TestStorage {
		fn get_active_session_for_nid(&self, nid: &str) -> Option<Session> {
			let data = self.0.lock().unwrap();
			data.active_sessions
				.get(nid)
				.and_then(|x| data.sessions_by_id.get(x).map(|x| x.clone()))
		}

		fn get_session_by_id(&self, _nid: &str, id: u64) -> Option<Session> {
			let data = self.0.lock().unwrap();
			data.sessions_by_id.get(&id).map(|x| x.clone())
		}

		fn clear_all_sessions_for_nid(&self, nid: &str) {
			let mut data = self.0.lock().unwrap();
			let active_session = data.active_sessions.remove(nid);
			let receive_only_sessions = data.receive_only_sessions.remove(nid);

			if let Some(session_id) = active_session {
				data.sessions_by_id.remove(&session_id);
			}
			if let Some(session_ids) = receive_only_sessions {
				for session_id in session_ids {
					data.sessions_by_id.remove(&session_id);
				}
			}
		}

		fn save_session(&self, session: Session, nid: &str, id: u64, receive_only: bool) {
			let mut data = self.0.lock().unwrap();
			if receive_only {
				let active_session_id = data.active_sessions.get(nid);
				if let Some(active_session_id) = active_session_id {
					if *active_session_id == id {
						data.active_sessions.remove(nid);
					}
				}
				data.receive_only_sessions
					.entry(nid.into())
					.or_default()
					.insert(id);
			} else {
				*data.active_sessions.entry(nid.into()).or_default() = id;
				data.receive_only_sessions
					.entry(nid.into())
					.or_default()
					.remove(&id);
			}
			use std::collections::hash_map::Entry::*;
			match data.sessions_by_id.entry(id) {
				Occupied(mut entry) => {
					entry.insert(session);
				}
				Vacant(entry) => {
					entry.insert(session);
				}
			}
		}

		fn get_my_x448_identity(&self) -> Option<KeyPairX448> {
			Some(self.0.lock().unwrap().secrets.x448_identity.clone())
		}
		fn get_my_ed448_identity(&self) -> Option<KeyPairEd448> {
			Some(self.0.lock().unwrap().secrets.ed448_identity.clone())
		}
		fn get_my_kyber_identity(&self) -> Option<KeyPairKyber> {
			Some(self.0.lock().unwrap().secrets.kyber_identity.clone())
		}

		fn get_identity_keys_for_nid(&self, nid: &str) -> Option<IdentityKeys> {
			let data = self.0.lock().unwrap();
			data.identity_keys.get(nid).map(|x| x.clone())
		}
		fn save_identity_keys_for_nid(&self, identity: &IdentityKeys, nid: &str) {
			let mut data = self.0.lock().unwrap();
			data.identity_keys
				.entry(nid.into())
				.or_insert_with(|| identity.clone());
		}

		fn get_prekey(&self, id: u64) -> Option<Prekey> {
			let data = self.0.lock().unwrap();
			data.secrets.prekeys.get(&id).map(|x| x.clone())
		}

		fn delete_prekey(&self, id: u64) {
			let mut data = self.0.lock().unwrap();
			data.secrets.prekeys.remove(&id);
		}

		fn get_signed_prekey(&self, _id: u64) -> Option<SignedKeyPair> {
			Some(self.0.lock().unwrap().secrets.signed_prekey.clone())
		}
	}

	struct TestApis {
		prekey_bundles: Mutex<HashMap<String, VecDeque<FetchedPrekeyBundle>>>,
	}

	impl TestApis {
		pub fn new(
			nid: &str,
			prekey_bundles: impl IntoIterator<Item = FetchedPrekeyBundle>,
		) -> Self {
			Self {
				prekey_bundles: Mutex::new(
					[(nid.into(), prekey_bundles.into_iter().collect())].into(),
				),
			}
		}
	}

	#[async_trait]
	impl super::Apis for TestApis {
		async fn fetch_prekey(
			&self,
			nid: &str,
			_auth_nid: &str,
			_auth_token: &str,
		) -> Result<FetchedPrekeyBundle, Error> {
			match self.prekey_bundles.lock().unwrap().get_mut(nid) {
				Some(ref mut bundles) => match bundles.pop_front() {
					Some(bundle) => Ok(bundle),
					None => Err(Error::NoPrekeyFound),
				},
				None => Err(Error::NoPrekeysForUser),
			}
		}
	}

	fn create_test_cryptors(
		node_id0: &str,
		node_id1: &str,
	) -> (
		Cryptor<TestStorage, TestApis>,
		Cryptor<TestStorage, TestApis>,
	) {
		let node_id_data = (generate_node_id_data(), generate_node_id_data());
		let node_storage = (
			TestStorage::new(node_id_data.0 .0),
			TestStorage::new(node_id_data.1 .0),
		);
		let node_apis = (
			TestApis::new(node_id1, node_id_data.1 .1),
			TestApis::new(node_id0, node_id_data.0 .1),
		);

		(
			Cryptor::new(Arc::new(node_storage.0), Arc::new(node_apis.0)),
			Cryptor::new(Arc::new(node_storage.1), Arc::new(node_apis.1)),
		)
	}

	// WARNING: this test fails with stack overflow on default stack size (2MB) in debug mode
	// In order to run tests properly you should do:
	// env RUST_MIN_STACK=4194304 cargo test
	#[tokio::test]
	async fn test_simultaneous_session_creation() {
		let peer0_nid = "abcdef01:1";
		let peer1_nid = "abcdef02:1";
		let (peer0, peer1) = create_test_cryptors(peer0_nid, peer1_nid);

		let before_peer0 = peer0
			.encrypt(b"before", Type::Chat, peer1_nid, peer0_nid, "token", false)
			.await
			.unwrap();
		let before_peer1 = peer1
			.encrypt(b"before", Type::Chat, peer0_nid, peer1_nid, "token", false)
			.await
			.unwrap();
		let before2_peer0 = peer0
			.encrypt(b"before2", Type::Chat, peer1_nid, peer0_nid, "token", false)
			.await
			.unwrap();
		let before2_peer1 = peer1
			.encrypt(b"before2", Type::Chat, peer0_nid, peer1_nid, "token", false)
			.await
			.unwrap();

		assert_eq!(
			peer1
				.decrypt(&before_peer0, peer0_nid, peer1_nid)
				.await
				.unwrap()
				.msg,
			b"before"
		);
		assert_eq!(
			peer0
				.decrypt(&before_peer1, peer1_nid, peer0_nid)
				.await
				.unwrap()
				.msg,
			b"before"
		);

		let after_peer0 = peer0
			.encrypt(b"after", Type::Chat, peer1_nid, peer0_nid, "token", false)
			.await
			.unwrap();
		let after_peer1 = peer1
			.encrypt(b"after", Type::Chat, peer0_nid, peer1_nid, "token", false)
			.await
			.unwrap();

		assert_eq!(
			peer1
				.decrypt(&after_peer0, peer0_nid, peer1_nid)
				.await
				.unwrap()
				.msg,
			b"after"
		);
		assert_eq!(
			peer0
				.decrypt(&after_peer1, peer1_nid, peer0_nid)
				.await
				.unwrap()
				.msg,
			b"after"
		);

		// Check out-of-order messages
		assert_eq!(
			peer1
				.decrypt(&before2_peer0, peer0_nid, peer1_nid)
				.await
				.unwrap()
				.msg,
			b"before2"
		);
		assert_eq!(
			peer0
				.decrypt(&before2_peer1, peer1_nid, peer0_nid)
				.await
				.unwrap()
				.msg,
			b"before2"
		);
	}
}
