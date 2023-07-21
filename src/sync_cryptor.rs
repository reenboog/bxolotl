use std::sync::Arc;

use prost::encoding::bool;

use crate::{
	job_queue,
	kyber::{
		self, DecryptionMode::Double, KeyBundle, KeyPairKyber, PrivateKeyKyber,
	},
	mac::AxolotlMac,
	message::Type,
	prekey::Prekey,
	serializable::{Deserializable, Serializable},
	session::{self, Session},
	x448::KeyPairX448,
};
use crate::cryptor::{Apis, Decrypted, Error, should_be_alice, Storage};

pub struct Cryptor<S, A> {
	storage: Arc<S>,
	apis: Arc<A>,
	tasks: job_queue::Queue<String>,
}

impl<S: Storage + Sync, A: Apis + Sync> Cryptor<S, A> {
	pub fn new(storage: Arc<S>, apis: Arc<A>) -> Self {
		Self {
			storage,
			apis,
			tasks: job_queue::Queue::new(),
		}
	}
}

impl<S: Storage + Sync, A: Apis + Sync> Cryptor<S, A> {
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
			if let Some(session) = self.storage.get_session_by_id(nid, kex.id()) {
				self.decrypt_with_session(session, mac, nid)
			} else {
				let identity = self
					.storage
					.get_my_x448_identity()
					.ok_or(Error::NoIdentityFound)?;
				let kyber_identity = self
					.storage
					.get_my_kyber_identity()
					.ok_or(Error::NoKyberIdentityFound)?;
				let signed_prekey = self
					.storage
					.get_signed_prekey(kex.signed_prekey_id)
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
					self.storage.clear_all_sessions_for_nid(nid);
					self.decrypt_with_session(session, mac, nid)
				} else {
					// do I have any other session for this nid?
					if let Some(current) = self.storage.get_active_session_for_nid(nid) {
						if current.role() == session::Role::Alice {
							if should_be_alice(my_nid, nid) {
								// the sender is considering herself Alice (but they'll fix themselves eventually), so keep
								// this session for some time in receive_only mode to decrypt their unacked (in terms of Axolotl) messages
								session.set_receive_only();

								self.decrypt_with_session(session, mac, nid)
							} else {
								// I was Alice, but at the same time some one initiated a session and I actually should be Bob
								// now, I'll delete my session and will use the new one
								self.storage.clear_all_sessions_for_nid(nid);
								self.decrypt_with_session(session, mac, nid)
							}
						} else {
							// I'm bob already, but from now on, I should be using this new session only
							self.storage.clear_all_sessions_for_nid(nid);
							self.decrypt_with_session(session, mac, nid)
						}
					} else {
						// this is a new and the only session, so proceed normally: decrypt, save, etc
						self.decrypt_with_session(session, mac, nid)
					}
				}
			}
		} else {
			if let Some(current) = self.storage.get_active_session_for_nid(nid) {
				// at this point, it could be save to delete any receive_only sessions, if any
				self.decrypt_with_session(current, mac, nid)
			} else {
				Err(Error::NoSessionFound)
			}
		}
	}

	fn decrypt_with_session(
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
				.save_session(session, nid, id, receive_only);

			// TODO: session itself could keep Option<prekey_id> and clear it per each decryption, if required
			if let Some(id) = mac
				.body()
				.key_exchange
				.as_ref()
				.and_then(|k| Some(k.x448_prekey_id))
			{
				self.storage.delete_prekey(id);
			}

			Ok(Decrypted {
				msg,
				_type: mac.body()._type,
			})
		} else {
			self.storage.clear_all_sessions_for_nid(nid);

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
			self.storage.clear_all_sessions_for_nid(nid);
		}

		if let Some(current) = self.storage.get_active_session_for_nid(nid) {
			self.encrypt_with_session(current, plaintext, _type, nid)
		} else {
			let my_identity = self
				.storage
				.get_my_x448_identity()
				.ok_or(Error::NoIdentityFound)?;
			let my_kyber_identity = self
				.storage
				.get_my_kyber_identity()
				.ok_or(Error::NoKyberIdentityFound)?;
			let my_signing_identity = self
				.storage
				.get_my_ed448_identity()
				.ok_or(Error::NoSigningIdentityFound)?;
			let my_ratchet = KeyPairX448::generate();
			let my_kyber_ratchet = KeyPairKyber::generate();
			let bundle = self.apis.fetch_prekey(nid, my_nid, auth_token).await?; // TODO: respect UserDoesNotExist + network errors

			if let Some(identity) = self.storage.get_identity_keys_for_nid(nid) {
				if identity.x448 != bundle.identity.x448
					|| identity.kyber != bundle.identity.kyber
					|| identity.ed448 != bundle.identity.ed448
				{
					return Err(Error::IdentityDoesNotMatch);
				}
			} else {
				self.storage
					.save_identity_keys_for_nid(&bundle.identity, nid);
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
		}
	}

	fn encrypt_with_session(
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
			.save_session(session, nid, id, receive_only);
		// Desktop keeps restarting indefinitely if encrypt throws, but it can't fail now

		return Ok(ciphertext.serialize());
	}
}