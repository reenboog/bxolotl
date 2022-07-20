use crate::{chain_key::ChainKey, root_key::RootKey, receive_chain::ReceiveChain, key_exchange::KeyExchange, hmac::Digest, signed_public_key::{SignedPublicKeyX448}, signed_key_pair::{SignedKeyPairX448}, master_key::{MasterKey}, message::{Message, Type}, ntru::{self, NtruEncrypted, NtruEncryptedKey, NtruedKeys, KeyPairNtru, PublicKeyNtru, PrivateKeyNtru}, serializable::{Serializable, Deserializable, self}, chain::{Chain, self}, message_key, x448::{KeyPairX448, PublicKeyX448}, ed448::KeyPairEd448};

pub const RATCHETS_BETWEEN_NTRU: u32 = 20;

enum Role {
	Alice, Bob
}

#[derive(Debug)]
enum Error {
	WrongNtruIdentity,
	UnknownNtruRatchet,
	NtruBadEncoding,
	NtruBadAesParams,
	NtruBadEphemeralKey,
	NtruWrongKey,
	NoRatchetSupplied,
	SkippedKeyMissing,
	NewCounterForOldChain,
	NewChainRequired,
	NoCurrentChain,
	NoLocalRatchet,
	NoLocalNtru,
	TooManyKeySkipped,
	WrongAesMaterial
}

// TODO: test
impl From<ntru::Error> for Error {
	fn from(err: ntru::Error) -> Self {
		match err {
			ntru::Error::DecodeError => Self::NtruBadEncoding,
			ntru::Error::WrongKey => Self::NtruWrongKey,
			ntru::Error::BadAesParams => Self::NtruBadAesParams,
			ntru::Error::WrongEphKeyLen => Self::NtruBadAesParams,  // TODO: a dedicated error?
			ntru::Error::WrongNtruKeyLen => Self::NtruBadAesParams,
			ntru::Error::BadNtruedFormat => Self::NtruBadEphemeralKey,
			ntru::Error::BadNtruEncryptedFormat => Self::NtruBadEphemeralKey,
			ntru::Error::BadNtruEncryptedKeyFormat => Self::NtruBadEphemeralKey,
			ntru::Error::WrongNtruIdentity => Self::WrongNtruIdentity,
			ntru::Error::UnknownNtruRatchet => Self::UnknownNtruRatchet, // TODO: a dedicated error?
		}
	}
}

impl From<message_key::Error> for Error {
	fn from(_: message_key::Error) -> Self {
		Self::WrongAesMaterial
	}
}

impl From<chain::Error> for Error {
	fn from(_: chain::Error) -> Self {
		Self::TooManyKeySkipped
	}
}

struct Session {
	id: u64,
	role: Role,

	counter: u32,
	prev_counter: u32, // prev sending chain len?
	ratchet_counter: u32,

	// saved for Bob only, alice uses her ntru_ratched instead; FIXME: move to Role? 
	my_ntru_identity: Option<KeyPairNtru>,

	// TODO: these two can be made non optional, if instead of resetting on decrypt a new ratched is generated
	my_ratchet: Option<KeyPairX448>, 
	my_ntru_ratchet: Option<KeyPairNtru>,

	// can be initially nil for Bob (until decrypt, plus, it can be ntru-encrypted itself)
	their_ratchet: Option<PublicKeyX448>,
	their_ratchet_ntru: PublicKeyNtru,

	unacked_key_exchange: Option<KeyExchange>, // FIXME: move to Role?

	alice_base_ephemeral_key: Option<PublicKeyX448>, // TODO: rather store base_key_id, for it's only used; move to Role

	root_key: RootKey,
	// TODO: can be made non optional if root_key is initialized in either alice/bob instead of encrypt as is now
	send_chain_key: Option<ChainKey>, 
	receive_chain: ReceiveChain
}

pub struct AxolotlMac {
	body: Message,
	mac: Digest
}

impl AxolotlMac {
	pub fn new(body: &Message, mac: &Digest) -> Self {
		Self { body: body.clone(), mac: mac.clone() }
	}

	pub fn body(&self) -> &Message {
		&self.body
	}

	pub fn mac(&self) -> &Digest {
		&&self.mac
	}
}

impl Serializable for AxolotlMac {
	fn serialize(&self) -> Vec<u8> {
			todo!()
	}
}

impl Session {
	pub fn alice(my_identity: KeyPairX448, 
		my_ephemeral: KeyPairX448,
		my_signing_identity: KeyPairEd448,
		my_ntru_identity: KeyPairNtru,
		my_ntru_ratchet: KeyPairNtru,
		their_identity: PublicKeyX448,
		their_signed_prekey: SignedPublicKeyX448,
		their_prekey: PublicKeyX448,
		their_ntru_prekey: PublicKeyNtru,
		their_ntru_identity: PublicKeyNtru) -> Self {
			
			let id = Self::derive_id(my_identity.public_key(), my_ephemeral.public_key(), &their_identity, &their_prekey);
			let master_key = MasterKey::alice(&my_identity, &my_ephemeral, &their_identity, &their_signed_prekey, &their_prekey);
			let key_exchange = KeyExchange {
				x448_identity: my_identity.public_key().clone(),
				ntru_encrypted_ephemeral: ntru::encrypt_ephemeral(my_ephemeral.public_key(), my_ntru_ratchet.public_key(), ntru::EncryptionMode::Double { first_key: &their_ntru_prekey, second_key: &their_ntru_identity }),
				ntru_identity: my_ntru_identity.public_key().clone(),
				ed448_identity: my_signing_identity.public_key().clone(),
				signed_prekey_id: their_signed_prekey.key().id(),
				x448_prekey_id: their_prekey.id()
			};

			Self { id,
				role: Role::Alice,
				counter: 0,
				prev_counter: 0,
				ratchet_counter: 0,
				my_ntru_identity: Some(my_ntru_identity),
				my_ratchet: None,
				my_ntru_ratchet: Some(my_ntru_ratchet),
				their_ratchet: Some(their_prekey),
				their_ratchet_ntru: their_ntru_prekey,
				unacked_key_exchange: Some(key_exchange),
				alice_base_ephemeral_key: None, // REVIEW: move to role? It makes sense for Bob only anyway
				root_key: master_key.root_key().clone(),
				send_chain_key: None, 
				receive_chain: ReceiveChain::new() // REVIEW: make optional?
			}
	}

	pub fn bob(my_identity: KeyPairX448,
		my_ntru_identity: KeyPairNtru,
		my_signed_prekey: SignedKeyPairX448,
		my_prekey: KeyPairX448,
		my_ntru_prekey: KeyPairNtru,
		their_identity: PublicKeyX448,
		their_ephemeral: PublicKeyX448,
		their_ratchet_ntru: PublicKeyNtru) -> Self {
			let id = Self::derive_id(&their_identity, &their_ephemeral, my_identity.public_key(), my_prekey.public_key());
			let master_key = MasterKey::bob(&my_identity, &my_signed_prekey, &my_prekey, &their_identity, &their_ephemeral);

			Self { id,
				role: Role::Bob, 
				counter: 0, 
				prev_counter: 0, 
				ratchet_counter: 0,
				my_ntru_identity: Some(my_ntru_identity), 
				my_ratchet: Some(my_prekey), 
				my_ntru_ratchet: Some(my_ntru_prekey),
				their_ratchet: None, 
				their_ratchet_ntru: their_ratchet_ntru, 
				unacked_key_exchange: None,
				alice_base_ephemeral_key: Some(their_ephemeral), 
				root_key: master_key.root_key().clone(),
				send_chain_key: None, // REVIEW: master_key.chain_key? –rather not, for it's not used until encrypt
				receive_chain: ReceiveChain::new() 
			}
	}

	fn derive_id(alice_identity: &PublicKeyX448,
		alice_ephemeral: &PublicKeyX448,
		bob_identity: &PublicKeyX448,
		bob_prekey: &PublicKeyX448) -> u64 {
			// TODO: implement
			// TODO: test
			// const auto buffer = concat_bytes({ alice_identity.key(), alice_ephemeral.key(), bob_identity.key(), bob_prekey.key() });
			// return bytes_to_long(buffer);
			// let bytes = alice_identity.as_bytes() + alice_ephemeral.as_bytes();
			// TODO: introduce a helper method or trait
			// u64::from_be_bytes(Sha256::digest(bytes).to_vec()[..8].try_into().unwrap())
			todo!();
	}
}

impl Session {
	// TODO: return result
	pub fn encrypt(&mut self, plaintext: &[u8], message_type: Type) -> AxolotlMac {
		if self.my_ratchet.is_none() {
			if self.ratchet_counter == RATCHETS_BETWEEN_NTRU {
				self.ratchet_counter = 0;
				self.my_ntru_ratchet = Some(KeyPairNtru::generate()); // TODO: don't generate, but inject instead
			}

			self.ratchet_counter = self.ratchet_counter + 1;
			self.my_ratchet = Some(KeyPairX448::generate()); // TODO: don't generate, but inject instead

			// REVIEW: do I need MasterKey at all?
			// TODO: don't hard unwrap
			let (ck, rk) = MasterKey::derive(&self.root_key, &self.my_ratchet.as_ref().unwrap(), &self.their_ratchet.as_ref().unwrap()).into(); 

			self.send_chain_key = Some(ck);
			self.root_key = rk;

			self.prev_counter = self.counter;
			self.counter = 0;
		}

		let mut msg = Message::new(message_type);

		if let Some(ref my_ntru_ratchet) = self.my_ntru_ratchet {
			// TODO: don't hard unwrap
			msg.set_ntru_encrypted_ratchet_key(ntru::encrypt_ephemeral(self.my_ratchet.as_ref().unwrap().public_key(), my_ntru_ratchet.public_key(), ntru::EncryptionMode::Once { key: &self.their_ratchet_ntru }));
		} else {
			msg.set_ratchet_key(self.my_ratchet.as_ref().unwrap().public_key().clone());
		}

		msg.set_counter(self.counter);
		msg.set_prev_counter(self.prev_counter);
		msg.set_key_exchange(self.unacked_key_exchange.clone());

		// TODO: don't hard unwrap
		let mk = self.send_chain_key.as_ref().unwrap().message_key(); 
		let mac = mk.encrypt(plaintext, &mut msg);

		self.counter = self.counter + 1;
		// TODO: don't hard unwrap
		self.send_chain_key = Some(self.send_chain_key.as_ref().unwrap().next());

		mac
	}

	fn decrypt_ntru_encrypted_ratchet<'a>(&'a self, eph: &NtruEncryptedKey) -> Result<NtruedKeys, Error> {
		use ntru::DecryptionMode::{Once, Double};

		let find_key = |id| -> Result<&PrivateKeyNtru, ntru::Error> {
			// TODO: check key id? it'll fail decrypting anyway, if somethign goes wrong
			Ok(self.receive_chain.ntru_key_pair(id).or(self.my_ntru_ratchet.as_ref()).ok_or(ntru::Error::UnknownNtruRatchet)?.private_key())
		};

		if eph.double_encrypted {
			// second key is the outer key, while the first key is the inner one, ie `encrypt(encrypt(data, first), second)
			let second_key = self.my_ntru_identity.as_ref().ok_or(Error::NoLocalNtru)?.private_key();

			Ok(ntru::decrypt_ephemeral(eph, Double { second_key, first_key: Box::new(find_key) })?)
		} else {
			Ok(ntru::decrypt_ephemeral::<ntru::KeySource>(eph, Once { key: find_key(eph.payload.encryption_key_id)? })?)
		}
	}

	fn decrypt_with_current_or_past_chain(&mut self, mac: &AxolotlMac, purported_ratchet: &PublicKeyX448) -> Result<Option<Vec<u8>>, Error> {
		// TODO: introduce Chain.id()
		if let Some(current) = self.receive_chain.current().map(|c| c.ratchet_key().id()) {
			if let Some(chain) = self.receive_chain.chain_mut(purported_ratchet) {
				let counter = mac.body.counter();

				if counter < chain.next_counter() {
					let skipped = chain.skipped_key(counter).ok_or(Error::TooManyKeySkipped)?;
					let decrypted = skipped.decrypt(mac)?;

					chain.remove(counter);

					// TODO: introduce Chain.id()
					if current != chain.ratchet_key().id() && !chain.has_skipped_keys() {
						self.receive_chain.remove_by_ratchet_key_id(current);
					}

					return Ok(Some(decrypted));
				} else {
					// TODO: introduce Chain.id()
					if chain.ratchet_key().id() != current {
						return Err(Error::NewCounterForOldChain);
					} else {
						let mut next = chain.stage(counter)?;
						let mk = next.message_key();
						let decrypted = mk.decrypt(mac)?;

						next.commit();

						return Ok(Some(decrypted));
					}
				}
			}
		}

		// no chain found -> create a new ratchet
		Ok(None)
	}

	// TODO: return Result
	pub fn decrypt(&mut self, mac: &AxolotlMac) -> Result<Vec<u8>, Error> {
		let msg = mac.body();
		let purported_ratchet: PublicKeyX448; // TODO: can I get rid of this?
		let purported_ntru_ratchet: PublicKeyNtru; // TODO: can I get rid of this?

		if let Some(ntru_encrypted_ratchet) = msg.ntru_encrypted_ratchet_key() {
			let NtruedKeys { ephemeral, ntru } = self.decrypt_ntru_encrypted_ratchet(ntru_encrypted_ratchet)?;

			purported_ratchet = ephemeral;
			purported_ntru_ratchet = ntru;
		} else {
			purported_ratchet = msg.ratchet_key().ok_or(Error::NoCurrentChain)?.clone();
			purported_ntru_ratchet = self.their_ratchet_ntru.clone();
		}

		// TODO: switch instead
		if let Ok(Some(decrypted)) = self.decrypt_with_current_or_past_chain(mac, &purported_ratchet) {
			return Ok(decrypted);
		}

		let my_ratchet = self.my_ratchet.as_ref().ok_or(Error::NoLocalRatchet)?;

		// the sender used this ratchet for the 1st time, so let's dh-rotate
		let (ck, rk) = MasterKey::derive(&self.root_key, my_ratchet, &purported_ratchet).into();
		let current = self.receive_chain.current_mut();
		let mut new_chain = Chain::new(purported_ratchet.clone(), ck, chain::MAX_KEYS_TO_SKIP);

		if let Some(ref my_ntru) = self.my_ntru_ratchet {
			new_chain.set_ntru_ratchet_key(my_ntru.clone());
		} else if let Some(ref current) = current {
			new_chain.set_ntru_ratchet_key(current.ntru_ratchet_key().as_ref().unwrap().clone()); // TODO: don't hard unwrap
		}

		let mut next = new_chain.stage(msg.counter()).unwrap(); // TODO: don't hard unwrap

		let decrypted = next.message_key().decrypt(mac)?;
		next.commit();

		if let Some(current) = current {
			current.stage(msg.prev_counter()).unwrap().commit(); // TODO: don't hard unwrap
		}

		self.receive_chain.set_current(new_chain);

		self.root_key = rk;
		self.their_ratchet = Some(purported_ratchet);
		self.their_ratchet_ntru = purported_ntru_ratchet;
		self.my_ratchet = None;
		self.my_ntru_ratchet = None;
		self.unacked_key_exchange = None;

		Ok(decrypted)
	}
}

#[test]
fn test_fail_when_skipped_too_many_keys() {
	todo!()
}

#[cfg(test)]
mod tests {
	#[test]
	fn derive_id() {
		todo!()
	}

	#[test]
	fn test_encrypt() {

	}
}