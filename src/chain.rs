use std::{collections::HashMap, mem, rc::Rc, borrow::Borrow};
use crate::{chain_key::{ChainKey}, message_key::MessageKey, x448::PublicKeyX448, ntru::KeyPairNtru};

pub const MAX_KEYS_TO_SKIP: u32 = 1000;

pub struct Next<'a> {
	parent: &'a mut Chain,
	counter: u32,
	keys_to_skip: HashMap<u32, Rc<MessageKey>>,
	chain_key: Rc<ChainKey>,
	message_key: Rc<MessageKey>
}

impl<'a> Next<'a> {
	fn new(parent: &'a mut Chain) -> Self {
		Self {
			keys_to_skip: HashMap::new(),
			counter: parent.next_counter(),
			chain_key: parent.chain_key(),
			message_key: Rc::new(parent.chain_key().message_key()),
			parent,
		}
	}

	fn counter(&self) -> u32 {
		self.counter
	}

	pub fn message_key(&self) -> &MessageKey {
		&self.message_key
	}

	fn advance(&mut self, counter: u32) {
		self.message_key = Rc::new(self.chain_key.message_key());

		if counter > self.counter {
			self.keys_to_skip.insert(self.counter, Rc::clone(&self.message_key));
		}

		self.chain_key = Rc::new(self.chain_key.next());
		self.counter += 1;
	}

	// Moves chain_key, keys_to_skip to parent, applies counter as next_counter and invalidates this Next
	// stage() -> [advance()] -> commit()
	pub fn commit(mut self) {
		self.parent.set_next_counter(self.counter);
		self.parent.set_chain_key(Rc::clone(&self.chain_key));

		mem::take(&mut self.keys_to_skip).into_iter().for_each(|(ctr, key)| {
			self.parent.insert_skipped_key(ctr, key);
		});
	}
}

#[derive(Debug)]
pub enum Error {
	TooManyKeysSkipped
}

#[derive(Debug, PartialEq)]
pub struct Chain {
	chain_key: Rc<ChainKey>,
	ratchet_key: PublicKeyX448, // used for id only
	ntru_ratchet_key: Option<KeyPairNtru>, // used for id only
	skipped_keys: HashMap<u32, Rc<MessageKey>>,
	next_counter: u32,
	max_keys_to_skip: u32
}

impl Chain {
	pub fn new(rk: PublicKeyX448, ck: ChainKey, max_keys: u32) -> Self {
		Self { 
			chain_key: Rc::new(ck),
			ratchet_key: rk, 
			ntru_ratchet_key: None, 
			skipped_keys: HashMap::new(), 
			next_counter: 0,
			max_keys_to_skip: max_keys
		}
	}
}

impl Chain {
	fn chain_key(&self) -> Rc<ChainKey> {
		Rc::clone(&self.chain_key)
	}

	fn set_chain_key(&mut self, ck: Rc<ChainKey>) {
		self.chain_key = ck;
	}
	// used for id mostly; TODO: replace with id()?
	pub fn ratchet_key(&self) -> &PublicKeyX448 {
		&self.ratchet_key
	}

	// used for id mostly
	pub fn ntru_ratchet_key(&self) -> &Option<KeyPairNtru> {
		&self.ntru_ratchet_key
	}

	pub fn set_ntru_ratchet_key(&mut self, key: KeyPairNtru) {
		self.ntru_ratchet_key = Some(key);
	}

	pub fn remove(&mut self, counter: u32) -> Option<Rc<MessageKey>> {
		self.skipped_keys.remove(&counter)
	}

	pub fn has_skipped_keys(&self) -> bool {
		!self.skipped_keys.is_empty()
	}

	pub fn next_counter(&self) -> u32 {
		self.next_counter
	}

	fn set_next_counter(&mut self, counter: u32) {
		self.next_counter = counter;
	}

	pub fn skipped_key(&self, counter: u32) -> Option<&MessageKey> {
		self.skipped_keys.get(&counter).map(|k| { k.borrow() })
	}

	// internal use only, so no need to check for max_keys_to_skip – `stage` will do the work
	fn insert_skipped_key(&mut self, counter: u32, key: Rc<MessageKey>) {
		self.skipped_keys.insert(counter, key);
	}

	pub fn stage(&mut self, purported_counter: u32) -> Result<Next, Error> {
		// the sender always attaches { counter, prev_count } to each message where prev_count can't
		// increase in the past: when a new ratchet is used, it throws away (= fixates prev_counter) the previous one
		let max_keys = self.max_keys_to_skip;
		let skipped_len = self.skipped_keys.len() as u32;
		let mut staged = Next::new(self);
		let keys_to_skip = purported_counter - staged.counter();

		if keys_to_skip + skipped_len >= max_keys {
			return Err(Error::TooManyKeysSkipped);
		}

		while purported_counter >= staged.counter() {
			staged.advance(purported_counter);
		}

		Ok(staged)
	}
}

#[cfg(test)]
mod tests {
	use std::rc::Rc;
	use crate::{x448::{PublicKeyX448, KeyTypeX448}, chain_key::ChainKey, key_pair::KeyPairSize, hmac::Key, message_key::MessageKey};
	use super::Chain;

	const RK: [u8; KeyTypeX448::PUB] = [42u8; KeyTypeX448::PUB];
	const CK: [u8; ChainKey::SIZE] = [11u8; ChainKey::SIZE];

	fn stub_chain() -> Chain {
		Chain::new(PublicKeyX448::from(&RK), ChainKey::new(Key::new(CK), 17), 9)
	}

	#[test]
	fn test_new() {
		let chain = stub_chain();

		assert_eq!(chain.chain_key().key().as_bytes().to_owned(), CK);
		assert_eq!(chain.ratchet_key().as_bytes().to_owned(), RK);
		assert!(chain.ntru_ratchet_key.is_none());
		assert!(!chain.has_skipped_keys());
		assert_eq!(chain.next_counter(), 0);
	}

	#[test]
	fn test_insert_remove_skipped_keys() {
		let mut chain = stub_chain();

		// should be empty by default
		assert!(!chain.has_skipped_keys());

		chain.insert_skipped_key(1, Rc::new(MessageKey::from(&[1u8; MessageKey::SIZE])));

		// lookup test
		assert!(chain.has_skipped_keys());
		assert!(chain.skipped_key(1).is_some());
		assert!(chain.skipped_key(2).is_none());

		chain.insert_skipped_key(2, Rc::new(MessageKey::from(&[2u8; MessageKey::SIZE])));

		assert!(chain.has_skipped_keys());
		assert!(chain.skipped_key(1).is_some());
		assert!(chain.skipped_key(2).is_some());
		assert!(chain.skipped_key(3).is_none());

		// remove non existing
		assert!(chain.remove(3).is_none());
		assert!(chain.has_skipped_keys());
		assert!(chain.skipped_key(1).is_some());
		assert!(chain.skipped_key(2).is_some());
		assert!(chain.skipped_key(3).is_none());

		// remove existing twice
		assert!(chain.remove(1).is_some());
		assert!(chain.remove(1).is_none());
		assert!(chain.has_skipped_keys());
		assert!(chain.skipped_key(1).is_none());
		assert!(chain.skipped_key(2).is_some());
		assert!(chain.skipped_key(3).is_none());

		// remove all and non existing
		(1..1000).collect::<Vec<_>>().into_iter().for_each(|i| { chain.remove(i); });

		assert!(!chain.has_skipped_keys());
	}

	#[test]
	fn test_stage() {
		// todo!()
	}

	#[test]
	fn test_too_many_keys_skipped() {
		// todo!()
		// TODO: tes too many, one key consumtion and then too many again (like in axolotl tests)
	}

	#[test]
	fn test_advance() {
		// todo!()
	}

	#[test]
	fn test_commit() {
		// todo!()
	}
}

mod serialize {
	use std::{rc::Rc, collections::HashMap};
	use prost::Message;
	use crate::{proto, serializable::{Serializable, Deserializable}, message_key::MessageKey, chain_key::ChainKey, x448::PublicKeyX448, ntru::KeyPairNtru};
	use super::{Chain, MAX_KEYS_TO_SKIP};

	#[derive(Debug)]
	pub enum Error {
		NoChainKey,
		WrongChainKeyLen,
		NoRatchetKey,
		WrongRatchetKeyLen,
		BadNtruKeyPair,
		NoSkippedKeys,
		BadFormat
	}

	impl From<&Chain> for proto::session_state::Chain {
		fn from(src: &Chain) -> Self {
			use proto::session_state::MessageKey as MK;

			let message_keys: Vec<MK> = src.skipped_keys.iter().map(|(k, v)| {
				let mut mk = MK::from(v.as_ref());

				mk.counter = Some(*k);
				mk
			}).collect();

			Self {
				ratchet_key: Some(src.ratchet_key().as_bytes().to_vec()),
				chain_key: Some(src.chain_key().as_ref().into()),
				message_keys,
				next_counter: Some(src.next_counter),
				ratchet_ntru_key_pair: src.ntru_ratchet_key().as_ref().map(|k| k.serialize()) // TODO: concat instead of serialize?
			}
		}
	}

	impl Serializable for Chain {
		fn serialize(&self) -> Vec<u8> {
			proto::session_state::Chain::from(self).encode_to_vec()
		}
	}

	impl TryFrom<proto::session_state::Chain> for Chain {
		type Error = Error;

		fn try_from(value: proto::session_state::Chain) -> Result<Self, Self::Error> {
			let skipped_keys = value.message_keys
				.into_iter()
				.filter_map(|k| {
					k.counter.and_then(|c| {
						MessageKey::try_from(k).ok().map(|mk| {
							(c, Rc::new(mk))
						})
					})
				})
				.collect::<HashMap<u32, Rc<MessageKey>>>();

			Ok(Self {
				chain_key: Rc::new(ChainKey::try_from(value.chain_key.ok_or(Error::NoChainKey)?).or(Err(Error::WrongChainKeyLen))?),
				ratchet_key: PublicKeyX448::try_from(value.ratchet_key.ok_or(Error::NoRatchetKey)?).or(Err(Error::WrongRatchetKeyLen))?,
				ntru_ratchet_key: value.ratchet_ntru_key_pair.map_or(Ok(None), |kp| Ok(Some(KeyPairNtru::deserialize(&kp).or(Err(Error::BadNtruKeyPair))?)))?,
				skipped_keys,
				next_counter: value.next_counter.unwrap_or(0),
				max_keys_to_skip: MAX_KEYS_TO_SKIP // doesn't need to be persisted
			})
		}
	}

	impl Deserializable for Chain {
		type Error = Error;

		fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> where Self: Sized {
			Self::try_from(proto::session_state::Chain::decode(buf).or(Err(Error::BadFormat))?)
		}
	}

	#[cfg(test)]
	mod tests {
    use crate::{chain::{Chain, MAX_KEYS_TO_SKIP}, x448::KeyPairX448, chain_key::ChainKey, hmac, serializable::{Serializable, Deserializable}};

		#[test]
		fn serialize_deserialize() {
			let kp = KeyPairX448::generate();
			let ck = ChainKey::new(hmac::Key::new([123u8; hmac::Key::SIZE]), 117);
			let ch = Chain::new(kp.public_key().to_owned(), ck, MAX_KEYS_TO_SKIP);
			let serialized = ch.serialize();
			let deserialized = Chain::deserialize(&serialized).unwrap();

			assert_eq!(deserialized, ch);
		}
	}
}