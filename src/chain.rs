use std::{collections::HashMap, mem, rc::Rc, borrow::Borrow};
use crate::{key_pair::{PublicKeyX448, KeyPairNtru}, chain_key::{ChainKey}, message_key::MessageKey};

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
		self.counter = self.counter + 1;
	}

	// Moves chain_key, keys_to_skip to parent, applies counter as next_counter and invalidates this Next
	// stage() -> [advance()] -> commit()
	pub fn commit(&mut self) {
		self.parent.set_next_counter(self.counter);
		self.parent.set_chain_key(Rc::clone(&self.chain_key));

		mem::replace(&mut self.keys_to_skip, HashMap::new()).into_iter().for_each(|(ctr, key)| {
			self.parent.insert_skipped_key(ctr, key);
		});

		drop(self);
	}
}

#[derive(Debug)]
pub enum Error {
	TooManyKeysSkipped
}

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

	pub fn remove(&mut self, counter: u32) {
		self.skipped_keys.remove(&counter);
	}

	pub fn has_skipped_keys(&self) -> bool {
		self.skipped_keys.len() > 0
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

	fn insert_skipped_key(&mut self, counter: u32, key: Rc<MessageKey>) {
		self.skipped_keys.insert(counter, key);
	}

	pub fn stage(&mut self, purported_counter: u32) -> Result<Next, Error> {
		let max_keys = self.max_keys_to_skip;
		let mut staged = Next::new(self);
		let keys_to_skip = purported_counter - staged.counter();

		if keys_to_skip >= max_keys {
			return Err(Error::TooManyKeysSkipped);
		}

		while purported_counter >= staged.counter() {
			staged.advance(purported_counter);
		}

		return Ok(staged);
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn it_works() {
		todo!()
	}

	#[test]
	fn test_get_set_ratchet_key() {
		todo!()
	}

	#[test]
	fn test_get_set_ntru_ratchet_key() {
		todo!()
	}

	#[test]
	fn test_has_skipped_keys() {
		todo!()
	}

	#[test]
	fn test_remove_key() {
		todo!()
	}

	#[test]
	fn test_get_next_counter() {
		todo!()
	}

	#[test]
	fn test_stage() {
		todo!()
	}

	#[test]
	fn test_too_many_keys_skipped() {
		todo!()
	}

	#[test]
	fn test_advance() {
		todo!()
	}

	#[test]
	fn test_commit() {
		todo!()
	}
}