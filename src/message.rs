use std::borrow::Borrow;

use crate::{key_exchange::KeyExchange, key_pair::PublicKeyX448, ntru::NtruEncryptedKey};

pub enum MessageType {
	Chat, InterDevice
}

pub struct Message {
	counter: u32,
	prev_counter: u32,
	// TODO: should it be optional? – yes, it's either ratchet_key or ntru_encrypted_ratchet_key
	ratchet_key: Option<PublicKeyX448>, // TODO: union/enum for ntru encrypted? TODO: introduce Cow?
	ntru_encrypted_ratchet_key: Option<NtruEncryptedKey>,
	ciphr_text: Vec<u8>, // TODO: introduce a type?
	key_exchange: Option<KeyExchange>,
	_type: MessageType, // TODO: rename
}

impl Message {
	pub fn new() -> Self {
		// TODO: implement
		todo!()
	}
}

impl Message {
	// set_ephemeral_key
	pub fn set_ratchet_key(&mut self, key: PublicKeyX448) {
		self.ratchet_key = Some(key);
	}

	pub fn ratchet_key(&self) -> Option<&PublicKeyX448> {
		self.ratchet_key.borrow().as_ref()
	}

	// set_allocated_ntru_encrypted_ephemeral_key
	// TODO: combine with set_ratchet via an enum?
	pub fn set_ntru_encrypted_ratchet_key(&mut self, key: NtruEncryptedKey) {
		self.ntru_encrypted_ratchet_key = Some(key);
	}

	pub fn ntru_encrypted_ratchet_key(&self) -> Option<&NtruEncryptedKey> {
		self.ntru_encrypted_ratchet_key.borrow().as_ref()
	}

	pub fn set_counter(&mut self, ctr: u32) {
		self.counter = ctr;
	}

	pub fn counter(&self) -> u32 {
		self.counter
	}

	pub fn set_prev_counter(&mut self, ctr: u32) {
		self.prev_counter = ctr;
	}

	pub fn prev_counter(&self) -> u32 {
		self.prev_counter
	}

	pub fn set_type(&mut self, t: MessageType) {
		self._type = t;
	}

	pub fn set_key_exchange(&mut self, kex: Option<KeyExchange>) {
		self.key_exchange = kex;
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn it_workd() {
		todo!()
	}
}