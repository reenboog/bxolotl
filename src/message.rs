use std::borrow::Borrow;
use crate::{key_exchange::KeyExchange, ntru::NtruEncryptedKey, x448::PublicKeyX448, serializable::{Serializable, Deserializable}, proto};

#[derive(Clone, Copy)]
pub enum MessageType {
	Chat, InterDevice
}

pub enum Error {
	BadFormat,
	NoCounter,
	NoPrevCounter,
	NoCiphertext,
	NoMessageType,
	UnknownType
}

// TODO: test
impl From<MessageType> for i32 {
	fn from(t: MessageType) -> Self {
		match t {
			MessageType::Chat => 0,
			MessageType::InterDevice => 1
		}
	}
}

// TODO: test
impl TryFrom<i32> for MessageType {
	type Error = Error;

	fn try_from(value: i32) -> Result<Self, Self::Error> {
		use MessageType::{Chat, InterDevice};

		match value {
			0 => Ok(Chat),
			1 => Ok(InterDevice),
			_ => Err(Error::UnknownType)
		}
	}
}

#[derive(Clone)]
pub struct Message {
	counter: u32,
	prev_counter: u32,
	// TODO: should it be optional? – yes, it's either ratchet_key or ntru_encrypted_ratchet_key
	ratchet_key: Option<PublicKeyX448>, // TODO: union/enum for ntru encrypted? TODO: introduce Cow?
	ntru_encrypted_ratchet_key: Option<NtruEncryptedKey>,
	ciphertext: Vec<u8>,
	key_exchange: Option<KeyExchange>,
	_type: MessageType, // TODO: rename
}

impl Message {
	pub fn new() -> Self {
		// TODO: implement
		todo!()
	}
}

impl From<&Message> for proto::CryptoMessage {
	fn from(src: &Message) -> Self {
		Self {
			ephemeral_key: src.ratchet_key.as_ref().map(|k| k.as_bytes().to_vec()),
			counter: Some(src.counter),
			previous_counter: Some(src.prev_counter),
			ciphertext: Some(src.ciphertext.clone()),
			key_exchange: src.key_exchange.as_ref().map(|kex| kex.into()),
			ntru_encrypted_ephemeral_key: src.ntru_encrypted_ratchet_key.as_ref().map(|k| k.into()),
			message_type: Some(i32::from(src._type))
		}
	}
}

// TODO: test
impl Serializable for Message {
	fn serialize(&self) -> Vec<u8> {
		use prost::Message;

		proto::CryptoMessage::from(self).encode_to_vec()
	}
}


impl TryFrom<proto::CryptoMessage> for Message {
	type Error = Error;

	fn try_from(value: proto::CryptoMessage) -> Result<Self, Self::Error> {
		Ok(Self {
			counter: value.counter.ok_or(Error::NoCounter)?,
			prev_counter: value.previous_counter.ok_or(Error::NoCounter)?,
			ratchet_key: todo!(), // TODO: introduce RatchetMode { raw, ntru_encrypted }?
			ntru_encrypted_ratchet_key: todo!(),
			ciphertext: value.ciphertext.ok_or(Error::NoCiphertext)?,
			key_exchange: todo!(), // TODO: convert
			_type: MessageType::try_from(value.message_type.ok_or(Error::NoMessageType)?)?
		})
	}
}

impl Deserializable for Message {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> {
		use prost::Message;

		Ok(Self::try_from(proto::CryptoMessage::decode(buf).or(Err(Error::BadFormat))?)?)
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

	pub fn ciphertext(&self) -> &[u8] {
		&self.ciphertext
	}

	pub fn set_ciphertext(&mut self, ct: &[u8]) {
		self.ciphertext = ct.to_vec();
	}
}

#[cfg(test)]
mod tests {
	use super::MessageType;

	#[test]
	fn test_message_serialize_deserialize() {
		todo!()
	}

	#[test]
	fn test_crypto_message_from_message() {
		todo!()
	}

	#[test]
	fn test_message_type_to_i32() {
		assert_eq!(i32::from(MessageType::Chat), 0);
		assert_eq!(i32::from(MessageType::InterDevice), 1);
	}
}