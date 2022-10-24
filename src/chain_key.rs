use crate::hkdf::Hkdf;
use crate::message_key::MessageKey;
use crate::serializable::{Serializable, Deserializable};
use crate::{hmac, proto};
use prost::Message;

#[derive(Debug, PartialEq)]
pub struct ChainKey {
	key: hmac::Key,
	counter: u32
}

#[derive(Debug, PartialEq)]
pub enum Error {
	NoKey,
	WrongKeyLen,
	NoCounter,
	BadFormat
}

const SEED: &[u8] = b"SecureMessenger";

impl ChainKey {
	pub const SIZE: usize = 32;

	pub fn new(key: hmac::Key, counter: u32) -> Self {
		Self { key, counter }
	}

	pub fn key(&self) -> &hmac::Key {
		&self.key
	}

	pub fn counter(&self) -> u32 {
		self.counter
	}

	pub fn message_key(&self) -> MessageKey {
		let mk = hmac::digest(&self.key, b"0");
		let material = Hkdf::new(mk).expand::<{MessageKey::SIZE}>(SEED);

		(&material).into()
	}

	pub fn next(&self) -> Self {
		Self::new(hmac::digest(&self.key, b"1").into(), self.counter + 1)
	}
}

impl From<&ChainKey> for proto::session_state::ChainKey {
	fn from(ck: &ChainKey) -> Self {
		Self {
			counter: Some(ck.counter),
			key: Some(ck.key.as_bytes().to_vec())
		}
	}
}

impl Serializable for ChainKey {
	fn serialize(&self) -> Vec<u8> {
		proto::session_state::ChainKey::from(self).encode_to_vec()
	}
}

impl TryFrom<proto::session_state::ChainKey> for ChainKey {
	type Error = Error;

	fn try_from(ck: proto::session_state::ChainKey) -> Result<Self, Self::Error> {
		Ok(Self {
			key: hmac::Key::try_from(ck.key.ok_or(Error::NoKey)?).or(Err(Error::WrongKeyLen))?,
			counter: ck.counter.ok_or(Error::NoCounter)?
		})
	}
}

impl Deserializable for ChainKey {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> where Self: Sized {
		Self::try_from(proto::session_state::ChainKey::decode(buf).or(Err(Error::BadFormat))?)
	}
}

#[cfg(test)]
mod tests {
	use super::{ChainKey, Error};
	use crate::{hmac::Key, serializable::{Serializable, Deserializable}};

	#[test]
	fn test_message_key() {
		let ck0 = ChainKey::new(Key::new([1u8; Key::SIZE]), 123);
		let mk0 = ck0.message_key();

		assert_eq!(mk0.enc_key().0, b"\x3b\x61\x92\x07\x04\x6d\x48\xd5\xcf\x15\x67\x9e\x25\x3a\xba\x7c\x7d\xd6\xfc\xcd\x5b\xdb\x9d\xb4\x47\x14\x25\x12\xcf\x1b\x35\x8a".to_owned());
		assert_eq!(mk0.mac_key().as_bytes(), b"\x1e\xd0\xba\x42\x8f\x2b\x3f\x93\xfc\x13\x6d\x3c\x0c\x89\xf6\x91\x39\xba\x1f\x00\x75\x9d\x61\x8a\x9d\xf5\x54\xfa\xa9\x46\x78\xbb");
		assert_eq!(mk0.iv().0, b"\xd2\x12\x6a\x28\x8e\x9e\xea\x4b\x72\x9e\x00\xff\x4f\x1e\xbd\x5c".to_owned());

		// different key -> different message key
		let ck1 = ChainKey::new(Key::new([2u8; Key::SIZE]), 123);
		let mk1 = ck1.message_key();

		assert_ne!(mk0.enc_key().0, mk1.enc_key().0);
		assert_ne!(mk0.mac_key().as_bytes(), mk1.mac_key().as_bytes());
		assert_ne!(mk0.iv().0, mk1.iv().0);
	}

	#[test]
	fn test_next() {
		let ck0 = ChainKey::new(Key::new([1u8; Key::SIZE]), 123);
		let next0 = ck0.next();

		assert_eq!(next0.counter, 124);
		assert_eq!(next0.key.as_bytes(), b"\x51\x0c\x69\x0a\xa8\x7a\x90\x0f\xee\x5f\x4f\x2b\x05\x15\x49\x59\x97\xba\x30\x3b\xbb\x6d\x48\x01\x24\x30\xac\xe0\x06\x11\x5c\x7e");

		// different key -> different next
		let ck1 = ChainKey::new(Key::new([2u8; Key::SIZE]), 123);
		let next1 = ck1.next();

		assert_eq!(next0.counter, next1.counter);
		assert_ne!(next0.key, next1.key);
	}

	#[test]
	fn test_serialize_deserialize() {
		let ck = ChainKey::new(Key::new([19u8; Key::SIZE]), 1984);
		let deserialized = ChainKey::deserialize(&ck.serialize());

		assert_eq!(Ok(ck), deserialized);
	}

	#[test]
	fn test_try_from() {
		use crate::proto::session_state::ChainKey as ProtoCK;

		assert_eq!(ChainKey::try_from(
			ProtoCK { counter: None, key: Some(Key::new([22u8; Key::SIZE]).as_bytes().to_vec()) }
		).err(), Some(Error::NoCounter));

		assert_eq!(ChainKey::try_from(
			ProtoCK { counter: Some(42), key: Some([22u8; 10].to_vec()) }
		).err(), Some(Error::WrongKeyLen));

		assert_eq!(ChainKey::try_from(
			ProtoCK { counter: Some(17), key: None }
		).err(), Some(Error::NoKey));

		let valid = ProtoCK {
			counter: Some(63),
			key: Some([22u8; Key::SIZE].to_vec())
		};

		assert_eq!(valid.counter, Some(63));
		assert_eq!(valid.key, Some([22u8; Key::SIZE].to_vec()));
	}

	#[test]
	fn test_deserialize_errors() {
		use crate::proto::session_state::ChainKey as ProtoCK;
		use prost::Message;

		assert_eq!(ChainKey::deserialize(
			&ProtoCK { counter: None, key: Some(Key::new([22u8; Key::SIZE]).as_bytes().to_vec()) }.encode_to_vec()
		).err(), Some(Error::NoCounter));

		assert_eq!(ChainKey::deserialize(
			&ProtoCK { counter: Some(42), key: Some([22u8; 10].to_vec()) }.encode_to_vec()
		).err(), Some(Error::WrongKeyLen));

		assert_eq!(ChainKey::deserialize(
			&ProtoCK { counter: Some(17), key: None }.encode_to_vec()
		).err(), Some(Error::NoKey));

		assert_eq!(ChainKey::deserialize(b"abra cadabra").err(), Some(Error::BadFormat));
	}
}