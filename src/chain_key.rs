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
		let material = Hkdf::from_ikm(mk.as_bytes()).expand::<{MessageKey::SIZE}>(SEED);

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
		let input = b"\xa1\x2e\x38\xd4\x89\xc3\xa1\x2e\x38\xd4\x89\xc3\xa1\x2e\x38\xd4\x89\xc3\xa1\x2e\x38\xd4\x89\xc3\xa1\x2e\x38\xd4\x89\xc3\xa1\x2e";
		let ck = ChainKey::new(Key::new(input.to_owned()), 0);
		let mk = ck.message_key();

		assert_eq!(mk.enc_key().as_bytes().to_vec(), b"\xbb\x9e\xc1\x31\x6b\x5d\xcd\xaf\x5b\xf3\xc8\x76\x40\x4e\x43\x90\xeb\xef\xb0\x1f\x02\xb5\x91\x35\xfe\xa1\x71\x6b\xfb\x2c\x9e\x66");
		assert_eq!(mk.mac_key().as_bytes().to_vec(), b"\xe6\x7f\x6f\x12\xa9\x56\x2d\x87\x66\x97\x4f\xe5\xb5\xc8\x41\xbc\x9a\x86\x42\x96\xa3\xdf\x20\x02\x3b\x89\x19\x4e\x24\xae\xe8\x5c");
		assert_eq!(mk.iv().as_bytes().to_vec(), b"\x10\xd1\x9f\x83\xfc\xbe\x2c\xa5\x46\x37\xe9\x45\x6c\x17\x3b\xc5");
	
		let next = ck.next();
		let mk = next.message_key();
		
		assert_eq!(mk.enc_key().as_bytes().to_vec(), b"\x23\xbe\x45\x22\xdc\x40\xdd\xda\x60\x57\xf5\xba\xf1\x80\x65\xc1\xd2\x64\x1c\xda\x1c\xb3\x6f\x2f\x9e\x65\x7e\xbe\xba\x45\x15\x2a");
		assert_eq!(mk.mac_key().as_bytes().to_vec(), b"\xf6\x99\xf4\x39\x68\x37\xbd\x52\x0c\xf0\x35\x0b\xeb\xb5\xf9\xa7\xb3\xaf\xe1\xb8\x82\x22\xe0\xb4\x38\x23\x1a\x4f\xad\xe5\xcc\x95");
		assert_eq!(mk.iv().as_bytes().to_vec(), b"\xb0\x4e\x6a\xcc\x8f\xa0\x47\xee\x95\x34\xb4\x71\xcf\x6e\x16\xcb");
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