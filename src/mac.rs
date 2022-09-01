use crate::{message::Message, hmac::Digest, proto, serializable::{Serializable, Deserializable}};

pub struct AxolotlMac {
	body: Message,
	mac: Digest
}

impl AxolotlMac {
	pub fn new(body: &Message, mac: &Digest) -> Self {
		Self { body: body.clone(), mac: *mac }
	}

	pub fn body(&self) -> &Message {
		&self.body
	}

	pub fn set_mac(&mut self, mac: Digest) {
		self.mac = mac
	}

	pub fn mac(&self) -> &Digest {
		&self.mac
	}
}

impl From<&AxolotlMac> for proto::AxolotlMac {
	fn from(src: &AxolotlMac) -> Self {
		Self {
			body: Some(proto::CryptoMessage::from(src.body())),
			mac: Some(src.mac().as_bytes().to_vec())
		}
	}
}

impl Serializable for AxolotlMac {
	fn serialize(&self) -> Vec<u8> {
		use prost::Message;

		proto::AxolotlMac::from(self).encode_to_vec()
	}
}

#[derive(Debug, PartialEq)]
pub enum Error {
	NoBody,
	BadBodyFormat,
	NoDigest,
	WrongDigestLen,
	BadFormat
}

impl TryFrom<proto::AxolotlMac> for AxolotlMac {
	type Error = Error;

	fn try_from(value: proto::AxolotlMac) -> Result<Self, Self::Error> {
		Ok(Self {
			body: Message::try_from(value.body.ok_or(Error::NoBody)?).or(Err(Error::BadBodyFormat))?,
			mac: Digest::try_from(value.mac.ok_or(Error::NoDigest)?).or(Err(Error::WrongDigestLen))?
		})
	}
}

impl Deserializable for AxolotlMac {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> where Self: Sized {
		use prost::Message;

		Self::try_from(proto::AxolotlMac::decode(buf).or(Err(Error::BadFormat))?)
	}
}

#[cfg(test)]
mod tests {
	use crate::key_pair::KeyPairSize;
	use crate::message::{Message, Type};
	use crate::serializable::{Deserializable, Serializable};
	use crate::x448::{PublicKeyX448, KeyTypeX448};
	use super::{AxolotlMac, Error};
	use crate::{hmac, proto};

	#[test]
	fn test_serialize_deserialize() {
		let mut msg = Message::new(Type::Chat);
		let ct = b"123";
		
		msg.set_counter(11);
		msg.set_prev_counter(3);
		msg.set_ciphertext(ct);
		msg.set_ratchet_key(PublicKeyX448::from(&[1u8; KeyTypeX448::PUB]));

		let mac_key = hmac::Key::new([42u8; hmac::Key::SIZE]);
		let digest = hmac::digest(&mac_key, &msg.serialize());

		let mac = AxolotlMac::new(&msg, &digest);
		let encoded = mac.serialize();
		let decoded = AxolotlMac::deserialize(&encoded).unwrap();

		assert_eq!(decoded.mac.as_bytes(), digest.as_bytes());
		assert_eq!(decoded.body().counter(), msg.counter());
		assert_eq!(decoded.body().prev_counter(), msg.prev_counter());
		assert_eq!(decoded.body().ciphertext(), msg.ciphertext());
	}

	#[test]
	fn test_deserialize_() {
		let encoded = b"\x0a\x62\x0a\x38\xca\xbe\x0a\x2b\xa9\xaf\xa5\x5b\x9a\x1b\xef\xba\x87\x1e\xd3\x4d\x62\x59\x0f\x9a\xf3\x5e\x32\x5e\x09\xfd\x1b\x76\x4b\xa5\xd8\xb9\xc3\x00\xd3\x81\xa3\x4e\x2a\x00\xc8\xb6\xb8\x39\x29\xe3\x33\xc5\x2d\x1d\x40\x89\x98\x5b\xf5\x44\x10\x03\x18\x01\x22\x20\xbe\x84\x12\x87\x46\x18\x5f\xef\xb8\x89\x64\xea\x2e\x95\x63\x74\x85\x76\xb2\x1b\x3b\xa8\x3f\xa1\x28\x5c\xfe\xff\xc6\x44\x92\x74\x38\x00\x12\x20\x21\x74\x6b\xcf\x3d\xe8\x76\xfc\x0f\xfb\x66\x3d\x95\x3e\x7b\x22\x3d\x52\xce\x36\x66\x12\x8f\x0d\x33\x70\xb1\x0b\xb3\x52\x14\x59";
		let mac = AxolotlMac::deserialize(encoded);

		assert!(mac.is_ok());
	}

	#[test]
	fn test_deserialize_errors() {
		let corrupted = b"\xff\x62\x0a\x38\xca\xbe\x0a\x2b\xa9\xaf\xa5\x5b\x9a\x1b\xef\xba\x87\x1e\xd3\x4d\x62\x59\x0f\x9a\xf3\x5e\x32\x5e\x09\xfd\x1b\x76\x4b\xa5\xd8\xb9\xc3\x00\xd3\x81\xa3\x4e\x2a\x00\xc8\xb6\xb8\x39\x29\xe3\x33\xc5\x2d\x1d\x40\x89\x98\x5b\xf5\x44\x10\x03\x18\x01\x22\x20\xbe\x84\x12\x87\x46\x18\x5f\xef\xb8\x89\x64\xea\x2e\x95\x63\x74\x85\x76\xb2\x1b\x3b\xa8\x3f\xa1\x28\x5c\xfe\xff\xc6\x44\x92\x74\x38\x00\x12\x20\x21\x74\x6b\xcf\x3d\xe8\x76\xfc\x0f\xfb\x66\x3d\x95\x3e\x7b\x22\x3d\x52\xce\x36\x66\x12\x8f\x0d\x33\x70\xb1\x0b\xb3\x52\x14\x59";
		let mac = AxolotlMac::deserialize(corrupted);

		assert_eq!(mac.err(), Some(Error::BadFormat));

		assert_eq!(AxolotlMac::try_from(proto::AxolotlMac { body: None, mac: Some(vec![1u8; hmac::Key::SIZE]) }).err(), Some(Error::NoBody));
		
		let mut msg = Message::new(Type::Chat);
		let ct = b"123";
		
		msg.set_counter(11);
		msg.set_prev_counter(3);
		msg.set_ciphertext(ct);
		msg.set_ratchet_key(PublicKeyX448::from(&[1u8; KeyTypeX448::PUB]));

		assert_eq!(AxolotlMac::try_from(proto::AxolotlMac { body: Some(proto::CryptoMessage::from(&msg)), mac: Some(vec![1u8; 10]) }).err(), Some(Error::WrongDigestLen));
		assert_eq!(AxolotlMac::try_from(proto::AxolotlMac { body: Some(proto::CryptoMessage::from(&msg)), mac: None }).err(), Some(Error::NoDigest));
	}
}