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

// TODO: test
impl From<&AxolotlMac> for proto::AxolotlMac {
	fn from(src: &AxolotlMac) -> Self {
		Self {
			body: Some(proto::CryptoMessage::from(src.body())),
			mac: Some(src.mac().as_bytes().to_vec())
		}
	}
}

// TODO: test
impl Serializable for AxolotlMac {
	fn serialize(&self) -> Vec<u8> {
		use prost::Message;

		proto::AxolotlMac::from(self).encode_to_vec()
	}
}

pub enum Error {
	NoBody,
	BadBodyFormat,
	NoDigest,
	WrongDigestLen,
	BadFormat
}

// TODO: test
impl TryFrom<proto::AxolotlMac> for AxolotlMac {
	type Error = Error;

	fn try_from(value: proto::AxolotlMac) -> Result<Self, Self::Error> {
		Ok(Self {
			body: Message::try_from(value.body.ok_or(Error::NoBody)?).or(Err(Error::BadBodyFormat))?,
			mac: Digest::try_from(value.mac.ok_or(Error::NoDigest)?).or(Err(Error::WrongDigestLen))?
		})
	}
}

// TODO: test
impl Deserializable for AxolotlMac {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> where Self: Sized {
		use prost::Message;

		Self::try_from(proto::AxolotlMac::decode(buf).or(Err(Error::BadFormat))?)
	}
}