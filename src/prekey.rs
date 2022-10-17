use prost::Message;
use crate::{proto, x448::{KeyPairX448, PrivateKeyX448, PublicKeyX448}, ntru::KeyPairNtru, serializable::{Serializable, Deserializable}};

#[derive(Debug)]
pub enum Error {
	WrongX448PrivateLen,
	WrongX448PublicLen,
	WrongNtruLen,
	NoX448Private,
	NoX448Public,
	NoNtru,
	BadFormat
}

#[derive(Debug, PartialEq)]
pub struct Prekey {
	pub key_x448: KeyPairX448,
	pub key_ntru: KeyPairNtru,
	pub last_resort: bool
}

impl From<&Prekey> for proto::PreKeyData {
	fn from(src: &Prekey) -> Self {
		Self {
			private_key_448: Some(src.key_x448.private_key().as_bytes().to_vec()),
			public_key_448: Some(src.key_x448.public_key().as_bytes().to_vec()),
			ntru_key_pair: Some(src.key_ntru.serialize()), // TODO: should this be serialized or simply concatenated?
			last_resort: Some(src.last_resort)
		}
	}
}

impl Serializable for Prekey {
	fn serialize(&self) -> Vec<u8> {
		proto::PreKeyData::from(self).encode_to_vec()
	}
}

impl TryFrom<proto::PreKeyData> for Prekey {
	type Error = Error;

	fn try_from(value: proto::PreKeyData) -> Result<Self, Self::Error> {
		let x448_priv = PrivateKeyX448::try_from(value.private_key_448.ok_or(Error::NoX448Private)?).or(Err(Error::WrongX448PrivateLen))?;
		let x448_pub = PublicKeyX448::try_from(value.public_key_448.ok_or(Error::NoX448Public)?).or(Err(Error::WrongX448PublicLen))?;
		let ntru = KeyPairNtru::deserialize(&value.ntru_key_pair.ok_or(Error::NoNtru)?).or(Err(Error::WrongNtruLen))?;
		let last_resort = value.last_resort.unwrap_or(false);

		Ok(Self {
			key_x448: KeyPairX448::new(x448_priv, x448_pub),
			key_ntru: ntru,
			last_resort
		})
	}
}

impl Deserializable for Prekey {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> where Self: Sized {
		Self::try_from(proto::PreKeyData::decode(buf).or(Err(Error::BadFormat))?)
	}
}

impl Prekey {
	pub fn id(&self) -> u64 {
		self.key_x448.public_key().id()
	}
}

#[cfg(test)]
mod tests {
	use crate::{x448::KeyPairX448, ntru::KeyPairNtru, serializable::{Serializable, Deserializable}};
	use super::Prekey;

	#[test]
	fn test_serialize_deserialize() {
		let pk = Prekey {
			key_x448: KeyPairX448::generate(),
			key_ntru: KeyPairNtru::generate(),
			last_resort: true 
		};
		let serialized = pk.serialize();
		let deserialized = Prekey::deserialize(&serialized).unwrap();

		assert_eq!(pk, deserialized);
	}
}