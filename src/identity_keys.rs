use prost::Message;

use crate::{x448::PublicKeyX448, kyber::PublicKeyKyber, ed448::PublicKeyEd448, proto, serializable::{Deserializable, Serializable}};

#[derive(Debug, PartialEq)]
pub enum Error {
	WrongX448,
	WrongEd448,
	WrongKyber,
	BadFormat
}

#[derive(Debug, PartialEq)]
pub struct IdentityKeys {
	pub x448: PublicKeyX448,
	pub ed448: PublicKeyEd448,
	pub kyber: PublicKeyKyber
}

impl From<&IdentityKeys> for proto::IdentityKeys {
	fn from(src: &IdentityKeys) -> Self {
		Self {
			x448: src.x448.as_bytes().to_vec(),
			ed448: src.ed448.as_bytes().to_vec(),
			kyber: src.kyber.as_bytes().to_vec()
		}
	}
}

impl Serializable for IdentityKeys {
	fn serialize(&self) -> Vec<u8> {
		proto::IdentityKeys::from(self).encode_to_vec()
	}
}

impl TryFrom<proto::IdentityKeys> for IdentityKeys {
	type Error = Error;

	fn try_from(value: proto::IdentityKeys) -> Result<Self, Self::Error> {
		let x448 = PublicKeyX448::try_from(value.x448).or(Err(Error::WrongX448))?;
		let ed448 = PublicKeyEd448::try_from(value.ed448).or(Err(Error::WrongEd448))?;
		let kyber = PublicKeyKyber::try_from(value.kyber).or(Err(Error::WrongKyber))?;

		Ok(Self { x448, kyber, ed448 })
	}
}

impl Deserializable for IdentityKeys {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> where Self: Sized {
		Self::try_from(proto::IdentityKeys::decode(buf).or(Err(Error::BadFormat))?)
	}
}

#[cfg(test)]
mod tests {
	use crate::{x448::KeyPairX448, ed448::KeyPairEd448, kyber::KeyPairKyber, serializable::{Serializable, Deserializable}};
	use super::IdentityKeys;

	#[test]
	fn test_serialize_deserialize() {
		let keys = IdentityKeys {
			x448: KeyPairX448::generate().public_key().clone(),
			ed448: KeyPairEd448::generate().public_key().clone(),
			kyber: KeyPairKyber::generate().public_key().clone()
		};
		let serialized = keys.serialize();
		let deserialized = IdentityKeys::deserialize(&serialized);

		assert_eq!(Ok(keys), deserialized);
	}
}