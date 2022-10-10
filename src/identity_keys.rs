use prost::Message;

use crate::{x448::PublicKeyX448, ntru::PublicKeyNtru, ed448::PublicKeyEd448, proto, serializable::Deserializable};

#[derive(Debug)]
pub enum Error {
	WrongX448,
	WrongEd448,
	WrongNtru,
	BadFormat
}

pub struct IdentityKeys {
	pub x448: PublicKeyX448,
	pub ntru: PublicKeyNtru,
	pub ed448: PublicKeyEd448
}

impl TryFrom<proto::IdentityKeys> for IdentityKeys {
	type Error = Error;

	fn try_from(value: proto::IdentityKeys) -> Result<Self, Self::Error> {
		let x448 = PublicKeyX448::try_from(value.x448).or(Err(Error::WrongX448))?;
		let ed448 = PublicKeyEd448::try_from(value.ed448).or(Err(Error::WrongEd448))?;
		let ntru = PublicKeyNtru::try_from(value.ntru).or(Err(Error::WrongNtru))?;

		Ok(Self { x448, ntru, ed448 })
	}
}

impl Deserializable for IdentityKeys {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> where Self: Sized {
		Self::try_from(proto::IdentityKeys::decode(buf).or(Err(Error::BadFormat))?)
	}
}