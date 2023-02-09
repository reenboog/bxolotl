use crate::{
	kyber::KeyPairKyber,
	proto,
	serializable::{Deserializable, Serializable},
	x448::{KeyPairX448, PrivateKeyX448, PublicKeyX448},
};
use prost::Message;

#[derive(Debug, PartialEq)]
pub enum Error {
	WrongX448PrivateLen,
	NoX448Private,
	WrongX448PublicLen,
	NoX448Public,
	WrongKyberLen,
	NoKyber,
	BadFormat,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Prekey {
	pub key_x448: KeyPairX448,
	pub key_kyber: KeyPairKyber,
	pub last_resort: bool,
}

mod to_serde {
	use super::Prekey;
	use serde::ser::{Serialize, SerializeStruct, Serializer};

	impl Serialize for Prekey {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			let mut state = serializer.serialize_struct("Prekey", 4)?;

			state.serialize_field("id", &self.id())?;
			state.serialize_field("key_x448", &self.key_x448)?;
			state.serialize_field("key_kyber", &self.key_kyber)?;
			state.serialize_field("last_resort", &self.last_resort)?;

			state.end()
		}
	}
}

impl From<&Prekey> for proto::PreKeyData {
	fn from(src: &Prekey) -> Self {
		Self {
			private_key_448: Some(src.key_x448.private_key().as_bytes().to_vec()),
			public_key_448: Some(src.key_x448.public_key().as_bytes().to_vec()),
			kyber_key_pair: Some(src.key_kyber.serialize()), // TODO: should this be serialized or simply concatenated?
			last_resort: Some(src.last_resort),
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
		let x448_priv =
			PrivateKeyX448::try_from(value.private_key_448.ok_or(Error::NoX448Private)?)
				.or(Err(Error::WrongX448PrivateLen))?;
		let x448_pub = PublicKeyX448::try_from(value.public_key_448.ok_or(Error::NoX448Public)?)
			.or(Err(Error::WrongX448PublicLen))?;
		let kyber = KeyPairKyber::deserialize(&value.kyber_key_pair.ok_or(Error::NoKyber)?)
			.or(Err(Error::WrongKyberLen))?;
		let last_resort = value.last_resort.unwrap_or(false);

		Ok(Self {
			key_x448: KeyPairX448::new(x448_priv, x448_pub),
			key_kyber: kyber,
			last_resort,
		})
	}
}

impl Deserializable for Prekey {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(proto::PreKeyData::decode(buf).or(Err(Error::BadFormat))?)
	}
}

impl Prekey {
	pub fn id(&self) -> u64 {
		self.key_x448.public_key().id()
	}
}

/// last_resort prekeys (private keys, in particular) should not be deleted from the DB
pub fn generate(count: u8, retain_last_resort: bool) -> Vec<Prekey> {
	(0..count)
		.map(|idx| Prekey {
			key_x448: KeyPairX448::generate(),
			key_kyber: KeyPairKyber::generate(),
			last_resort: retain_last_resort && idx == count - 1,
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::Prekey;
	use crate::{
		kyber::KeyPairKyber,
		prekey::generate,
		serializable::{Deserializable, Serializable},
		x448::KeyPairX448,
	};

	#[test]
	fn test_serialize_deserialize() {
		let pk = Prekey {
			key_x448: KeyPairX448::generate(),
			key_kyber: KeyPairKyber::generate(),
			last_resort: true,
		};
		let serialized = pk.serialize();
		let deserialized = Prekey::deserialize(&serialized);

		assert_eq!(Ok(pk), deserialized);
	}

	#[test]
	fn generate_prekeys() {
		let prekeys = generate(3, true);

		assert_eq!(3, prekeys.len());
		assert_eq!(false, prekeys.get(0).unwrap().last_resort);
		assert_eq!(false, prekeys.get(1).unwrap().last_resort);
		assert_eq!(true, prekeys.get(2).unwrap().last_resort);
	}

	#[test]
	fn generate_prekeys_no_last_resort() {
		let prekeys = generate(3, false);

		assert_eq!(3, prekeys.len());
		assert_eq!(false, prekeys.get(0).unwrap().last_resort);
		assert_eq!(false, prekeys.get(1).unwrap().last_resort);
		assert_eq!(false, prekeys.get(2).unwrap().last_resort);
	}
}
