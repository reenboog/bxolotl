use crate::{proto, private_key::PrivateKey, public_key::PublicKey, serializable::{Deserializable, Serializable}};
use prost::Message;

#[derive(Debug, PartialEq)]
pub enum Error {
	WrongPrivKeyLen,
	WrongPubKeyLen,
	BadFormat
}

#[derive(Debug, PartialEq)]
pub struct KeyPair<T, const PRIV_SIZE: usize, const PUB_SIZE: usize> {
	private: PrivateKey<T, PRIV_SIZE>,
	public: PublicKey<T, PUB_SIZE>
}

impl<T, const PRIV_SIZE: usize, const PUB_SIZE: usize> KeyPair<T, PRIV_SIZE, PUB_SIZE> {
	pub fn new(private: PrivateKey<T, PRIV_SIZE>, public: PublicKey<T, PUB_SIZE>) -> Self {
		Self { private, public }
	}

	pub fn public_key(&self) -> &PublicKey<T, PUB_SIZE> {
		&self.public
	}

	pub fn private_key(&self) -> &PrivateKey<T, PRIV_SIZE> {
		&self.private
	}

	pub fn id(&self) -> u64 {
		self.public_key().id()
	}
}

impl<T, const PRIV_SIZE: usize, const PUB_SIZE: usize> Clone for KeyPair<T, PRIV_SIZE, PUB_SIZE> {
	fn clone(&self) -> Self {
		Self::new(self.private.clone(), self.public.clone())
	}
}

impl<T, const PRIV_SIZE: usize, const PUB_SIZE: usize> From<&KeyPair<T, PRIV_SIZE, PUB_SIZE>> for proto::KeyPair {
	fn from(src: &KeyPair<T, PRIV_SIZE, PUB_SIZE>) -> Self {
		Self {
			private_key: src.private_key().as_bytes().to_vec(),
			public_key: src.public_key().as_bytes().to_vec()
		}
	}
}

impl<T, const PRIV_SIZE: usize, const PUB_SIZE: usize> Serializable for KeyPair<T, PRIV_SIZE, PUB_SIZE> {
	fn serialize(&self) -> Vec<u8> {
		proto::KeyPair::from(self).encode_to_vec()
	}
}

impl<T, const PRIV_SIZE: usize, const PUB_SIZE: usize> TryFrom<proto::KeyPair> for KeyPair<T, PRIV_SIZE, PUB_SIZE> {
	type Error = Error;

	fn try_from(value: proto::KeyPair) -> Result<Self, Self::Error> {
		let private = PrivateKey::<T, PRIV_SIZE>::try_from(value.private_key).or(Err(Error::WrongPrivKeyLen))?;
		let public = PublicKey::<T, PUB_SIZE>::try_from(value.public_key).or(Err(Error::WrongPubKeyLen))?;

		Ok(Self::new(private, public))
	}
}

impl<T, const PRIV_SIZE: usize, const PUB_SIZE: usize> Deserializable for KeyPair<T, PRIV_SIZE, PUB_SIZE> {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> where Self: Sized {
		Self::try_from(proto::KeyPair::decode(buf).or(Err(Error::BadFormat))?)
	}
}

pub trait KeyPairSize {
	const PRIV: usize;
	const PUB: usize;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Debug, PartialEq)]
	struct TestKeyType;

	#[test]
	fn test_new() {

		let private = PrivateKey::<TestKeyType, 2>::new(b"12".to_owned());
		let public = PublicKey::<TestKeyType, 4>::new(b"1234".to_owned());

		let _ = KeyPair::<TestKeyType, 2, 4>::new(private, public);

		// this won't compile because of different types:
		// let bad_key = PublicKey::<OtherType, 4>::new(b"1234".to_owned());
		// let kp = KeyPair::<TestKeyType, 2, 4>::new(private, bad_key);

		// this won't compile because of different sizes:
		// let bad_key = PublicKey::<TestKeyType, 10>::new(b"0123456789".to_owned());
		// let kp = KeyPair::<TestKeyType, 2, 4>::new(private, bad_key);
	}

	#[test]
	fn test_serialize_deserialize() {
		let private = PrivateKey::<TestKeyType, 2>::new(b"12".to_owned());
		let public = PublicKey::<TestKeyType, 4>::new(b"abcd".to_owned());

		let kp = KeyPair::<TestKeyType, 2, 4>::new(private, public);
		let serialized = kp.serialize();
		let deserialized = KeyPair::<TestKeyType, 2, 4>::deserialize(&serialized);

		assert_eq!(Ok(kp), deserialized);
	}
}