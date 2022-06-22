use std::{marker::PhantomData, fmt::Error, array::TryFromSliceError};

use sha2::{Sha256, Digest};

pub struct PublicKey<T, const SIZE: usize> {
	bytes: [u8; SIZE],
	_marker: PhantomData<T>
}

impl<T, const SIZE: usize> PublicKey<T, SIZE> {
	pub fn new(bytes: [u8; SIZE]) -> Self {
		Self { 
			bytes,
			_marker: PhantomData
		}
	}

	pub fn as_bytes(&self) -> &[u8; SIZE] {
		&self.bytes
	}
}

impl<T, const SIZE: usize> PublicKey<T, SIZE> {
	// REVIEW: should it be i64 or u64? On iOS, protobuf definitions are mapped to UInt64
	pub fn id(&self) -> u64 {
		u64::from_be_bytes(Sha256::digest(self.bytes).to_vec()[..8].try_into().unwrap())
	}
}

impl<T, const SIZE: usize> From<&[u8; SIZE]> for PublicKey<T, SIZE> {
	fn from(bytes: &[u8; SIZE]) -> Self {
		Self::new(bytes.clone())
	}
}

impl<T, const SIZE: usize> TryFrom<Vec<u8>> for PublicKey<T, SIZE> {
    type Error = TryFromSliceError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
			let slice: [u8; SIZE] = value.as_slice().try_into()?;

			Ok(Self::new(slice))
    }
}

#[cfg(test)]
mod tests {
	use super::PublicKey;

	struct TestKeyType;
	type TestPublicKey = PublicKey<TestKeyType, 10>;

	#[test]
	fn test_as_bytes() {
		let key = TestPublicKey::new(b"0123456789".to_owned());

		assert_eq!(key.as_bytes(), b"0123456789");
	}

	#[test]
	fn test_from_bytes() {
		let key: TestPublicKey = b"0123456789".into();

		assert_eq!(key.as_bytes(), b"0123456789");
	}

	#[test]
	fn test_try_from_vec() {
		let k0 = TestPublicKey::try_from(b"0123456789".to_vec());

		assert!(k0.is_ok());

		let k1 = TestPublicKey::try_from(b"0123".to_vec());

		assert!(k1.is_err());
	}

	#[test]
	fn test_id() {
		let key = TestPublicKey::new(b"0123456789".to_owned());
		let id = key.id();

		assert_eq!(9572568648884945950, id);
	}
}