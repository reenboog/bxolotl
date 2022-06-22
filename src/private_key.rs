use std::{marker::PhantomData, array::TryFromSliceError};

// TODO: introduce a macro to avoid duplicating what's implemented in PublicKey
pub struct PrivateKey<T, const SIZE: usize> {
	bytes: [u8; SIZE],
	_marker: PhantomData<T>
}

impl<T, const SIZE: usize> PrivateKey<T, SIZE> {
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

impl<T, const SIZE: usize> From<&[u8; SIZE]> for PrivateKey<T, SIZE> {
	fn from(bytes: &[u8; SIZE]) -> Self {
		Self::new(bytes.clone())
	}
}

impl<T, const SIZE: usize> TryFrom<Vec<u8>> for PrivateKey<T, SIZE> {
    type Error = TryFromSliceError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
			let slice: [u8; SIZE] = value.as_slice().try_into()?;

			Ok(Self::new(slice))
    }
}

#[cfg(test)]
mod tests {
	use super::PrivateKey;

	struct TestKeyType;
	type TestPrivateKey = PrivateKey<TestKeyType, 10>;

	#[test]
	fn test_as_bytes() {
		let key = PrivateKey::<TestKeyType, 10>::new(b"0123456789".to_owned());

		assert_eq!(key.as_bytes(), b"0123456789");
	}

	#[test]
	fn test_from_bytes() {
		let key: TestPrivateKey = b"0123456789".into();

		assert_eq!(key.as_bytes(), b"0123456789");
	}

	#[test]
	fn test_try_from_vec() {
		let k0 = TestPrivateKey::try_from(b"0123456789".to_vec());

		assert!(k0.is_ok());

		let k1 = TestPrivateKey::try_from(b"0123".to_vec());

		assert!(k1.is_err());
	}
}
