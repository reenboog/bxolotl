use crate::{key::key, id};

key!(PublicKey);

impl<T, const SIZE: usize> PublicKey<T, SIZE> {
	// TODO: should it be i64 or u64? On iOS, protobuf definitions are mapped to UInt64
	pub fn id(&self) -> u64 {
		id::from_bytes(&self.bytes)
	}
}

impl<T, const SIZE: usize> PartialEq for PublicKey<T, SIZE> {
	fn eq(&self, other: &Self) -> bool {
		self.bytes == other.bytes && self._marker == other._marker
	}
}

#[cfg(test)]
mod tests {
	use super::PublicKey;

	struct TestKeyType;
	type TestPublicKey = PublicKey<TestKeyType, 10>;

	#[test]
	fn test_id() {
		let key = TestPublicKey::new(b"0123456789".to_owned());
		let id = key.id();

		assert_eq!(9572568648884945950, id);
	}
}