use sha2::{Sha256, Digest};

pub fn from_bytes(bytes: &[u8]) -> u64 {
	u64::from_be_bytes(Sha256::digest(bytes).to_vec()[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
	use super::from_bytes;

	#[test]
	fn test_id() {
		let id = from_bytes(b"0123456789");

		assert_eq!(9572568648884945950, id);
	}
}