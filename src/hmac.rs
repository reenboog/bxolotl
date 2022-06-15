use sha2::Sha256;
use hmac::{Hmac, Mac};

const KEY_SIZE: usize = 32;
const MAC_SIZE: usize = 32;

type HmacSha256 = Hmac<Sha256>;

pub struct Key([u8; KEY_SIZE]);
pub struct Digest([u8; MAC_SIZE]);

impl From<&[u8; KEY_SIZE]> for Key {
	fn from(slice: &[u8; KEY_SIZE]) -> Self {
		Self(slice.clone())
	}
}

impl From<&[u8; MAC_SIZE]> for Digest {
	fn from(slice: &[u8; MAC_SIZE]) -> Self {
		Self(slice.clone())
	}
}

// TODO: introduce a module or a struct

pub fn digest(key: &Key, msg: &[u8]) -> Digest {
	let mut mac = HmacSha256::new_from_slice(&key.0).unwrap();

	mac.update(msg);

	Digest(mac.finalize().into_bytes().into())
}

pub fn verify(msg: &[u8], key: &Key, hash: &Digest) -> bool {
	let mut mac = HmacSha256::new_from_slice(&key.0).unwrap();

	mac.update(msg);

	mac.verify_slice(&hash.0).is_ok()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_non_zero_digest() {
		let key = Key([123u8; KEY_SIZE]);
		let msg = b"abcdef";
		let digest = digest(&key, msg);

		assert_ne!(digest.0, [0u8; MAC_SIZE]);
	}

	#[test]
	fn test_digest_same_inut_with_different_keys() {
		let key1 = Key([123u8; KEY_SIZE]);
		let key2 = Key([42u8; KEY_SIZE]);
		let msg = b"abcdef";

		let d1 = digest(&key1, msg);
		let d2 = digest(&key2, msg);

		assert_ne!(d1.0, d2.0);
	}

	#[test]
	fn test_digest_different_input_with_same_key() {
		let key = Key([123u8; KEY_SIZE]);
		let msg1 = b"abcdef";
		let msg2 = b"12345";

		let d1 = digest(&key, msg1);
		let d2 = digest(&key, msg2);

		assert_ne!(d1.0, d2.0);
	}

	#[test]
	fn test_same_digest_for_same_inputs_and_keys() {
		let key = Key([123u8; KEY_SIZE]);
		let msg = b"abcdef";
		let d1 = digest(&key, msg);
		let d2 = digest(&key, msg);

		assert_eq!(d1.0, d2.0);
	}

	#[test]
	fn test_verify() {
		let key = Key([2u8; KEY_SIZE]);
		let msg = b"hi there";
		let digest = digest(&key, msg);

		assert!(verify(msg, &key, &digest));
	}
}