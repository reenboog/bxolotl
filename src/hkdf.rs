use crate::hmac::{Digest, self};

pub struct Hkdf {
	prk: Digest
}

impl Hkdf {
	pub fn new(prk: Digest) -> Self {
		Self { prk }
	}

	pub fn new_from_ikm(ikm: &[u8; hmac::Key::SIZE], salt: &[u8]) -> Self {
		Self::new(hmac::digest(&hmac::Key(ikm.clone()), salt))
	}

	// TODO: introduce a new type for expanded?, clarify its size; or may be just a const or a combined type, ie KeyMac?
	pub fn expand<const LEN: usize>(&self, info: &[u8]) -> [u8; LEN] {
		assert!(LEN > 1); // TODO: would be nice to introduce a compile time type with checks

		let n = (LEN - 1) / Digest::SIZE + 1;

		let mut res = Vec::<u8>::new();
		let mut prev = Vec::<u8>::new();

		for i in 1..n + 1 {
			let mut input = prev;

			input.extend(info);
			input.push(i as u8);

			prev = hmac::digest(&self.prk.into(), &input[..]).as_bytes().to_vec();
			res.extend(prev.clone());
		} 

		res[..LEN].try_into().unwrap()
	}
	// TODO: introduce extract: fn extract(salt, ikm) -> prk
	// TODO: introduce expand: fn expand(prk, info, len) -> [u8; len] (OKM, output key marerial)
}

#[cfg(test)]
mod tests {
	use crate::{hmac::Digest, hkdf::Hkdf};

	const DIGEST: &[u8; 32] = b"\x95\x25\x9b\x85\xc5\x2d\x50\x60\x14\xa9\xba\x39\xc4\x13\x94\x72\xe2\x7f\x97\x88\x5d\xc4\x00\x70\xfb\xda\x54\x3b\x74\xb3\xda\x61";
	const RES: &[u8; 80] = b"\x3b\x61\x92\x07\x04\x6d\x48\xd5\xcf\x15\x67\x9e\x25\x3a\xba\x7c\x7d\xd6\xfc\xcd\x5b\xdb\x9d\xb4\x47\x14\x25\x12\xcf\x1b\x35\x8a\x1e\xd0\xba\x42\x8f\x2b\x3f\x93\xfc\x13\x6d\x3c\x0c\x89\xf6\x91\x39\xba\x1f\x00\x75\x9d\x61\x8a\x9d\xf5\x54\xfa\xa9\x46\x78\xbb\xd2\x12\x6a\x28\x8e\x9e\xea\x4b\x72\x9e\x00\xff\x4f\x1e\xbd\x5c";

	#[test]
	fn test_not_zeroes() {
		let digest = Digest(DIGEST.to_owned());
		let res = Hkdf::new(digest).expand::<80>(b"SecureMessenger");

		assert_ne!(res, [0u8; 80]);
	}

	#[test]
	fn test_extract_from_ikm() {
		let key = [1u8; 32];
		let salt = b"0".to_owned();

		let res = Hkdf::new_from_ikm(&key, &salt).expand::<80>(b"SecureMessenger");

		assert_eq!(res, RES.to_owned());
	}

	#[test]
	fn test_expand() {
		let digest = Digest(DIGEST.to_owned());
		let res = Hkdf::new(digest).expand::<80>(b"SecureMessenger");

		assert_eq!(res, RES.to_owned());
	}

	#[test]
	fn test_expand_to_non_block_size() {
		let digest = Digest(DIGEST.to_owned());
		let res = Hkdf::new(digest).expand::<>(b"SecureMessenger");

		assert_eq!(res, b"\x3b\x61".to_owned());
	}

	#[test]
	fn test_expand_same_info_wrong_digest() {
		let digest = Digest(b"\x05\x25\x9b\x85\xc5\x2d\x50\x60\x14\xa9\xba\x39\xc4\x13\x94\x72\xe2\x7f\x97\x88\x5d\xc4\x00\x70\xfb\xda\x54\x3b\x74\xb3\xda\x61".to_owned());
		let res = Hkdf::new(digest).expand::<80>(b"SecureMessenger");

		assert_ne!(res, RES.to_owned());
	}

	#[test]
	fn test_expand_same_digest_wrong_info() {
		let digest = Digest(DIGEST.to_owned());
		let res = Hkdf::new(digest).expand::<80>(b"NotSecureMessenger");

		assert_ne!(res, RES.to_owned());
	}
}