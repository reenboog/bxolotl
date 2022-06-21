use crate::hmac::{Digest};

// TODO: make generic and specify a concrete type, ie Hkdf32
// rfc-5869 based
pub struct Hkdf {
	// prk: [u8; hmac::MAC_SIZE]
	// HKDF is Hash-KDF. Hence, its prk is bound to the underlying hash function
	prk: Digest
}

impl Hkdf {
	// TODO: ikm, salt, info, len: salt = key (32 bytes), ikm = msg, len - the desired output length
	pub fn new(prk: Digest) -> Self {
		Self { prk }
	}

	// TODO: introduce a new type for expanded, clarify its size; or may be just a const or a combined type, ie KeyMac?
	// return a vec?
	pub fn expand<const LEN: usize>(&self, info: &[u8]) -> [u8; LEN] {
		todo!()
	}
	// TODO: introduce extract: fn extract(salt, ikm) -> prk
	// TODO: introduce expand: fn expand(prk, info, len) -> [u8; len] (OKM, output key marerial)
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_not_zeroes() {
		todo!()
	}

	#[test]
	fn test_extract() {
		todo!()
	}

	#[test]
	fn test_expand() {
		todo!()
	}
}