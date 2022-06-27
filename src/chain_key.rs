use crate::hkdf::Hkdf;
use crate::hmac::Digest;
use crate::message_key::MessageKey;
use crate::{hmac, hkdf};

// TODO: use (when introduced) key! macro
pub struct ChainKey {
	pub key: hmac::Key, // 32 bytes
	pub counter: u32		// > 0
}

const SEED: &[u8] = b"SecureMessenger";

impl ChainKey {
	// TODO: introduce a dedicated type for this buffer; KeyBuf?
	pub fn new(key: hmac::Key, counter: u32) -> Self {
		Self { key: key, counter }
	}
}

impl ChainKey {
	pub fn message_key(&self) -> MessageKey {
		// 1 hkdf from self.key
		// 2 split into MessageKey(enc_key, mac_key, iv)

		// static const bytes_t SeedBytes = ciphr::bytes_from_string(MessageKeysSeed);

		// static type size for into() would be great

		let mk = hmac::digest(&self.key, b"0"); // TODO: sure about this value? it's 48
		let key_material = Hkdf::new(mk).expand::<80>(SEED); // introduce a type (via into?)
		// let enc_key: hmac::Key = key_material[..32].into();

    // const bytes_t mk = hmac::generate(_key, bytes_t(1, static_cast<std::byte>('0')));
    // const bytes_t key_material = hkdf(mk).expand(SeedBytes, 32 + 32 + 16);
    // const bytes_t enc_key(key_material.begin(), key_material.begin() + 32);
    // const bytes_t mac_key(key_material.begin() + 32, key_material.begin() + 64);
    // const bytes_t iv(key_material.begin() + 64, key_material.begin() + 80);
    // return message_keys(enc_key, mac_key, iv);

		todo!()
	}

	pub fn next(&self) -> Self {
		// TODO: Self::new instead?
		Self {
			key: hmac::digest(&self.key, b"1").into(), // TODO: usre about this value?
			counter: self.counter + 1
		}
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_len() {
		assert_eq!(0, b'0');
	}
}