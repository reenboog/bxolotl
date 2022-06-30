use crate::{session::AxolotlMac, aes_cbc, hmac, message::Message};

pub struct MessageKey {
	enc_key: aes_cbc::Key, // derived from chain_key.get_message_keys via kdf
	iv: aes_cbc::Iv, 			// derived from chain_key.get_message_keys via kdf
	mac_key: hmac::Key, // derived from chain_key.get_message_keys via kdf
	ts: u64
}

impl MessageKey {
	// CryptoMessage is expected to be passed as well, but I'd move it to another place
	// currently called `box`
	// TODO: move to another entity?
	pub fn encrypt(&self, plaintext: &[u8], msg: &mut Message) -> AxolotlMac {
		// aes_cbc is used
		todo!()
	}

	// TODO: return result
	pub fn decrypt(&self, mac: &AxolotlMac) -> Vec<u8> {
		todo!()
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_encrypt() {
		todo!()
	}
}