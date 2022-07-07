use crate::{session::AxolotlMac, aes_cbc::{self, AesCbc}, hmac, message::Message, serializable::Serializable, chain_key};

pub struct MessageKey {
	enc_key: aes_cbc::Key, // derived from chain_key.get_message_keys via kdf
	iv: aes_cbc::Iv, 			// derived from chain_key.get_message_keys via kdf
	mac_key: hmac::Key, // derived from chain_key.get_message_keys via kdf
	ts: u64
}

pub struct Error;

impl From<aes_cbc::Error> for Error {
	fn from(_: aes_cbc::Error) -> Self {
		Self
	}
}

impl MessageKey {
	pub fn encrypt(&self, plaintext: &[u8], msg: &mut Message) -> AxolotlMac {
		let aes = AesCbc::new(self.enc_key.clone(), self.iv.clone());
		let ct = aes.encrypt(plaintext);

		msg.set_ciphrtext(&ct);

		let mac = hmac::digest(&self.mac_key, &msg.serialize());

		AxolotlMac::new(msg, &mac)
	}

	// TODO: return result
	pub fn decrypt(&self, mac: &AxolotlMac) -> Result<Vec<u8>, Error>  {
		todo!()
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_encrypt_decrypt() {
		todo!()
	}
}