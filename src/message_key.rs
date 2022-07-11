use crate::{session::AxolotlMac, aes_cbc::{self, AesCbc}, hmac, message::Message, serializable::Serializable};

pub struct MessageKey {
	enc_key: aes_cbc::Key, // derived from chain_key.get_message_keys via kdf
	mac_key: hmac::Key, // derived from chain_key.get_message_keys via kdf
	iv: aes_cbc::Iv, 			// derived from chain_key.get_message_keys via kdf
}

pub enum Error {
	BadKeyMaterial,
	WrongMac
}

impl From<aes_cbc::Error> for Error {
	fn from(_: aes_cbc::Error) -> Self {
		Self::BadKeyMaterial
	}
}

impl MessageKey {
	pub const SIZE: usize = {aes_cbc::Key::SIZE + aes_cbc::Iv::SIZE + hmac::Key::SIZE};
}

impl From<&[u8; MessageKey::SIZE]> for MessageKey {
	fn from(src: &[u8; MessageKey::SIZE]) -> Self {
		Self {
			enc_key: aes_cbc::Key(src[..aes_cbc::Key::SIZE].try_into().unwrap()),
			mac_key: hmac::Key::new(src[aes_cbc::Key::SIZE..aes_cbc::Key::SIZE + hmac::Key::SIZE].try_into().unwrap()),
			iv: aes_cbc::Iv(src[aes_cbc::Key::SIZE + hmac::Key::SIZE..].try_into().unwrap())
		}
	}
}

impl MessageKey {
	pub fn enc_key(&self) -> &aes_cbc::Key {
		&self.enc_key
	}

	pub fn mac_key(&self) -> &hmac::Key {
		&self.mac_key
	}

	pub fn iv(&self) -> &aes_cbc::Iv {
		&self.iv
	}
}

impl MessageKey {
	pub fn encrypt(&self, plaintext: &[u8], msg: &mut Message) -> AxolotlMac {
		let aes = AesCbc::new(&self.enc_key, &self.iv);
		let ct = aes.encrypt(plaintext);

		msg.set_ciphrtext(&ct);

		let mac = hmac::digest(&self.mac_key, &msg.serialize());

		AxolotlMac::new(msg, &mac)
	}

	pub fn decrypt(&self, mac: &AxolotlMac) -> Result<Vec<u8>, Error>  {
		if !hmac::verify(&mac.body().serialize(), &self.mac_key, mac.mac()) {
			Err(Error::WrongMac)
		} else {
			let aes = AesCbc::new(&self.enc_key, &self.iv);

			Ok(aes.decrypt(mac.body().ciphrtext())?)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::MessageKey;

	// Needs Message::serialize/deserialize first
	#[test]
	fn test_encrypt_decrypt() {
		todo!()
	}

	#[test]
	fn test_bad_key_material() {
		todo!()
	}

	#[test]
	fn test_decrypt_with_wrong_mac() {
		todo!()
	}

	#[test]
	fn test_from_slice() {
		// should not panic
		let _: MessageKey = (&[1u8; MessageKey::SIZE]).into();
	}

}