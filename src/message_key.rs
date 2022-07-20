use crate::{session::AxolotlMac, aes_cbc::{self, AesCbc}, hmac, message::Message, serializable::Serializable};

pub struct MessageKey {
	enc_key: aes_cbc::Key, // derived from chain_key.get_message_keys via kdf
	mac_key: hmac::Key, // derived from chain_key.get_message_keys via kdf
	iv: aes_cbc::Iv, 			// derived from chain_key.get_message_keys via kdf
}

#[derive(Debug, PartialEq)]
pub enum Error {
	BadKeyMaterial,
	WrongMac
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
		let aes = AesCbc::new(self.enc_key, self.iv);
		let ct = aes.encrypt(plaintext);

		msg.set_ciphertext(&ct);

		let mac = hmac::digest(&self.mac_key, &msg.serialize());

		AxolotlMac::new(msg, &mac)
	}

	pub fn decrypt(&self, mac: &AxolotlMac) -> Result<Vec<u8>, Error>  {
		if !hmac::verify(&mac.body().serialize(), &self.mac_key, mac.mac()) {
			Err(Error::WrongMac)
		} else {
			let aes = AesCbc::new(self.enc_key, self.iv);

			Ok(aes.decrypt(mac.body().ciphertext()).or(Err(Error::BadKeyMaterial))?)
		}
	}
}

#[cfg(test)]
mod tests {
	use crate::{message::{Message, Type}, x448::KeyPairX448, hmac::Digest, serializable::Deserializable};
	use super::{MessageKey, Error};

	#[test]
	fn test_from_slice() {
		// should not panic
		let _: MessageKey = (&[1u8; MessageKey::SIZE]).into();
	}

	#[test]
	fn test_encrypt_decrypt() {
		let eph_kp = KeyPairX448::generate();
		let pt = b"123";
		let key = MessageKey::from(b"\xbb\x31\x2c\x0f\x67\x91\x6b\x2d\x87\x15\x99\xf4\xe5\x1f\x8b\x82\x51\xd9\x53\xe8\xd7\x54\xb7\x4e\xd4\x05\x83\x5e\x83\x93\x13\x79\xc6\x5f\x8a\xa7\x97\x12\x4a\xaf\x5a\x1f\x20\x95\xde\xde\xe6\x38\xe7\x4c\x80\xdb\xed\x79\x98\xe8\x78\x62\xd0\x5b\xa2\x6f\x80\xa0\xda\x23\xb8\x6a\x9b\x27\x24\x52\x14\xfb\xed\x93\x72\xb2\x57\xf8");

		let mut msg = Message::new(Type::Chat);
		msg.set_ratchet_key(eph_kp.public_key().clone());

		let encrypted = key.encrypt(pt, &mut msg);
		let decrypted = key.decrypt(&encrypted).unwrap();

		assert_eq!(decrypted, pt);
	}

	#[test]
	fn test_bad_key_material() {
		let eph_kp = KeyPairX448::generate();
		let pt = b"123";
		let key = MessageKey::from(b"\xbb\x31\x2c\x0f\x67\x91\x6b\x2d\x87\x15\x99\xf4\xe5\x1f\x8b\x82\x51\xd9\x53\xe8\xd7\x54\xb7\x4e\xd4\x05\x83\x5e\x83\x93\x13\x79\xc6\x5f\x8a\xa7\x97\x12\x4a\xaf\x5a\x1f\x20\x95\xde\xde\xe6\x38\xe7\x4c\x80\xdb\xed\x79\x98\xe8\x78\x62\xd0\x5b\xa2\x6f\x80\xa0\xda\x23\xb8\x6a\x9b\x27\x24\x52\x14\xfb\xed\x93\x72\xb2\x57\xf8");

		let mut msg = Message::new(Type::Chat);
		msg.set_ratchet_key(eph_kp.public_key().clone());

		let encrypted = key.encrypt(pt, &mut msg);
		// same mac key & iv, but enc key's 1st byte is wrong
		let wrong_key = MessageKey::from(b"\xaa\x31\x2c\x0f\x67\x91\x6b\x2d\x87\x15\x99\xf4\xe5\x1f\x8b\x82\x51\xd9\x53\xe8\xd7\x54\xb7\x4e\xd4\x05\x83\x5e\x83\x93\x13\x79\xc6\x5f\x8a\xa7\x97\x12\x4a\xaf\x5a\x1f\x20\x95\xde\xde\xe6\x38\xe7\x4c\x80\xdb\xed\x79\x98\xe8\x78\x62\xd0\x5b\xa2\x6f\x80\xa0\xda\x23\xb8\x6a\x9b\x27\x24\x52\x14\xfb\xed\x93\x72\xb2\x57\xf8");

		assert_eq!(wrong_key.decrypt(&encrypted).err(), Some(Error::BadKeyMaterial));

		// same enc key & mac key, but iv's last byte is wrong
		let wrong_iv = MessageKey::from(b"\xaa\x31\x2c\x0f\x67\x91\x6b\x2d\x87\x15\x99\xf4\xe5\x1f\x8b\x82\x51\xd9\x53\xe8\xd7\x54\xb7\x4e\xd4\x05\x83\x5e\x83\x93\x13\x79\xc6\x5f\x8a\xa7\x97\x12\x4a\xaf\x5a\x1f\x20\x95\xde\xde\xe6\x38\xe7\x4c\x80\xdb\xed\x79\x98\xe8\x78\x62\xd0\x5b\xa2\x6f\x80\xa0\xda\x23\xb8\x6a\x9b\x27\x24\x52\x14\xfb\xed\x93\x72\xb2\x57\xff");

		assert_eq!(wrong_iv.decrypt(&encrypted).err(), Some(Error::BadKeyMaterial));

		// makr sure the thing actually decrypts
		let decrypted = key.decrypt(&encrypted).unwrap();

		assert_eq!(decrypted, pt);
	}

	#[test]
	fn test_decrypt_with_wrong_mac() {
		let eph_kp = KeyPairX448::generate();
		let pt = b"123";
		let key = MessageKey::from(b"\xbb\x31\x2c\x0f\x67\x91\x6b\x2d\x87\x15\x99\xf4\xe5\x1f\x8b\x82\x51\xd9\x53\xe8\xd7\x54\xb7\x4e\xd4\x05\x83\x5e\x83\x93\x13\x79\xc6\x5f\x8a\xa7\x97\x12\x4a\xaf\x5a\x1f\x20\x95\xde\xde\xe6\x38\xe7\x4c\x80\xdb\xed\x79\x98\xe8\x78\x62\xd0\x5b\xa2\x6f\x80\xa0\xda\x23\xb8\x6a\x9b\x27\x24\x52\x14\xfb\xed\x93\x72\xb2\x57\xf8");

		let mut msg = Message::new(Type::Chat);
		msg.set_ratchet_key(eph_kp.public_key().clone());

		let encrypted = key.encrypt(pt, &mut msg);
		// same enc & iv key, but mac's last byte is wrong
		let wrong_mac = MessageKey::from(b"\xbb\x31\x2c\x0f\x67\x91\x6b\x2d\x87\x15\x99\xf4\xe5\x1f\x8b\x82\x51\xd9\x53\xe8\xd7\x54\xb7\x4e\xd4\x05\x83\x5e\x83\x93\x13\x79\xc6\x5f\x8a\xa7\x97\x12\x4a\xaf\x5a\x1f\x20\x95\xde\xde\xe6\x38\xe7\x4c\x80\xdb\xed\x79\x98\xe8\x78\x62\xd0\x5b\xa2\x6f\x80\xff\xda\x23\xb8\x6a\x9b\x27\x24\x52\x14\xfb\xed\x93\x72\xb2\x57\xf8");

		assert_eq!(wrong_mac.decrypt(&encrypted).err(), Some(Error::WrongMac));

		// makr sure the thing actually decrypts
		let decrypted = key.decrypt(&encrypted).unwrap();

		assert_eq!(decrypted, pt);
	}	
}