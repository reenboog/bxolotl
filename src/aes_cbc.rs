use aes::cipher::{block_padding::{Pkcs7, UnpadError}, BlockEncryptMut, BlockDecryptMut, KeyIvInit};

type Encryptor = cbc::Encryptor<aes::Aes256>;
type Decryptor = cbc::Decryptor<aes::Aes256>;

#[derive(Clone, Copy)]
pub struct Key(pub [u8; Self::SIZE]);

impl Key {
	pub const SIZE: usize = 32;
}

#[derive(Clone, Copy)]
pub struct Iv(pub [u8; Self::SIZE]);

impl Iv {
	pub const SIZE: usize = 16;
}

pub struct AesCbc<'a> {
	pub key: &'a Key,
	pub iv: &'a Iv
}

#[derive(Debug)]
pub struct Error;

impl From<UnpadError> for Error {
	fn from(_: UnpadError) -> Self {
		Self
	}
}

impl<'a> AesCbc<'a> {
	pub fn new(key: &'a Key, iv: &'a Iv) -> Self {
		Self { key, iv }
	}
}

// REVIEW: get rid of AesCbc and keep the functions instead?

impl<'a> AesCbc<'a> {
	pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
		Encryptor::new(&self.key.0.into(), &self.iv.0.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext)
	}

	pub fn decrypt(&self, ciphrtext: &[u8]) -> Result<Vec<u8>, Error> {
		Ok(Decryptor::new(&self.key.0.into(), &self.iv.0.into()).decrypt_padded_vec_mut::<Pkcs7>(ciphrtext)?)
	}
}

#[cfg(test)]
mod tests {
	use super::{AesCbc, Key, Iv};

	const KEY_SIZE: usize = Key::SIZE;
	const IV_SIZE: usize = Iv::SIZE;

	#[test]
	fn test_decrypt() {
		let key = Key(b"256BitsKey256BitsKey256BitsKey25".to_owned());
		let iv = Iv(b"InitializationVr".to_owned());
		let ct = b"\x46\xbe\xfd\xd9\xf2\xf7\x19\x7a\xbc\xec\x49\x9e\xce\xe0\x96\xa3\x3d\x69\x31\xa7\x4b\x41\xe0\xa5\xbb\x1a\xdb\x74\xc7\xb8\x47\xd7";
		let plain = b"12345678901234567";

		let aes = AesCbc::new(&key, &iv);
		let res = aes.decrypt(ct);

		assert_eq!(res.unwrap(), plain);
	}

	#[test]
	fn test_encrypt_decrypt() {
		let aes = AesCbc::new(&Key([1u8; KEY_SIZE]), &Iv([2u8; IV_SIZE]));
		let pt = b"hi there";
		let ct = aes.encrypt(pt);
		let res = aes.decrypt(&ct);

		assert_eq!(res.unwrap(), pt);
	}

	#[test]
	fn test_decryption_fails_with_wrong_material() {
		let aes = AesCbc::new(&Key([1u8; KEY_SIZE]), &Iv([2u8; IV_SIZE]));
		let pt = b"hi there";
		let ct = aes.encrypt(pt);

		// wrong key
		let wrong_aes = AesCbc::new(&Key([3u8; KEY_SIZE]), &Iv([2u8; IV_SIZE]));
		assert!(wrong_aes.decrypt(&ct).is_err());
		
		// wrong iv
		let wrong_aes = AesCbc::new(&Key([1u8; KEY_SIZE]), &Iv([3u8; IV_SIZE]));
		assert!(wrong_aes.decrypt(&ct).is_err());

		// wrong key and iv
		let wrong_aes = AesCbc::new(&Key([5u8; KEY_SIZE]), &Iv([3u8; IV_SIZE]));
		assert!(wrong_aes.decrypt(&ct).is_err());
	}
}