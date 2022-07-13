use aes::cipher::{block_padding::{Pkcs7, UnpadError}, BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use prost::Message;
use rand::Rng;
use crate::{proto, serializable::{Serializable, Deserializable}};

type Encryptor = cbc::Encryptor<aes::Aes256>;
type Decryptor = cbc::Decryptor<aes::Aes256>;

#[derive(Clone, Copy)]
pub struct Key(pub [u8; Self::SIZE]);

impl Key {
	pub const SIZE: usize = 32;

	pub fn generate() -> Self {
		Self(rand::thread_rng().gen())
	}
}

#[derive(Clone, Copy)]
pub struct Iv(pub [u8; Self::SIZE]);

impl Iv {
	pub const SIZE: usize = 16;

	pub fn generate() -> Self {
		Self(rand::thread_rng().gen())
	}
}

pub struct AesCbc {
	pub key: Key,
	pub iv: Iv
}

#[derive(Debug)]
pub enum Error {
	BadAesParamsFormat,
	UnpaddingFailed,
	WrongKeyLen,
	WrongIvLen
}

impl From<UnpadError> for Error {
	fn from(_: UnpadError) -> Self {
		Self::UnpaddingFailed
	}
}

impl AesCbc {
	pub fn new(key: Key, iv: Iv) -> Self {
		Self { key, iv }
	}

	pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
		Encryptor::new(&self.key.0.into(), &self.iv.0.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext)
	}

	pub fn decrypt(&self, ciphrtext: &[u8]) -> Result<Vec<u8>, Error> {
		Ok(Decryptor::new(&self.key.0.into(), &self.iv.0.into()).decrypt_padded_vec_mut::<Pkcs7>(ciphrtext)?)
	}
}

// TODO: test
impl From<&AesCbc> for proto::AesParams {
	fn from(src: &AesCbc) -> Self {
		Self {
			aes_key: src.key.0.to_vec(),
			iv: src.iv.0.to_vec()
		}
	}
}

// TODO: test
impl TryFrom<Vec<u8>> for Key {
	type Error = Error;

	// TODO: unify via `std::array::TryFromSliceError` instead?
	fn try_from(buf: Vec<u8>) -> Result<Key, Self::Error> {
		Ok(Self(TryInto::<[u8; Self::SIZE]>::try_into(buf.as_slice()).or_else(|_| Err(Error::WrongKeyLen))?))
	}
}

// TODO: test
impl TryFrom<Vec<u8>> for Iv {
	type Error = Error;

	// TODO: unify via `std::array::TryFromSliceError` instead?
	fn try_from(buf: Vec<u8>) -> Result<Iv, Self::Error> {
		Ok(Self(TryInto::<[u8; Self::SIZE]>::try_into(buf.as_slice()).or_else(|_| Err(Error::WrongIvLen))?))
	}
}

// TODO: test
impl Serializable for AesCbc {
	fn serialize(&self) -> Vec<u8> {
		proto::AesParams::from(self).encode_to_vec()
	}
}

impl TryFrom<proto::AesParams> for AesCbc {
	type Error = Error;

	fn try_from(value: proto::AesParams) -> Result<Self, Self::Error> {
		let key = Key::try_from(value.aes_key)?;
		let iv = Iv::try_from(value.iv)?;

		Ok(Self::new(key, iv))
	}
}

impl Deserializable for AesCbc {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> {
		Ok(Self::try_from(proto::AesParams::decode(buf).or_else(|_| Err(Error::BadAesParamsFormat))?)?)
  }
}

#[cfg(test)]
mod tests {
	use super::{AesCbc, Key, Iv};

	const KEY_SIZE: usize = Key::SIZE;
	const IV_SIZE: usize = Iv::SIZE;

	#[test]
	fn test_gen_iv_key_unique() {
		let k0 = Key::generate();
		let k1 = Key::generate();

		assert_ne!(k0.0, k1.0);

		let iv0 = Iv::generate();
		let iv1 = Iv::generate();

		assert_ne!(iv0.0, iv1.0);
	}

	#[test]
	fn test_gen_iv_key_non_zeroes() {
		let k = Key::generate();
		let iv = Iv::generate();

		assert_ne!(k.0, [0u8; Key::SIZE]);
		assert_ne!(iv.0, [0u8; Iv::SIZE]);
	}

	#[test]
	fn test_decrypt() {
		let key = Key(b"256BitsKey256BitsKey256BitsKey25".to_owned());
		let iv = Iv(b"InitializationVr".to_owned());
		let ct = b"\x46\xbe\xfd\xd9\xf2\xf7\x19\x7a\xbc\xec\x49\x9e\xce\xe0\x96\xa3\x3d\x69\x31\xa7\x4b\x41\xe0\xa5\xbb\x1a\xdb\x74\xc7\xb8\x47\xd7";
		let plain = b"12345678901234567";

		let aes = AesCbc::new(key, iv);
		let res = aes.decrypt(ct);

		assert_eq!(res.unwrap(), plain);
	}

	#[test]
	fn test_encrypt_decrypt() {
		let aes = AesCbc::new(Key([1u8; KEY_SIZE]), Iv([2u8; IV_SIZE]));
		let pt = b"hi there";
		let ct = aes.encrypt(pt);
		let res = aes.decrypt(&ct);

		assert_eq!(res.unwrap(), pt);
	}

	#[test]
	fn test_decrypt_fails_with_wrong_material() {
		let aes = AesCbc::new(Key([1u8; KEY_SIZE]), Iv([2u8; IV_SIZE]));
		let pt = b"hi there";
		let ct = aes.encrypt(pt);

		// wrong key
		let wrong_aes = AesCbc::new(Key([3u8; KEY_SIZE]), Iv([2u8; IV_SIZE]));
		assert!(wrong_aes.decrypt(&ct).is_err());
		
		// wrong iv
		let wrong_aes = AesCbc::new(Key([1u8; KEY_SIZE]), Iv([3u8; IV_SIZE]));
		assert!(wrong_aes.decrypt(&ct).is_err());

		// wrong key and iv
		let wrong_aes = AesCbc::new(Key([5u8; KEY_SIZE]), Iv([3u8; IV_SIZE]));
		assert!(wrong_aes.decrypt(&ct).is_err());
	}
}