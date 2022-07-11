use crate::{aes_cbc::AesCbc, serializable::{Deserializable, self}, private_key::PrivateKey, public_key::PublicKey, x448::PublicKeyX448, key_pair::{KeyPairSize, KeyPair}, proto};
// TODO: check if it's cbc
// pub struct AesParams(AesCbc);

#[derive(Clone)]
pub struct NtruEncrypted {
	pub encryption_key_id: u64, // encrypting_ntru_key_id
	pub aes_params: Vec<u8>, // ntru_encrypted_aes_params; TODO: why keep encoded?
	// decrypts to either another NtruEncrypted or to straight to (PublicKeyX448, PublickKeyNtru)
	pub payload: Vec<u8> // aes_encrypted_data; TODO: why keep encoded?
}

// decrypted NtruEncrypted: x448 + ntru ratches
pub struct NtruedKeys {
	pub ephemeral: PublicKeyX448,
	pub ntru: PublicKeyNtru
}

impl Deserializable for NtruedKeys {
    type Error = serializable::Error;

    fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> where Self: Sized {
			// TODO: protobuf implement:
			// 1 proto::NtruedKeys::decode(buf)
			// 2 TryFrom<proto:NtruedKeys>
			todo!()
    }
}

impl Deserializable for NtruEncrypted {
	type Error = serializable::Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> where Self: Sized {
		// TODO: protobuf implement:
		// 1 proto::NtruEncrypted::decode(buf)
		// 2 TryFrom<proto:NtruEncrypted>
		todo!()
	}
}

impl From<&NtruEncrypted> for proto::NtruEncrypted {
	fn from(src: &NtruEncrypted) -> Self {
		Self {
			encrypting_ntru_key_id: src.encryption_key_id,
			ntru_encrypted_aes_params: src.aes_params.clone(),
			aes_encrypted_data: src.payload.clone()
		}
	}
}

#[derive(Clone)]
pub struct NtruEncryptedKey {
	pub key_id: u64, // ephemeral_key_id
	pub double_encrypted: bool,
	pub payload: NtruEncrypted // ntru_encrypted
}

impl From<&NtruEncryptedKey> for proto::NtruEncryptedEphemeralKey {
	fn from(src: &NtruEncryptedKey) -> Self {
		Self {
			ephemeral_key_id: src.key_id,
			double_encrypted: src.double_encrypted,
			ntru_encrypted: proto::NtruEncrypted::from(&src.payload)
		}
	}
}

pub fn encrypt_sealed(plain: &[u8], key: &PublicKeyNtru) -> NtruEncrypted {
	todo!()
}

// TODO: should I pass a key pair instead of just private key and check if ciphertext.encryption_key_id == pair.public.id?
pub fn decrypt_sealed(ciphertext: &NtruEncrypted, key: &PrivateKeyNtru) -> Vec<u8> {
	todo!()
}

// encrypts (eph, ntru) with encrypting_key and optionally with second_encrypting_key, if present
// double encryption is now done only for initial key exchange
pub fn encrypt_ephemeral(eph: &PublicKeyX448, ntru: &PublicKeyNtru, encrypting_key: &PublicKeyNtru, second_encrypting_key: Option<&PublicKeyNtru>) -> NtruEncryptedKey {
	todo!()
}

pub struct KeyTypeNtru;

impl KeyPairSize for KeyTypeNtru {
	const PRIV: usize = ntrust::bridge::PRIVATE_KEY_SIZE;
	const PUB: usize = ntrust::bridge::PUBLIC_KEY_SIZE;
}

pub type PrivateKeyNtru = PrivateKey<KeyTypeNtru, { KeyTypeNtru::PRIV }>;
pub type PublicKeyNtru = PublicKey<KeyTypeNtru, { KeyTypeNtru::PUB }>;

pub type KeyPairNtru = KeyPair<KeyTypeNtru, { KeyTypeNtru::PRIV }, { KeyTypeNtru::PUB }>;

impl KeyPairNtru {
	pub fn generate() -> Self {
		use ntrust::bridge::{PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, ntru_generate_key_pair};

		let mut priv_key_len = PRIVATE_KEY_SIZE;
		let mut pub_key_len = PUBLIC_KEY_SIZE;

		let mut private = [0u8; PRIVATE_KEY_SIZE];
		let mut public = [0u8; PUBLIC_KEY_SIZE];

		unsafe {
			let res = ntru_generate_key_pair(&mut pub_key_len, public.as_mut_ptr(), &mut priv_key_len, private.as_mut_ptr());

			if res != 0 {
				panic!("NTRU key generation failed {}", res);
			}
		};

		Self::new(PrivateKeyNtru::new(private), PublicKeyNtru::new(public))
	}
}

impl PublicKeyNtru {
	pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
		use ntrust::bridge::ntru_encrypt;
		use std::ptr::null_mut;

		unsafe {
			let key = self.as_bytes().as_ptr();
			let key_len = self.as_bytes().len();
			let msg_len = msg.len() as u16;
			let mut ct_len = 0u16;

			ntru_encrypt(key_len, key, msg_len, msg.as_ptr(), &mut ct_len, null_mut());

			let mut ct = vec![0u8; ct_len as usize];
			ntru_encrypt(key_len, key, msg_len, msg.as_ptr(), &mut ct_len, ct.as_mut_ptr());

			ct
		}
	}
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	WrongKey
}

impl PrivateKeyNtru {
	pub fn decrypt(self, ct: &[u8]) -> Result<Vec<u8>, Error> {
		use ntrust::bridge::ntru_decrypt;
		use std::ptr::null_mut;

		unsafe {
			let key = self.as_bytes().as_ptr();
			let key_len = self.as_bytes().len();
			let ct_len = ct.len() as u16;
			let mut pt_len = 0u16;

			ntru_decrypt(key_len, key, ct_len, ct.as_ptr(), &mut pt_len, null_mut());

			let mut pt = vec![0u8; pt_len as usize];
			let res = ntru_decrypt(key_len, key, ct_len, ct.as_ptr(), &mut pt_len, pt.as_mut_ptr());

			if res != 0 {
				Err(Error::WrongKey)
			} else {
				pt.resize(pt_len as usize, 0u8);

				Ok(pt)
			}
		}

	}
}

#[cfg(test)]
mod tests {
	use crate::{ntru::{KeyTypeNtru}, key_pair::KeyPairSize};
	use super::{KeyPairNtru, Error};

	#[test]
	fn test_gen_keypair_non_zeroes() {
		let kp = KeyPairNtru::generate();

		assert_ne!(kp.private_key().as_bytes(), &[0u8; KeyTypeNtru::PRIV]);
		assert_ne!(kp.public_key().as_bytes(), &[0u8; KeyTypeNtru::PUB]);
	}

	#[test]
	fn test_gen_keypair_unique() {
		let kp0 = KeyPairNtru::generate();
		let kp1 = KeyPairNtru::generate();

		assert_ne!(kp0.private_key().as_bytes(), kp1.private_key().as_bytes());
		assert_ne!(kp0.public_key().as_bytes(), kp1.public_key().as_bytes());
	}

	#[test]
	fn test_encrypt_decrypt() {
		let msg = b"hello there";
		let kp = KeyPairNtru::generate();

		let encrypted = kp.public_key().encrypt(msg);
		let decrypted = kp.private_key().clone().decrypt(&encrypted);

		assert_eq!(Ok(msg.to_vec()), decrypted);
	}

	#[test]
	fn test_decryption_fails_with_wrong_key() {
		let msg = b"hello there";
		let kp = KeyPairNtru::generate();
		let encrypted = kp.public_key().encrypt(msg);
		let decrypted = KeyPairNtru::generate().private_key().clone().decrypt(&encrypted);

		assert_eq!(Err(Error::WrongKey), decrypted);
	}

	#[test]
	fn test_encrypt_ephemeral() {
		// todo!()
	}

	#[test]
	fn test_encrypt_ephemeral_with_second_key() {
		// todo!()
	}
}