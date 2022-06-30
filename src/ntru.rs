
use crate::{aes_cbc::AesCbc, key_pair::{PublicKeyNtru, PrivateKeyNtru, PublicKeyX448}};

// TODO: check if it's cbc
pub struct AesParams(AesCbc);

pub struct NtruEncrypted {
	encryption_key_id: u64, // encrypting_ntru_key_id
	aes_params: Vec<u8>, // ntru_encrypted_aes_params; TODO: why keep encoded?
	payload: Vec<u8> // aes_encrypted_data; TODO: why keep encoded?
}

pub struct NtruEncryptedKey {
	key_id: u64, // ephemeral_key_id
	double_encrypted: bool,
	payload: NtruEncrypted // ntru_encrypted
}

pub fn encrypt(plain: &[u8], key: &PublicKeyNtru) -> NtruEncrypted {
	todo!()
}

// TODO: should I pass a key pair instead of just private key and check if ciphertext.encryption_key_id == pair.public.id?
pub fn decrypt(ciphertext: &NtruEncrypted, key: &PrivateKeyNtru) -> Vec<u8> {
	todo!()
}

// encrypts (eph, ntru) with encrypting_key and optionally with second_encrypting_key, if present
// double encryption is now done only for initial key exchange
pub fn encrypt_ephemeral(eph: &PublicKeyX448, ntru: &PublicKeyNtru, encrypting_key: &PublicKeyNtru, second_encrypting_key: Option<&PublicKeyNtru>) -> NtruEncryptedKey {
	todo!()
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_encrypt_decrypt() {
		todo!()
	}

	#[test]
	fn test_encrypt_ephemeral() {
		todo!()
	}

	#[test]
	fn test_encrypt_ephemeral_with_second_key() {
		todo!()
	}
}