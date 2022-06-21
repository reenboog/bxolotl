const KEY_SIZE: usize = 32;
const IV_SIZE: usize = 16;

pub struct Key(pub [u8; KEY_SIZE]);
pub struct Iv(pub [u8; IV_SIZE]);

pub struct AesCbc {
	pub key: Key,
	pub iv: Iv
}

impl AesCbc {
	pub fn new(key: Key, iv: Iv) -> Self {
		Self { key, iv }
	}
}

impl AesCbc {
	pub fn encrypt(plaintext: &[u8]) -> Vec<u8> {
		todo!()
	}

	pub fn decrypt(ciphrtext: &[u8]) -> Vec<u8> {
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