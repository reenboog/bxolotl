use crate::{x448::KeyPairX448, ntru::KeyPairNtru};

pub struct Prekey {
	pub key_x448: KeyPairX448,
	pub key_ntru: KeyPairNtru,
	pub last_resort: bool
}

impl Prekey {
	// pub fn new(key_x448: KeyPairX448, key_ntru: KeyPairNtru, last_resort: bool) -> Self {
	// 	Self { key_x448, key_ntru, last_resort }
	// }

	pub fn id(&self) -> u64 {
		self.key_x448.public_key().id()
	}
}