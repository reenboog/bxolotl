use crate::key_pair::{KeyPairX448, KeyPairNtru};

struct Prekey {
	key_x448: KeyPairX448,
	key_ntru: KeyPairNtru,
	last_resort: bool
}

impl Prekey {
	pub fn new(key_x448: KeyPairX448, key_ntru: KeyPairNtru, last_resort: bool) -> Self {
		Self { key_x448, key_ntru, last_resort }
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_new() {
		todo!();
	}
}