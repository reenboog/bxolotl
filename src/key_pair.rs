use crate::{private_key::PrivateKey, public_key::PublicKey};

pub struct KeyPair<T, const PRIV_SIZE: usize, const PUB_SIZE: usize> {
	private: PrivateKey<T, PRIV_SIZE>,
	public: PublicKey<T, PUB_SIZE>
}

impl<T, const PRIV_SIZE: usize, const PUB_SIZE: usize> KeyPair<T, PRIV_SIZE, PUB_SIZE> {
	pub fn new(private: PrivateKey<T, PRIV_SIZE>, public: PublicKey<T, PUB_SIZE>) -> Self {
		Self { private, public }
	}

	pub fn public_key(&self) -> &PublicKey<T, PUB_SIZE> {
		&self.public
	}

	pub fn private_key(&self) -> &PrivateKey<T, PRIV_SIZE> {
		&self.private
	}
}
// TODO: introduce size() for this or any another phantom type to check when deserializing
pub struct KeyTypeX448;

pub type PrivateKeyX448 = PrivateKey<KeyTypeX448, 56>;
pub type PublicKeyX448 = PublicKey<KeyTypeX448, 56>;

pub struct KeyTypeNtru;

pub type PrivateKeyNtru = PrivateKey<KeyTypeNtru, 1120>;
pub type PublicKeyNtru = PublicKey<KeyTypeNtru, 1027>;

pub type KeyPairX448 = KeyPair<KeyTypeX448, 56, 56>;
pub type KeyPairNtru = KeyPair<KeyTypeNtru, 1120, 1027>;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_new() {
		struct TestKeyType;

		let private = PrivateKey::<TestKeyType, 2>::new(b"12".to_owned());
		let public = PublicKey::<TestKeyType, 4>::new(b"1234".to_owned());

		let _ = KeyPair::<TestKeyType, 2, 4>::new(private, public);

		// this won't compile because of different types:
		// let bad_key = PublicKey::<OtherType, 4>::new(b"1234".to_owned());
		// let kp = KeyPair::<TestKeyType, 2, 4>::new(private, bad_key);

		// this won't compile because of different sizes:
		// let bad_key = PublicKey::<TestKeyType, 10>::new(b"0123456789".to_owned());
		// let kp = KeyPair::<TestKeyType, 2, 4>::new(private, bad_key);
	}
}