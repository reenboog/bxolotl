use crate::{key_pair::{KeyPairSize, KeyPair}, private_key::{PrivateKey, SharedKey}, public_key::PublicKey};

pub struct KeyTypeX448;

impl KeyPairSize for KeyTypeX448 {
	const PRIV: usize = 56;
	const PUB: usize = 56;
}

impl KeyTypeX448 {
	const SHARED: usize = 56;
}

pub type PrivateKeyX448 = PrivateKey<KeyTypeX448, { KeyTypeX448::PRIV }>;
pub type PublicKeyX448 = PublicKey<KeyTypeX448, { KeyTypeX448::PUB }>;
pub type KeyPairX448 = KeyPair<KeyTypeX448, { KeyTypeX448::PRIV }, { KeyTypeX448::PUB }>;
pub type SharedKeyX448 = SharedKey<KeyTypeX448, { KeyTypeX448::SHARED }>;

impl PrivateKeyX448 {
	pub fn generate() -> Self {
		use x448::Secret;

		let mut csprng = rand_07::thread_rng();
		let secret = Secret::new(&mut csprng);

		secret.as_bytes().into()
	}
}

impl PublicKeyX448 {
	pub fn from_private(key: &PrivateKeyX448) -> Self {
		use x448::{Secret, PublicKey};

		let secret = Secret::from(key);
		let public = PublicKey::from(&secret);

		public.as_bytes().into()
	}
}

impl From<&PrivateKeyX448> for x448::Secret {
	fn from(key: &PrivateKeyX448) -> Self {
		// TODO: how about low order points?
		Self::from_bytes(key.as_bytes()).unwrap()
	}
}

impl From<&PublicKeyX448> for x448::PublicKey {
	fn from(key: &PublicKeyX448) -> Self {
		// TODO: how about low order points?
		Self::from_bytes(key.as_bytes()).unwrap()
	}
}

impl KeyPairX448 {
	pub fn generate() -> Self {
		let private = PrivateKeyX448::generate();
		let public = PublicKeyX448::from_private(&private);

		Self::new(private, public)
	}
}

pub fn dh_exchange(private: &PrivateKeyX448, public: &PublicKeyX448) -> SharedKeyX448 {
	use x448::{Secret, PublicKey};

	let private = Secret::from(private);
	let public = PublicKey::from(public);
	let shared = private.as_diffie_hellman(&public).unwrap();

	SharedKeyX448::new(shared.as_bytes().clone())
}

#[cfg(test)]
mod tests {
	use crate::key_pair::KeyPairSize;
	use super::{PrivateKeyX448, KeyTypeX448, PublicKeyX448, KeyPairX448, dh_exchange};

	#[test]
	fn test_gen_private_not_zeroes() {
		let key = PrivateKeyX448::generate();

		assert_ne!(key.as_bytes().to_owned(), [0u8; KeyTypeX448::PRIV])
	}

	#[test]
	fn test_public_from_private() {
		let private = PrivateKeyX448::new(b"\x9a\x8f\x49\x25\xd1\x51\x9f\x57\x75\xcf\x46\xb0\x4b\x58\x00\xd4\xee\x9e\xe8\xba\xe8\xbc\x55\x65\xd4\x98\xc2\x8d\xd9\xc9\xba\xf5\x74\xa9\x41\x97\x44\x89\x73\x91\x00\x63\x82\xa6\xf1\x27\xab\x1d\x9a\xc2\xd8\xc0\xa5\x98\x72\x6b".to_owned());
		let public = PublicKeyX448::from_private(&private);

		assert_eq!(public.as_bytes().to_owned(), b"\x9b\x08\xf7\xcc\x31\xb7\xe3\xe6\x7d\x22\xd5\xae\xa1\x21\x07\x4a\x27\x3b\xd2\xb8\x3d\xe0\x9c\x63\xfa\xa7\x3d\x2c\x22\xc5\xd9\xbb\xc8\x36\x64\x72\x41\xd9\x53\xd4\x0c\x5b\x12\xda\x88\x12\x0d\x53\x17\x7f\x80\xe5\x32\xc4\x1f\xa0".to_owned());
	}

	#[test]
	fn test_gen_keypair_non_zeroes() {
		let kp = KeyPairX448::generate();

		assert_ne!(kp.private_key().as_bytes().to_owned(), [0u8; KeyTypeX448::PRIV]);
		assert_ne!(kp.public_key().as_bytes().to_owned(), [0u8; KeyTypeX448::PUB]);
	}

	#[test]
	fn test_dh_exchange() {
		let alice_kp = KeyPairX448::generate();
		let bob_kp = KeyPairX448::generate();
		let dh_ab = dh_exchange(alice_kp.private_key(), bob_kp.public_key());
		let dh_ba = dh_exchange(bob_kp.private_key(), alice_kp.public_key());

		assert_ne!(dh_ab.as_bytes().to_owned(), [0u8; KeyTypeX448::SHARED]);
		assert_eq!(dh_ab.as_bytes().to_owned(), dh_ba.as_bytes().to_owned());
	}
}