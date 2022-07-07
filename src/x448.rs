use crate::{key_pair::{KeyPairSize, KeyPair}, private_key::PrivateKey, public_key::PublicKey};

pub struct KeyTypeX448;

impl KeyPairSize for KeyTypeX448 {
	const PRIV: usize = 56;
	const PUB: usize = 56;
}

pub type PrivateKeyX448 = PrivateKey<KeyTypeX448, { KeyTypeX448::PRIV }>;
pub type PublicKeyX448 = PublicKey<KeyTypeX448, { KeyTypeX448::PUB }>;
pub type KeyPairX448 = KeyPair<KeyTypeX448, { KeyTypeX448::PRIV }, { KeyTypeX448::PUB }>;

impl KeyPairX448 {
	// TODO: implement, replace with new?
	pub fn generate() -> Self {
		todo!()
	}
}

impl Clone for PublicKeyX448 {
	fn clone(&self) -> Self {
		Self::new(self.as_bytes().clone())
	}
}