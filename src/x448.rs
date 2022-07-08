use ring::hkdf::KeyType;

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
pub type SharedKeyX448 = SharedKey<KeyTypeX448, { KeyTypeX448::SHARED }>;
pub type KeyPairX448 = KeyPair<KeyTypeX448, { KeyTypeX448::PRIV }, { KeyTypeX448::PUB }>;

impl KeyPairX448 {
	// TODO: implement, replace with new?
	pub fn generate() -> Self {
		todo!()
	}
}

pub fn dh_exchange(private: &PrivateKeyX448, public: &PublicKeyX448) -> SharedKeyX448 {
	// convert private
	// convert public
	// get result
	// convert result
	todo!()
}