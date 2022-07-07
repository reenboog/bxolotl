use crate::{key_pair::{KeyPairSize, KeyPair}, private_key::PrivateKey, public_key::PublicKey};

const SIZE: usize = 114;

pub struct Signature {
	bytes: [u8; SIZE]
}

impl Signature {
	pub fn as_bytes(&self) -> &[u8; SIZE] {
		&self.bytes
	}
}

pub struct KeyTypeEd448;

impl KeyPairSize for KeyTypeEd448 {
	const PRIV: usize = 57;
	const PUB: usize = 57;
}

pub type PrivateKeyEd448 = PrivateKey<KeyTypeEd448, { KeyTypeEd448::PRIV }>;
pub type PublicKeyEd448 = PublicKey<KeyTypeEd448, { KeyTypeEd448::PUB }>;
pub type KeyPairEd448 = KeyPair<KeyTypeEd448, { KeyTypeEd448::PRIV }, { KeyTypeEd448::PUB }>;

impl PrivateKeyEd448 {
	pub fn sign(&self, msg: &[u8]) -> Signature {
		// TODO: implement
		// TODO: test success verify
		// TODO: test failure verify
		todo!()
	}
}

impl PublicKeyEd448 {
	pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
		// TODO: implement
		todo!()
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_new() {
		todo!()
	}
}