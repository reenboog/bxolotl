use crate::{ed448::{Signature, PublicKeyEd448}, x448::PublicKeyX448};

// TODO: make more generic?,ie any public key signed with any signing key?
// Represents any public key signed by en Ed448Key
#[derive(Clone)]
pub struct SignedPublicKey {
	key: PublicKeyX448,
	signature: Signature
}

impl SignedPublicKey {
	pub fn new(key: PublicKeyX448, signature: Signature) -> Self {
		Self { key, signature }
	}

	pub fn key(&self) -> &PublicKeyX448 {
		&self.key
	}

	pub fn signature(&self) -> &Signature {
		&self.signature
	}
}

impl SignedPublicKey {
	pub fn verify(&self, signing_key_pub: &PublicKeyEd448) -> bool {
		signing_key_pub.verify(self.key.as_bytes(), &self.signature)
	}
}

pub type SignedPublicKeyX448 = SignedPublicKey;

#[cfg(test)]
mod tests {
	use crate::{x448::{PublicKeyX448, KeyPairX448}, ed448::KeyPairEd448};
	use super::SignedPublicKeyX448;

	#[test]
	fn test_sign_verify() {
		let signing_keypair = KeyPairEd448::generate();
		let public = PublicKeyX448::new(b"\x9b\x08\xf7\xcc\x31\xb7\xe3\xe6\x7d\x22\xd5\xae\xa1\x21\x07\x4a\x27\x3b\xd2\xb8\x3d\xe0\x9c\x63\xfa\xa7\x3d\x2c\x22\xc5\xd9\xbb\xc8\x36\x64\x72\x41\xd9\x53\xd4\x0c\x5b\x12\xda\x88\x12\x0d\x53\x17\x7f\x80\xe5\x32\xc4\x1f\xa0".to_owned());
		let signature = signing_keypair.private_key().sign(public.as_bytes());
		let signed_public = SignedPublicKeyX448::new(public, signature);

		assert!(signed_public.verify(signing_keypair.public_key()));
	}

	#[test]
	fn test_verification_fails_with_wrong_key() {
		let signing_keypair = KeyPairEd448::generate();
		let public = KeyPairX448::generate().public_key().to_owned();
		let signature = signing_keypair.private_key().sign(public.as_bytes());
		let signed_public = SignedPublicKeyX448::new(public, signature);

		assert!(!signed_public.verify(&KeyPairEd448::generate().public_key()));
	}
}