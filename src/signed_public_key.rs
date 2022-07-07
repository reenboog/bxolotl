use crate::{ed448::{Signature, PublicKeyEd448}, x448::PublicKeyX448};

// TODO: make more generic?,ie any public key signed with any signing key?
// Represents any public key signed by en Ed448Key
pub struct SignedPublicKey {
	key: PublicKeyX448,
	signature: Signature
}

impl SignedPublicKey {
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
	#[test]
	fn test_sign_verify() {
		todo!()
	}
}