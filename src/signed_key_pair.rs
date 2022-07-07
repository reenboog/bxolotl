use crate::{signed_public_key::{SignedPublicKeyX448}, x448::PrivateKeyX448};

// TODO: make generic (aggregate KeyPair?)
// Represents any key pair signed by an Ed448 key
pub struct SignedKeyPair {
	private: PrivateKeyX448,
	public: SignedPublicKeyX448
}

impl SignedKeyPair {
	pub fn private(&self) -> &PrivateKeyX448 {
		&self.private
	}

	pub fn public(&self) -> &SignedPublicKeyX448 {
		&self.public
	}
}

pub type SignedKeyPairX448 = SignedKeyPair;