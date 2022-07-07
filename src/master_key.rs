use crate::{chain_key::ChainKey, root_key::RootKey, signed_public_key::{SignedPublicKeyX448}, signed_key_pair::{SignedKeyPairX448}, x448::{KeyPairX448, PublicKeyX448}};

// TODO: use (ChainKey, RootKey) instead
pub struct MasterKey {
	chain_key: ChainKey,
	root_key: RootKey
}

impl MasterKey {
	pub fn chain_key(&self) -> &ChainKey {
		&self.chain_key
	}

	pub fn root_key(&self) -> &RootKey {
		&self.root_key
	}
}

impl From<MasterKey> for (ChainKey, RootKey) {
	fn from(key: MasterKey) -> Self {
		(key.chain_key, key.root_key)
	}
}

pub fn alice(my_identity: &KeyPairX448,
	my_ephemeral: &KeyPairX448,
	their_identity: &PublicKeyX448,
	their_signed_prekey: &SignedPublicKeyX448,
	their_prekey: &PublicKeyX448) -> MasterKey {
	todo!()
}

pub fn bob(my_identity: &KeyPairX448,
	my_signed_prekey: &SignedKeyPairX448,
	my_prekey: &KeyPairX448,
	their_identity: &PublicKeyX448,
	their_ephemeral: &PublicKeyX448) -> MasterKey {
	todo!()
}

pub fn derive(root: &RootKey, my_ratchet: &KeyPairX448, their_ratchet: &PublicKeyX448) -> MasterKey {
	todo!()
}

#[cfg(test)]

mod tests {

	#[test]
	fn test_dh_unknown_failed() {
		todo!()
	}

	#[test]
	fn test_dh_alice() {
		todo!()
	}

	#[test]
	fn test_dh_bob() {
		todo!()
	}
}