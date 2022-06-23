use crate::{chain_key::ChainKey, root_key::RootKey, key_pair::{KeyPairX448, PublicKeyX448}, signed_public_key::SignedPublicKey, signed_key_pair::SignedKeyPair};

struct MasterKey {
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

pub fn alice(my_identity: &KeyPairX448,
	my_ephemeral: &KeyPairX448,
	their_identity: &PublicKeyX448,
	their_signed_prekey: &SignedPublicKey,
	their_prekey: &PublicKeyX448) -> MasterKey {
	todo!()
}

pub fn bob(my_identity: &KeyPairX448,
	my_signed_prekey: &SignedKeyPair,
	my_prekey: &KeyPairX448,
	their_identity: &PublicKeyX448,
	their_ephemeral: &PublicKeyX448
) -> MasterKey {
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