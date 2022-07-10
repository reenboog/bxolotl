use crate::{chain_key::ChainKey, root_key::RootKey, signed_public_key::{SignedPublicKeyX448}, signed_key_pair::{SignedKeyPairX448}, x448::{KeyPairX448, PublicKeyX448, dh_exchange}, hkdf};

pub struct MasterKey {
	chain_key: ChainKey,
	root_key: RootKey
}

impl MasterKey {
	pub fn new(root_key: RootKey, chain_key: ChainKey) -> Self {
		Self { root_key, chain_key }
	}

	pub fn from_secret(secret: &[u8]) -> MasterKey {
		use sha2::{Sha256, Digest};
		use crate::hmac;

		let digest = Sha256::digest(secret);
		let material = hkdf::Hkdf::from_ikm(&digest.into()).expand_no_info::<{RootKey::SIZE + ChainKey::SIZE}>();
		let root = RootKey::new(material[..RootKey::SIZE].try_into().unwrap());
		let chain = ChainKey::new(hmac::Key::from(&material[RootKey::SIZE..].try_into().unwrap()), 0);

		MasterKey::new(root, chain)
	}

	pub fn alice(my_identity: &KeyPairX448,
		my_ephemeral: &KeyPairX448,
		their_identity: &PublicKeyX448,
		their_signed_prekey: &SignedPublicKeyX448,
		their_prekey: &PublicKeyX448) -> MasterKey {
			// TODO: would be nice to restrict what can be dh-ed with what to avoid mistakes (same for bob)
			let a1 = dh_exchange(my_identity.private_key(), their_signed_prekey.key());
			let a2 = dh_exchange(my_ephemeral.private_key(), their_identity);
			let a3 = dh_exchange(my_ephemeral.private_key(), their_signed_prekey.key());
			let a4 = dh_exchange(my_ephemeral.private_key(), their_prekey);

			let secret = [a1, a2, a3, a4].map(|a| a.as_bytes().to_owned()).concat();

			MasterKey::from_secret(&secret)
	}

	pub fn bob(my_identity: &KeyPairX448,
		my_signed_prekey: &SignedKeyPairX448,
		my_prekey: &KeyPairX448,
		their_identity: &PublicKeyX448,
		their_ephemeral: &PublicKeyX448) -> MasterKey {
			let a1 = dh_exchange(my_signed_prekey.private(), their_identity);
			let a2 = dh_exchange(my_identity.private_key(), their_ephemeral);
			let a3 = dh_exchange(my_signed_prekey.private(), their_ephemeral);
			let a4 = dh_exchange(my_prekey.private_key(), their_ephemeral);

			let secret = [a1, a2, a3, a4].map(|a| a.as_bytes().to_owned()).concat();

			MasterKey::from_secret(&secret)
	}

	pub fn derive(root: &RootKey, my_ratchet: &KeyPairX448, their_ratchet: &PublicKeyX448) -> MasterKey {
		todo!()
	}

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

#[cfg(test)]
mod tests {

	#[test]
	fn test_master_unknown_failed() {
		todo!()
	}

	#[test]
	fn test_master_alice() {
		todo!()
	}

	#[test]
	fn test_master_bob() {
		todo!()
	}

	#[test]
	fn test_derive() {
		todo!()
	}
}