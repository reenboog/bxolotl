use crate::{chain_key::ChainKey, root_key::RootKey, signed_public_key::{SignedPublicKeyX448}, signed_key_pair::{SignedKeyPairX448}, x448::{KeyPairX448, PublicKeyX448, dh_exchange}, hmac, hkdf};

pub struct MasterKey {
	chain_key: ChainKey,
	root_key: RootKey
}

impl MasterKey {
	pub fn new(root_key: RootKey, chain_key: ChainKey) -> Self {
		Self { root_key, chain_key }
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

	pub fn from_secret(secret: &[u8]) -> MasterKey {
		use sha2::{Sha256, Digest};

		let digest = Sha256::digest(secret);
		let material = hkdf::Hkdf::from_ikm(&digest).expand_no_info::<{RootKey::SIZE + ChainKey::SIZE}>();
		let root = RootKey::new(material[..RootKey::SIZE].try_into().unwrap());
		let chain = ChainKey::new(hmac::Key::from(&material[RootKey::SIZE..].try_into().unwrap()), 0);

		MasterKey::new(root, chain)
	}

	pub fn derive(root: &RootKey, my_ratchet: &KeyPairX448, their_ratchet: &PublicKeyX448) -> MasterKey {
		let agreement = dh_exchange(my_ratchet.private_key(), their_ratchet);
		let digest = hmac::digest(&hmac::Key::from(root.as_bytes()), agreement.as_bytes());
		let material = hkdf::Hkdf::from_ikm(digest.as_bytes()).expand_no_info::<{RootKey::SIZE + ChainKey::SIZE}>();
		let root = RootKey::new(material[..RootKey::SIZE].try_into().unwrap());
		let chain = ChainKey::new(hmac::Key::from(&material[RootKey::SIZE..].try_into().unwrap()), 0);

		MasterKey::new(root, chain)
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
	use crate::{hmac, x448::{PrivateKeyX448, PublicKeyX448, KeyPairX448}, chain_key::ChainKey, root_key::RootKey, ed448::{PrivateKeyEd448, PublicKeyEd448, self}, signed_public_key::SignedPublicKey};

use super::MasterKey;

	#[test]
	fn test_master_unknown_failed() {
		todo!()
	}

	fn alice_identity_x448_priv() -> PrivateKeyX448 {
		PrivateKeyX448::new(b"\x69\x53\xeb\x5c\xc3\xd8\x28\xcc\xe4\x35\x02\x14\x4e\x7c\x10\xc8\xc5\x0e\x35\xfd\x82\x9c\x7d\x68\x04\x38\x46\x96\x65\xbd\x83\x27\x88\xbb\x05\x8d\x35\xcc\xbf\x9e\x20\x46\x9a\x21\x11\xff\xc6\xff\xa8\x43\x14\x00\x2a\x89\x03\x7a".to_owned())
	}

	fn alice_identity_x448_pub() -> PublicKeyX448 {
		PublicKeyX448::new(b"\x5e\xa7\x96\xf3\x81\x87\x73\xc3\xd1\xdb\xa9\x99\xa7\x61\xdf\x5a\x4e\x07\x49\x7d\x2a\x59\xb1\x65\x88\x24\xa2\x3b\x66\xfd\x92\xbf\xb2\xec\xd3\xc4\xe0\xe5\x5c\xde\x28\x4c\x8f\x63\x1e\xc5\x10\xa4\x51\x06\x8a\xaf\x5c\x4b\x09\xf9".to_owned())
	}

	fn alice_ephemeral_x448_priv() -> PrivateKeyX448 {
		PrivateKeyX448::new(b"\x52\xcc\x5c\x4b\xef\x58\xa2\xf0\xa3\xbe\xe2\xa0\x37\x02\x3a\x6e\xd3\x75\x26\x6d\x0a\x5a\x3e\xab\x05\x63\xfa\x15\x1e\x70\x33\xe9\x18\x2d\x29\xb9\x95\xda\xe3\x31\xe6\x82\xf9\xc3\xc7\xd4\x3d\x51\xf8\x4e\x79\x78\x4a\x91\xfc\xda".to_owned())
	}

	fn alice_ephemeral_x448_pub() -> PublicKeyX448 {
		PublicKeyX448::new(b"\x52\xf0\xfe\xd0\xf8\xa2\xdd\x9d\xc6\xd9\x94\x5e\x69\x5b\x27\xf5\x73\xae\x0e\x44\x92\x93\xf0\x3b\x2b\xe0\x9e\x5a\xea\xd2\x69\xff\x1e\xa0\xea\xdc\xfa\xa8\x28\x96\x6f\xac\x89\x1f\x2d\xe7\x65\xc7\x80\x86\xa6\xf2\xe4\x9e\x15\xb1".to_owned())
	}

	// fn bob_identity_x448_priv() -> PrivateKeyX448 {
	// 	PrivateKeyX448::new(b"\xac\x19\x3a\x01\x36\x85\xe9\xce\xe2\xe6\xd2\x76\x51\x8c\xd6\xe6\xac\x5a\x34\x40\x19\x10\x47\x49\x8a\x96\xb4\x26\x85\x03\x0d\x35\x2d\x88\x3f\xc7\xde\x3c\xa0\x0c\x5a\x6e\xc9\xd5\x96\x0b\x6d\x99\xc7\x22\x5b\x6c\x76\x1f\xd1\x40".to_owned())
	// }

	fn bob_identity_x448_pub() -> PublicKeyX448 {
		PublicKeyX448::new(b"\xc2\xf9\xc6\x7d\x53\x33\x13\x9b\x10\xc5\x4b\x41\xed\x81\x63\x38\xdb\xcc\x60\xa9\x8d\xec\x68\xa5\xe9\x67\x92\x3a\x7d\xf4\xc3\x85\x99\x97\xc8\x7e\x4a\x6f\x4d\x29\xfd\x8e\x8b\x26\x00\x11\xb8\xcd\x6a\x48\xbb\x8c\xd3\x54\xec\xf0".to_owned())
	}

	// fn bob_prekey_x448_priv() -> PrivateKeyX448 {
	// 	PrivateKeyX448::new(b"\x25\xad\xaa\x22\x21\x94\xce\xa4\xd5\x5f\x37\x35\x9b\x25\x6b\x83\xb9\x60\x38\xbf\xc6\x4d\x71\x77\x81\x4f\x7b\xbc\xe6\x54\x0a\xb2\x95\x06\x6b\x12\xe7\x26\xce\xe1\xa5\xba\x50\x80\xf3\x9c\x62\x52\xb8\x38\x56\x1b\xe3\x97\x73\x19".to_owned())
	// }

	fn bob_prekey_x448_pub() -> PublicKeyX448 {
		PublicKeyX448::new(b"\x39\x23\x5a\x2c\x2d\xf6\x5a\x68\xda\xbb\x2a\x69\xec\xac\xfb\x23\x01\xf3\xa7\x6f\x8d\x7c\x01\xb1\x1f\xaa\x29\xff\x17\x87\x97\x17\xd3\x1c\xe0\x59\xc6\x0e\x57\x31\xe2\x61\x43\x69\x7c\x3f\x6e\xf7\xfa\x30\xe9\xff\x5b\xeb\x09\x1d".to_owned())
	}

	fn bob_signing_priv() -> PrivateKeyEd448 {
		PrivateKeyEd448::new(b"\xe6\x96\x39\x2a\x5b\xd9\xa0\xff\xa9\x5b\x08\xcf\x4f\xee\xd3\x88\xa7\x4c\x23\xdb\x48\x83\x7c\x7b\x14\x34\x64\x6d\xaf\x94\x1e\x37\x9b\x5d\x39\xc0\xc6\x7c\x8d\x5f\xa1\xf1\xc0\xad\x00\x37\xfe\xc3\xa5\x82\x51\xa0\x2c\xd7\xf6\x1a\x32".to_owned())
	}

	// fn bob_signing_pub() -> PublicKeyEd448 {
	// 	PublicKeyEd448::new(b"\xd2\x5c\x65\xdb\xa9\x59\xae\x4b\xe1\x41\x94\x7b\xc1\x6d\x88\xd5\x16\x52\x38\x18\x5a\x38\x91\xd0\x9a\xf8\xa5\x4d\x7f\xc7\x00\x65\xfa\xc0\x42\x33\xc2\xf2\xf0\xb1\xa3\x37\xfc\x85\x51\x7d\x11\x10\x33\x6d\xa7\x87\x85\x0e\xec\x2b\x80".to_owned())
	// }

	// fn bob_signed_prekey_x448_priv() -> PrivateKeyX448 {
	// 	PrivateKeyX448::new(b"\x45\x17\x44\x65\xca\x53\xfa\xd8\xf5\x5b\xf9\x94\xa8\x62\x6f\x91\x7f\x7b\x35\xff\x8a\x0a\x8e\x68\x4e\x6b\x7b\x26\xca\x63\xe6\x91\x30\x75\x23\x9a\x77\x84\x21\xef\x2f\x88\x37\x3e\x2e\x04\xc6\xb6\x83\x11\x92\xfe\x3a\xb5\xbc\x91".to_owned())
	// }

	fn bob_signed_prekey_x448_pub() -> PublicKeyX448 {
		PublicKeyX448::new(b"\x44\xda\xaf\xf7\x6c\xcf\x55\xe7\x4d\x24\xad\x0a\xe6\x8f\xb3\xdf\x69\x36\x39\xc3\x7b\xf2\x95\x9c\x9e\x94\x6b\xc6\xc1\xa3\xc7\xab\x81\x73\x08\x29\x23\xeb\x82\xda\x95\x16\x38\xe4\x31\x35\xd1\x97\xce\x03\x99\xc8\x01\x68\x02\x45".to_owned())
	}

	fn bob_signed_prekey() -> SignedPublicKey {
		SignedPublicKey::new(bob_signed_prekey_x448_pub(), bob_signing_priv().sign(bob_signed_prekey_x448_pub().as_bytes()))
	}

	fn expected_chain() -> ChainKey {
		ChainKey { 
			key: hmac::Key::from(b"\xc2\x8d\x58\xbd\x31\x7e\x21\xbf\xd1\x20\x4a\x11\xed\xf1\x14\x20\xe0\x79\x13\xe0\x55\xac\x3f\xc0\xd6\x1a\xd0\x77\x17\x43\x96\x7f"), 
			counter: 0
		}
	}

	fn expected_root() -> RootKey {
		RootKey::new(b"\x15\xcb\xd4\xe9\xb7\x3d\xc4\x55\xf9\x0c\xa3\xb5\xcf\x82\x12\x42\x60\x8a\x7e\x0b\x64\x0e\xfd\x63\x56\xca\xee\x5f\xe4\x3e\xfe\x55".to_owned())
	}

	#[test]
	fn test_master_alice() {
		let key = MasterKey::alice(
			&KeyPairX448::new(alice_identity_x448_priv(), alice_identity_x448_pub()),
			&KeyPairX448::new(alice_ephemeral_x448_priv(), alice_ephemeral_x448_pub()),
			&bob_identity_x448_pub(),
			&bob_signed_prekey(),
			&bob_prekey_x448_pub());

		assert_eq!(key.root_key().as_bytes(), expected_root().as_bytes());
		assert_eq!(key.chain_key().key().as_bytes(), expected_chain().key().as_bytes());
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