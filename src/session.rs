use crate::{public_key::{PublicKeyX448, PublicKey}, chain_key::ChainKey, key_pair::{KeyPairX448, KeyPairNtru}, root_key::RootKey};

enum Role {
	Alice, Bob
}

// const bytes_t material = hkdf(sha::sha2_256(secret)).expand(64);
// const bytes_t root_key_data(material.begin(), material.begin() + 32);
// const bytes_t chain_key_data(material.begin() + 32, material.begin() + 64);
// return master_key(root_key_data, chain_key(chain_key_data, 0));

struct Id(u64);

impl Id {
	// add parameters
	fn new() {
		todo!()
	}
}

struct Session {
	id: Id, // u64?
	role: Role,
	counter: i32, // u32?
	prev_counter: i32, // u32?
	ratchet_counter: i32, // u32?
	their_identity: Option<PublicKeyX448>, // make non optiona? embed into role?
	root_key: RootKey,
	send_chain_key: ChainKey,
	// receive_chain
	my_ratchet: KeyPairX448,
	my_ratchet_ntru: KeyPairNtru,
	their_ratchet: KeyPairX448,
	their_ratchet_ntru: KeyPairNtru,
	// unacked_key_exchange
	alice_base_key: PublicKeyX448,
	my_identity_ntru: KeyPairNtru
}

pub struct AcolotlMac {
	body: Vec<u8>, // TODO: introduce a new type?
	mac: [u8; 32] // TODO: fix the size
}

impl Session {
	fn encrypt(&self, msg: &[u8]) -> AcolotlMac {
		todo!()
	}

	fn decrypt(&self, mac: &AcolotlMac) -> Vec<u8> {
		todo!()
	}
}