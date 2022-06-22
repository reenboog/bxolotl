use crate::{chain_key::ChainKey, key_pair::{KeyPairX448, KeyPairNtru, PublicKeyX448, PublicKeyNtru}, root_key::RootKey, receive_chain::ReceiveChain, message::KeyExchange};

enum Role {
	Alice, Bob
}

// const bytes_t material = hkdf(sha::sha2_256(secret)).expand(64);
// const bytes_t root_key_data(material.begin(), material.begin() + 32);
// const bytes_t chain_key_data(material.begin() + 32, material.begin() + 64);
// return master_key(root_key_data, chain_key(chain_key_data, 0));

struct Id(u64);

impl Id {
	pub fn new(id: u64) -> Self {
		Self(id)
	}
}

struct Session {
	id: Id,
	role: Role,

	counter: u32,
	prev_counter: u32,
	ratchet_counter: u32,

	my_identity_ntru: KeyPairNtru,

	root_key: RootKey,
	// TODO: can be made non optional if root_key is initialized in either alice/bob instead of encrypt as is now
	send_chain_key: Option<ChainKey>, 
	receive_chain: ReceiveChain,

	// TODO: these two can be made non optional, if instead of resetting on decrypt a new ratched is generated
	my_ratchet: Option<KeyPairX448>, 
	my_ratchet_ntru: Option<KeyPairNtru>,

	their_ratchet: Option<PublicKeyX448>, // TODO: try making non optional
	their_ratchet_ntru: Option<PublicKeyNtru>, // TODO: try making non optional

	unacked_key_exchange: Option<KeyExchange>,

	alice_base_key: PublicKeyX448 // TODO: rather store base_key_id, for it's only used 
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

impl Session {
	fn alice() -> Self {
		todo!()
	}

	fn bob() -> Self {
		todo!()
	}
}