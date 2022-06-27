use crate::{chain_key::ChainKey, key_pair::{KeyPairX448, KeyPairNtru, PublicKeyX448, PublicKeyNtru}, root_key::RootKey, receive_chain::ReceiveChain, key_exchange::KeyExchange, hmac::Digest, signed_public_key::{SignedPublicKey, SignedPublicKeyX448}, signed_key_pair::{SignedKeyPair, SignedKeyPairX448}, master_key};

enum Role {
	Alice, Bob
}

struct Session {
	id: u64,
	role: Role,

	counter: u32,
	prev_counter: u32, // prev sending chain len?
	ratchet_counter: u32,

	// saved for Bob only, alice uses her ntru_ratched instead; FIXME: move to Role? 
	my_ntru_identity: Option<KeyPairNtru>,

	// TODO: these two can be made non optional, if instead of resetting on decrypt a new ratched is generated
	my_ratchet: Option<KeyPairX448>, 
	my_ntru_ratchet: Option<KeyPairNtru>,

	// can be initially nil for Bob (until decrypt, plus, it can be ntru-encrypted itself)
	their_ratchet: Option<PublicKeyX448>,
	their_ratchet_ntru: PublicKeyNtru,

	unacked_key_exchange: Option<KeyExchange>, // FIXME: move to Role?

	alice_base_ephemeral_key: Option<PublicKeyX448>, // TODO: rather store base_key_id, for it's only used; move to Role

	root_key: RootKey,
	// TODO: can be made non optional if root_key is initialized in either alice/bob instead of encrypt as is now
	send_chain_key: Option<ChainKey>, 
	receive_chain: ReceiveChain
}

pub struct AcolotlMac {
	body: Vec<u8>, // TODO: introduce a new type?
	mac: Digest
}

impl Session {
	pub fn alice(my_identity: KeyPairX448, 
		my_ephemeral: KeyPairX448,
		my_signing_identity: SignedKeyPairX448,
		my_ntru_identity: KeyPairNtru,
		my_ntru_ratchet: KeyPairNtru,
		their_identity: PublicKeyX448,
		their_signed_prekey: SignedPublicKeyX448,
		their_prekey: PublicKeyX448,
		their_prekey_id: u64,	// combine with prekey? make i64?
		their_ntru_prekey: PublicKeyNtru,
		their_ntru_identity: PublicKeyNtru) -> Self {
			let id = Self::derive_id(my_identity.public_key(), my_ephemeral.public_key(), &their_identity, &their_prekey);
			let master_key = master_key::alice(&my_identity, &my_ephemeral, &their_identity, &their_signed_prekey, &their_prekey);
			let key_exchange = KeyExchange::new(); // TODO: populate

			Self { id,
				role: Role::Alice,
				counter: 0,
				prev_counter: 0,
				ratchet_counter: 0,
				my_ntru_identity: Some(my_ntru_identity),
				my_ratchet: None,
				my_ntru_ratchet: Some(my_ntru_ratchet),
				their_ratchet: Some(their_prekey),
				their_ratchet_ntru: their_ntru_prekey,
				unacked_key_exchange: Some(key_exchange),
				alice_base_ephemeral_key: None, // REVIEW: move to role? It makes sense for Bob only anyway
				root_key: master_key.root_key().clone(),
				send_chain_key: None, 
				receive_chain: ReceiveChain::new() // REVIEW: make optional?
			}
	}

	pub fn bob(my_identity: KeyPairX448,
		my_ntru_identity: KeyPairNtru,
		my_signed_prekey: SignedKeyPairX448,
		my_prekey: KeyPairX448,
		my_ntru_prekey: KeyPairNtru,
		their_identity: PublicKeyX448,
		their_ephemeral: PublicKeyX448,
		their_ratchet_ntru: PublicKeyNtru) -> Self {
			let id = Self::derive_id(&their_identity, &their_ephemeral, my_identity.public_key(), my_prekey.public_key());
			let master_key = master_key::bob(&my_identity, &my_signed_prekey, &my_prekey, &their_identity, &their_ephemeral);

			Self { id,
				role: Role::Bob, 
				counter: 0, 
				prev_counter: 0, 
				ratchet_counter: 0,
				my_ntru_identity: Some(my_ntru_identity), 
				my_ratchet: Some(my_prekey), 
				my_ntru_ratchet: Some(my_ntru_prekey),
				their_ratchet: None, 
				their_ratchet_ntru: their_ratchet_ntru, 
				unacked_key_exchange: None,
				alice_base_ephemeral_key: Some(their_ephemeral), 
				root_key: master_key.root_key().clone(),
				send_chain_key: None, // REVIEW: master_key.chain_key? –rather not, for it's not used until encrypt
				receive_chain: ReceiveChain::new() 
			}
	}

	fn derive_id(alice_identity: &PublicKeyX448,
		alice_ephemeral: &PublicKeyX448,
		bob_identity: &PublicKeyX448,
		bob_prekey: &PublicKeyX448) -> u64 {
			// TODO: implement
			// TODO: test
			// const auto buffer = concat_bytes({ alice_identity.key(), alice_ephemeral.key(), bob_identity.key(), bob_prekey.key() });
			// return bytes_to_long(buffer);
			// let bytes = alice_identity.as_bytes() + alice_ephemeral.as_bytes();
			// TODO: introduce a helper method or trait
			// u64::from_be_bytes(Sha256::digest(bytes).to_vec()[..8].try_into().unwrap())
			todo!();
	}
}

impl Session {
	fn encrypt(&self, msg: &[u8]) -> AcolotlMac {
		todo!()
	}

	fn decrypt(&self, mac: &AcolotlMac) -> Vec<u8> {
		todo!()
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn derive_id() {
		todo!()
	}
}