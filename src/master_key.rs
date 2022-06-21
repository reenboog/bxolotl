
// master_key master_key::alice(const ciphr::key_pair &my_identity,
// 	const ciphr::key_pair &my_ephemeral,
// 	const ciphr::public_key &their_identity,
// 	const ciphr::signed_public_key &their_signedprekey,
// 	const ciphr::public_key &their_prekey)
// {
// const auto a1 = ecc::x448::calculate_agreement(my_identity.private_key(), their_signedprekey.key());
// const auto a2 = ecc::x448::calculate_agreement(my_ephemeral.private_key(), their_identity.key());
// const auto a3 = ecc::x448::calculate_agreement(my_ephemeral.private_key(), their_signedprekey.key());
// const auto a4 = ecc::x448::calculate_agreement(my_ephemeral.private_key(), their_prekey.key());
// const auto c = concat_bytes({ a1, a2, a3, a4 });
// return master_key_from_secret(c);
// }

// master_key master_key::bob(const ciphr::key_pair &my_identity,
// const ciphr::key_pair &my_signedprekey,
// const ciphr::key_pair &my_prekey,
// const ciphr::public_key &their_identity,
// const ciphr::public_key &their_ephemeral)
// {
// const auto a1 = ecc::x448::calculate_agreement(my_signedprekey.private_key(), their_identity.key());
// const auto a2 = ecc::x448::calculate_agreement(my_identity.private_key(), their_ephemeral.key());
// const auto a3 = ecc::x448::calculate_agreement(my_signedprekey.private_key(), their_ephemeral.key());
// const auto a4 = ecc::x448::calculate_agreement(my_prekey.private_key(), their_ephemeral.key());
// const auto c = concat_bytes({ a1, a2, a3, a4 });
// return master_key_from_secret(c);
// }

use crate::{chain_key::ChainKey, root_key::RootKey, public_key::{PublicKeyX448}, key_pair::{KeyPair, KeyPairX448}};

// Derived by DH-ing an ephemeral key against a bunch of identity keys: either for Alice or Bob
// Do I need this?
struct MasterKey {
	chain_key: ChainKey, 	// 32 bytes as well, `expand`-ed for each message?
	root_key: RootKey			// 32 bytes
}

struct PrivateKey;

enum Ratchet {
	Sending(KeyPairX448, PublicKeyX448), // my private key
	Receiving(PrivateKey, PublicKeyX448)
}

// master_key master_key_from_secret(const bytes_t &secret)
// {
//     const bytes_t material = hkdf(sha::sha2_256(secret)).expand(64);
//     const bytes_t root_key_data(material.begin(), material.begin() + 32);
//     const bytes_t chain_key_data(material.begin() + 32, material.begin() + 64);
//     return master_key(root_key_data, chain_key(chain_key_data, 0));
// }

#[cfg(test)]

mod tests {
	#[test]
	fn test_dh_alice() {
		todo!()
	}

	#[test]
	fn test_dh_bob() {
		todo!()
	}
}