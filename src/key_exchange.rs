use crate::proto;

#[derive(Clone, Copy)]
pub struct KeyExchange {
	// TODO: implement
	v: u32
}

impl KeyExchange {
	// TODO: implement
	pub fn new() -> Self {
		Self {
			v: 0
		}
	}
}

impl From<&KeyExchange> for proto::KeyExchange {
	fn from(_: &KeyExchange) -> Self {
		todo!()
		// Self {
		// 	identity_key: (), 
		// 	ntru_encrypted_ephemeral_key: (), 
		// 	identity_key_ntru: (), 
		// 	identity_signing_key_448: (), 
		// 	signed_pre_key_id: (), 
		// 	pre_448_key_id: ()
		// }
	}
}