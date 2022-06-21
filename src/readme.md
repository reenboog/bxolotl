Session::alice/bob -> MasterKey { RootKey(32), ChainKey { key[32], counter } }
MasterKey::derive(root, my_ratchet, their_ratcher) -> MasterKey




AxolotlSession.encrypt(plain) -> AxolotlMac:

ChainKey(key, counter)
chain_key.get_message_key() -> MessageKey
		MessageKey.box(plain) -> AxolotlMac
		{ AesCbc.encrypt(enc_key, iv), Hmac(ciphr)) }



hkdf {
	fn expand()

	hmac {
		fn generate()
		fn verify()
	}
}

ec_key_pair {
	priv_bytes
	pub_bytes
}

ntru_key_pair {
	fn decrypt()

	priv_bytes
	ntru_pub_key {
		bytes

		fn encrypt()
	}
}

root_key {
	bytes

	fn derive()
}

chain_key {
	bytes

	get_message_keys()
	get_next()
}

receive_chain {
	[chain]
}

chain {
	current
	next
}

key_pair {
	priv_bytes
	pub_bytes
}

signed_ec_pub_key {
	bytes
	signature
}

signed_ec_key_pair {
	priv_bytes
	public
}