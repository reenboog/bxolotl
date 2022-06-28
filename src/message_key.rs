use crate::{session::AxolotlMac, aes_cbc, hmac, message::Message};

pub struct MessageKey {
	enc_key: aes_cbc::Key, // derived from chain_key.get_message_keys via kdf
	iv: aes_cbc::Iv, 			// derived from chain_key.get_message_keys via kdf
	mac_key: hmac::Key, // derived from chain_key.get_message_keys via kdf
	ts: u64
}

impl MessageKey {
	// CryptoMessage is expected to be passed as well, but I'd move it to another place
	// currently called `box`
	// TODO: move to another entity?
	pub fn encrypt(&self, plaintext: &[u8], msg: &mut Message) -> AxolotlMac {
		// aes_cbc is used
		todo!()
	}

	pub fn decrypt(&self, mac: &AxolotlMac) -> Vec<u8> {
		todo!()
	}

// 	main::AxolotlMAC message_keys::box(const ciphr::bytes_t &plain_text, main::CryptoMessage &msg) const
// {
//     aes_cbc cipher(_enc_key, _iv);
//     const bytes_t encrypted = cipher.encrypt(plain_text);
//     msg.set_ciphertext(encrypted.data(), encrypted.size());

//     const auto msg_size = msg.ByteSize();
//     bytes_t buffer(msg_size, ZeroByte);
//     msg.SerializeToArray(buffer.data(), msg_size);

//     const bytes_t mac = hmac::generate(_mac_key, buffer);
//     main::AxolotlMAC output;
//     output.set_allocated_body(new main::CryptoMessage(msg));
//     output.set_mac(bytes_to_string(mac));

//     return output;
// }

// ciphr::bytes_t message_keys::unbox(const main::AxolotlMAC &input) const
// {
//     const main::CryptoMessage &body(input.body());
//     bytes_t buffer(body.ByteSize(), ZeroByte);
//     body.SerializeToArray(buffer.data(), body.ByteSize());

//     if (!hmac::verify(_mac_key, buffer, bytes_from_string(input.mac()))) {
//         throw invalid_mac_exception();
//     }

//     aes_cbc cipher(_enc_key, _iv);
//     return cipher.decrypt(bytes_from_string(input.body().ciphertext()));
// }

}

#[cfg(test)]
mod tests {
	#[test]
	fn test_encrypt() {
		todo!()
	}
}