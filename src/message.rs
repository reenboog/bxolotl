// TODO: use proto definitions instead?
// Corresponds to CryptoMessage

use crate::key_exchange::KeyExchange;


enum MessageType {
	Chat, InterDevice
}

struct Message {
	ephemeral_key: Option<[u8; 32]>, // TODO: introduce a type (ecc448?)
	counter: u32,
	prev_counter: u32,
	ciphr_text: Vec<u8>, // TODO: introduce a type?
	key_exchange: KeyExchange,
	message_type: MessageType, // TODO: rename
	// TODO: other fields
}