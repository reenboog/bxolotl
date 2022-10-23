use std::borrow::Borrow;
use crate::{key_exchange::KeyExchange, kyber::KyberEncryptedEnvelope, x448::PublicKeyX448, serializable::{Serializable, Deserializable}, proto};

// MessageType
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Type {
	Chat = 0, 
	InterDevice = 1
}

#[derive(PartialEq, Debug)]
pub enum Error {
	BadFormat,
	NoCounter,
	NoPrevCounter,
	NoCiphertext,
	NoMessageType,
	UnknownType,
	BadEphemeralKeyFormat,
	BadKyberEncryptedKeyFormat,
	BadKeyExchange,
	NoRatchetKeySupplied
}

impl TryFrom<i32> for Type {
	type Error = Error;

	fn try_from(value: i32) -> Result<Self, Self::Error> {
		use Type::{Chat, InterDevice};

		match value {
			0 => Ok(Chat),
			1 => Ok(InterDevice),
			_ => Err(Error::UnknownType)
		}
	}
}

// TODO: introduce getter & setters?
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
	pub counter: u32,
	pub prev_counter: u32,
	// TODO: introduce RatchetMode { raw, kyber_encrypted }?
	pub ratchet_key: Option<PublicKeyX448>,
	pub kyber_encrypted_ratchet_key: Option<KyberEncryptedEnvelope>,
	pub ciphertext: Vec<u8>,
	pub key_exchange: Option<KeyExchange>,
	pub _type: Type,
}

impl Message {
	pub fn new(t: Type) -> Self {
		Self {
			counter: 0,
			prev_counter: 0,
			ratchet_key: None,
			kyber_encrypted_ratchet_key: None,
			ciphertext: vec![],
			key_exchange: None,
			_type: t 
		}
	}
}

impl From<&Message> for proto::CryptoMessage {
	fn from(src: &Message) -> Self {
		Self {
			ephemeral_key: src.ratchet_key.as_ref().map(|k| k.as_bytes().to_vec()),
			kyber_encrypted_ephemeral_key: src.kyber_encrypted_ratchet_key.as_ref().map(|k| k.into()),
			counter: Some(src.counter),
			previous_counter: Some(src.prev_counter),
			ciphertext: Some(src.ciphertext.clone()),
			key_exchange: src.key_exchange.as_ref().map(|kex| kex.into()),
			message_type: Some(src._type as i32)
		}
	}
}

impl Serializable for Message {
	fn serialize(&self) -> Vec<u8> {
		use prost::Message;

		proto::CryptoMessage::from(self).encode_to_vec()
	}
}

impl TryFrom<proto::CryptoMessage> for Message {
	type Error = Error;

	fn try_from(msg: proto::CryptoMessage) -> Result<Self, Self::Error> {
		// either ratchet or kyber_encrypted_ratchet
		let mut ratchet_key: Option<PublicKeyX448> = None;
		let mut kyber_encrypted_ratchet_key: Option<KyberEncryptedEnvelope> = None;

		if let Some(key) = msg.ephemeral_key {
			ratchet_key = Some(PublicKeyX448::try_from(key).or(Err(Error::BadEphemeralKeyFormat))?);
		} else if let Some(key) = msg.kyber_encrypted_ephemeral_key {
			kyber_encrypted_ratchet_key = Some(KyberEncryptedEnvelope::try_from(key).or(Err(Error::BadKyberEncryptedKeyFormat))?);
		} else {
			return Err(Error::NoRatchetKeySupplied)
		}

		Ok(Self {
			counter: msg.counter.ok_or(Error::NoCounter)?, // REVIEW: how about 0?
			prev_counter: msg.previous_counter.ok_or(Error::NoPrevCounter)?, // REVIEW: how about 0?
			ratchet_key,
			kyber_encrypted_ratchet_key,
			ciphertext: msg.ciphertext.ok_or(Error::NoCiphertext)?,
			key_exchange: msg.key_exchange.map_or(Ok(None), |kex| Ok(Some(KeyExchange::try_from(kex).or(Err(Error::BadKeyExchange))?)))?,
			_type: Type::try_from(msg.message_type.ok_or(Error::NoMessageType)?)?
		})
	}
}

impl Deserializable for Message {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> {
		use prost::Message;

		Self::try_from(proto::CryptoMessage::decode(buf).or(Err(Error::BadFormat))?)
	}
}

impl Message {
	// set_ephemeral_key
	pub fn set_ratchet_key(&mut self, key: PublicKeyX448) {
		self.ratchet_key = Some(key);
	}

	pub fn ratchet_key(&self) -> Option<&PublicKeyX448> {
		self.ratchet_key.borrow().as_ref()
	}

	// TODO: combine with set_ratchet via an enum?
	pub fn set_kyber_encrypted_ratchet_key(&mut self, key: KyberEncryptedEnvelope) {
		self.kyber_encrypted_ratchet_key = Some(key);
	}

	pub fn kyber_encrypted_ratchet_key(&self) -> Option<&KyberEncryptedEnvelope> {
		self.kyber_encrypted_ratchet_key.borrow().as_ref()
	}

	pub fn set_counter(&mut self, ctr: u32) {
		self.counter = ctr;
	}

	pub fn counter(&self) -> u32 {
		self.counter
	}

	pub fn set_prev_counter(&mut self, ctr: u32) {
		self.prev_counter = ctr;
	}

	pub fn prev_counter(&self) -> u32 {
		self.prev_counter
	}

	pub fn set_type(&mut self, t: Type) {
		self._type = t;
	}

	pub fn set_key_exchange(&mut self, kex: Option<KeyExchange>) {
		self.key_exchange = kex;
	}

	pub fn ciphertext(&self) -> &[u8] {
		&self.ciphertext
	}

	pub fn set_ciphertext(&mut self, ct: &[u8]) {
		self.ciphertext = ct.to_vec();
	}
}

#[cfg(test)]
mod tests {
	use crate::{serializable::{Serializable, Deserializable}, x448::KeyPairX448, kyber::{KeyPairKyber, self}, key_exchange::KeyExchange, ed448::KeyPairEd448};
	use super::{Type, Error, Message};

	#[test]
	fn test_serialize_deserialize() {
		let eph_kp = KeyPairX448::generate();
		let mut msg = Message::new(Type::Chat);
		let ct = b"123";
		let kyber = KeyPairKyber::generate();
		let encrypting_kyber = KeyPairKyber::generate();
		let kyber_encrypted_eph = kyber::encrypt_keys(eph_kp.public_key(), kyber.public_key(), kyber::EncryptionMode::Once { key: encrypting_kyber.public_key() });
		let ed_identity = KeyPairEd448::generate();
		let kex = KeyExchange {
			x448_identity: KeyPairX448::generate().public_key().clone(),
			kyber_encrypted_ephemeral: kyber_encrypted_eph,
			kyber_identity: kyber.public_key().clone(),
			ed448_identity: ed_identity.public_key().clone(),
			signed_prekey_id: 123,
			x448_prekey_id: 456,
			force_reset: true 
		};

		msg.set_counter(3);
		msg.set_prev_counter(18);
		msg.set_ratchet_key(eph_kp.public_key().clone());
		msg.set_ciphertext(ct);
		msg.set_key_exchange(Some(kex.clone()));

		let serialized = msg.serialize();
		let deserialized = Message::deserialize(&serialized);

		assert_eq!(Ok(msg), deserialized);
	}

	#[test]
	fn test_deserialize_with_kyber_encrypted_ephemeral_specified() {
		let kp = KeyPairX448::generate();
		let kyber = KeyPairKyber::generate();
		let encrypting_kyber = KeyPairKyber::generate();
		let kyber_encrypted = kyber::encrypt_keys(kp.public_key(), kyber.public_key(), kyber::EncryptionMode::Once { key: encrypting_kyber.public_key() });
		let mut msg = Message::new(Type::InterDevice);
		let ct = b"123";

		msg.set_counter(3);
		msg.set_prev_counter(18);
		msg.set_kyber_encrypted_ratchet_key(kyber_encrypted.clone());
		msg.set_ciphertext(ct);

		let serialized = msg.serialize();
		let deserialized = Message::deserialize(&serialized);

		assert_eq!(Ok(msg), deserialized);
	}

	#[test]
	fn test_deserialize_no_ephemeral_key_specified() {
		let mut msg = Message::new(Type::InterDevice);
		let ct = b"123";

		msg.set_counter(3);
		msg.set_prev_counter(18);
		msg.set_ciphertext(ct);

		let serialized = msg.serialize();
		let deserialized = Message::deserialize(&serialized);

		assert_eq!(Some(Error::NoRatchetKeySupplied), deserialized.err());
	}

	#[test]
	fn test_i32_to_type() {
		assert_eq!(Ok(Type::Chat), 0.try_into());
		assert_eq!(Ok(Type::InterDevice), 1.try_into());
		assert_eq!(Err(Error::UnknownType), Type::try_from(2));
		assert_eq!(Err(Error::UnknownType), Type::try_from(-1));
		assert_eq!(Err(Error::UnknownType), Type::try_from(i32::MAX));
	}
}