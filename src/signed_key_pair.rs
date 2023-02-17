use crate::{
	ed448::Signature,
	proto,
	serializable::Deserializable,
	signed_public_key::SignedPublicKeyX448,
	x448::{KeyPairX448, PrivateKeyX448},
};
use prost::Message;

#[derive(Debug)]
pub enum Error {
	BadSignature,
	BadKey,
	BadFormat,
}
// Represents any key pair signed by an Ed448 key
#[derive(Clone)]
pub struct SignedKeyPair {
	private: PrivateKeyX448,
	public: SignedPublicKeyX448,
}

impl SignedKeyPair {
	pub fn new(private: PrivateKeyX448, public: SignedPublicKeyX448) -> Self {
		Self { private, public }
	}

	pub fn private(&self) -> &PrivateKeyX448 {
		&self.private
	}

	pub fn public(&self) -> &SignedPublicKeyX448 {
		&self.public
	}
}

impl TryFrom<proto::SignedKeyPair> for SignedKeyPairX448 {
	type Error = Error;

	fn try_from(value: proto::SignedKeyPair) -> Result<Self, Self::Error> {
		let signature = Signature::try_from(value.signature).or(Err(Error::BadSignature))?;
		let kp = KeyPairX448::try_from(value.key_pair).or(Err(Error::BadKey))?;

		Ok(Self {
			private: kp.private_key().clone(),
			public: SignedPublicKeyX448::new(kp.public_key().clone(), signature),
		})
	}
}

impl Deserializable for SignedKeyPairX448 {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error>
	where
		Self: Sized,
	{
		Self::try_from(proto::SignedKeyPair::decode(buf).or(Err(Error::BadFormat))?)
	}
}

pub type SignedKeyPairX448 = SignedKeyPair;
