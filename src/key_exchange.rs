use crate::{proto, x448::PublicKeyX448, kyber::{EncryptedEnvelope, PublicKeyKyber}, ed448::PublicKeyEd448, id};

#[derive(Debug)]
pub enum Error {
	NoX448Identity,
	WrongX448IdentityLen,
	NoKyberEncryptedEphemeral,
	BadKyberEncryptedEphemeralFormat,
	NoKyberIdentity,
	WrongKyberIdentityLen,
	NoEd448Identity,
	WrongEd448IdentityLen,
	NoSignedPrekeyId,
	NoX448PrekeyId
}

#[derive(Clone, Debug, PartialEq)]
pub struct KeyExchange {
	pub x448_identity: PublicKeyX448,
	pub kyber_encrypted_ephemeral: EncryptedEnvelope,
	pub kyber_identity: PublicKeyKyber,
	pub ed448_identity: PublicKeyEd448,
	pub signed_prekey_id: u64,
	pub x448_prekey_id: u64,
	pub force_reset: bool
}

impl KeyExchange {
	pub fn derive_id(identity: &PublicKeyX448, prekey_id: u64, eph_key_id: u64) -> u64 {
		id::from_bytes(&[&identity.as_bytes()[..], &prekey_id.to_le_bytes(), &eph_key_id.to_le_bytes()].concat())
	}

	pub fn id(&self) -> u64 {
		Self::derive_id(&self.x448_identity, self.x448_prekey_id, self.kyber_encrypted_ephemeral.key_id)
	}
}

impl From<&KeyExchange> for proto::KeyExchange {
	fn from(kex: &KeyExchange) -> Self {
		Self {
			identity_key: Some(kex.x448_identity.as_bytes().to_vec()),
			kyber_encrypted_ephemeral_key: Some((&kex.kyber_encrypted_ephemeral).into()),
			identity_key_kyber: Some(kex.kyber_identity.as_bytes().to_vec()),
			identity_signing_key_448: Some(kex.ed448_identity.as_bytes().to_vec()),
			signed_pre_key_id: Some(kex.signed_prekey_id),
			pre_448_key_id: Some(kex.x448_prekey_id),
			force_reset: Some(kex.force_reset)
		}
	}
}

impl TryFrom<proto::KeyExchange> for KeyExchange {
	type Error = Error;

	fn try_from(kex: proto::KeyExchange) -> Result<Self, Self::Error> {
		Ok(Self {
			x448_identity: PublicKeyX448::try_from(kex.identity_key.ok_or(Error::NoX448Identity)?).or(Err(Error::WrongX448IdentityLen))?,
			kyber_encrypted_ephemeral: EncryptedEnvelope::try_from(kex.kyber_encrypted_ephemeral_key.ok_or(Error::NoKyberEncryptedEphemeral)?).or(Err(Error::BadKyberEncryptedEphemeralFormat))?,
			kyber_identity: PublicKeyKyber::try_from(kex.identity_key_kyber.ok_or(Error::NoKyberIdentity)?).or(Err(Error::WrongKyberIdentityLen))?,
			ed448_identity: PublicKeyEd448::try_from(kex.identity_signing_key_448.ok_or(Error::NoEd448Identity)?).or(Err(Error::WrongEd448IdentityLen))?,
			signed_prekey_id: kex.signed_pre_key_id.ok_or(Error::NoSignedPrekeyId)?,
			x448_prekey_id: kex.pre_448_key_id.ok_or(Error::NoX448PrekeyId)?,
			force_reset: kex.force_reset.unwrap_or(false)
		})
	}
}

#[cfg(test)]
mod tests {
	use crate::{x448::PublicKeyX448, key_exchange::KeyExchange};

	#[test]
	fn test_derive_id() {
		let alice_identity = PublicKeyX448::from(b"\x3e\xb7\xa8\x29\xb0\xcd\x20\xf5\xbc\xfc\x0b\x59\x9b\x6f\xec\xcf\x6d\xa4\x62\x71\x07\xbd\xb0\xd4\xf3\x45\xb4\x30\x27\xd8\xb9\x72\xfc\x3e\x34\xfb\x42\x32\xa1\x3c\xa7\x06\xdc\xb5\x7a\xec\x3d\xae\x07\xbd\xc1\xc6\x7b\xf3\x36\x09");
		let bob_prekey = PublicKeyX448::from(b"\x52\xf0\xfe\xd0\xf8\xa2\xdd\x9d\xc6\xd9\x94\x5e\x69\x5b\x27\xf5\x73\xae\x0e\x44\x92\x93\xf0\x3b\x2b\xe0\x9e\x5a\xea\xd2\x69\xff\x1e\xa0\xea\xdc\xfa\xa8\x28\x96\x6f\xac\x89\x1f\x2d\xe7\x65\xc7\x80\x86\xa6\xf2\xe4\x9e\x15\xb1");
		let alice_eph = PublicKeyX448::from(b"\x43\x6a\xa5\xc5\x72\x9a\xc9\x54\x5b\x7e\x11\xd3\x96\x6a\xc4\x7d\x20\x5c\x12\xbb\x5b\x7d\x81\x73\xae\xd5\x32\x50\x51\x4c\x3e\x51\xe8\x1b\xeb\x9b\x3a\xed\x32\x23\x5f\x3e\xb9\x9e\x8e\xca\x81\x6b\x33\x27\x84\xba\x54\x6c\x8d\xd3");

		assert_eq!(KeyExchange::derive_id(&alice_identity, bob_prekey.id(), alice_eph.id()), 17911676340712605602);
	}
}