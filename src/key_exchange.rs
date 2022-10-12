use crate::{proto, x448::PublicKeyX448, ntru::{NtruEncryptedKey, PublicKeyNtru}, ed448::PublicKeyEd448};

#[derive(Debug)]
pub enum Error {
	NoX448Identity,
	WrongX448IdentityLen,
	NoNtruEncryptedEphemeral,
	BadNtruEncryptedEphemeralFormat,
	NoNtruIdentity,
	WrongNtruIdentityLen,
	NoEd448Identity,
	WrongEd448IdentityLen,
	NoSignedPrekeyId,
	NoX448PrekeyId
}

#[derive(Clone)]
pub struct KeyExchange {
	pub x448_identity: PublicKeyX448,
	pub ntru_encrypted_ephemeral: NtruEncryptedKey,
	pub ntru_identity: PublicKeyNtru,
	pub ed448_identity: PublicKeyEd448,
	pub signed_prekey_id: u64,
	pub x448_prekey_id: u64
}

impl From<&KeyExchange> for proto::KeyExchange {
	fn from(kex: &KeyExchange) -> Self {
		Self {
			identity_key: Some(kex.x448_identity.as_bytes().to_vec()),
			ntru_encrypted_ephemeral_key: Some((&kex.ntru_encrypted_ephemeral).into()),
			identity_key_ntru: Some(kex.ntru_identity.as_bytes().to_vec()),
			identity_signing_key_448: Some(kex.ed448_identity.as_bytes().to_vec()),
			signed_pre_key_id: Some(kex.signed_prekey_id),
			pre_448_key_id: Some(kex.x448_prekey_id)
		}
	}
}

impl TryFrom<proto::KeyExchange> for KeyExchange {
	type Error = Error;

	fn try_from(kex: proto::KeyExchange) -> Result<Self, Self::Error> {
		Ok(Self {
			x448_identity: PublicKeyX448::try_from(kex.identity_key.ok_or(Error::NoX448Identity)?).or(Err(Error::WrongX448IdentityLen))?,
			ntru_encrypted_ephemeral: NtruEncryptedKey::try_from(kex.ntru_encrypted_ephemeral_key.ok_or(Error::NoNtruEncryptedEphemeral)?).or(Err(Error::BadNtruEncryptedEphemeralFormat))?,
			ntru_identity: PublicKeyNtru::try_from(kex.identity_key_ntru.ok_or(Error::NoNtruIdentity)?).or(Err(Error::WrongNtruIdentityLen))?,
			ed448_identity: PublicKeyEd448::try_from(kex.identity_signing_key_448.ok_or(Error::NoEd448Identity)?).or(Err(Error::WrongEd448IdentityLen))?,
			signed_prekey_id: kex.signed_pre_key_id.ok_or(Error::NoSignedPrekeyId)?,
			x448_prekey_id: kex.pre_448_key_id.ok_or(Error::NoX448PrekeyId)? 
		})
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_try_from() {
		// todo!()
	}
}