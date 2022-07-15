use prost::Message;
use crate::{aes_cbc::{AesCbc, self}, serializable::{Deserializable, Serializable}, private_key::PrivateKey, public_key::PublicKey, x448::PublicKeyX448, key_pair::{KeyPairSize, KeyPair}, proto};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	WrongKey,
	WrongEphKeyLen,
	WrongNtruKeyLen,
	DecodeError,
	BadAesParams,
	BadNtruedFormat,
	BadNtruEncryptedFormat,
	BadNtruEncryptedKeyFormat,
	WrongNtruIdentity,
	UnknownNtruRatchet
}

impl From<aes_cbc::Error> for Error {
	fn from(_: aes_cbc::Error) -> Self {
		Self::BadAesParams
	}
}

#[derive(Clone)]
pub struct NtruEncrypted {
	pub encryption_key_id: u64, // encrypting_ntru_key_id
	pub aes_params: Vec<u8>, // ntru_encrypted_aes_params 
	// decrypts to either another NtruEncrypted or to straight to NtruedKeys
	pub payload: Vec<u8> // aes_encrypted_data
}

// TODO: test
impl From<&NtruEncrypted> for proto::NtruEncrypted {
	fn from(src: &NtruEncrypted) -> Self {
		Self {
			encrypting_ntru_key_id: src.encryption_key_id,
			ntru_encrypted_aes_params: src.aes_params.clone(),
			aes_encrypted_data: src.payload.clone()
		}
	}
}

// TODO: test
impl Serializable for NtruEncrypted {
	fn serialize(&self) -> Vec<u8> {
		proto::NtruEncrypted::from(self).encode_to_vec()
	}
}

// TODO: test
impl TryFrom<proto::NtruEncrypted> for NtruEncrypted {
	type Error = Error;

	fn try_from(value: proto::NtruEncrypted) -> Result<Self, Self::Error> {
		Ok(Self {
			encryption_key_id: value.encrypting_ntru_key_id,
			aes_params: value.ntru_encrypted_aes_params,
			payload: value.aes_encrypted_data 
		})
	}
}

// TODO: test
impl Deserializable for NtruEncrypted {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> where Self: Sized {
		Ok(Self::try_from(proto::NtruEncrypted::decode(buf).or(Err(Error::BadNtruEncryptedFormat))?)?)
	}
}

// decrypted NtruEncrypted: x448 + ntru ratches
pub struct NtruedKeys {
	pub ephemeral: PublicKeyX448,
	pub ntru: PublicKeyNtru
}

// TODO: test
impl From<&NtruedKeys> for proto::NtruEd448KeyPair {
	fn from(value: &NtruedKeys) -> Self {
		Self {
			ephemeral_key: value.ephemeral.as_bytes().to_vec(),
			ntru_key: value.ntru.as_bytes().to_vec()
		}
	}
}

// TODO: test
impl Serializable for NtruedKeys {
	fn serialize(&self) -> Vec<u8> {
		proto::NtruEd448KeyPair::from(self).encode_to_vec()
	}
}

// TODO: test
impl TryFrom<proto::NtruEd448KeyPair> for NtruedKeys {
	type Error = Error;

	fn try_from(value: proto::NtruEd448KeyPair) -> Result<Self, Self::Error> {
		let ephemeral = PublicKeyX448::try_from(value.ephemeral_key).or(Err(Error::WrongEphKeyLen))?;
		let ntru = PublicKeyNtru::try_from(value.ntru_key).or(Err(Error::WrongNtruKeyLen))?;

		Ok(Self { ephemeral, ntru })
	}
}

// TODO: test
impl Deserializable for NtruedKeys {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> {
		Ok(Self::try_from(proto::NtruEd448KeyPair::decode(buf).or(Err(Error::BadNtruedFormat))?)?)
	}
}

#[derive(Clone)]
pub struct NtruEncryptedKey {
	pub key_id: u64, // ephemeral_key_id
	pub double_encrypted: bool,
	pub payload: NtruEncrypted // ntru_encrypted
}

impl From<&NtruEncryptedKey> for proto::NtruEncryptedEphemeralKey {
	fn from(src: &NtruEncryptedKey) -> Self {
		Self {
			ephemeral_key_id: src.key_id,
			double_encrypted: src.double_encrypted,
			ntru_encrypted: proto::NtruEncrypted::from(&src.payload)
		}
	}
}

impl Serializable for NtruEncryptedKey {
	fn serialize(&self) -> Vec<u8> {
		proto::NtruEncryptedEphemeralKey::from(self).encode_to_vec()
	}
}

impl TryFrom<proto::NtruEncryptedEphemeralKey> for NtruEncryptedKey {
	type Error = Error;

	fn try_from(value: proto::NtruEncryptedEphemeralKey) -> Result<Self, Self::Error> {
		Ok(Self {
			key_id: value.ephemeral_key_id,
			double_encrypted: value.double_encrypted,
			payload: NtruEncrypted::try_from(value.ntru_encrypted)?
		})
	}
}

impl Deserializable for NtruEncryptedKey {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> {
		Ok(Self::try_from(proto::NtruEncryptedEphemeralKey::decode(buf).or(Err(Error::BadNtruEncryptedKeyFormat))?)?)
	}
}

pub enum EncryptionMode<'a> {
	Once { key: &'a PublicKeyNtru },
	Double { first_key: &'a PublicKeyNtru, second_key: &'a PublicKeyNtru }
}

pub type KeySource<'a> = dyn Fn(u64) -> Result<&'a PrivateKeyNtru, Error>;

pub enum DecryptionMode<'a, F> 
where
	F: Fn(u64) -> Result<&'a PrivateKeyNtru, Error> + ?Sized
{
	Once { key: &'a PrivateKeyNtru },
	Double { second_key: &'a PrivateKeyNtru, first_key: Box<F> }
}

impl<'a> EncryptionMode<'a> {
	pub fn is_double(&self) -> bool {
		matches!(self, Self::Double { first_key: _, second_key: _ })
	}
}

// TODO: inject key & iv
pub fn encrypt_sealed(plain: &[u8], pk: &PublicKeyNtru) -> NtruEncrypted {
	use crate::aes_cbc::{Key, Iv};

	let key = Key::generate();
	let iv = Iv::generate();
	let aes = AesCbc::new(key, iv);
	let serialized_aes = aes.serialize();
	let ntru_encrypted_aes_params = pk.encrypt(&serialized_aes);
	let aes_encrypted_payload = AesCbc::new(key, iv).encrypt(plain);

	NtruEncrypted {
		encryption_key_id: pk.id(),
		aes_params: ntru_encrypted_aes_params,
		payload: aes_encrypted_payload
	}
}

pub fn decrypt_sealed(msg: &NtruEncrypted, key: &PrivateKeyNtru) -> Result<Vec<u8>, Error> {
	// todo: check if key = key.id? it simply won't decrypt if it's a wrong key
	let decrypted = key.decrypt(&msg.aes_params)?;
	let aes = AesCbc::deserialize(&decrypted)?;

	Ok(aes.decrypt(&msg.payload)?)
}

// encrypts (eph, ntru) with encrypting_key and optionally with second_encrypting_key, if present
// double encryption is now done only for initial key exchange
pub fn encrypt_ephemeral(eph: &PublicKeyX448, ntru: &PublicKeyNtru, mode: EncryptionMode) -> NtruEncryptedKey {
	let serialized_ntrued = NtruedKeys {
		ephemeral: eph.clone(),
    ntru: ntru.clone()
	}.serialize();

	use EncryptionMode::{Once, Double};

	NtruEncryptedKey {
		key_id: eph.id(),
		double_encrypted: mode.is_double(),
		payload: match mode {
			Once { key } => encrypt_sealed(&serialized_ntrued, key),
			Double { first_key, second_key } => encrypt_sealed(&encrypt_sealed(&serialized_ntrued, first_key).serialize(), second_key) 
		} 
	}
}

pub fn decrypt_ephemeral<'a, F>(eph: &NtruEncryptedKey, mode: DecryptionMode<'a, F>) -> Result<NtruedKeys, Error>
where
	F: Fn(u64) -> Result<&'a PrivateKeyNtru, Error> + ?Sized
{
	use DecryptionMode::{Once, Double};

	match mode {
    Once { key } => NtruedKeys::deserialize(&decrypt_sealed(&eph.payload, key)?),
    Double { second_key, first_key } => {
			let encrypted = NtruEncrypted::deserialize(&decrypt_sealed(&eph.payload, second_key)?)?;
			let key = first_key(encrypted.encryption_key_id)?;

			NtruedKeys::deserialize(&decrypt_sealed(&encrypted, key)?)
		} 
	}
}

pub struct KeyTypeNtru;

impl KeyPairSize for KeyTypeNtru {
	const PRIV: usize = ntrust::bridge::PRIVATE_KEY_SIZE;
	const PUB: usize = ntrust::bridge::PUBLIC_KEY_SIZE;
}

pub type PrivateKeyNtru = PrivateKey<KeyTypeNtru, { KeyTypeNtru::PRIV }>;
pub type PublicKeyNtru = PublicKey<KeyTypeNtru, { KeyTypeNtru::PUB }>;

pub type KeyPairNtru = KeyPair<KeyTypeNtru, { KeyTypeNtru::PRIV }, { KeyTypeNtru::PUB }>;

impl KeyPairNtru {
	pub fn generate() -> Self {
		use ntrust::bridge::{PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, ntru_generate_key_pair};

		let mut priv_key_len = PRIVATE_KEY_SIZE;
		let mut pub_key_len = PUBLIC_KEY_SIZE;

		let mut private = [0u8; PRIVATE_KEY_SIZE];
		let mut public = [0u8; PUBLIC_KEY_SIZE];

		unsafe {
			let res = ntru_generate_key_pair(&mut pub_key_len, public.as_mut_ptr(), &mut priv_key_len, private.as_mut_ptr());

			if res != 0 {
				// REVIEW: which is worse: to panic or to return a zeroed buf? (as for me, to panic is better)
				panic!("NTRU key generation failed {}", res);
			}
		};

		Self::new(PrivateKeyNtru::new(private), PublicKeyNtru::new(public))
	}
}

impl PublicKeyNtru {
	pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
		use ntrust::bridge::ntru_encrypt;
		use std::ptr::null_mut;

		unsafe {
			let key = self.as_bytes().as_ptr();
			let key_len = self.as_bytes().len();
			let msg_len = msg.len() as u16;
			let mut ct_len = 0u16;

			ntru_encrypt(key_len, key, msg_len, msg.as_ptr(), &mut ct_len, null_mut());

			let mut ct = vec![0u8; ct_len as usize];
			ntru_encrypt(key_len, key, msg_len, msg.as_ptr(), &mut ct_len, ct.as_mut_ptr());

			ct
		}
	}
}

impl PrivateKeyNtru {
	pub fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
		use ntrust::bridge::ntru_decrypt;
		use std::ptr::null_mut;

		unsafe {
			let key = self.as_bytes().as_ptr();
			let key_len = self.as_bytes().len();
			let ct_len = ct.len() as u16;
			let mut pt_len = 0u16;

			ntru_decrypt(key_len, key, ct_len, ct.as_ptr(), &mut pt_len, null_mut());

			let mut pt = vec![0u8; pt_len as usize];
			let res = ntru_decrypt(key_len, key, ct_len, ct.as_ptr(), &mut pt_len, pt.as_mut_ptr());

			if res != 0 {
				Err(Error::WrongKey)
			} else {
				pt.resize(pt_len as usize, 0u8);

				Ok(pt)
			}
		}

	}
}

#[cfg(test)]
mod tests {
	use crate::{ntru::{KeyTypeNtru, PrivateKeyNtru}, key_pair::KeyPairSize, x448::{KeyPairX448}};
	use super::{KeyPairNtru, Error, encrypt_sealed, decrypt_sealed, encrypt_ephemeral, decrypt_ephemeral, KeySource, EncryptionMode, DecryptionMode};

	#[test]
	fn test_gen_keypair_non_zeroes() {
		let kp = KeyPairNtru::generate();

		assert_ne!(kp.private_key().as_bytes(), &[0u8; KeyTypeNtru::PRIV]);
		assert_ne!(kp.public_key().as_bytes(), &[0u8; KeyTypeNtru::PUB]);
	}

	#[test]
	fn test_gen_keypair_unique() {
		let kp0 = KeyPairNtru::generate();
		let kp1 = KeyPairNtru::generate();

		assert_ne!(kp0.private_key().as_bytes(), kp1.private_key().as_bytes());
		assert_ne!(kp0.public_key().as_bytes(), kp1.public_key().as_bytes());
	}

	#[test]
	fn test_encrypt_decrypt() {
		let msg = b"Hey, Carlos";
		let kp = KeyPairNtru::generate();

		let encrypted = kp.public_key().encrypt(msg);
		let decrypted = kp.private_key().decrypt(&encrypted);

		assert_eq!(Ok(msg.to_vec()), decrypted);
	}

	#[test]
	fn test_decrypt_fails_with_wrong_key() {
		let msg = b"Don't forget to run regularly";
		let kp = KeyPairNtru::generate();
		let encrypted = kp.public_key().encrypt(msg);
		let decrypted = KeyPairNtru::generate().private_key().decrypt(&encrypted);

		assert_eq!(Err(Error::WrongKey), decrypted);
	}

	#[test]
	fn test_encrypt_decrypt_sealed() {
		let msg = b"And your kudos are appreciated also!";
		let kp = KeyPairNtru::generate();
		let sealed = encrypt_sealed(msg, kp.public_key());
		let unsealed = decrypt_sealed(&sealed, kp.private_key());

		assert_eq!(Ok(msg.to_vec()), unsealed);
	}

	#[test]
	fn test_decrypt_sealed_fails_with_wrong_key() {
		let msg = b"Thanks";
		let kp = KeyPairNtru::generate();
		let sealed = encrypt_sealed(msg, kp.public_key());
		let unsealed = decrypt_sealed(&sealed, KeyPairNtru::generate().private_key());

		assert_eq!(Err(Error::WrongKey), unsealed);
	}

	#[test]
	fn test_encrypt_decrypt_ephemeral_mode_once() -> Result<(), Error> {
		let eph = KeyPairX448::generate();
		let ntru = KeyPairNtru::generate();
		let kp = KeyPairNtru::generate();

		let encrypted = encrypt_ephemeral(eph.public_key(), ntru.public_key(), EncryptionMode::Once { key: kp.public_key() });
		let decrypted = decrypt_ephemeral::<KeySource>(&encrypted, DecryptionMode::Once { key: kp.private_key() })?;

		assert_eq!(eph.public_key().as_bytes(), decrypted.ephemeral.as_bytes());
		assert_eq!(ntru.public_key().as_bytes(), decrypted.ntru.as_bytes());

		Ok(())
	}

	#[test]
	fn test_decrypt_ephemeral_mode_once_fails_with_wrong_key() {
		let eph = KeyPairX448::generate();
		let ntru = KeyPairNtru::generate();
		let kp = KeyPairNtru::generate();

		let encrypted = encrypt_ephemeral(eph.public_key(), ntru.public_key(), EncryptionMode::Once { key: kp.public_key() });
		let decrypted = decrypt_ephemeral::<KeySource>(&encrypted, DecryptionMode::Once { key: KeyPairNtru::generate().private_key() });

		assert_eq!(decrypted.err(), Some(Error::WrongKey));
	}

	#[test]
	fn test_encrypt_decrypt_ephemeral_mode_double() -> Result<(), Error> {
		let eph = KeyPairX448::generate();
		let ntru = KeyPairNtru::generate();
		let kp_first = KeyPairNtru::generate();
		let kp_second = KeyPairNtru::generate();

		let find_key = |_| -> Result<&PrivateKeyNtru, Error> {
			Ok(kp_first.private_key())
		};

		let encrypted = encrypt_ephemeral(eph.public_key(), ntru.public_key(), EncryptionMode::Double { first_key: kp_first.public_key(), second_key: kp_second.public_key() });
		let decrypted = decrypt_ephemeral(&encrypted, DecryptionMode::Double { second_key: kp_second.private_key(), first_key: Box::new(find_key) })?;

		assert_eq!(eph.public_key().as_bytes(), decrypted.ephemeral.as_bytes());
		assert_eq!(ntru.public_key().as_bytes(), decrypted.ntru.as_bytes());

		Ok(())
	}

	#[test]
	fn test_decrypt_ephemeral_mode_double_fails_with_wrong_keys() -> Result<(), Error> {
		let eph = KeyPairX448::generate();
		let ntru = KeyPairNtru::generate();
		let kp_first = KeyPairNtru::generate();
		let kp_second = KeyPairNtru::generate();
		let wrong_first_kp = KeyPairNtru::generate();
		let wrong_second_kp = KeyPairNtru::generate();

		let find_key = |_| -> Result<&PrivateKeyNtru, Error> {
			Ok(kp_first.private_key())
		};

		let find_wrong_key = |_| -> Result<&PrivateKeyNtru, Error> {
			Ok(wrong_first_kp.private_key())
		};

		let encrypted = encrypt_ephemeral(eph.public_key(), ntru.public_key(), EncryptionMode::Double { first_key: kp_first.public_key(), second_key: kp_second.public_key() });
		let failed_with_wrong_second_key = decrypt_ephemeral(&encrypted, DecryptionMode::Double { second_key: wrong_second_kp.private_key(), first_key: Box::new(find_key) });

		assert_eq!(failed_with_wrong_second_key.err(), Some(Error::WrongKey));

		let failed_with_wrong_first_key = decrypt_ephemeral(&encrypted, DecryptionMode::Double { second_key: kp_second.private_key(), first_key: Box::new(find_wrong_key) });

		assert_eq!(failed_with_wrong_first_key.err(), Some(Error::WrongKey));

		// make sure it actually decrypts
		let decrypted = decrypt_ephemeral(&encrypted, DecryptionMode::Double { second_key: kp_second.private_key(), first_key: Box::new(find_key) })?;

		assert_eq!(eph.public_key().as_bytes(), decrypted.ephemeral.as_bytes());
		assert_eq!(ntru.public_key().as_bytes(), decrypted.ntru.as_bytes());

		Ok(())
	}

	#[test]
	fn test_decrypt_ephemeral_mode_once_fails_as_wrong_mode() -> Result<(), Error> {
		let eph = KeyPairX448::generate();
		let ntru = KeyPairNtru::generate();
		let kp_first = KeyPairNtru::generate();
		let kp_second = KeyPairNtru::generate();

		let first_key = |_| -> Result<&PrivateKeyNtru, Error> {
			Ok(kp_first.private_key())
		};

		let second_key = |_| -> Result<&PrivateKeyNtru, Error> {
			Ok(kp_second.private_key())
		};

		let encrypted = encrypt_ephemeral(eph.public_key(), ntru.public_key(), EncryptionMode::Once { key: kp_first.public_key() });

		// decrypted the inner buffer, but failed to deserialize the outer NtruEncrypted
		let correct_first_second_as_first  = decrypt_ephemeral(&encrypted, DecryptionMode::Double { second_key: kp_first.private_key(), first_key: Box::new(first_key) });
		assert_eq!(correct_first_second_as_first.err(), Some(Error::BadNtruEncryptedFormat));

		// decrypted the inner buffer, but failed to deserialize the outer NtruEncrypted
		let correct_first_wrong_second  = decrypt_ephemeral(&encrypted, DecryptionMode::Double { second_key: kp_first.private_key(), first_key: Box::new(second_key) });
		assert_eq!(correct_first_wrong_second.err(), Some(Error::BadNtruEncryptedFormat));

		// fails with the first buffer, so it's a generic `WrongKey`
		let wrong_first_second_as_first  = decrypt_ephemeral(&encrypted, DecryptionMode::Double { second_key: kp_second.private_key(), first_key: Box::new(first_key) });
		assert_eq!(wrong_first_second_as_first.err(), Some(Error::WrongKey));

		// fails with the first buffer, so it's a generic `WrongKey`
		let wrong_first_wrong_second  = decrypt_ephemeral(&encrypted, DecryptionMode::Double { second_key: kp_second.private_key(), first_key: Box::new(second_key) });
		assert_eq!(wrong_first_wrong_second.err(), Some(Error::WrongKey));

		// make sure it actually decrypts
		let decrypted = decrypt_ephemeral::<KeySource>(&encrypted, DecryptionMode::Once { key: kp_first.private_key() })?;

		assert_eq!(eph.public_key().as_bytes(), decrypted.ephemeral.as_bytes());
		assert_eq!(ntru.public_key().as_bytes(), decrypted.ntru.as_bytes());

		Ok(())
	}

	#[test]
	fn test_decrypt_ephemeral_mode_double_fails_as_wrong_mode() -> Result<(), Error> {
		let eph = KeyPairX448::generate();
		let ntru = KeyPairNtru::generate();
		let kp_first = KeyPairNtru::generate();
		let kp_second = KeyPairNtru::generate();

		let find_key = |_| -> Result<&PrivateKeyNtru, Error> {
			Ok(kp_first.private_key())
		};

		let encrypted = encrypt_ephemeral(eph.public_key(), ntru.public_key(), EncryptionMode::Double { first_key: kp_first.public_key(), second_key: kp_second.public_key() });
		
		// first should go inside, so it's a generic `WrongKey`
		let correct_first = decrypt_ephemeral::<KeySource>(&encrypted, DecryptionMode::Once { key: kp_first.private_key() });
		assert_eq!(correct_first.err(), Some(Error::WrongKey));

		// the outer layer decrypts fine, but there should be one more NtruEncrypted, not NtruedKeys
		let correct_second = decrypt_ephemeral::<KeySource>(&encrypted, DecryptionMode::Once { key: kp_second.private_key() });
		assert_eq!(correct_second.err(), Some(Error::BadNtruedFormat));

		// make sure it actually decrypts
		let decrypted = decrypt_ephemeral(&encrypted, DecryptionMode::Double { second_key: kp_second.private_key(), first_key: Box::new(find_key) })?;

		assert_eq!(eph.public_key().as_bytes(), decrypted.ephemeral.as_bytes());
		assert_eq!(ntru.public_key().as_bytes(), decrypted.ntru.as_bytes());

		Ok(())
	}
}