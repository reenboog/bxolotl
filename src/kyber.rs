use prost::Message;
use pqcrypto_kyber::kyber1024::{keypair, encapsulate, decapsulate, Ciphertext, SharedSecret};
use crate::{key_pair::{KeyPairSize, KeyPair}, private_key::PrivateKey, public_key::PublicKey};
use crate::{aes_cbc::{AesCbc, self, Iv}, serializable::{Deserializable, Serializable}, x448::PublicKeyX448, proto};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	WrongCiphertext,
	WrongEphKeyLen,
	WrongKyberKeyLen,
	WrongIvLen,
	WrongKeyLen,
	DecodeError,
	BadAesParams,
	BadKyberedKeysFormat,
	BadKyberEncryptedFormat,
	BadKyberEncryptedKeyFormat,
	WrongKyberIdentity,
	UnknownKyberRatchet
}

impl From<aes_cbc::Error> for Error {
	fn from(_: aes_cbc::Error) -> Self {
		Self::BadAesParams
	}
}

impl From<pqcrypto_traits::Error> for Error {
	fn from(_: pqcrypto_traits::Error) -> Self {
		Self::WrongCiphertext
	}
}

#[derive(Debug, PartialEq)]
pub struct KeyTypeKyber;

impl KeyPairSize for KeyTypeKyber {
	const PRIV: usize = pqcrypto_kyber::kyber1024::secret_key_bytes();
	const PUB: usize = pqcrypto_kyber::kyber1024::public_key_bytes();
}

pub type PrivateKeyKyber = PrivateKey<KeyTypeKyber, { KeyTypeKyber::PRIV }>;
pub type PublicKeyKyber = PublicKey<KeyTypeKyber, { KeyTypeKyber::PUB }>;

pub type KeyPairKyber = KeyPair<KeyTypeKyber, { KeyTypeKyber::PRIV }, { KeyTypeKyber::PUB }>;

impl KeyPairKyber {
	pub fn generate() -> Self {
		use pqcrypto_traits::kem::{PublicKey, SecretKey};

		let (pk, sk) = keypair();

		// TODO: do not hard-unwrap
		Self::new(PrivateKeyKyber::try_from(sk.as_bytes().to_vec()).unwrap(), PublicKeyKyber::try_from(pk.as_bytes().to_vec()).unwrap())
	}
}

impl PublicKeyKyber {
	pub fn encapsulate(&self) -> (SharedSecret, Ciphertext) {
		use pqcrypto_traits::kem::PublicKey;

		let pk = pqcrypto_kyber::kyber1024::PublicKey::from_bytes(self.as_bytes()).unwrap();

		encapsulate(&pk)
	}
}

impl PrivateKeyKyber {
	pub fn decapsulate(&self, ct: &[u8]) -> Result<SharedSecret, Error> {
		use pqcrypto_traits::kem::{SecretKey, Ciphertext};

		let sk = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(self.as_bytes())?;
		let ciphertext = &pqcrypto_kyber::kyber1024::Ciphertext::from_bytes(ct)?;
		let ss = decapsulate(ciphertext, &sk);

		Ok(ss)
	}
}

// TODO: reuse for x448 as well
mod to_serde {
	use serde::ser::{Serialize, SerializeStruct, Serializer};
	use super::KeyPairKyber;
	
	impl Serialize for KeyPairKyber {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
			S: Serializer
		{
			let mut state = serializer.serialize_struct("KeyPairKyber", 2)?;

			state.serialize_field("private", &base64::encode(self.private_key().as_bytes()))?;
			state.serialize_field("public", &base64::encode(self.public_key().as_bytes()))?;

			state.end()
		}
	}
}

/// Encrypts KeyBundle, so that bundle.x448.id = envelope.key_id
/// The hierarchy goes as follows:
/// EncryptedEnvelope {
/// 	Encrypted {
/// 		KeyBundle | Encrypted
/// 	}
/// }
/// Corresponds to proto::KyberEncryptedEphemeralKey
#[derive(Clone, Debug, PartialEq)]
pub struct EncryptedEnvelope {
	/// id of the encrypted x448 key of payload.payload
	pub key_id: u64,
	/// if yes, payload.payload is KyberEncrypted
	pub double_encrypted: bool,
	/// contains either KyberedKeys or another KyberEncrypted, if `double_encrypted` is true
	pub payload: Encrypted
}

impl From<&EncryptedEnvelope> for proto::KyberEncryptedEphemeralKey {
	fn from(src: &EncryptedEnvelope) -> Self {
		Self {
			ephemeral_key_id: src.key_id,
			double_encrypted: src.double_encrypted,
			kyber_encrypted: proto::KyberEncrypted::from(&src.payload)
		}
	}
}

impl Serializable for EncryptedEnvelope {
	fn serialize(&self) -> Vec<u8> {
		proto::KyberEncryptedEphemeralKey::from(self).encode_to_vec()
	}
}

impl TryFrom<proto::KyberEncryptedEphemeralKey> for EncryptedEnvelope {
	type Error = Error;

	fn try_from(value: proto::KyberEncryptedEphemeralKey) -> Result<Self, Self::Error> {
		Ok(Self {
			key_id: value.ephemeral_key_id,
			double_encrypted: value.double_encrypted,
			payload: Encrypted::try_from(value.kyber_encrypted)?
		})
	}
}

impl Deserializable for EncryptedEnvelope {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> {
		Self::try_from(proto::KyberEncryptedEphemeralKey::decode(buf).or(Err(Error::BadKyberEncryptedKeyFormat))?)
	}
}

/// Anything encrypted with a kyber key (specified by `encryption_key_id`). To be precise, it's aes-encrypted, where
/// key = kyber_pub.encapsulate().secret, iv = gen_random()
/// In general, used to encrypt KeyBundle, either once (with a prekey), eg when it's time to kyber-encrypt
/// the next ratchet or twice: enc(identity, enc(prekey, data)) during the initial key exchange (the only scenario for double encryption)
/// Corresponds to proto::KyberEncrypted
#[derive(Clone, Debug, PartialEq)]
pub struct Encrypted {
	/// id of the public kyber key used to encapsulate-encrypt `payload`
	pub encryption_key_id: u64,
	/// output of Kyber::encapsulate
	// TODO: introduce Ciphertext & SharedSecret instead of Vec
	pub ciphertext: Vec<u8>, 
	/// used to aes-encrypt/decrypt `payload` in encrypt/decrypt_sealed
	pub iv: Iv,
	/// decrypts either to Encrypted or to straight to KeyBundle
	pub payload: Vec<u8>
}

impl From<&Encrypted> for proto::KyberEncrypted {
	fn from(src: &Encrypted) -> Self {
		Self {
			encapsulation_key_id: src.encryption_key_id,
			ciphertext: src.ciphertext.clone(),
			aes_iv: src.iv.0.to_vec(),
			aes_encrypted_data: src.payload.clone()
		}
	}
}

impl Serializable for Encrypted {
	fn serialize(&self) -> Vec<u8> {
		proto::KyberEncrypted::from(self).encode_to_vec()
	}
}

impl TryFrom<proto::KyberEncrypted> for Encrypted {
	type Error = Error;

	fn try_from(value: proto::KyberEncrypted) -> Result<Self, Self::Error> {
		Ok(Self {
			encryption_key_id: value.encapsulation_key_id,
			ciphertext: value.ciphertext,
			iv: Iv::try_from(value.aes_iv).or(Err(Error::WrongIvLen))?,
			payload: value.aes_encrypted_data 
		})
	}
}

impl Deserializable for Encrypted {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> where Self: Sized {
		Self::try_from(proto::KyberEncrypted::decode(buf).or(Err(Error::BadKyberEncryptedFormat))?)
	}
}

// decrypted KyberEncrypted proto object (to be renamed): x448 + kyber ratches
#[derive(Debug, PartialEq)]
pub struct KeyBundle {
	pub ephemeral: PublicKeyX448,
	pub kyber: PublicKeyKyber
}

impl From<&KeyBundle> for proto::KyberX448KeyPair {
	fn from(value: &KeyBundle) -> Self {
		Self {
			ephemeral_key: value.ephemeral.as_bytes().to_vec(),
			kyber_key: value.kyber.as_bytes().to_vec()
		}
	}
}

impl Serializable for KeyBundle {
	fn serialize(&self) -> Vec<u8> {
		proto::KyberX448KeyPair::from(self).encode_to_vec()
	}
}

impl TryFrom<proto::KyberX448KeyPair> for KeyBundle {
	type Error = Error;

	fn try_from(value: proto::KyberX448KeyPair) -> Result<Self, Self::Error> {
		let ephemeral = PublicKeyX448::try_from(value.ephemeral_key).or(Err(Error::WrongEphKeyLen))?;
		let kyber = PublicKeyKyber::try_from(value.kyber_key).or(Err(Error::WrongKyberKeyLen))?;

		Ok(Self { ephemeral, kyber })
	}
}

impl Deserializable for KeyBundle {
	type Error = Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> {
		Self::try_from(proto::KyberX448KeyPair::decode(buf).or(Err(Error::BadKyberedKeysFormat))?)
	}
}

pub enum EncryptionMode<'a> {
    Once { key: &'a PublicKeyKyber },
    Double { first_key: &'a PublicKeyKyber, second_key: &'a PublicKeyKyber }
}

pub type KeySource<'a> = dyn Fn(u64) -> Result<&'a PrivateKeyKyber, Error>;

pub enum DecryptionMode<'a, F> 
where
	F: Fn(u64) -> Result<&'a PrivateKeyKyber, Error> + ?Sized
{
	Once { key: &'a PrivateKeyKyber},
	Double { second_key: &'a PrivateKeyKyber, first_key: Box<F> }
}

impl<'a> EncryptionMode<'a>
{
	fn is_double(&self) -> bool {
		matches!(self, Self::Double { first_key: _, second_key: _ })
	}
}

pub fn encrypt_sealed(plain: &[u8], pk: &PublicKeyKyber) -> Encrypted {
	use crate::aes_cbc::{Key};
	use pqcrypto_traits::kem::{SharedSecret, Ciphertext};

	let (shared_secret, ciphertext) = pk.encapsulate();
	// FIXME: use hkdf instead? otherwise, it's a strong assumption that shared_secret has the same size as aes_cbc::Key
	let key = Key::try_from(shared_secret.as_bytes().to_vec()).unwrap();
	let iv = Iv::generate();

	let aes = AesCbc::new(key, iv);
	let payload = aes.encrypt(plain);

	Encrypted {
		encryption_key_id: pk.id(),
		ciphertext: ciphertext.as_bytes().to_vec(),
		iv,
		payload
	}
}

pub fn decrypt_sealed(msg: &Encrypted, sk: &PrivateKeyKyber) -> Result<Vec<u8>, Error> {
	use crate::aes_cbc::{Key};
	use pqcrypto_traits::kem::SharedSecret;

	// todo: check if key = key.id? it simply won't decrypt if it's a wrong key
	let shared_secret = sk.decapsulate(&msg.ciphertext)?;
	let iv = msg.iv;
	// FIXME: hkdf instead?
	let key = Key::try_from(shared_secret.as_bytes().to_vec()).or(Err(Error::WrongKeyLen))?;
	let aes = AesCbc::new(key, iv);

	Ok(aes.decrypt(&msg.payload)?)
}

/// encrypts (eph, kyber) with encrypting_key and optionally with second_encrypting_key, if present
/// double encryption is now done only for initial key exchange
pub fn encrypt_keys(eph: &PublicKeyX448,
	kyber: &PublicKeyKyber,
	mode: EncryptionMode) -> EncryptedEnvelope {
	let serialized_kybered = KeyBundle {
		ephemeral: eph.clone(),
		kyber: kyber.clone()
	}.serialize();

	use EncryptionMode::{Once, Double};

	EncryptedEnvelope {
		key_id: eph.id(),
		double_encrypted: mode.is_double(),
		payload: match mode {
			Once { key } => encrypt_sealed(&serialized_kybered, key),
			Double { first_key, second_key } => encrypt_sealed(&encrypt_sealed(&serialized_kybered, first_key).serialize(), second_key) 
		} 
	}
}

pub fn decrypt_keys<'a, F>(eph: &EncryptedEnvelope, mode: DecryptionMode<'a, F>) -> Result<KeyBundle, Error>
where
	F: Fn(u64) -> Result<&'a PrivateKeyKyber, Error> + ?Sized
{
	use DecryptionMode::{Once, Double};

	match mode {
    Once { key } => KeyBundle::deserialize(&decrypt_sealed(&eph.payload, key)?),
    Double { second_key, first_key } => {
			let encrypted = Encrypted::deserialize(&decrypt_sealed(&eph.payload, second_key)?)?;
			let key = first_key(encrypted.encryption_key_id)?;

			KeyBundle::deserialize(&decrypt_sealed(&encrypted, key)?)
		} 
	}
}

#[cfg(test)]
mod tests {
	use pqcrypto_traits::kem::{Ciphertext, SharedSecret};
	use crate::{x448::KeyPairX448, serializable::{Serializable, Deserializable}, aes_cbc::Iv};
	use super::{KeyTypeKyber, PrivateKeyKyber, KeyPairKyber, Error, encrypt_sealed, decrypt_sealed, encrypt_keys, decrypt_keys, KeySource, EncryptionMode, DecryptionMode, KeyBundle, Encrypted, EncryptedEnvelope};
	use crate::key_pair::KeyPairSize;

	#[test]
	fn test_serialize_deserialize_kybered_keys() {
		let kybered = KeyBundle {
			ephemeral: KeyPairX448::generate().public_key().to_owned(),
			kyber: KeyPairKyber::generate().public_key().to_owned()
		};
		let serialized = kybered.serialize();
		let deserialized = KeyBundle::deserialize(&serialized);

		assert_eq!(Ok(kybered), deserialized);
	}

	#[test]
	fn test_serialize_deserialize_kyber_encrypted() {
		let ke = Encrypted {
			encryption_key_id: 42,
			ciphertext: b"oh, my".to_vec(),
			iv: Iv([7u8; Iv::SIZE]),
			payload: b"no payment or loading required".to_vec() 
		};
		let serialized = ke.serialize();
		let deserialized = Encrypted::deserialize(&serialized);

		assert_eq!(Ok(ke), deserialized);
	}

	#[test]
	fn test_serialize_deserialize_kyber_encrypted_envelope() {
		let env = EncryptedEnvelope {
			key_id: 42,
			double_encrypted: true,
			payload: Encrypted {
				encryption_key_id: 42,
				ciphertext: b"oh, my".to_vec(),
				iv: Iv([7u8; Iv::SIZE]),
				payload: b"no payment or loading required".to_vec() 
			} 
		};
		let serialized = env.serialize();
		let deserialized = EncryptedEnvelope::deserialize(&serialized);
		
		assert_eq!(Ok(env), deserialized);
	}

	#[test]
	fn test_gen_keypair_non_zeroes() {
		let kp = KeyPairKyber::generate();

		assert_ne!(kp.private_key().as_bytes(), &[0u8; KeyTypeKyber::PRIV]);
		assert_ne!(kp.public_key().as_bytes(), &[0u8; KeyTypeKyber::PUB]);
	}

	#[test]
	fn test_gen_keypair_unique() {
		let kp0 = KeyPairKyber::generate();
		let kp1 = KeyPairKyber::generate();

		assert_ne!(kp0.private_key(), kp1.private_key());
		assert_ne!(kp0.public_key(), kp1.public_key());
	}

	#[test]
	fn test_encapsulate_unique_output_with_same_key() {
		let kp = KeyPairKyber::generate();
		let (sk0, ct0) = kp.public_key().encapsulate();
		let (sk1, ct1) = kp.public_key().encapsulate();

		assert_ne!(sk0.as_bytes(), sk1.as_bytes());
		assert_ne!(ct0.as_bytes(), ct1.as_bytes());
	}

	#[test]
	fn test_encapsulate_decapsulate() {
		let kp = KeyPairKyber::generate();

		let (secret, ciphrtext) = kp.public_key().encapsulate();
		let decapsulated = kp.private_key().decapsulate(ciphrtext.as_bytes()).unwrap();

		assert_eq!(secret.as_bytes(), decapsulated.as_bytes());
	}

	#[test]
	fn test_decapsulate_with_wrong_key_produces_wrong_secret() {
		let kp = KeyPairKyber::generate();
		let (shared, ct) = kp.public_key().encapsulate();
		let wrong_shared = KeyPairKyber::generate().private_key().decapsulate(ct.as_bytes()).unwrap();

		assert_ne!(shared.as_bytes(), wrong_shared.as_bytes());
	}

	#[test]
	fn test_encrypt_decrypt_sealed() {
		let msg = b"And your kudos are appreciated also!";
		let kp = KeyPairKyber::generate();
		let sealed = encrypt_sealed(msg, kp.public_key());
		let unsealed = decrypt_sealed(&sealed, kp.private_key());

		assert_eq!(Ok(msg.to_vec()), unsealed);
	}

	#[test]
	fn test_decrypt_sealed_fails_with_decapsulation_error() {
		let msg = b"Thanks";
		let kp = KeyPairKyber::generate();
		let mut sealed = encrypt_sealed(msg, kp.public_key());

		sealed.ciphertext = vec![1, 2, 3];

		let unsealed = decrypt_sealed(&sealed, kp.private_key());

		assert_eq!(Err(Error::WrongCiphertext), unsealed);
	}

	#[test]
	fn test_decrypt_sealed_fails_with_bad_aes() {
		let msg = b"Thanks";
		let kp = KeyPairKyber::generate();
		let sealed = encrypt_sealed(msg, kp.public_key());
		let unsealed = decrypt_sealed(&sealed, KeyPairKyber::generate().private_key());

		assert_eq!(Err(Error::BadAesParams), unsealed);
	}

	#[test]
	fn test_encrypt_decrypt_ephemeral_mode_once() -> Result<(), Error> {
		let eph = KeyPairX448::generate();
		let kyber = KeyPairKyber::generate();
		let kp = KeyPairKyber::generate();

		let encrypted = encrypt_keys(eph.public_key(), kyber.public_key(), EncryptionMode::Once { key: kp.public_key() });
		let decrypted = decrypt_keys::<KeySource>(&encrypted, DecryptionMode::Once { key: kp.private_key() })?;

		assert_eq!(eph.public_key(), &decrypted.ephemeral);
		assert_eq!(kyber.public_key(), &decrypted.kyber);

		Ok(())
	}

	#[test]
	fn test_decrypt_ephemeral_mode_once_fails_with_bad_aes() {
		let eph = KeyPairX448::generate();
		let kyber = KeyPairKyber::generate();
		let kp = KeyPairKyber::generate();

		let encrypted = encrypt_keys(eph.public_key(), kyber.public_key(), 
			EncryptionMode::Once { key: kp.public_key() });
		let decrypted = decrypt_keys::<KeySource>(&encrypted, DecryptionMode::Once { key: KeyPairKyber::generate().private_key() });

		assert_eq!(decrypted.err(), Some(Error::BadAesParams));
	}

	#[test]
	fn test_encrypt_decrypt_ephemeral_mode_double() -> Result<(), Error> {
		let eph = KeyPairX448::generate();
		let kyber = KeyPairKyber::generate();
		let kp_first = KeyPairKyber::generate();
		let kp_second = KeyPairKyber::generate();

		let find_key = |_| -> Result<&PrivateKeyKyber, Error> {
			Ok(kp_first.private_key())
		};

		let encrypted = encrypt_keys(eph.public_key(), kyber.public_key(), EncryptionMode::Double { first_key: kp_first.public_key(), second_key: kp_second.public_key() });
		let decrypted = decrypt_keys(&encrypted, DecryptionMode::Double { second_key: kp_second.private_key(), first_key: Box::new(find_key) })?;

		assert_eq!(eph.public_key(), &decrypted.ephemeral);
		assert_eq!(kyber.public_key(), &decrypted.kyber);

		Ok(())
	}

	#[test]
	fn test_decrypt_ephemeral_mode_double_fails_with_wrong_keys() -> Result<(), Error> {
		let eph = KeyPairX448::generate();
		let kyber = KeyPairKyber::generate();

		let kp_first = KeyPairKyber::generate();
		let kp_second = KeyPairKyber::generate();
		
		let wrong_first_kp = KeyPairKyber::generate();
		let wrong_second_kp = KeyPairKyber::generate();

		let find_key = |_| -> Result<&PrivateKeyKyber, Error> {
			Ok(kp_first.private_key())
		};

		let find_wrong_key = |_| -> Result<&PrivateKeyKyber, Error> {
			Ok(wrong_first_kp.private_key())
		};

		let encrypted = encrypt_keys(eph.public_key(), kyber.public_key(), EncryptionMode::Double { first_key: kp_first.public_key(), second_key: kp_second.public_key() });
		let failed_with_wrong_second_key = decrypt_keys(&encrypted, DecryptionMode::Double { second_key: wrong_second_kp.private_key(), first_key: Box::new(find_key) });

		assert_eq!(failed_with_wrong_second_key.err(), Some(Error::BadAesParams));

		let failed_with_wrong_first_key = decrypt_keys(&encrypted, DecryptionMode::Double { second_key: kp_second.private_key(), first_key: Box::new(find_wrong_key) });

		assert_eq!(failed_with_wrong_first_key.err(), Some(Error::BadAesParams));

		// make sure it actually decrypts
		let decrypted = decrypt_keys(&encrypted, DecryptionMode::Double { second_key: kp_second.private_key(), first_key: Box::new(find_key) })?;

		assert_eq!(eph.public_key(), &decrypted.ephemeral);
		assert_eq!(kyber.public_key(), &decrypted.kyber);

		Ok(())
	}

	#[test]
	fn test_decrypt_ephemeral_mode_once_fails_as_wrong_mode() -> Result<(), Error> {
		let eph = KeyPairX448::generate();
		let kyber = KeyPairKyber::generate();
		let kp_first = KeyPairKyber::generate();
		let kp_second = KeyPairKyber::generate();

		let first_key = |_| -> Result<&PrivateKeyKyber, Error> {
			Ok(kp_first.private_key())
		};

		let second_key = |_| -> Result<&PrivateKeyKyber, Error> {
			Ok(kp_second.private_key())
		};

		let encrypted = encrypt_keys(eph.public_key(), kyber.public_key(), EncryptionMode::Once { key: kp_first.public_key() });

		// decrypted the inner buffer, but failed to deserialize the outer KyberEncrypted
		let correct_first_second_as_first  = decrypt_keys(&encrypted, DecryptionMode::Double { second_key: kp_first.private_key(), first_key: Box::new(first_key) });
		assert_eq!(correct_first_second_as_first.err(), Some(Error::BadKyberEncryptedFormat));

		// decrypted the inner buffer, but failed to deserialize the outer KyberEncrypted
		let correct_first_wrong_second  = decrypt_keys(&encrypted, DecryptionMode::Double { second_key: kp_first.private_key(), first_key: Box::new(second_key) });
		assert_eq!(correct_first_wrong_second.err(), Some(Error::BadKyberEncryptedFormat));

		// fails with the first buffer, so it's a generic `BadAesParams`
		let wrong_first_second_as_first  = decrypt_keys(&encrypted, DecryptionMode::Double { second_key: kp_second.private_key(), first_key: Box::new(first_key) });
		assert_eq!(wrong_first_second_as_first.err(), Some(Error::BadAesParams));

		// fails with the first buffer, so it's a generic `BadAesParams`
		let wrong_first_wrong_second  = decrypt_keys(&encrypted, DecryptionMode::Double { second_key: kp_second.private_key(), first_key: Box::new(second_key) });
		assert_eq!(wrong_first_wrong_second.err(), Some(Error::BadAesParams));

		// make sure it actually decrypts
		let decrypted = decrypt_keys::<KeySource>(&encrypted, DecryptionMode::Once { key: kp_first.private_key() })?;

		assert_eq!(eph.public_key(), &decrypted.ephemeral);
		assert_eq!(kyber.public_key(), &decrypted.kyber);

		Ok(())
	}

	#[test]
	fn test_decrypt_ephemeral_mode_double_fails_as_wrong_mode() -> Result<(), Error> {
		let eph = KeyPairX448::generate();
		let kyber = KeyPairKyber::generate();
		let kp_first = KeyPairKyber::generate();
		let kp_second = KeyPairKyber::generate();

		let find_key = |_| -> Result<&PrivateKeyKyber, Error> {
			Ok(kp_first.private_key())
		};

		let encrypted = encrypt_keys(eph.public_key(), kyber.public_key(), EncryptionMode::Double { first_key: kp_first.public_key(), second_key: kp_second.public_key() });
		
		// first should go inside, so it's a generic `BadAesParams`
		let correct_first = decrypt_keys::<KeySource>(&encrypted, DecryptionMode::Once { key: kp_first.private_key() });
		assert_eq!(correct_first.err(), Some(Error::BadAesParams));

		// the outer layer decrypts fine, but there should be one more KyberEncrypted, not KyberedKeys
		let correct_second = decrypt_keys::<KeySource>(&encrypted, DecryptionMode::Once { key: kp_second.private_key() });
		assert_eq!(correct_second.err(), Some(Error::BadKyberedKeysFormat));

		// make sure it actually decrypts
		let decrypted = decrypt_keys(&encrypted, DecryptionMode::Double { second_key: kp_second.private_key(), first_key: Box::new(find_key) })?;

		assert_eq!(eph.public_key(), &decrypted.ephemeral);
		assert_eq!(kyber.public_key(), &decrypted.kyber);

		Ok(())
	}
}