trait SizedKeyPair {
	fn priv_size() -> usize;
	fn pub_size() -> usize;
}

pub struct KeyPair<const PRIV_KEY_SIZE: usize, const PUB_KEY_SIZE: usize> {
	private: [u8; PRIV_KEY_SIZE], // TODO: replace with PrivateKey?
	public: [u8; PUB_KEY_SIZE]		// TODO: replace with PublicKey?
}

impl<const PRIV_KEY_SIZE: usize, const PUB_KEY_SIZE: usize> SizedKeyPair for KeyPair<PRIV_KEY_SIZE, PUB_KEY_SIZE> {
	fn priv_size() -> usize {
		PRIV_KEY_SIZE
	}

	fn pub_size() -> usize {
		PUB_KEY_SIZE
	}
}

impl<const PRIV_KEY_SIZE: usize, const PUB_KEY_SIZE: usize> KeyPair<PRIV_KEY_SIZE, PUB_KEY_SIZE> {
	pub fn from_private(private: &[u8; PRIV_KEY_SIZE]) -> Self {
		todo!()
	}
	
	pub fn new(private: &[u8; PRIV_KEY_SIZE], public: &[u8; PUB_KEY_SIZE]) -> Self {
		Self {
			private: private.clone(),
			public: public.clone()
		}
	}
}

pub type KeyPairX448 = KeyPair<56, 56>;
pub type KeyPairNtru = KeyPair<1120, 1027>;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_size_specs() {
		todo!()
	}
	
	#[test]
	fn test_new() {
		let pair = KeyPair::<2, 4>::new(&[1u8, 2], &[1u8, 2, 3, 4]);

		assert_eq!(5, KeyPair::<5, 5>::priv_size());

		assert_eq!(pair.private.len(), 2);
		assert_eq!(pair.public.len(), 4);
	}
}