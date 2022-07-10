#[derive(Clone, Copy)]
pub struct RootKey([u8; Self::SIZE]);

impl RootKey {
	pub const SIZE: usize = 32;

	pub fn new(bytes: [u8; Self::SIZE]) -> Self {
		Self(bytes)
	}
}

// used to derive chain keys and subsequent root keys