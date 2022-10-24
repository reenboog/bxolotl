#[derive(Clone, Copy, PartialEq, Debug)]
pub struct RootKey([u8; Self::SIZE]);

impl RootKey {
	pub const SIZE: usize = 32;

	pub fn new(bytes: [u8; Self::SIZE]) -> Self {
		Self(bytes)
	}

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.0
	}
}

impl TryFrom<Vec<u8>> for RootKey {
	type Error = std::array::TryFromSliceError;

	fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
		let slice: [u8; Self::SIZE] = value.as_slice().try_into()?;

		Ok(Self::new(slice))
	}
}