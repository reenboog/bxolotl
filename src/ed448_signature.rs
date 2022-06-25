const SIZE: usize = 114;

pub struct Ed448Signature {
	bytes: [u8; SIZE],
}

impl Ed448Signature {
	pub fn as_bytes(&self) -> &[u8; SIZE] {
		&self.bytes
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_new() {
		todo!()
	}
}