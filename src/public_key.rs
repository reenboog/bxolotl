pub struct PublicKey<const SIZE: usize> {
	key: [u8; SIZE]
}

impl<const SIZE: usize> PublicKey<SIZE> {
	fn id() -> u64 {
		todo!()
	}
}

pub type PublicKeyX448 = PublicKey<56>;

#[cfg(test)]
mod tests {
	#[test]
	fn test_calc_id() {
		todo!()
	}
}