use std::{collections::VecDeque};
use crate::{chain::Chain, x448::PublicKeyX448, ntru::KeyPairNtru, proto};

#[derive(Debug, PartialEq)]
pub struct ReceiveChain {
	chains: VecDeque<Chain>
}

impl ReceiveChain {
	pub fn new() -> Self {
		Self {
			chains: VecDeque::new()
		}
	}
}

impl Default for ReceiveChain {
	fn default() -> Self {
		Self::new()
	}
}

impl ReceiveChain {
	pub fn len(&self) -> usize {
		self.chains.len()
	}

	pub fn is_empty(&self) -> bool {
		self.chains.is_empty()
	}

	pub fn current(&self) -> Option<&Chain> {
		self.chains.front()
	}

	pub fn current_mut(&mut self) -> Option<&mut Chain> {
		self.chains.front_mut()
	}

	// Prepend chain to the deque & remove the current chain if it has no skipped keys left
	pub fn set_current(&mut self, chain: Chain) {
		if let Some(prev) = self.chains.front() {
			// Clean up, if no more skipped keys left
			if !prev.has_skipped_keys() {
				self.chains.pop_front();
			}
		}

		self.chains.push_front(chain);
	}

	pub fn remove_by_ratchet_key_id(&mut self, id: u64) {
		self.chains.retain(|c| c.ratchet_key().id() != id);
	}

	pub fn remove(&mut self, chain: &Chain) {
		self.remove_by_ratchet_key_id(chain.ratchet_key().id());
	}

	// TODO: accept ratchet key id
	pub fn chain_mut(&mut self, ratchet: &PublicKeyX448) -> Option<&mut Chain> {
		// originally, the keys are compared, not ids
		self.chains.iter_mut().find(|c| c.ratchet_key().id() == ratchet.id())
	}

	pub fn ntru_key_pair(&self, id: u64) -> Option<&KeyPairNtru> {
		self.chains.iter().flat_map(|c| c.ntru_ratchet_key()).find(|pk| pk.public_key().id() == id)
	}
}

impl From<&ReceiveChain> for Vec<proto::session_state::Chain> {
	fn from(src: &ReceiveChain) -> Self {
		src.chains.iter().map(|c| c.into()).collect::<Vec<proto::session_state::Chain>>()
	}
}

#[derive(Debug)]
pub enum Error {
	BadChain
}

impl TryFrom<Vec<proto::session_state::Chain>> for ReceiveChain {
	type Error = Error;

	fn try_from(value: Vec<proto::session_state::Chain>) -> Result<Self, Self::Error> {
		Ok(Self {
			chains: value
				.into_iter()
				.map(|c| Chain::try_from(c).or(Err(Error::BadChain)))
				.collect::<Result<VecDeque<Chain>, Error>>()?
		})
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_get_current() {
		// todo!()
	}

	#[test]
	fn test_set_current() {
		// todo!()
	}

	#[test]
	fn test_remove() {
		// todo!()
	}

	#[test]
	fn test_get_ntru_key_pair() {
		// todo!()
	}
}
