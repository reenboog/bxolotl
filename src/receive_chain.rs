use std::{collections::VecDeque};
use crate::{chain::Chain, key_pair::{PublicKeyX448, KeyPairNtru}};

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

impl ReceiveChain {
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

#[cfg(test)]
mod tests {
	#[test]
	fn test_get_current() {
		todo!()
	}

	#[test]
	fn test_set_current() {
		todo!()
	}

	#[test]
	fn test_remove() {
		todo!()
	}

	#[test]
	fn test_get_ntru_key_pair() {
		todo!()
	}
}
