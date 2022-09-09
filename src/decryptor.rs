use std::{sync::Arc};

use async_trait::async_trait;
use prost::encoding::bool;
use crate::{prekey::Prekey, session::Session};

#[async_trait]
pub trait Sessions {
	// TODO: replace with `Nid`
	async fn get(&self, nid: &str) -> Option<Session>;
	async fn save(&mut self, session: &Session) -> bool; // TODO: introduce result
}

#[async_trait]
pub trait Prekeys {
	async fn get(&mut self, id: u64) -> Option<Prekey>; // TODO: use Result instead
}

pub struct Decryptor {
	sessions: Arc<dyn Sessions>,
	prekeys: Arc<dyn Prekeys>
}

impl Decryptor {
	pub fn new(sessions: Arc<dyn Sessions>, prekeys: Arc<dyn Prekeys>) -> Self {
		Self {
			sessions: Arc::clone(&sessions),
			prekeys: Arc::clone(&prekeys)
		}
	}
}

pub enum Error {
	BadMacFormat
}

impl Decryptor {
	pub async fn decrypt(&mut self, mac: &[u8], nid: &str, my_nid: &str) -> Result<Vec<u8>, Error> {
		// let mac = AxolotlMac::deserialize(mac).or(Err(Error::BadMacFormat))?;
		// let mut sessions = self.sessions.load(nid).await;

		// match sessions.decrypt(&mac, my_nid) {
		// 	Ok(bytes) => return Ok(bytes),
		// 	Err(err) => match err {
		// 		crate::session_list::Error::NewSessionRequired(_) => todo!()
		// 	}
		// }
		// // check if key exchange exists: mac.body().key_exchange (respect roles)
		// // ts is in ChatMessage, so server_ts shoul dbe used for Recover { ts } instead

		// // find a session
		// // but if I'm bob and there's a key exchange, I should mark that session as inactive_for_send (should be respected by Encryptor)

		todo!()
	}
}
