aes cbc pkcs7 for messge keys
 - cipher
 - aes
 - cbc

send(msg, nid):
1 store.save(PendingSend { nid, msg.serialized() } )
2 encrypt
	2.1 axolotl.encrypt(pending) -> body, updated_session 																					 // nothing to fail
	2.2 store.save(updated_session) 																																 // safe failure 
	2.3 store.save_if_required(Encrypted { mac { session.counter, session.ratchet, ... }, body } ) 	 // safe: if Encrypted is lost, just a counter is lost; if this is done first, it will break the session by duplicating counters
3 send(Send { encrypted } ).await <- ACK
4 store.delete(encrypted) // should still be deleted whether acked or timed out. What if it crashes?*
5 store.delete(pending)

*It is important to delete all encrypted MultiSends for the backend could have received some of them while being unable to send ACKs. Otherwise, if reused, the backend could deliver duplicate messages which can break its underlying Axolotl session

receive(mac, nid):
1 store.save_if_not_saved(PendingDecrypt)
2 sender.ack(msg)
3 store.get_first(PendingDecrypt).for_each { decrypt (msg) }