# bxolotl: Post-Quantum Double Ratchet Cryptography

`bxolotl` is a **Rust library** implementing a state-of-the-art **Double Ratchet Protocol** for end-to-end encryption. It is designed to provide **perfect forward secrecy** and **future secrecy**, with a crucial integration of **Post-Quantum Cryptography (PQC)** to future-proof communication against potential quantum attacks.

---

## Features

* **Double Ratchet Protocol (Axolotl-style):** Secure session management ensuring forward and future secrecy for continuous, synchronous communication.
* **Post-Quantum Hybrid Cryptography:** Integrates the classical **X448** elliptic curve Diffie-Hellman with the **Kyber** (NTRU/ML-KEM) lattice-based Key Encapsulation Mechanism (KEM) to secure the initial key exchange and subsequent ratchets.
* **Cryptographic Primitives:** Utilizes strong, modern curves and algorithms:
    * **X448:** For Elliptic Curve Diffie-Hellman (ECDH) key agreement.
    * **Ed448:** For digital signatures (identity and signed prekeys).
    * **Kyber (KEM):** For Post-Quantum safe key exchange.
    * **AxolotlMac:** For message authentication and integrity.
* **Storage Abstraction:** Defines `Storage` and `AsyncStorage` traits, allowing for flexible persistence of sensitive session data (identity keys, prekeys, and sessions) in any backend.
* **Asynchronous Support:** Built with `async_trait` and `tokio::sync::Mutex` for thread-safe, non-blocking operation, suitable for high-performance applications.
* **Job Queue for Concurrency:** Uses an internal task queue to serialize encryption/decryption tasks per **Node ID (`nid`)**, preventing race conditions during session state updates.

---

## Architecture Overview

The core logic is managed by the generic struct `Cryptor<S, A>`, which abstracts away storage and API communication.

| Component | Description |
| :--- | :--- |
| **`Cryptor<S, A>`** | The main engine responsible for managing sessions, encrypting, and decrypting messages. It handles session setup (Alice/Bob roles), ratchet progression, and prekey fetching. |
| **`Storage` / `AsyncStorage`** | Traits for key and session persistence. Defines methods for retrieving and saving identity keys, prekeys, and active/receive-only sessions. |
| **`Apis`** | A trait for interacting with a backend service to **fetch Prekey Bundles** for new session establishments. |
| **`Session`** | The state machine for a single end-to-end encrypted conversation. Manages root keys, chain keys, and message keys. |
| **Prekeys** | Consumable keys (`Prekey` struct) used in the initial handshake to establish the first secret. They include both **X448** and **Kyber** public keys. |
| **`KeyExchange`** | Struct modeling the initial message data exchanged to bootstrap a new session, containing public identity keys, signed prekey ID, and Kyber-encrypted ephemeral keys. |

### Key Exchange and Ratcheting

The session establishment follows a hybrid approach:

1.  **Initial Handshake:** Alice fetches Bob's prekey bundle (containing X448 and Kyber public keys, plus a signed X448 prekey). Alice uses **Kyber KEM** to encrypt an ephemeral key, ensuring the session is protected against future quantum attacks from the very first message.
2.  **Ratcheting:** The session uses **X448** for its continuous Diffie-Hellman ratcheting, with a forced **Kyber ratchet** every `RATCHETS_BETWEEN_KYBER` (defined as **20**) messages to periodically refresh the PQC protection layer.
