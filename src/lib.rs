//! # symbolon
//!
//! A small, dependency-light peer-to-peer secure messaging library.
//!
//! ## What "very secure" means here, concretely
//!
//! - **Mutual authentication**: both peers cryptographically prove they
//!   hold the private key matching a long-term identity public key that
//!   the *other* peer already trusts (pinned out-of-band). See
//!   [`handshake`] and [`identity`].
//! - **Confidentiality + integrity**: every single message, including the
//!   control/acknowledgement traffic, is encrypted and authenticated with
//!   ChaCha20-Poly1305 under keys unique to that connection. See
//!   [`crypto`].
//! - **Forward secrecy**: session keys come from a fresh ephemeral
//!   X25519 Diffie-Hellman exchange every connection, not from the
//!   long-term identity keys, so recording today's traffic doesn't help an
//!   attacker who later steals a long-term private key.
//! - **No silently missing messages**: every data message is sequence
//!   numbered, acknowledged, gap-detected, and durably staged until
//!   acknowledged, so a peer that disconnects and reconnects gets exactly
//!   the messages it missed - no more, no less, still in order. See
//!   [`reliability`] and [`session`].
//!
//! ## Module map
//!
//! - [`identity`] / [`peer`]: long-term Ed25519 identity keys and the
//!   pinned-peer trust registry.
//! - [`handshake`]: the mutual-auth + key-exchange protocol.
//! - [`crypto`]: AEAD encryption primitives and nonce management.
//! - [`framing`]: length-prefixed message framing over a byte stream.
//! - [`message`]: wire encoding for control (ack / resume) messages.
//! - [`ratchet`]: Double Ratchet - per-message forward secrecy and
//!   post-compromise healing inside the transport encryption.
//! - [`reliability`]: sequence numbering, acknowledgement, gap detection.
//! - [`storage`]: pluggable storage traits (event log, key custody, state
//!   blobs) with file and in-memory defaults.
//! - [`transport`]: pluggable byte-stream transport (TCP by default, in-memory
//!   for tests and simulation) - how peers are found/connected is the app's job.
//! - [`session`]: ties everything together into a usable send/recv API.
//! - [`group`]: group chat as a signed, hash-chained full-mesh of
//!   [`session::Session`]s - see that module's docs for the design
//!   rationale (why full-mesh, and how it avoids the equivocation and
//!   membership-forgery pitfalls that come with it).
//! - [`error`]: the crate's error type.
//!
//! See `tests/` for end-to-end examples, including simulated disconnects,
//! reordering, and active tampering.

pub mod clock;
pub mod crypto;
pub mod discovery;
pub mod error;
pub mod framing;
pub mod group;
pub mod handshake;
pub mod identity;
pub mod message;
pub mod peer;
pub mod persistence;
pub mod ratchet;
pub mod reliability;
pub mod session;
pub mod sessionstate;
pub mod storage;
pub mod trace;
pub mod transport;
pub mod truststore;

pub use error::{ChatError, Result};
pub use identity::{Identity, PeerRegistry};
pub use session::{Reconnected, Role, Session};
