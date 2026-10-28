//! Thin re-export module so the public API reads naturally as
//! `symbolon::peer::PeerRegistry` even though the implementation
//! lives alongside `Identity` in `identity.rs` (they're tightly coupled:
//! both revolve around the same Ed25519 keys).

pub use crate::identity::{fingerprint, PeerId, PeerRegistry};
