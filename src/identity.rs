//! Long-term peer identity.
//!
//! # Trust model
//!
//! This library does **not** use a certificate authority. In a pure P2P
//! setting there usually isn't one to trust anyway. Instead every peer has a
//! long-term Ed25519 keypair, and *before* two peers ever talk to each other
//! they must exchange their public keys (or a fingerprint of them) over some
//! channel they already trust: read out loud on a phone call, scanned as a
//! QR code in person, published somewhere both sides already trust, etc.
//! This is the same "pin the key, verify out of band" model SSH's
//! `known_hosts` and Signal's "safety numbers" use, and it is the only sound
//! way to get real mutual authentication without a CA.
//!
//! We deliberately do **not** implement Trust-On-First-Use (silently
//! trusting whichever key shows up first). TOFU is convenient but it means
//! an attacker who is on-path for the *very first* connection can plant
//! themselves permanently. Callers who want TOFU can implement it explicitly
//! on top of [`PeerRegistry`] (add the key the first time you see it) —
//! but the default posture here is "only talk to peers I already know".

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use std::collections::HashMap;

use crate::error::{ChatError, Result};

/// A stable, human-showable identifier for a peer: the SHA-256 fingerprint
/// of their long-term public key, hex-encoded. This is what you'd read
/// aloud / compare on a QR code to verify you're pinning the right key.
pub type PeerId = String;

/// Derive the [`PeerId`] fingerprint for a given Ed25519 public key.
pub fn fingerprint(public_key: &VerifyingKey) -> PeerId {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(public_key.as_bytes());
    // Hex-encode manually so we don't need to pull in a `hex` crate.
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Our own long-term identity: a signing keypair that proves "I am me"
/// across sessions and reconnects. Generate this once and persist the
/// private key somewhere safe (a real deployment would store this
/// encrypted-at-rest; that's outside this crate's scope).
pub struct Identity {
    pub(crate) signing_key: SigningKey,
}

impl Identity {
    /// Generate a brand-new random identity keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Identity { signing_key }
    }

    /// Recreate an identity from previously-saved private key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Identity {
            signing_key: SigningKey::from_bytes(bytes),
        }
    }

    /// The 32 raw private key bytes, for persistence. Handle with care:
    /// anyone who obtains these can impersonate us to every peer that has
    /// our public key pinned.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Our long-term public key, safe to share with anyone.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Our own fingerprint, suitable for display / out-of-band verification.
    pub fn fingerprint(&self) -> PeerId {
        fingerprint(&self.public_key())
    }

    /// Sign an arbitrary message with our long-term identity key. Used
    /// exactly once per connection, during the handshake, to bind our
    /// identity to that specific session's ephemeral keys.
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        self.signing_key.sign(message)
    }
}

/// The set of peer identities we've pinned and are willing to talk to.
///
/// This is deliberately a simple allow-list: connections from (or to)
/// identities that are not in here are rejected before any application data
/// is exchanged, closing off impersonation and unknown-attacker MITM
/// attempts against the handshake.
#[derive(Default)]
pub struct PeerRegistry {
    trusted: HashMap<PeerId, VerifyingKey>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin a peer's public key as trusted. Call this only after verifying
    /// the key out-of-band (see module docs).
    pub fn trust(&mut self, public_key: VerifyingKey) -> PeerId {
        let id = fingerprint(&public_key);
        self.trusted.insert(id.clone(), public_key);
        id
    }

    /// Look up whether a given public key is trusted, returning its
    /// fingerprint if so.
    pub fn verify_trusted(&self, public_key: &VerifyingKey) -> Result<PeerId> {
        let id = fingerprint(public_key);
        if self.trusted.contains_key(&id) {
            Ok(id)
        } else {
            Err(ChatError::UnknownPeer)
        }
    }

    /// Verify a signature was produced by the given (trusted) public key
    /// over the given message.
    pub fn verify_signature(
        public_key: &VerifyingKey,
        message: &[u8],
        signature: &ed25519_dalek::Signature,
    ) -> Result<()> {
        public_key
            .verify(message, signature)
            .map_err(|_| ChatError::HandshakeAuthenticationFailed)
    }
}

/// Encode a public key as 64 lowercase hex characters - the form people
/// copy/paste or put in a QR code when pinning each other out-of-band.
pub fn encode_public_key(key: &VerifyingKey) -> String {
    key.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse the output of [`encode_public_key`]. Rejects wrong length,
/// non-hex characters, and byte strings that are not a valid Ed25519 point.
/// Surrounding whitespace is tolerated (pasted keys often carry a newline).
pub fn decode_public_key(hex: &str) -> Result<VerifyingKey> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(ChatError::MalformedMessage("public key must be 64 hex characters"));
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| ChatError::MalformedMessage("public key is not hex"))?;
        bytes[i] = u8::from_str_radix(pair, 16).map_err(|_| ChatError::MalformedMessage("public key is not hex"))?;
    }
    VerifyingKey::from_bytes(&bytes).map_err(|_| ChatError::InvalidPublicKey)
}

#[cfg(test)]
mod key_hex_tests {
    use super::*;

    #[test]
    fn public_key_hex_round_trips() {
        let id = Identity::generate();
        let hex = encode_public_key(&id.public_key());
        assert_eq!(hex.len(), 64);
        assert_eq!(decode_public_key(&hex).unwrap(), id.public_key());
        assert_eq!(decode_public_key(&format!("  {hex}\n")).unwrap(), id.public_key());
    }

    #[test]
    fn malformed_public_key_strings_are_rejected() {
        for bad in ["", "abcd", &"zz".repeat(32), &"0".repeat(63), &"0".repeat(65), "é".repeat(32).as_str()] {
            assert!(decode_public_key(bad).is_err(), "accepted {bad:?}");
        }
    }
}
