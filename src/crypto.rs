//! Symmetric encryption for the message layer.
//!
//! # Why per-direction keys instead of one shared key?
//!
//! A single AEAD key must never be used to encrypt two different messages
//! under the same nonce - doing so catastrophically breaks ChaCha20-Poly1305
//! (it leaks the XOR of the two plaintexts and lets an attacker forge
//! messages). If both peers encrypted with the *same* key and both started
//! their nonce counters at zero, they could easily collide.
//!
//! We sidestep the whole problem by deriving **two independent keys** from
//! the shared handshake secret - one for "initiator to responder" traffic
//! and one for "responder to initiator" traffic. Each side then only ever
//! *encrypts* with its own send key and *decrypts* with its own recv key,
//! and each direction keeps its own strictly-increasing counter. Since the
//! two directions never share a key, nonce reuse across directions is
//! impossible by construction; nonce reuse *within* a direction is
//! prevented by the sequence-number counter only ever incrementing (see
//! `reliability.rs`).
//!
//! # Nonce construction
//!
//! ChaCha20-Poly1305 needs a 12-byte nonce. We build it from the 8-byte
//! big-endian message sequence number, left-padded with four zero bytes:
//! `nonce = 0x00000000 || seq_be`. Because `seq` never repeats within a
//! direction (it's a monotonic counter, checked in `reliability.rs`), this
//! nonce is guaranteed unique per (key, direction) pair for the lifetime of
//! that key.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

use crate::error::{ChatError, Result};

/// One AEAD key, wrapped so we can implement `Drop` to zero it if desired
/// later without touching call sites. (`chacha20poly1305`'s own `Key`
/// already zeroizes on drop internally via the `zeroize` crate.)
#[derive(Clone)]
pub struct AeadKey(pub [u8; 32]);

/// Logical channel discriminant, mixed into the nonce so the "data" stream
/// and the "control" (ack / resume) stream can each keep their own
/// independent, simple monotonic counter under the *same* per-direction key
/// without ever colliding on a nonce. Without this, message #5 on the data
/// channel and message #5 on the control channel would reuse the exact same
/// nonce under the same key, which is exactly the situation AEAD ciphers
/// must never allow.
#[derive(Clone, Copy)]
pub enum Channel {
    Data = 0,
    Control = 1,
}

/// Build the 12-byte nonce for a given channel + message sequence number.
/// Layout: `[1 byte channel][3 zero bytes][8 byte big-endian seq]`.
fn nonce_for(channel: Channel, seq: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[0] = channel as u8;
    bytes[4..12].copy_from_slice(&seq.to_be_bytes());
    *Nonce::from_slice(&bytes)
}

/// Encrypt `plaintext` under `key` for message number `seq` on `channel`,
/// authenticating (but not encrypting) the associated data `aad` as well.
/// `aad` is used to bind context - such as the visible channel/seq header -
/// into the authentication tag without needing to encrypt it.
pub fn encrypt(key: &AeadKey, channel: Channel, seq: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = nonce_for(channel, seq);
    cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| ChatError::DecryptionFailed) // encryption itself can't really fail here
}

/// Decrypt and authenticate `ciphertext`. Returns `Err(ChatError::DecryptionFailed)`
/// if the authentication tag doesn't match - i.e. the data was corrupted or
/// tampered with, or `seq`/`channel`/`aad` don't match what the sender
/// actually used.
pub fn decrypt(key: &AeadKey, channel: Channel, seq: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = nonce_for(channel, seq);
    cipher
        .decrypt(&nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| ChatError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let key = AeadKey([7u8; 32]);
        let ct = encrypt(&key, Channel::Data, 42, b"context", b"hello").unwrap();
        let pt = decrypt(&key, Channel::Data, 42, b"context", &ct).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn detects_tampering() {
        let key = AeadKey([7u8; 32]);
        let mut ct = encrypt(&key, Channel::Data, 42, b"context", b"hello").unwrap();
        ct[0] ^= 0xFF; // flip a bit
        assert!(decrypt(&key, Channel::Data, 42, b"context", &ct).is_err());
    }

    #[test]
    fn detects_wrong_sequence_number() {
        let key = AeadKey([7u8; 32]);
        let ct = encrypt(&key, Channel::Data, 42, b"context", b"hello").unwrap();
        assert!(decrypt(&key, Channel::Data, 43, b"context", &ct).is_err());
    }

    #[test]
    fn detects_wrong_aad() {
        let key = AeadKey([7u8; 32]);
        let ct = encrypt(&key, Channel::Data, 42, b"context", b"hello").unwrap();
        assert!(decrypt(&key, Channel::Data, 42, b"different", &ct).is_err());
    }

    #[test]
    fn data_and_control_channels_never_collide_even_at_same_seq() {
        let key = AeadKey([7u8; 32]);
        let ct_data = encrypt(&key, Channel::Data, 1, b"", b"hello").unwrap();
        let ct_ctrl = encrypt(&key, Channel::Control, 1, b"", b"hello").unwrap();
        assert_ne!(ct_data, ct_ctrl);
        assert!(decrypt(&key, Channel::Control, 1, b"", &ct_data).is_err());
        assert!(decrypt(&key, Channel::Data, 1, b"", &ct_ctrl).is_err());
    }
}
