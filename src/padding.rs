//! Optional message padding: hide how long a message really is.
//!
//! Encryption hides what a message says but not how big it is, and size alone
//! leaks a lot ("yes" versus a paragraph, a short reply versus a pasted
//! log). Padding rounds every message up to a multiple of a **block size**, so
//! an observer only learns which block a message fell in.
//!
//! # How it works
//!
//! The padding goes INSIDE the encrypted payload, so an eavesdropper sees only
//! the total size:
//!
//! ```text
//! plaintext = payload || 0x80 || 0x00 0x00 ... 0x00
//!                        ^ marker   ^ zeros up to the next multiple of the block size
//! ```
//!
//! (This is the classic "ISO/IEC 7816-4" scheme.) The receiver always strips
//! it the same way: drop trailing zeros, then require the `0x80` marker. That
//! means:
//!
//! * the receiver needs no setting and no negotiation: it accepts padded and
//!   unpadded messages alike, so each side may pick its own padding for what
//!   it SENDS (and a peer on a different setting still works);
//! * the marker is always present, even with padding off, so **padding off
//!   costs exactly one byte per message**; that one byte is what lets the
//!   receiver tell padding from payload without a length field or flags
//!   (the flags header is on hold, see the plan);
//! * a payload that itself ends in zeros or `0x80` is fine, because the marker
//!   is added after it and the receiver strips from the END.
//!
//! # What it costs and what it hides
//!
//! On average a message grows by about half a block. A group post of 11 bytes
//! is about 160 bytes before padding, so a 256-byte block makes it 256, and
//! every message of up to roughly 100 bytes of text looks identical. Bigger
//! blocks hide more and cost more. Padding applies to application messages
//! only; the channel byte and the sequence number stay visible on the wire
//! (and are authenticated), so an observer can still tell data from
//! keepalives and count messages. Padding does NOT hide when you talk or how
//! many messages you send.
//!
//! Padding is a SENDING setting: see
//! [`crate::session::SessionConfig::padding`] and
//! [`crate::session::Session::set_padding`].

use crate::error::{ChatError, Result};

/// The byte that ends the payload and starts the zero padding.
const MARKER: u8 = 0x80;

/// How outgoing messages are padded. The default is [`Padding::OFF`].
///
/// Pick a preset ([`Padding::STANDARD`], [`Padding::STRONG`]) or a custom block
/// size with [`Padding::block`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Padding {
    /// Block size in bytes; 0 means "no padding".
    block: u16,
}

impl Padding {
    /// No padding (the default): every message is just its payload plus the
    /// one marker byte.
    pub const OFF: Padding = Padding { block: 0 };

    /// 256-byte blocks. Hides the exact length of short chat messages at a
    /// cost of about 128 bytes per message on average. The size most chat
    /// apps would want.
    pub const STANDARD: Padding = Padding { block: 256 };

    /// 1024-byte blocks. Hides more (messages look alike up to about 1 KB)
    /// and costs about 512 bytes per message on average.
    pub const STRONG: Padding = Padding { block: 1024 };

    /// The smallest custom block size accepted. Anything smaller hides almost
    /// nothing, so it is more likely a mistake than a choice.
    pub const MIN_BLOCK: u16 = 16;

    /// A custom block size in bytes (at least [`Padding::MIN_BLOCK`]).
    pub fn block(size: u16) -> Result<Padding> {
        if size < Self::MIN_BLOCK {
            return Err(ChatError::InvalidConfig(
                "padding block size must be at least 16 bytes (use Padding::OFF to disable)",
            ));
        }
        Ok(Padding { block: size })
    }

    /// The block size in bytes, or 0 when padding is off.
    pub fn block_size(self) -> u16 {
        self.block
    }

    /// `true` unless this is [`Padding::OFF`].
    pub fn is_on(self) -> bool {
        self.block != 0
    }

    /// Rebuild from a stored block size (0 = off). Used for the atomic
    /// setting inside a session; sizes between 1 and 15 cannot be built
    /// through the public API, so they never reach here.
    pub(crate) fn from_raw(block: u16) -> Padding {
        Padding { block }
    }
}

/// Add the marker and the zero padding to `payload`.
///
/// The result is `payload.len() + 1` rounded up to a multiple of the block
/// size (or exactly `payload.len() + 1` with padding off).
pub fn pad(payload: &[u8], padding: Padding) -> Vec<u8> {
    let with_marker = payload.len() + 1;
    let total = match padding.block as usize {
        0 => with_marker,
        b => with_marker.div_ceil(b) * b,
    };
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(payload);
    out.push(MARKER);
    out.resize(total, 0);
    out
}

/// Remove the padding added by [`pad`], in place, and return the payload.
///
/// Fails if the data does not end in `0x80` followed only by zeros, which
/// means the message was not produced by [`pad`] (a bug or a tampered peer;
/// the message is authenticated, so only the peer itself could cause this).
pub fn unpad(mut data: Vec<u8>) -> Result<Vec<u8>> {
    // Walk back over the zeros; the first non-zero byte must be the marker.
    let mut end = data.len();
    while end > 0 && data[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 || data[end - 1] != MARKER {
        return Err(ChatError::MalformedMessage("missing padding marker"));
    }
    data.truncate(end - 1);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_settings() -> Vec<Padding> {
        vec![
            Padding::OFF,
            Padding::STANDARD,
            Padding::STRONG,
            Padding::block(16).unwrap(),
            Padding::block(100).unwrap(),
            Padding::block(u16::MAX).unwrap(),
        ]
    }

    #[test]
    fn every_length_round_trips_under_every_setting() {
        for p in all_settings() {
            for len in 0..700usize {
                let payload: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                let back = unpad(pad(&payload, p)).unwrap();
                assert_eq!(back, payload, "block {} len {len}", p.block_size());
            }
        }
    }

    #[test]
    fn payloads_ending_in_zeros_or_the_marker_survive() {
        for tail in [
            &[0u8][..],
            &[0, 0, 0],
            &[0x80],
            &[0x80, 0],
            &[0, 0x80, 0, 0x80],
        ] {
            for p in all_settings() {
                let mut payload = b"data".to_vec();
                payload.extend_from_slice(tail);
                assert_eq!(unpad(pad(&payload, p)).unwrap(), payload);
            }
        }
        // And the empty payload.
        for p in all_settings() {
            assert_eq!(unpad(pad(b"", p)).unwrap(), b"");
        }
    }

    #[test]
    fn off_adds_exactly_one_byte() {
        assert_eq!(pad(b"hello", Padding::OFF).len(), 6);
        assert_eq!(pad(b"", Padding::OFF).len(), 1);
    }

    #[test]
    fn on_rounds_up_to_a_multiple_of_the_block() {
        for p in [
            Padding::STANDARD,
            Padding::STRONG,
            Padding::block(100).unwrap(),
        ] {
            let b = p.block_size() as usize;
            for len in 0..(3 * b) {
                let n = pad(&vec![1u8; len], p).len();
                assert_eq!(n % b, 0, "block {b} len {len}");
                // At least the payload and the marker, and never a whole block too many.
                assert!(n > len && n <= len + b, "block {b} len {len} gave {n}");
            }
        }
    }

    #[test]
    fn lengths_in_the_same_block_look_identical() {
        // 1 to 255 bytes of payload all become one 256-byte block.
        let sizes: std::collections::HashSet<usize> = (1..=255)
            .map(|len| pad(&vec![9u8; len], Padding::STANDARD).len())
            .collect();
        assert_eq!(sizes, [256].into_iter().collect());
        // 256 needs room for the marker, so it spills into the next block.
        assert_eq!(pad(&[9u8; 256], Padding::STANDARD).len(), 512);
    }

    #[test]
    fn data_that_was_not_padded_is_refused() {
        assert!(unpad(vec![]).is_err(), "empty");
        assert!(unpad(vec![0, 0, 0]).is_err(), "only zeros");
        assert!(unpad(b"no marker".to_vec()).is_err(), "no marker");
        assert!(unpad(vec![1, 2, 0x81, 0, 0]).is_err(), "wrong marker byte");
    }

    #[test]
    fn tiny_custom_blocks_are_refused() {
        for bad in [0u16, 1, 15] {
            assert!(matches!(
                Padding::block(bad),
                Err(ChatError::InvalidConfig(_))
            ));
        }
        assert!(Padding::block(16).is_ok());
    }

    #[test]
    fn the_default_is_off() {
        assert_eq!(Padding::default(), Padding::OFF);
        assert!(!Padding::OFF.is_on());
        assert!(Padding::STANDARD.is_on());
    }
}
