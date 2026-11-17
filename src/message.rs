//! Wire encoding for control-channel messages.
//!
//! These are the small housekeeping messages peers send each other on the
//! `Channel::Control` stream (see `crypto.rs`) - as opposed to the actual
//! chat payloads, which travel on `Channel::Data` and are treated as opaque
//! bytes by this crate (we don't need to understand *what* the application
//! is saying to reliably deliver it).
//!
//! Every control message is encrypted just like a data message before it
//! goes on the wire; what's defined here is only the *plaintext* layout,
//! i.e. what you get after `crypto::decrypt` succeeds.

use crate::error::{ChatError, Result};

/// The different kinds of control message, distinguished by their first
/// plaintext byte.
#[derive(Debug, PartialEq, Eq)]
pub enum ControlMessage {
    /// "Here's what I've received from you so far." Sent after processing
    /// every incoming data message, so the sender always has an up to date
    /// picture of what still needs resending.
    Ack {
        /// Highest sequence number received with no gaps before it.
        cumulative_ack: u64,
        /// Specific higher sequence numbers that are still missing (holes
        /// caused by reordering or a dropped connection).
        missing: Vec<u64>,
    },
    /// "This is a fresh connection (or a reconnect) - please resend
    /// anything you sent me after this sequence number that I might have
    /// missed." Sent once, immediately after a handshake completes.
    ResumeRequest {
        /// The highest sequence number we had already fully received before
        /// this connection was established (0 if none yet).
        last_contiguous_seq: u64,
    },
    /// Keepalive probe: "are you still there?" The peer answers with a
    /// [`ControlMessage::Pong`] carrying the same `nonce`. Like every
    /// control message it is encrypted and authenticated, so an attacker
    /// cannot forge liveness for a dead peer.
    Ping { nonce: u64 },
    /// Reply to a [`ControlMessage::Ping`]; also yields a round-trip time.
    Pong { nonce: u64 },
}

const TAG_ACK: u8 = 0x01;
const TAG_RESUME_REQUEST: u8 = 0x02;
const TAG_PING: u8 = 0x03;
const TAG_PONG: u8 = 0x04;

impl ControlMessage {
    /// Serialize to the plaintext bytes that get encrypted and sent.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            ControlMessage::Ack {
                cumulative_ack,
                missing,
            } => {
                let mut out = Vec::with_capacity(1 + 8 + 2 + missing.len() * 8);
                out.push(TAG_ACK);
                out.extend_from_slice(&cumulative_ack.to_be_bytes());
                out.extend_from_slice(&(missing.len() as u16).to_be_bytes());
                for seq in missing {
                    out.extend_from_slice(&seq.to_be_bytes());
                }
                out
            }
            ControlMessage::ResumeRequest {
                last_contiguous_seq,
            } => {
                let mut out = Vec::with_capacity(9);
                out.push(TAG_RESUME_REQUEST);
                out.extend_from_slice(&last_contiguous_seq.to_be_bytes());
                out
            }
            ControlMessage::Ping { nonce } => {
                let mut out = vec![TAG_PING];
                out.extend_from_slice(&nonce.to_be_bytes());
                out
            }
            ControlMessage::Pong { nonce } => {
                let mut out = vec![TAG_PONG];
                out.extend_from_slice(&nonce.to_be_bytes());
                out
            }
        }
    }

    /// Parse plaintext bytes back into a [`ControlMessage`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (&tag, rest) = bytes
            .split_first()
            .ok_or(ChatError::MalformedMessage("empty control message"))?;
        match tag {
            TAG_ACK => {
                if rest.len() < 10 {
                    return Err(ChatError::MalformedMessage("ack too short"));
                }
                let cumulative_ack = u64::from_be_bytes(rest[0..8].try_into().unwrap());
                let count = u16::from_be_bytes(rest[8..10].try_into().unwrap()) as usize;
                let expected_len = 10 + count * 8;
                if rest.len() != expected_len {
                    return Err(ChatError::MalformedMessage(
                        "ack missing-list length mismatch",
                    ));
                }
                let mut missing = Vec::with_capacity(count);
                for chunk in rest[10..].chunks_exact(8) {
                    missing.push(u64::from_be_bytes(chunk.try_into().unwrap()));
                }
                Ok(ControlMessage::Ack {
                    cumulative_ack,
                    missing,
                })
            }
            TAG_RESUME_REQUEST => {
                if rest.len() != 8 {
                    return Err(ChatError::MalformedMessage("resume request wrong length"));
                }
                let last_contiguous_seq = u64::from_be_bytes(rest.try_into().unwrap());
                Ok(ControlMessage::ResumeRequest {
                    last_contiguous_seq,
                })
            }
            TAG_PING | TAG_PONG => {
                if rest.len() != 8 {
                    return Err(ChatError::MalformedMessage("ping/pong wrong length"));
                }
                let nonce = u64::from_be_bytes(rest.try_into().unwrap());
                Ok(if tag == TAG_PING {
                    ControlMessage::Ping { nonce }
                } else {
                    ControlMessage::Pong { nonce }
                })
            }
            _ => Err(ChatError::MalformedMessage("unknown control message tag")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_round_trips() {
        let msg = ControlMessage::Ack {
            cumulative_ack: 5,
            missing: vec![7, 9],
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn ack_with_no_missing_round_trips() {
        let msg = ControlMessage::Ack {
            cumulative_ack: 42,
            missing: vec![],
        };
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn resume_request_round_trips() {
        let msg = ControlMessage::ResumeRequest {
            last_contiguous_seq: 100,
        };
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn ping_and_pong_round_trip_and_reject_bad_lengths() {
        for msg in [
            ControlMessage::Ping { nonce: 7 },
            ControlMessage::Pong { nonce: u64::MAX },
        ] {
            assert_eq!(ControlMessage::decode(&msg.encode()).unwrap(), msg);
        }
        assert!(ControlMessage::decode(&[TAG_PING, 1, 2]).is_err());
        assert!(ControlMessage::decode(&[TAG_PONG]).is_err());
    }

    #[test]
    fn rejects_truncated_ack() {
        let mut bytes = ControlMessage::Ack {
            cumulative_ack: 1,
            missing: vec![2],
        }
        .encode();
        bytes.truncate(bytes.len() - 1);
        assert!(ControlMessage::decode(&bytes).is_err());
    }
}
