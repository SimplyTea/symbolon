//! Error types for the secure P2P messaging library.
//!
//! Every fallible operation in this crate returns a [`ChatError`] so callers
//! get a single, well-documented type to match on instead of a grab-bag of
//! crate-specific error types leaking out of our public API.

use std::fmt;

/// All the things that can go wrong while running the secure chat protocol.
#[derive(Debug)]
pub enum ChatError {
    /// A message arrived that could not be decrypted / authenticated.
    /// This is the AEAD "the ciphertext or tag didn't match" case. It fires
    /// on bit-flip corruption *and* on active tampering attempts, since an
    /// AEAD cannot (and must not) tell those two apart.
    DecryptionFailed,

    /// A peer's handshake signature did not verify against the public key we
    /// have pinned for them. This means either the peer does not actually
    /// hold the private key we expect (impersonation attempt / MITM), or the
    /// handshake transcript was tampered with in transit.
    HandshakeAuthenticationFailed,

    /// We received a well-formed handshake message from an identity key we
    /// don't have pinned in our [`crate::peer::PeerRegistry`]. We refuse to
    /// blindly trust unknown keys (no Trust-On-First-Use by default).
    UnknownPeer,

    /// The peer's declared identity public key or ephemeral public key was
    /// not a valid point on the curve.
    InvalidPublicKey,

    /// A frame on the wire violated the length-prefixed framing protocol
    /// (e.g. claimed a size larger than our sanity limit, so we don't let a
    /// malicious peer force us to allocate unbounded memory).
    FrameTooLarge,

    /// The connection was closed (cleanly or otherwise) while we still
    /// expected more bytes.
    ConnectionClosed,

    /// Wraps a lower-level I/O error (socket errors, etc).
    Io(std::io::Error),

    /// A message body could not be parsed according to our wire format.
    MalformedMessage(&'static str),

    /// The protocol / handshake version the peer sent isn't one we support.
    UnsupportedVersion,
    /// The peer's build speaks a different major.minor (only the patch may
    /// differ). Carries both versions so the cause is obvious.
    VersionMismatch {
        ours: crate::handshake::Version,
        theirs: crate::handshake::Version,
    },

    /// A reconnect handshake authenticated a DIFFERENT peer than the one
    /// this session belongs to. The ratchet and outbox are specific to one
    /// peer, so the connection is refused.
    PeerMismatch,

    /// The peer reconnected with a different SESSION EPOCH: it has started
    /// a brand-new session (typically because its app restarted and lost the
    /// ratchet/outbox state), so this session can no longer be resumed. Use
    /// [`crate::session::Session::reconnect_or_replace`] to be handed a fresh
    /// session automatically.
    PeerRestarted,
    /// A newer session for the same peer took over this one's saved state,
    /// so this (older) session may no longer send: two sessions writing one
    /// state slot would reuse encryption keys. Use the newer session.
    SessionSuperseded,
    /// The handshake didn't complete within the configured timeout - either
    /// the peer is unreachable, unresponsive, or deliberately stalling
    /// (e.g. a slowloris-style resource-exhaustion attempt).
    HandshakeTimedOut,
    /// The action requires a tier permission (add/remove/read/write) that
    /// the acting member's current tier does not grant.
    PermissionDenied,

    // --- Group-chat specific errors ---
    /// A roster operation (Add/Remove) was signed by someone who is not a
    /// current member of the group - only current members may change
    /// membership.
    UnauthorizedRosterOp,
    /// A roster operation's `prev_hash` didn't match our current roster
    /// history tip - either it's stale (we've already moved past that
    /// point) or it's an attempt to fork the group's membership history.
    RosterHistoryMismatch,
    /// A roster operation's signature did not verify.
    RosterSignatureInvalid,
    /// An application message claimed to be from a sender who is not (or
    /// is no longer) a member of the group.
    SenderNotAMember,
    /// A sender's per-sender hash chain didn't continue correctly - either
    /// corruption, reordering, or (most importantly) a sign that the
    /// sender may have told different members different things
    /// (equivocation) and their two chains have diverged.
    SenderChainBroken,
    /// The Double Ratchet refused a message: malformed header, replayed or
    /// already-consumed message key, too many skipped messages, a degenerate
    /// (low-order) DH key, or an AEAD failure. The payload says which.
    Ratchet(&'static str),
}

impl fmt::Display for ChatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChatError::DecryptionFailed => {
                write!(
                    f,
                    "authenticated decryption failed (corrupt or tampered message)"
                )
            }
            ChatError::HandshakeAuthenticationFailed => {
                write!(
                    f,
                    "peer failed to prove ownership of their pinned identity key"
                )
            }
            ChatError::UnknownPeer => write!(f, "peer identity key is not in our trusted registry"),
            ChatError::InvalidPublicKey => write!(f, "peer sent an invalid public key"),
            ChatError::FrameTooLarge => {
                write!(f, "incoming frame exceeds the maximum allowed size")
            }
            ChatError::ConnectionClosed => write!(f, "connection closed unexpectedly"),
            ChatError::Io(e) => write!(f, "I/O error: {e}"),
            ChatError::MalformedMessage(reason) => write!(f, "malformed message: {reason}"),
            ChatError::UnsupportedVersion => write!(f, "unsupported protocol version"),
            ChatError::VersionMismatch { ours, theirs } => write!(
                f,
                "version mismatch: this build is {ours}, the peer is {theirs} (major.minor must match; patch may differ)"
            ),
            ChatError::PeerMismatch => write!(
                f,
                "reconnected to a different peer than this session belongs to"
            ),
            ChatError::PeerRestarted => write!(
                f,
                "peer restarted and lost its session state; a fresh session is required"
            ),
            ChatError::SessionSuperseded => write!(
                f,
                "a newer session for this peer took over the saved state; use that one"
            ),
            ChatError::HandshakeTimedOut => write!(
                f,
                "handshake did not complete within the configured timeout"
            ),
            ChatError::PermissionDenied => write!(
                f,
                "acting member's current tier does not grant the required permission"
            ),
            ChatError::UnauthorizedRosterOp => {
                write!(
                    f,
                    "roster operation was proposed by someone who is not a current group member"
                )
            }
            ChatError::RosterHistoryMismatch => {
                write!(f, "roster operation does not build on our current roster history (stale or forked)")
            }
            ChatError::RosterSignatureInvalid => {
                write!(f, "roster operation signature did not verify")
            }
            ChatError::SenderNotAMember => {
                write!(f, "message sender is not a current member of the group")
            }
            ChatError::Ratchet(why) => write!(f, "ratchet rejected message: {why}"),
            ChatError::SenderChainBroken => {
                write!(f, "sender's message hash chain is broken (reordering, corruption, or equivocation)")
            }
        }
    }
}

impl std::error::Error for ChatError {}

impl From<std::io::Error> for ChatError {
    fn from(e: std::io::Error) -> Self {
        ChatError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ChatError>;
