//! Observability hooks: WHAT the library is doing, without exposing secrets.
//!
//! The library never prints or logs on its own. Instead it reports
//! [`TraceEvent`]s to a [`Tracer`] you supply (via
//! [`crate::session::SessionConfig::tracer`] and
//! [`crate::group::GroupHubConfig::tracer`]). Route them to `println!`, the
//! `log`/`tracing` crates, a metrics counter, a UI "connection details"
//! panel, or a test assertion.
//!
//! # What events never contain
//! No keys, no plaintext, no ciphertext, no nonces, no signatures, no message
//! payloads. Only things that are already public to a network observer or
//! that you own: peer fingerprints, sequence numbers, counts, durations,
//! short static reason strings. This is a design rule, enforced by the
//! event types themselves (there is nowhere to put a secret). Adding a field
//! that could hold one is a review-blocking change.
//!
//! # Rules for implementors
//! * `event` is called synchronously on library threads (the reader, the
//!   keepalive, the group pump). Keep it fast and never block: a slow tracer
//!   slows the protocol. Hand off to a channel if you need to do real work.
//! * It must not panic. A panic on a library thread ends that thread.
//! * Events can be frequent (one per message, one per rejected frame). A
//!   remote attacker can make you emit `FrameRejected` as fast as they can
//!   send junk, so rate-limit or aggregate before writing to disk.

use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::identity::PeerId;

/// One thing that happened. See the module docs for what is excluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceEvent {
    // ---- session ----
    /// A handshake began. `role` is `"initiator"` or `"responder"`.
    HandshakeStarted {
        role: &'static str,
    },
    /// Handshake finished; `peer` is the authenticated fingerprint.
    HandshakeCompleted {
        peer: PeerId,
    },
    /// Handshake failed (untrusted key, bad signature, timeout, I/O...).
    /// `reason` is the error's display text (contains no secrets).
    HandshakeFailed {
        reason: String,
    },
    /// We accepted a message into the outbox and assigned it `seq`.
    MessageQueued {
        seq: u64,
    },
    /// An authenticated data frame with `seq` arrived.
    DataReceived {
        seq: u64,
    },
    /// A frame failed authentication or parsing and was dropped.
    FrameRejected,
    /// We re-sent `count` messages (after a peer ack gap or a resume).
    Retransmitted {
        count: usize,
    },
    PingSent {
        nonce: u64,
    },
    /// A ping was answered after `rtt`.
    PongReceived {
        rtt: Duration,
    },
    /// Nothing authenticated for `idle`: link declared dead and closed.
    LinkDead {
        idle: Duration,
    },
    /// The reader stopped because the connection ended.
    LinkClosed,
    /// A reconnect resumed the same session (nothing lost).
    ReconnectResumed,
    /// The peer had restarted; a brand-new session replaced the old one.
    ReconnectReplaced,

    // ---- group ----
    /// A roster operation was verified and applied; roster is now `version`.
    RosterApplied {
        version: u64,
    },
    /// A roster operation failed verification and was ignored.
    RosterRejected,
    /// A group message passed every check and was accepted.
    GroupMessageAccepted {
        author: PeerId,
        seq: u64,
    },
    /// A group message was dropped. `reason` is a short static string.
    GroupMessageRejected {
        author: PeerId,
        reason: &'static str,
    },
    /// A message claims a roster version we have not reached; parked.
    GroupMessageDeferred {
        author: PeerId,
    },
    /// A message's existence was recorded without its content.
    ExistenceRecorded {
        author: PeerId,
        seq: u64,
    },
    /// Content arrived for a message we had only a notice of.
    ContentFilled {
        author: PeerId,
        seq: u64,
    },
    /// A saved session was picked up again after a restart.
    SessionRestored {
        peer: PeerId,
    },
    /// Saved session state was thrown away (peer lost its state, or the file
    /// was unreadable).
    SessionStateDiscarded {
        peer: PeerId,
        reason: &'static str,
    },
    /// Writing to the event store failed (see `GroupHub::persistence_healthy`).
    PersistFailed,
}

/// Receiver of [`TraceEvent`]s. See the module docs for the rules.
pub trait Tracer: Send + Sync + Debug {
    fn event(&self, event: &TraceEvent);
}

/// Discards everything (the default). Costs one virtual call per event.
#[derive(Debug, Default)]
pub struct NoopTracer;

impl Tracer for NoopTracer {
    fn event(&self, _event: &TraceEvent) {}
}

/// Remembers every event in memory. Handy in tests; unbounded, so not for
/// long-running production use.
#[derive(Debug, Default)]
pub struct CollectingTracer {
    events: Mutex<Vec<TraceEvent>>,
}

impl CollectingTracer {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    /// Everything seen so far, oldest first.
    pub fn events(&self) -> Vec<TraceEvent> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    /// Does any event satisfy `pred`?
    pub fn any(&self, pred: impl Fn(&TraceEvent) -> bool) -> bool {
        self.events().iter().any(pred)
    }
}

impl Tracer for CollectingTracer {
    fn event(&self, event: &TraceEvent) {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(event.clone());
    }
}

/// Wrap a closure as a tracer: `FnTracer::new(|e| println!("{e:?}"))`.
pub struct FnTracer<F: Fn(&TraceEvent) + Send + Sync>(F);

impl<F: Fn(&TraceEvent) + Send + Sync> FnTracer<F> {
    pub fn new(f: F) -> Self {
        FnTracer(f)
    }
}

impl<F: Fn(&TraceEvent) + Send + Sync> Debug for FnTracer<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FnTracer")
    }
}

impl<F: Fn(&TraceEvent) + Send + Sync> Tracer for FnTracer<F> {
    fn event(&self, event: &TraceEvent) {
        (self.0)(event)
    }
}
