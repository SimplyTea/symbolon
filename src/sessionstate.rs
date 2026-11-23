//! Saving a session's state so an APP RESTART resumes it instead of
//! starting over.
//!
//! # What is saved
//! Everything that makes a session "the same conversation": the Double
//! Ratchet (secret keys!), the outbox (messages not yet acknowledged), the
//! inbox (ordering state), our session epoch, the peer's epoch, and a queue
//! of messages that were decrypted but not yet handed to the application.
//! The file is encrypted with a key derived from our identity, so it is
//! only as exposed as the identity file itself. Transport keys are NOT
//! saved: every connection runs a fresh handshake, so forward secrecy per
//! connection is unchanged.
//!
//! # The one rule that makes this safe: save BEFORE you act
//! A ratchet message key must never encrypt two different messages. If we
//! sent message N, crashed, and came back from a snapshot taken BEFORE N,
//! we would encrypt a different message N under the same key. So:
//!   * `send`: state (including the new ciphertext) is written before the
//!     bytes go on the wire. If the write fails the send is rolled back and
//!     reports an error; nothing was sent.
//!   * receive: after decrypting, state is written BEFORE the peer is told
//!     "got it" (the ack lets the peer delete its copy). A crash cannot lose
//!     a message the peer already forgot.
//!
//! # Delivery guarantee
//! AT LEAST ONCE across a crash. A message returned by `recv()` is removed
//! from the saved queue right afterwards; a crash between those two points
//! delivers it again on restart. Applications that cannot tolerate a
//! duplicate must de-duplicate (the group layer does, by author sequence).
//!
//! # Cost
//! Every send and receive rewrites the whole (small) state file atomically.
//! That is simple and crash-safe; an append-only journal is the optimization
//! if outboxes get large.
//!
//! # Resuming
//! Both sides keep the same session epoch (see
//! [`crate::session::Session`]) across restarts, so the peer's reconnect
//! logic sees "same session" and resumes. To resume as the INITIATOR set
//! [`crate::session::SessionConfig::expect_peer`] (we must know who we
//! are dialing to pick the right saved state); the responder learns who is
//! calling during the handshake and picks the state then. If the peer lost
//! its own state (a different epoch), our saved state is discarded and a
//! fresh session starts, exactly like [`crate::session::Reconnected::Replaced`].

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::AeadKey;
use crate::error::{ChatError, Result};
use crate::identity::{Identity, PeerId};
use crate::ratchet::Ratchet;
use crate::reliability::{Inbox, Outbox};
use crate::storage::{open, seal, StateStore};

const MAGIC: &[u8; 4] = b"SYMS";
const FORMAT: u8 = 2; // 2: the peer id is 32 raw bytes (was a length-prefixed hex string)
/// Sanity cap on queued-undelivered messages in a state file.
const MAX_PENDING: usize = 100_000;

/// Where and how session states are stored. One per application; share it
/// through [`crate::session::SessionConfig::persistence`].
pub struct SessionPersistence {
    store: Arc<dyn StateStore>,
    key: AeadKey,
}

/// Which session currently OWNS each saved-state slot, process-wide, keyed by
/// (the store object, peer). A newer session (restored or fresh) takes
/// ownership; older ones are then refused further saves
/// ([`ChatError::SessionSuperseded`]), because two live sessions sharing one
/// slot would fork the ratchet and reuse message keys. Keyed by the store
/// object (not by [`SessionPersistence`]) so two `SessionPersistence` values
/// built over clones of the same `Arc` store still share one ownership
/// table. Two separately-opened stores that point at the same directory
/// are NOT detected: open the store once and share it.
static OWNERS: Mutex<Option<std::collections::HashMap<(usize, PeerId), u64>>> = Mutex::new(None);

impl fmt::Debug for SessionPersistence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionPersistence(..)")
    }
}

impl SessionPersistence {
    /// Persist session states into `store`, encrypted under a key derived
    /// from `identity`.
    pub fn new(store: Arc<dyn StateStore>, identity: &Identity) -> Arc<Self> {
        let hk = Hkdf::<Sha256>::new(None, &identity.secret_bytes());
        let mut k = [0u8; 32];
        hk.expand(b"symbolon/session-state/key/v1", &mut k)
            .expect("32 bytes is a valid HKDF output length");
        Arc::new(SessionPersistence {
            store,
            key: AeadKey(k),
        })
    }

    /// A new session takes over the state for `peer`; returns its ticket.
    fn claim(&self, peer: &PeerId) -> u64 {
        let mut guard = OWNERS.lock().unwrap();
        let g = guard
            .get_or_insert_with(Default::default)
            .entry((self.store_id(), *peer))
            .or_insert(0);
        *g += 1;
        *g
    }

    fn is_owner(&self, peer: &PeerId, ticket: u64) -> bool {
        OWNERS
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|m| m.get(&(self.store_id(), *peer)))
            == Some(&ticket)
    }

    fn store_id(&self) -> usize {
        Arc::as_ptr(&self.store) as *const () as usize
    }

    fn name(peer: &PeerId) -> String {
        format!("session-{peer}")
    }

    /// Our epoch for this peer's saved session, if there is a readable one.
    pub(crate) fn saved_epoch(&self, peer: &PeerId) -> Option<[u8; 16]> {
        self.load(peer).ok().flatten().map(|s| s.own_epoch)
    }

    /// Load and fully validate the saved state for `peer`.
    /// `Ok(None)`: nothing saved. `Err`: present but unreadable (wrong key,
    /// corruption, tampering).
    pub(crate) fn load(&self, peer: &PeerId) -> Result<Option<SavedState>> {
        let Some(blob) = self.store.get(&Self::name(peer))? else {
            return Ok(None);
        };
        let plain = open(&self.key, &blob)?;
        let st = SavedState::decode(&plain)?;
        if st.peer_id != *peer {
            // A file copied between peers' slots must not be believed.
            return Err(ChatError::MalformedMessage(
                "saved session belongs to another peer",
            ));
        }
        Ok(Some(st))
    }

    pub(crate) fn discard(&self, peer: &PeerId) {
        let _ = self.store.delete(&Self::name(peer));
    }

    fn write(&self, peer: &PeerId, plain: &[u8]) -> Result<()> {
        self.store.put(&Self::name(peer), &seal(&self.key, plain)?)
    }
}

/// A decoded state file.
pub(crate) struct SavedState {
    pub peer_id: PeerId,
    pub own_epoch: [u8; 16],
    pub peer_epoch: [u8; 16],
    pub ratchet: Ratchet,
    pub outbox: Outbox,
    pub inbox: Inbox,
    pub pending: Vec<Vec<u8>>,
}

fn put_blob(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

impl SavedState {
    fn decode(b: &[u8]) -> Result<SavedState> {
        const BAD: ChatError = ChatError::MalformedMessage("bad saved session state");
        struct C<'a>(&'a [u8]);
        impl<'a> C<'a> {
            fn take(&mut self, n: usize) -> Result<&'a [u8]> {
                if self.0.len() < n {
                    return Err(BAD);
                }
                let (h, t) = self.0.split_at(n);
                self.0 = t;
                Ok(h)
            }
            fn u32(&mut self) -> Result<u32> {
                Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
            }
            fn blob(&mut self) -> Result<&'a [u8]> {
                let n = self.u32()? as usize;
                self.take(n)
            }
        }
        let mut c = C(b);
        if c.take(4)? != MAGIC || c.take(1)?[0] != FORMAT {
            return Err(BAD);
        }
        let peer_id = PeerId::from_bytes(c.take(32)?.try_into().unwrap());
        let own_epoch: [u8; 16] = c.take(16)?.try_into().unwrap();
        let peer_epoch: [u8; 16] = c.take(16)?.try_into().unwrap();
        let ratchet = Ratchet::from_bytes(c.blob()?)?;
        let outbox = Outbox::from_bytes(c.blob()?).ok_or(BAD)?;
        let inbox = Inbox::from_bytes(c.blob()?).ok_or(BAD)?;
        let n = c.u32()? as usize;
        if n > MAX_PENDING {
            return Err(BAD);
        }
        let mut pending = Vec::new();
        for _ in 0..n {
            pending.push(c.blob()?.to_vec());
        }
        if !c.0.is_empty() {
            return Err(BAD);
        }
        Ok(SavedState {
            peer_id,
            own_epoch,
            peer_epoch,
            ratchet,
            outbox,
            inbox,
            pending,
        })
    }
}

/// Owned by one live session: knows how to snapshot it.
///
/// LOCKING: take `commit` first if you intend to save; then you may lock
/// `ratchet`, `outbox`, `inbox`, `pending` in that order. `commit` makes
/// "receive + decrypt + queue" and "snapshot" atomic with respect to each
/// other, so a snapshot can never see an inbox that has advanced past a
/// ratchet that has not yet decrypted those messages.
pub(crate) struct StateSaver {
    persistence: Arc<SessionPersistence>,
    peer_id: PeerId,
    own_epoch: [u8; 16],
    peer_epoch: [u8; 16],
    pub ratchet: Arc<Mutex<Ratchet>>,
    pub outbox: Arc<Mutex<Outbox>>,
    pub inbox: Arc<Mutex<Inbox>>,
    /// Decrypted messages not yet returned by `recv()` (oldest first).
    pub pending: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pub commit: Mutex<()>,
    failed: AtomicBool,
    ticket: u64,
}

impl StateSaver {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        persistence: Arc<SessionPersistence>,
        peer_id: PeerId,
        own_epoch: [u8; 16],
        peer_epoch: [u8; 16],
        ratchet: Arc<Mutex<Ratchet>>,
        outbox: Arc<Mutex<Outbox>>,
        inbox: Arc<Mutex<Inbox>>,
        pending: Arc<Mutex<VecDeque<Vec<u8>>>>,
    ) -> Arc<Self> {
        let ticket = persistence.claim(&peer_id);
        Arc::new(StateSaver {
            ticket,
            persistence,
            peer_id,
            own_epoch,
            peer_epoch,
            ratchet,
            outbox,
            inbox,
            pending,
            commit: Mutex::new(()),
            failed: AtomicBool::new(false),
        })
    }

    /// True once any save has failed (and until one succeeds again).
    pub fn failing(&self) -> bool {
        self.failed.load(Ordering::SeqCst)
    }

    /// Snapshot given the ratchet and outbox guards the caller already holds.
    pub fn save_locked(&self, r: &Ratchet, ob: &Outbox) -> Result<()> {
        if !self.persistence.is_owner(&self.peer_id, self.ticket) {
            return Err(ChatError::SessionSuperseded);
        }
        let ib = self.inbox.lock().unwrap();
        let pend = self.pending.lock().unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(FORMAT);
        out.extend_from_slice(self.peer_id.as_bytes());
        out.extend_from_slice(&self.own_epoch);
        out.extend_from_slice(&self.peer_epoch);
        put_blob(&mut out, &r.to_bytes());
        put_blob(&mut out, &ob.to_bytes());
        put_blob(&mut out, &ib.to_bytes());
        out.extend_from_slice(&(pend.len() as u32).to_be_bytes());
        for m in pend.iter() {
            put_blob(&mut out, m);
        }
        let res = self.persistence.write(&self.peer_id, &out);
        self.failed.store(res.is_err(), Ordering::SeqCst);
        res
    }

    /// Snapshot, taking the ratchet and outbox locks ourselves.
    pub fn save(&self) -> Result<()> {
        let r = self.ratchet.lock().unwrap();
        let ob = self.outbox.lock().unwrap();
        self.save_locked(&r, &ob)
    }
}
