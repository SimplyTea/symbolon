//! Guaranteed, gap-free, in-order delivery on top of an unreliable
//! transport (TCP gives us in-order-per-connection delivery, but a
//! disconnect/reconnect resets that guarantee, and we want to survive
//! exactly that).
//!
//! # The guarantee we're building
//!
//! "If a peer disconnects and reconnects, they will not be missing any
//! message that was sent to them before the disconnect, and they won't
//! silently process messages out of order."
//!
//! We get this with three pieces, mirroring TCP's own design but scoped to
//! whole application messages instead of bytes:
//!
//! 1. **Sequence numbers.** Every data message a peer sends is tagged with
//!    a strictly increasing `u64`, starting at 1 (0 is reserved to mean
//!    "nothing acknowledged yet").
//! 2. **An outbox.** The sender keeps every message it has sent, keyed by
//!    sequence number, until the receiver confirms it arrived. If the
//!    connection drops before that confirmation arrives, the message is
//!    still sitting in the outbox and gets resent once a new connection
//!    (and successful mutual-authentication handshake) is established.
//! 3. **Acknowledgements with gap reporting.** The receiver doesn't just say
//!    "I've got everything up to N" (cumulative ack) - it also reports any
//!    *specific* higher sequence numbers it has already received out of
//!    order, so the sender knows precisely which single messages are
//!    missing and only needs to resend those, not the whole backlog.
//!
//! The receiver also buffers out-of-order messages and only ever hands
//! messages to the application in strict sequence order, so "missing
//! previous information" can never silently happen even under packet
//! reordering within a single connection.

use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Tracks messages *we* have sent that might still need to be resent.
#[derive(Default)]
pub struct Outbox {
    /// The sequence number that will be assigned to the *next* message we
    /// stage. Starts at 1.
    next_seq: u64,
    /// Every message we've sent that hasn't yet been cumulatively
    /// acknowledged, keyed by its sequence number. This module doesn't care
    /// whether the stored bytes are plaintext or ciphertext - `session.rs`
    /// stores plaintext here and re-encrypts fresh (under whatever the
    /// *current* session key is) every time a message is (re)sent, which is
    /// what lets old messages still be resent correctly after a reconnect
    /// establishes a brand new session key.
    unacked: BTreeMap<u64, Vec<u8>>,
}

impl Outbox {
    pub fn new() -> Self {
        Outbox {
            next_seq: 1,
            unacked: BTreeMap::new(),
        }
    }

    /// Record a newly-sent message and return the sequence number assigned
    /// to it. Call this once, right before writing `wire_bytes` to the
    /// socket, so that even if the write itself fails partway through we
    /// still know we *tried* to send it and will retry after reconnecting.
    pub fn stage(&mut self, wire_bytes: Vec<u8>) -> u64 {
        let seq = self.reserve_seq();
        self.store(seq, wire_bytes);
        seq
    }

    /// Reserve the next sequence number without storing anything yet.
    /// Useful when the caller needs the sequence number *before* it can
    /// produce the final bytes to store (e.g. because the sequence number
    /// itself is mixed into the encryption nonce - see `session.rs`).
    pub fn reserve_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    /// Store the bytes for a previously-reserved sequence number.
    pub fn store(&mut self, seq: u64, bytes: Vec<u8>) {
        self.unacked.insert(seq, bytes);
    }

    /// Process an incoming acknowledgement: drop every message with
    /// `seq <= cumulative_ack` from the outbox (the peer has confirmed
    /// receiving all of them, in order), except we never drop anything the
    /// peer explicitly lists as still missing (defensive - a correct peer
    /// won't do this, but we don't want a buggy/malicious ack to make us
    /// throw away data it hasn't actually got).
    pub fn apply_ack(&mut self, cumulative_ack: u64, missing: &[u64]) {
        let missing_set: BTreeSet<u64> = missing.iter().copied().collect();
        self.unacked
            .retain(|&seq, _| seq > cumulative_ack || missing_set.contains(&seq));
    }

    /// Wire bytes for every message the peer has told us (via `missing`)
    /// that it still hasn't received - these should be resent immediately.
    pub fn messages_to_resend(&self, missing: &[u64]) -> Vec<(u64, Vec<u8>)> {
        missing
            .iter()
            .filter_map(|seq| self.unacked.get(seq).map(|bytes| (*seq, bytes.clone())))
            .collect()
    }

    /// All still-unacknowledged messages with `seq > since`, in order. Used
    /// right after a fresh handshake to replay everything the other side
    /// might have missed while we were disconnected.
    pub fn messages_after(&self, since: u64) -> Vec<(u64, Vec<u8>)> {
        self.unacked
            .range((std::ops::Bound::Excluded(since), std::ops::Bound::Unbounded))
            .map(|(seq, bytes)| (*seq, bytes.clone()))
            .collect()
    }

    /// Undo [`Outbox::reserve_seq`] + [`Outbox::store`] for `seq`, which
    /// must be the most recently reserved number. Used when persisting the
    /// new state failed and the send is being abandoned.
    /// The highest sequence number handed out so far (0 if none yet).
    /// A session records this when a connection begins, so a resume
    /// request only replays messages that existed BEFORE the link was
    /// up: anything stored afterwards is written by `send()` itself.
    pub fn highest_seq(&self) -> u64 {
        self.next_seq - 1
    }

    pub fn rollback(&mut self, seq: u64) {
        self.unacked.remove(&seq);
        if self.next_seq == seq + 1 {
            self.next_seq = seq;
        }
    }

    /// Serialize (for the session state file). Stored blobs are already
    /// ratchet ciphertext.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.next_seq.to_be_bytes());
        out.extend_from_slice(&(self.unacked.len() as u32).to_be_bytes());
        for (seq, blob) in &self.unacked {
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            out.extend_from_slice(blob);
        }
        out
    }

    pub(crate) fn from_bytes(b: &[u8]) -> Option<Outbox> {
        let mut c = Cursor(b);
        let next_seq = c.u64()?;
        let n = c.u32()?;
        let mut unacked = BTreeMap::new();
        for _ in 0..n {
            let seq = c.u64()?;
            let len = c.u32()? as usize;
            unacked.insert(seq, c.take(len)?.to_vec());
        }
        (c.0.is_empty() && next_seq >= 1).then_some(Outbox { next_seq, unacked })
    }

    /// How many messages are still awaiting acknowledgement. Exposed for
    /// tests / observability.
    pub fn pending_count(&self) -> usize {
        self.unacked.len()
    }
}

/// Bounds-checked reader for the state encodings below. Every method
/// returns `None` instead of panicking on short input.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Some(h)
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
}

/// Tracks messages *we* have received, detects gaps, and only releases
/// messages to the application in strict sequence order.
#[derive(Default)]
pub struct Inbox {
    /// The next sequence number we expect to deliver in order. Everything
    /// below this has already been delivered to the application exactly
    /// once. Starts at 1.
    expected_next: u64,
    /// Payloads we've received that arrived ahead of `expected_next` (i.e.
    /// out of order) and are being held until the gap in front of them
    /// closes.
    buffered: HashMap<u64, Vec<u8>>,
}

impl Inbox {
    pub fn new() -> Self {
        Inbox {
            expected_next: 1,
            buffered: HashMap::new(),
        }
    }

    /// Record an incoming message. Returns the list of payloads (in order)
    /// that can now be delivered to the application - this may be empty (if
    /// `seq` was ahead of what we're waiting for, or a duplicate), exactly
    /// one (the common case), or several at once (if this message fills a
    /// gap that unblocks a run of already-buffered messages).
    pub fn receive(&mut self, seq: u64, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if seq < self.expected_next {
            // Old duplicate (e.g. a resend that we'd already processed
            // before a connection drop). Already delivered - ignore.
            return Vec::new();
        }
        if seq == self.expected_next {
            let mut deliverable = vec![payload];
            self.expected_next += 1;
            // Drain any subsequent messages that were already buffered and
            // are now contiguous.
            while let Some(next) = self.buffered.remove(&self.expected_next) {
                deliverable.push(next);
                self.expected_next += 1;
            }
            deliverable
        } else {
            // Out of order / ahead of what we need - hold onto it. If we've
            // already seen this exact seq before it's a harmless duplicate
            // overwrite.
            self.buffered.insert(seq, payload);
            Vec::new()
        }
    }

    /// Serialize (for the session state file).
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.expected_next.to_be_bytes());
        let mut keys: Vec<_> = self.buffered.keys().copied().collect();
        keys.sort_unstable();
        out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
        for k in keys {
            let blob = &self.buffered[&k];
            out.extend_from_slice(&k.to_be_bytes());
            out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            out.extend_from_slice(blob);
        }
        out
    }

    pub(crate) fn from_bytes(b: &[u8]) -> Option<Inbox> {
        let mut c = Cursor(b);
        let expected_next = c.u64()?;
        let n = c.u32()?;
        let mut buffered = HashMap::new();
        for _ in 0..n {
            let seq = c.u64()?;
            let len = c.u32()? as usize;
            buffered.insert(seq, c.take(len)?.to_vec());
        }
        (c.0.is_empty() && expected_next >= 1).then_some(Inbox {
            expected_next,
            buffered,
        })
    }

    /// The highest sequence number that has been fully, contiguously
    /// delivered - i.e. what we should put in the "cumulative_ack" field of
    /// our next ack. `0` means nothing has been delivered yet.
    pub fn cumulative_ack(&self) -> u64 {
        self.expected_next - 1
    }

    /// Sequence numbers strictly greater than `cumulative_ack()` that we
    /// have *not* received yet, but that must exist because we've already
    /// received something with a higher sequence number. These are exactly
    /// the "holes" the sender should retransmit.
    pub fn missing_seqs(&self) -> Vec<u64> {
        if self.buffered.is_empty() {
            return Vec::new();
        }
        let highest_seen = *self.buffered.keys().max().unwrap();
        (self.expected_next..highest_seen)
            .filter(|seq| !self.buffered.contains_key(seq))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbox_assigns_increasing_sequence_numbers() {
        let mut outbox = Outbox::new();
        assert_eq!(outbox.stage(vec![1]), 1);
        assert_eq!(outbox.stage(vec![2]), 2);
        assert_eq!(outbox.stage(vec![3]), 3);
        assert_eq!(outbox.pending_count(), 3);
    }

    #[test]
    fn outbox_drops_acked_messages() {
        let mut outbox = Outbox::new();
        outbox.stage(vec![1]);
        outbox.stage(vec![2]);
        outbox.stage(vec![3]);
        outbox.apply_ack(2, &[]);
        assert_eq!(outbox.pending_count(), 1); // only seq 3 remains
        assert_eq!(outbox.messages_after(0).len(), 1);
    }

    #[test]
    fn outbox_keeps_explicitly_missing_messages_even_below_cumulative_ack() {
        // Defensive case: shouldn't happen with a correct peer, but a
        // cumulative ack should never cause us to discard something the
        // peer says it's still missing.
        let mut outbox = Outbox::new();
        outbox.stage(vec![1]);
        outbox.stage(vec![2]);
        outbox.apply_ack(2, &[2]);
        assert_eq!(outbox.pending_count(), 1);
    }

    #[test]
    fn inbox_delivers_in_order_messages_immediately() {
        let mut inbox = Inbox::new();
        assert_eq!(inbox.receive(1, vec![1]), vec![vec![1]]);
        assert_eq!(inbox.receive(2, vec![2]), vec![vec![2]]);
        assert_eq!(inbox.cumulative_ack(), 2);
        assert!(inbox.missing_seqs().is_empty());
    }

    #[test]
    fn inbox_buffers_out_of_order_and_drains_on_gap_fill() {
        let mut inbox = Inbox::new();
        // seq 3 arrives before seq 2 (network reordering).
        assert_eq!(inbox.receive(3, vec![3]), Vec::<Vec<u8>>::new());
        assert_eq!(inbox.cumulative_ack(), 0); // nothing delivered yet
        assert_eq!(inbox.missing_seqs(), vec![1, 2]);

        // seq 1 arrives.
        assert_eq!(inbox.receive(1, vec![1]), vec![vec![1]]);
        assert_eq!(inbox.missing_seqs(), vec![2]);

        // seq 2 arrives - this should unblock 2 *and* the buffered 3.
        let delivered = inbox.receive(2, vec![2]);
        assert_eq!(delivered, vec![vec![2], vec![3]]);
        assert_eq!(inbox.cumulative_ack(), 3);
        assert!(inbox.missing_seqs().is_empty());
    }

    #[test]
    fn inbox_ignores_duplicate_old_messages() {
        let mut inbox = Inbox::new();
        inbox.receive(1, vec![1]);
        // A resend of seq 1 (e.g. peer didn't see our ack before reconnect).
        assert_eq!(inbox.receive(1, vec![1]), Vec::<Vec<u8>>::new());
        assert_eq!(inbox.cumulative_ack(), 1);
    }

    #[test]
    fn full_reconnect_scenario_no_message_is_lost() {
        // Simulates: sender sends 1,2,3; only 1 and 3 make it across before
        // a disconnect (2 is lost in flight); on reconnect the sender
        // replays everything the receiver's ack says is still missing.
        let mut outbox = Outbox::new();
        let mut inbox = Inbox::new();

        let w1 = outbox.stage(b"one".to_vec());
        let _w2 = outbox.stage(b"two".to_vec());
        let w3 = outbox.stage(b"three".to_vec());

        // Only messages 1 and 3 arrive before the "disconnect".
        let d1 = inbox.receive(w1, b"one".to_vec());
        let d3 = inbox.receive(w3, b"three".to_vec());
        assert_eq!(d1, vec![b"one".to_vec()]);
        assert!(d3.is_empty()); // buffered, waiting on 2

        // Receiver's ack after "reconnect": cumulative=1, missing=[2].
        let cum = inbox.cumulative_ack();
        let missing = inbox.missing_seqs();
        assert_eq!(cum, 1);
        assert_eq!(missing, vec![2]);

        // Sender resends exactly what's missing.
        let resend = outbox.messages_to_resend(&missing);
        assert_eq!(resend.len(), 1);
        assert_eq!(resend[0].0, 2);

        // Receiver processes the resent message 2 - this should also
        // release the buffered message 3.
        let delivered = inbox.receive(resend[0].0, resend[0].1.clone());
        assert_eq!(delivered, vec![b"two".to_vec(), b"three".to_vec()]);
        assert_eq!(inbox.cumulative_ack(), 3);
    }
}
