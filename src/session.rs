//! A `Session` is the main entry point applications use: it wraps a TCP
//! connection to one specific, mutually-authenticated peer, and provides a
//! simple `send` / `recv` API. Underneath, it wires together:
//!
//! - [`crate::handshake`] for mutual authentication + key exchange,
//! - [`crate::crypto`] for encrypting/decrypting every message,
//! - [`crate::reliability`] for gap-free ordered delivery across reconnects.
//!
//! # Concurrency model
//!
//! Deliberately simple / low-dependency: one background thread per session
//! reads and decrypts incoming frames (and reacts to control messages),
//! pushing decrypted, in-order application payloads into a channel that
//! [`Session::recv`] reads from. Sending happens directly on the caller's
//! thread. No async runtime, no thread pool - just `std::net` and
//! `std::thread`.
//!
//! # Surviving a disconnect
//!
//! A [`Session`] can be re-pointed at a brand new `TcpStream` via
//! [`Session::reconnect`] after the old connection dies. Doing this:
//!
//! 1. Re-runs the full mutual-authentication handshake on the new socket
//!    (fresh ephemeral keys - forward secrecy is preserved per-connection).
//! 2. Keeps the *same* [`crate::reliability::Outbox`] /
//!    [`crate::reliability::Inbox`], so sequence numbers and pending
//!    messages carry over unchanged.
//! 3. Immediately exchanges resume requests so each side replays anything
//!    the other might have missed while disconnected.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::crypto::{self, AeadKey, Channel};
use crate::error::{ChatError, Result};
use crate::framing::{read_frame, write_frame};
use crate::handshake::{self, HandshakeResult, ProgressCallback};
use crate::identity::{Identity, PeerId, PeerRegistry};
use crate::message::ControlMessage;
use crate::ratchet::{Ratchet, RatchetInfo};
use crate::reliability::{Inbox, Outbox};

/// Tunable knobs for a [`Session`]. All fields have sensible defaults via
/// [`SessionConfig::default`] - pass a customized one to
/// [`Session::establish_with`] / [`Session::reconnect_with`] to override
/// them (e.g. from UI-exposed settings).
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// How long to wait for the handshake to complete before giving up and
    /// returning [`ChatError::HandshakeTimedOut`]. `None` disables the
    /// timeout entirely (blocks forever - the old, less internet-safe
    /// default). A real deployment facing the open internet should always
    /// set this; a bounded default is used unless overridden.
    pub handshake_timeout: Option<Duration>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig { handshake_timeout: Some(Duration::from_secs(10)) }
    }
}

/// Which side of the TCP connection we are. Symmetric peers still need to
/// agree on this for the handshake's initiator/responder roles.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Initiator,
    Responder,
}

/// The live per-direction key material for the current physical connection.
/// Replaced wholesale on every reconnect (fresh ephemeral handshake).
struct SessionKeys {
    send_key: AeadKey,
    recv_key: AeadKey,
}

pub struct Session {
    /// Our own identity's fingerprint - stored so UIs can display "you" vs
    /// "peer" without holding onto the `Identity` themselves.
    own_id: PeerId,
    peer_id: Mutex<PeerId>,
    /// Protocol version negotiated during the most recent (re)connection.
    negotiated_version: Mutex<u16>,
    /// Hash of the most recent handshake transcript (see
    /// [`Session::session_id`]).
    transcript_hash: Mutex<[u8; 32]>,
    keys: Arc<Mutex<SessionKeys>>,
    write_stream: Arc<Mutex<TcpStream>>,
    /// A separate handle to the current socket purely so `reconnect` can
    /// call `shutdown()` on it to force the old background reader thread to
    /// wake up from its blocking read and exit before we start a new one.
    shutdown_handle: Mutex<Option<TcpStream>>,
    reader_thread: Mutex<Option<JoinHandle<()>>>,

    outbox: Arc<Mutex<Outbox>>,
    inbox: Arc<Mutex<Inbox>>,
    /// Double Ratchet state. Lives for the whole `Session`, *across*
    /// reconnects: the transport keys are replaced on every new TCP
    /// connection, but the message-level ratchet just keeps turning.
    /// Lock order when both are needed: ratchet, then outbox.
    ratchet: Arc<Mutex<Ratchet>>,
    /// Independent monotonic counter for the control channel (acks, resume
    /// requests), kept separate from the data channel's sequence numbers -
    /// see `crypto::Channel` docs for why that separation matters.
    control_seq: Arc<Mutex<u64>>,

    incoming_rx: Mutex<Receiver<Result<Vec<u8>>>>,
}

/// Build the associated data bound into every message's authentication tag:
/// the visible channel + sequence header. Tampering with either would then
/// be caught even though they're sent in the clear.
fn build_aad(channel: Channel, seq: u64) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[0] = channel as u8;
    aad[1..9].copy_from_slice(&seq.to_be_bytes());
    aad
}

/// Encode one wire frame body: `[channel:1][seq:8][ciphertext...]`.
fn encode_wire_message(key: &AeadKey, channel: Channel, seq: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    let aad = build_aad(channel, seq);
    let ciphertext = crypto::encrypt(key, channel, seq, &aad, plaintext)?;
    let mut out = Vec::with_capacity(9 + ciphertext.len());
    out.push(channel as u8);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decode `[channel:1][seq:8][ciphertext...]` and authenticate-decrypt it.
fn decode_wire_message(key: &AeadKey, frame: &[u8]) -> Result<(Channel, u64, Vec<u8>)> {
    if frame.len() < 9 {
        return Err(ChatError::MalformedMessage("frame shorter than header"));
    }
    let channel = match frame[0] {
        0 => Channel::Data,
        1 => Channel::Control,
        _ => return Err(ChatError::MalformedMessage("unknown channel byte")),
    };
    let seq = u64::from_be_bytes(frame[1..9].try_into().unwrap());
    let aad = build_aad(channel, seq);
    let plaintext = crypto::decrypt(key, channel, seq, &aad, &frame[9..])?;
    Ok((channel, seq, plaintext))
}

impl Session {
    /// Establish a brand new session using default [`SessionConfig`] and no
    /// progress reporting. See [`Session::establish_with`] for the fully
    /// configurable / observable version.
    pub fn establish(
        stream: TcpStream,
        role: Role,
        identity: &Identity,
        registry: &PeerRegistry,
    ) -> Result<Session> {
        Self::establish_with(stream, role, identity, registry, SessionConfig::default(), None)
    }

    /// Establish a brand new session by performing the mutual-authentication
    /// handshake over `stream` and starting the background receive loop.
    /// `role` must match how `stream` was obtained (the side that called
    /// `TcpStream::connect` is the [`Role::Initiator`]; the side that got
    /// the stream from `TcpListener::accept` is the [`Role::Responder`]).
    ///
    /// `on_progress`, if given, is called synchronously with each
    /// [`HandshakeProgress`] step as it happens - suitable for driving a
    /// UI's "connecting / verifying peer" indicator with the peer's actual
    /// fingerprint as soon as it's known, before the handshake even
    /// finishes.
    pub fn establish_with(
        mut stream: TcpStream,
        role: Role,
        identity: &Identity,
        registry: &PeerRegistry,
        config: SessionConfig,
        on_progress: Option<ProgressCallback<'_>>,
    ) -> Result<Session> {
        let handshake_result = run_handshake(&mut stream, role, identity, registry, config.handshake_timeout, on_progress)?;

        let (tx, rx) = mpsc::channel();
        let outbox = Arc::new(Mutex::new(Outbox::new()));
        let inbox = Arc::new(Mutex::new(Inbox::new()));
        let control_seq = Arc::new(Mutex::new(1u64));
        let ratchet = Arc::new(Mutex::new(Ratchet::from_seed(handshake_result.ratchet)?));
        let keys = Arc::new(Mutex::new(SessionKeys {
            send_key: handshake_result.send_key,
            recv_key: handshake_result.recv_key,
        }));

        let read_stream = stream.try_clone()?;
        let write_stream = Arc::new(Mutex::new(stream.try_clone()?));

        let session = Session {
            own_id: identity.fingerprint(),
            peer_id: Mutex::new(handshake_result.peer_id),
            negotiated_version: Mutex::new(handshake_result.negotiated_version),
            transcript_hash: Mutex::new(handshake_result.transcript_hash),
            keys,
            write_stream,
            shutdown_handle: Mutex::new(Some(stream.try_clone()?)),
            reader_thread: Mutex::new(None),
            outbox,
            inbox,
            ratchet,
            control_seq,
            incoming_rx: Mutex::new(rx),
        };

        session.spawn_reader(read_stream, tx);
        session.send_resume_request()?;
        Ok(session)
    }

    /// Re-establish this session on a brand new TCP connection after a
    /// disconnect, without losing any pending messages or sequence-number
    /// state, using default [`SessionConfig`] and no progress reporting.
    pub fn reconnect(&self, stream: TcpStream, role: Role, identity: &Identity, registry: &PeerRegistry) -> Result<()> {
        self.reconnect_with(stream, role, identity, registry, SessionConfig::default(), None)
    }

    /// Re-establish this session on a brand new TCP connection after a
    /// disconnect, without losing any pending messages or sequence-number
    /// state. Performs a fresh mutual-authentication handshake (so forward
    /// secrecy still holds per-connection), then asks the peer to replay
    /// anything sent while we were apart, and replays our own backlog too.
    pub fn reconnect_with(
        &self,
        mut stream: TcpStream,
        role: Role,
        identity: &Identity,
        registry: &PeerRegistry,
        config: SessionConfig,
        on_progress: Option<ProgressCallback<'_>>,
    ) -> Result<()> {
        // Stop the old reader thread cleanly before starting a new one, so
        // we never have two threads touching the inbox/outbox at once.
        if let Some(old) = self.shutdown_handle.lock().unwrap().take() {
            let _ = old.shutdown(std::net::Shutdown::Both);
        }
        if let Some(handle) = self.reader_thread.lock().unwrap().take() {
            let _ = handle.join();
        }

        let handshake_result = run_handshake(&mut stream, role, identity, registry, config.handshake_timeout, on_progress)?;

        *self.peer_id.lock().unwrap() = handshake_result.peer_id;
        *self.negotiated_version.lock().unwrap() = handshake_result.negotiated_version;
        *self.transcript_hash.lock().unwrap() = handshake_result.transcript_hash;
        *self.keys.lock().unwrap() = SessionKeys {
            send_key: handshake_result.send_key,
            recv_key: handshake_result.recv_key,
        };
        *self.write_stream.lock().unwrap() = stream.try_clone()?;
        *self.shutdown_handle.lock().unwrap() = Some(stream.try_clone()?);

        let read_stream = stream.try_clone()?;
        let (tx, rx) = mpsc::channel();
        // Any application payloads that were delivered-but-unread on the old
        // connection stay queued in the *old* channel and would be lost if
        // we just replaced it. In this crate `recv()` is expected to be
        // drained promptly, so we document this rather than engineering
        // around it: drain the old queue into the new one first.
        {
            let old_rx = self.incoming_rx.lock().unwrap();
            while let Ok(leftover) = old_rx.try_recv() {
                let _ = tx.send(leftover);
            }
        }
        *self.incoming_rx.lock().unwrap() = rx;

        self.spawn_reader(read_stream, tx);
        self.send_resume_request()?;
        Ok(())
    }

    /// Send an application payload. Returns the sequence number assigned to
    /// it. The message is durably staged in the outbox *before* it hits the
    /// socket, so even if the write fails (connection just died) it will
    /// automatically be retried the next time [`Session::reconnect`] runs.
    pub fn send(&self, payload: &[u8]) -> Result<u64> {
        // Ratchet-encrypt exactly once, under the ratchet lock so that ratchet
        // order always equals sequence order (the receiver's inbox delivers
        // in sequence order and the ratchet expects that). The outbox stores
        // the *ciphertext*: a retransmission must resend the identical blob,
        // because a ratchet message key can never be used twice.
        let (seq, blob) = {
            let mut r = self.ratchet.lock().unwrap();
            let mut ob = self.outbox.lock().unwrap();
            let seq = ob.reserve_seq();
            let blob = r.encrypt(payload)?;
            ob.store(seq, blob.clone());
            (seq, blob)
        };
        self.write_data_frame(seq, &blob)?;
        Ok(seq)
    }

    /// Block until the next application message - delivered strictly in
    /// order, with no gaps - is available.
    pub fn recv(&self) -> Result<Vec<u8>> {
        self.incoming_rx
            .lock()
            .unwrap()
            .recv()
            .map_err(|_| ChatError::ConnectionClosed)?
    }

    /// Non-blocking variant of [`Session::recv`], for tests / polling.
    pub fn try_recv(&self) -> Option<Vec<u8>> {
        self.incoming_rx.lock().unwrap().try_recv().ok().and_then(|r| r.ok())
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id.lock().unwrap().clone()
    }

    /// Our own identity's fingerprint - so a UI can show "you" alongside
    /// "peer" without needing to hold onto the `Identity` separately.
    pub fn own_id(&self) -> &PeerId {
        &self.own_id
    }

    /// The protocol version currently in use for this connection (see
    /// `handshake::negotiate_version`). Changes across a `reconnect` if the
    /// two sides end up negotiating differently (e.g. after an upgrade).
    pub fn negotiated_version(&self) -> u16 {
        *self.negotiated_version.lock().unwrap()
    }

    /// The hash of the handshake transcript for the current connection, as
    /// 64 lowercase hex characters. It covers both identities, both
    /// ephemeral keys and both protocol versions, so BOTH peers compute the
    /// identical value - read it aloud (or compare it in a UI) as an extra
    /// check that nobody is sitting in the middle of the connection. It is
    /// not secret, and it changes on every (re)connect.
    pub fn session_id(&self) -> String {
        self.transcript_hash.lock().unwrap().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Non-secret snapshot of the Double Ratchet's position (counters and
    /// our current public ratchet key) - for debug UIs and tests.
    pub fn ratchet_info(&self) -> RatchetInfo {
        self.ratchet.lock().unwrap().info()
    }

    /// Number of sent messages still awaiting acknowledgement. Exposed
    /// mainly for tests demonstrating the reliability guarantees.
    pub fn pending_unacked(&self) -> usize {
        self.outbox.lock().unwrap().pending_count()
    }

    // ---- internal helpers ----

    fn write_data_frame(&self, seq: u64, plaintext: &[u8]) -> Result<()> {
        let key = self.keys.lock().unwrap().send_key.clone();
        let wire = encode_wire_message(&key, Channel::Data, seq, plaintext)?;
        let mut w = self.write_stream.lock().unwrap();
        write_frame(&mut *w, &wire)
    }

    fn write_control_frame(&self, body: &[u8]) -> Result<()> {
        let seq = {
            let mut cs = self.control_seq.lock().unwrap();
            let s = *cs;
            *cs += 1;
            s
        };
        let key = self.keys.lock().unwrap().send_key.clone();
        let wire = encode_wire_message(&key, Channel::Control, seq, body)?;
        let mut w = self.write_stream.lock().unwrap();
        write_frame(&mut *w, &wire)
    }

    fn send_resume_request(&self) -> Result<()> {
        let last_contiguous_seq = self.inbox.lock().unwrap().cumulative_ack();
        let body = ControlMessage::ResumeRequest { last_contiguous_seq }.encode();
        self.write_control_frame(&body)
    }

    fn spawn_reader(&self, mut read_stream: TcpStream, tx: Sender<Result<Vec<u8>>>) {
        let keys = Arc::clone(&self.keys);
        let outbox = Arc::clone(&self.outbox);
        let inbox = Arc::clone(&self.inbox);
        let ratchet = Arc::clone(&self.ratchet);
        let write_stream = Arc::clone(&self.write_stream);
        let control_seq = Arc::clone(&self.control_seq);

        let handle = std::thread::spawn(move || {
            loop {
                let frame = match read_frame(&mut read_stream) {
                    Ok(f) => f,
                    Err(_) => break, // connection closed / broken - stop; reconnect() will replace us
                };
                let recv_key = keys.lock().unwrap().recv_key.clone();
                let (channel, seq, plaintext) = match decode_wire_message(&recv_key, &frame) {
                    Ok(v) => v,
                    Err(_) => continue, // drop unauthenticated / malformed frames silently
                };

                match channel {
                    Channel::Data => {
                        let delivered = inbox.lock().unwrap().receive(seq, plaintext);
                        for blob in delivered {
                            // The transport already authenticated this blob
                            // and the inbox ordered/deduplicated it; now peel
                            // the ratchet layer. A failure here means the two
                            // ratchets disagree (bug or active compromise) -
                            // surface it to `recv()` instead of silently
                            // dropping a message.
                            let msg = ratchet.lock().unwrap().decrypt(&blob);
                            if tx.send(msg).is_err() {
                                return; // receiver side of the app dropped the session
                            }
                        }
                        // Let the sender know what we've got / are missing.
                        let (cumulative_ack, missing) = {
                            let ib = inbox.lock().unwrap();
                            (ib.cumulative_ack(), ib.missing_seqs())
                        };
                        let body = ControlMessage::Ack { cumulative_ack, missing }.encode();
                        let cseq = {
                            let mut cs = control_seq.lock().unwrap();
                            let s = *cs;
                            *cs += 1;
                            s
                        };
                        let send_key = keys.lock().unwrap().send_key.clone();
                        if let Ok(wire) = encode_wire_message(&send_key, Channel::Control, cseq, &body) {
                            let mut w = write_stream.lock().unwrap();
                            let _ = write_frame(&mut *w, &wire);
                        }
                    }
                    Channel::Control => {
                        let Ok(control) = ControlMessage::decode(&plaintext) else { continue };
                        match control {
                            ControlMessage::Ack { cumulative_ack, missing } => {
                                let to_resend = {
                                    let mut ob = outbox.lock().unwrap();
                                    ob.apply_ack(cumulative_ack, &missing);
                                    ob.messages_to_resend(&missing)
                                };
                                for (rseq, payload) in to_resend {
                                    let send_key = keys.lock().unwrap().send_key.clone();
                                    if let Ok(wire) = encode_wire_message(&send_key, Channel::Data, rseq, &payload) {
                                        let mut w = write_stream.lock().unwrap();
                                        let _ = write_frame(&mut *w, &wire);
                                    }
                                }
                            }
                            ControlMessage::ResumeRequest { last_contiguous_seq } => {
                                let to_resend = outbox.lock().unwrap().messages_after(last_contiguous_seq);
                                for (rseq, payload) in to_resend {
                                    let send_key = keys.lock().unwrap().send_key.clone();
                                    if let Ok(wire) = encode_wire_message(&send_key, Channel::Data, rseq, &payload) {
                                        let mut w = write_stream.lock().unwrap();
                                        let _ = write_frame(&mut *w, &wire);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        *self.reader_thread.lock().unwrap() = Some(handle);
    }
}

/// Dispatch to the right handshake role, applying `timeout` (if any) as a
/// socket read timeout for the duration of the handshake only - normal
/// post-handshake operation relies on `reconnect`/background-thread logic
/// instead of a read timeout, so it's cleared again before returning.
fn run_handshake(
    stream: &mut TcpStream,
    role: Role,
    identity: &Identity,
    registry: &PeerRegistry,
    timeout: Option<Duration>,
    on_progress: Option<ProgressCallback<'_>>,
) -> Result<HandshakeResult> {
    // Chat traffic is many small request/response frames: disable Nagle so a
    // frame leaves immediately instead of waiting to be coalesced (latency
    // matters far more than packing efficiency here).
    stream.set_nodelay(true)?;
    stream.set_read_timeout(timeout)?;
    let result = match role {
        Role::Initiator => handshake::run_initiator(stream, identity, registry, on_progress),
        Role::Responder => handshake::run_responder(stream, identity, registry, on_progress),
    };
    // Always clear the timeout again before handing the socket off to
    // normal operation, regardless of whether the handshake succeeded.
    let _ = stream.set_read_timeout(None);

    result.map_err(|e| match e {
        ChatError::Io(ref io_err)
            if matches!(io_err.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
        {
            ChatError::HandshakeTimedOut
        }
        other => other,
    })
}

// Trait bound reminders (documentation only): TcpStream implements both
// Read and Write, which is all `framing` and `handshake` require.
#[allow(dead_code)]
fn _assert_stream_bounds<S: Read + Write>() {}
