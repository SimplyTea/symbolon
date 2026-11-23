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
//! A [`Session`] can be re-pointed at a brand new connection (TCP, or any
//! [`crate::transport::Connection`]) via
//! [`Session::reconnect`] after the old connection dies. Doing this:
//!
//! 1. Re-runs the full mutual-authentication handshake on the new socket
//!    (fresh ephemeral keys - forward secrecy is preserved per-connection).
//! 2. Keeps the *same* [`crate::reliability::Outbox`] /
//!    [`crate::reliability::Inbox`], so sequence numbers and pending
//!    messages carry over unchanged.
//! 3. Immediately exchanges resume requests so each side replays anything
//!    the other might have missed while disconnected.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::clock::{Clock, SystemClock};
use crate::trace::{NoopTracer, TraceEvent, Tracer};

use crate::crypto::{self, AeadKey, Channel};
use crate::error::{ChatError, Result};
use crate::framing::{read_frame, write_frame};
use crate::handshake::{self, HandshakeResult, ProgressCallback};
use crate::identity::{Identity, PeerId, PeerRegistry};
use crate::message::ControlMessage;
use crate::padding::{self, Padding};
use crate::ratchet::{Ratchet, RatchetInfo};
use crate::reliability::{Inbox, Outbox};
use crate::sessionstate::{SavedState, SessionPersistence, StateSaver};
use crate::transport::Connection;

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

    /// Keepalive: when nothing at all has been received from the peer for
    /// this long, send an encrypted ping (see [`crate::message::ControlMessage::Ping`]).
    /// `None` disables the heartbeat and with it dead-peer detection.
    /// Busy links never send pings, because real traffic already proves
    /// the peer is alive.
    pub heartbeat_interval: Option<Duration>,

    /// If NOTHING authenticated arrives for this long, the link is declared
    /// dead and closed, which makes [`Session::recv`] fail so the app can
    /// reconnect (see [`Session::reconnect_over`]). Should be at least
    /// 2-3x `heartbeat_interval` so one lost ping does not kill a healthy
    /// link. Ignored when the heartbeat is disabled.
    pub dead_after: Duration,

    /// Time source for keepalive and liveness. Defaults to the real clock;
    /// tests inject a [`crate::clock::ManualClock`]. Fixed when the session is
    /// first created: a later reconnect keeps using the original clock.
    pub clock: Arc<dyn Clock>,

    /// Receiver for [`TraceEvent`]s (default: discards them). Fixed when the
    /// session is first created, like the clock.
    pub tracer: Arc<dyn Tracer>,

    /// Save session state so an app restart can resume it (see
    /// [`crate::sessionstate`]). `None` (default): sessions live only in
    /// memory, as before.
    pub persistence: Option<Arc<SessionPersistence>>,

    /// Who we expect to reach. REQUIRED to resume a saved session as the
    /// INITIATOR (we must know which saved state to use before dialing).
    /// When set, a handshake that authenticates anyone else fails with
    /// [`ChatError::PeerMismatch`]. Responders do not need it.
    pub expect_peer: Option<PeerId>,

    /// Padding applied to what THIS side sends (default: [`Padding::OFF`]).
    /// See [`crate::padding`] for what it hides and costs. It is a sending
    /// setting only: the receiving side strips padding whatever its own
    /// setting is. Can be changed later with [`Session::set_padding`].
    pub padding: Padding,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            handshake_timeout: Some(Duration::from_secs(10)),
            heartbeat_interval: Some(Duration::from_secs(10)),
            dead_after: Duration::from_secs(30),
            clock: Arc::new(SystemClock::new()),
            tracer: Arc::new(NoopTracer),
            persistence: None,
            expect_peer: None,
            padding: Padding::OFF,
        }
    }
}

/// Liveness bookkeeping for the CURRENT connection, shared between the
/// reader thread, the keepalive thread and the application-facing getters.
struct LinkState {
    /// When we last received any frame that authenticated successfully.
    clock: Arc<dyn Clock>,
    tracer: Arc<dyn Tracer>,
    /// (clock time).
    last_rx: Mutex<Duration>,
    /// `true` while the current connection is believed healthy. Set false
    /// when the reader exits (EOF/error) or the keepalive declares it dead.
    alive: AtomicBool,
    /// Bumped on every (re)connect and on drop; a keepalive thread exits as
    /// soon as the generation it was started for is no longer current.
    generation: AtomicU64,
    /// The outstanding ping, if any: (nonce, when sent).
    ping_sent: Mutex<Option<(u64, Duration)>>,
    /// Round-trip time measured by the most recent answered ping.
    last_rtt: Mutex<Option<Duration>>,
    ping_counter: AtomicU64,
}

impl LinkState {
    /// Time since anything authenticated last arrived.
    fn idle(&self) -> Duration {
        self.clock
            .now()
            .saturating_sub(*self.last_rx.lock().unwrap())
    }

    fn new(clock: Arc<dyn Clock>, tracer: Arc<dyn Tracer>) -> LinkState {
        LinkState {
            last_rx: Mutex::new(clock.now()),
            clock,
            tracer,
            alive: AtomicBool::new(true),
            generation: AtomicU64::new(0),
            ping_sent: Mutex::new(None),
            last_rtt: Mutex::new(None),
            ping_counter: AtomicU64::new(1),
        }
    }
}

/// Encrypt and send one control-channel body. Shared by the reader thread
/// (pongs) and the keepalive thread (pings).
fn send_control(
    keys: &Mutex<SessionKeys>,
    control_seq: &Mutex<u64>,
    write_stream: &Mutex<Box<dyn Write + Send>>,
    body: &[u8],
) -> Result<()> {
    let seq = {
        let mut cs = control_seq.lock().unwrap();
        let s = *cs;
        *cs += 1;
        s
    };
    let key = keys.lock().unwrap().send_key.clone();
    let wire = encode_wire_message(&key, Channel::Control, seq, body)?;
    let mut w = write_stream.lock().unwrap();
    write_frame(&mut *w, &wire)
}

/// What [`Session::reconnect_or_replace`] did with the new connection.
// `Replaced` carries a whole Session by value on purpose: it is the rare
// outcome and boxing it would change the public API for no practical gain.
#[allow(clippy::large_enum_variant)]
pub enum Reconnected {
    /// Same peer, same session state on both sides: this session was resumed
    /// in place and unacknowledged messages are being re-delivered.
    Resumed,
    /// The peer had restarted and lost its session state, so the old session
    /// cannot continue. This is a brand-new session over the same connection;
    /// the application should switch to it and drop the old one. Messages the
    /// old session had not yet delivered are NOT carried over (the peer no
    /// longer has the state needed to receive them).
    Replaced(Session),
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
    /// Random identifier of THIS session's state (ratchet/outbox/inbox);
    /// constant across its reconnects, different for every new `Session`.
    own_epoch: [u8; 16],
    /// The epoch the peer presented when this session was established. A
    /// reconnect that presents a different one means the peer lost its state.
    peer_epoch: Mutex<[u8; 16]>,
    /// Protocol version negotiated during the most recent (re)connection.
    negotiated_version: Mutex<crate::handshake::Version>,
    /// Hash of the most recent handshake transcript (see
    /// [`Session::session_id`]).
    transcript_hash: Mutex<[u8; 32]>,
    keys: Arc<Mutex<SessionKeys>>,
    write_stream: Arc<Mutex<Box<dyn Write + Send>>>,
    /// A separate handle to the current socket purely so `reconnect` can
    /// call `shutdown()` on it to force the old background reader thread to
    /// wake up from its blocking read and exit before we start a new one.
    shutdown_handle: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Liveness state of the current connection (see [`LinkState`]).
    link: Arc<LinkState>,
    reader_thread: Mutex<Option<JoinHandle<()>>>,

    outbox: Arc<Mutex<Outbox>>,
    /// Highest outbox sequence number that existed when the CURRENT
    /// connection began. The peer's resume request replays only messages
    /// up to this number: anything stored later is written by `send()` on
    /// the new link, so replaying it too would put the same bytes on the
    /// wire twice (harmless, since the receiver drops duplicates, but
    /// wasteful). Captured after the writer is swapped, so a message
    /// stored before the swap is replayed (at worst twice, never lost).
    resend_ceiling: Arc<std::sync::atomic::AtomicU64>,
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

    /// Present when [`SessionConfig::persistence`] was set.
    saver: Option<Arc<StateSaver>>,
    /// Decrypted messages not yet returned by `recv()` (mirrors the channel;
    /// only kept up to date when `saver` is present).
    pending: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// Was this session resumed from saved state?
    restored: bool,
    /// Block size used to pad outgoing messages (0 = off). Atomic so an app
    /// can change the setting while the session is running.
    padding_block: std::sync::atomic::AtomicU16,
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
fn encode_wire_message(
    key: &AeadKey,
    channel: Channel,
    seq: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
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
        Self::establish_with(
            stream,
            role,
            identity,
            registry,
            SessionConfig::default(),
            None,
        )
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
        stream: TcpStream,
        role: Role,
        identity: &Identity,
        registry: &PeerRegistry,
        config: SessionConfig,
        on_progress: Option<ProgressCallback<'_>>,
    ) -> Result<Session> {
        Self::establish_over(
            Box::new(stream),
            role,
            identity,
            registry,
            config,
            on_progress,
        )
    }

    /// Like [`Session::establish_with`] but over ANY [`Connection`] (see
    /// [`crate::transport`]): a WebSocket, a Tor stream, an in-memory pipe
    /// in a test, and so on. The caller decides how the connection was
    /// found and opened; the protocol is identical on top of it.
    pub fn establish_over(
        mut conn: Box<dyn Connection>,
        role: Role,
        identity: &Identity,
        registry: &PeerRegistry,
        config: SessionConfig,
        on_progress: Option<ProgressCallback<'_>>,
    ) -> Result<Session> {
        // Which epoch do we present? A saved session must present the epoch
        // it was saved with; anything else gets a fresh random one.
        let fresh_epoch = || {
            let mut e = [0u8; 16];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut e);
            e
        };
        let epoch_for = |peer: &PeerId| {
            config
                .persistence
                .as_ref()
                .and_then(|p| p.saved_epoch(peer))
                .unwrap_or_else(fresh_epoch)
        };
        let initiator_epoch = match &config.expect_peer {
            Some(p) => epoch_for(p),
            None => fresh_epoch(),
        };
        let handshake_result = traced_handshake(
            &mut conn,
            role,
            identity,
            registry,
            &initiator_epoch,
            &epoch_for,
            &config,
            on_progress,
        )?;
        if let Some(expected) = &config.expect_peer {
            if handshake_result.peer_id != *expected {
                return Err(ChatError::PeerMismatch);
            }
        }
        let parts = conn.into_parts()?;

        // Is there saved state we can pick up? Only if the peer presents the
        // epoch we saw last time (it kept ITS state) and we presented ours.
        let mut restored = None;
        if let Some(p) = &config.persistence {
            match p.load(&handshake_result.peer_id) {
                Ok(Some(st))
                    if st.own_epoch == handshake_result.own_epoch
                        && st.peer_epoch == handshake_result.peer_epoch =>
                {
                    restored = Some(st);
                }
                Ok(Some(_)) => {
                    // Peer restarted or we presented a different epoch:
                    // the saved ratchet can never work again.
                    config.tracer.event(&TraceEvent::SessionStateDiscarded {
                        peer: handshake_result.peer_id,
                        reason: "peer no longer holds the matching session",
                    });
                    p.discard(&handshake_result.peer_id);
                }
                Ok(None) => {}
                Err(_) => {
                    config.tracer.event(&TraceEvent::SessionStateDiscarded {
                        peer: handshake_result.peer_id,
                        reason: "saved state unreadable",
                    });
                    p.discard(&handshake_result.peer_id);
                }
            }
        }
        Self::from_handshake(identity, handshake_result, parts, &config, restored)
    }

    /// Turn a completed handshake plus its split connection into a live
    /// session (fresh ratchet, outbox, inbox; reader and keepalive running).
    fn from_handshake(
        identity: &Identity,
        handshake_result: HandshakeResult,
        parts: crate::transport::ConnectionParts,
        config: &SessionConfig,
        restored: Option<SavedState>,
    ) -> Result<Session> {
        let (tx, rx) = mpsc::channel();
        let was_restored = restored.is_some();
        let (ratchet, outbox, inbox, pending_msgs) = match restored {
            Some(st) => (st.ratchet, st.outbox, st.inbox, st.pending),
            None => (
                Ratchet::from_seed(handshake_result.ratchet)?,
                Outbox::new(),
                Inbox::new(),
                Vec::new(),
            ),
        };
        // A restored outbox may hold unacked messages from before the
        // restart; they all count as "existed before this link".
        let resend_ceiling = Arc::new(std::sync::atomic::AtomicU64::new(outbox.highest_seq()));
        let outbox = Arc::new(Mutex::new(outbox));
        let inbox = Arc::new(Mutex::new(inbox));
        let control_seq = Arc::new(Mutex::new(1u64));
        let ratchet = Arc::new(Mutex::new(ratchet));
        let pending: Arc<Mutex<VecDeque<Vec<u8>>>> =
            Arc::new(Mutex::new(pending_msgs.iter().cloned().collect()));
        // Messages that were decrypted but not yet read before the restart
        // go back to the application first, in order.
        for m in pending_msgs {
            let _ = tx.send(Ok(m));
        }
        let keys = Arc::new(Mutex::new(SessionKeys {
            send_key: handshake_result.send_key,
            recv_key: handshake_result.recv_key,
        }));

        let saver = config.persistence.as_ref().map(|p| {
            StateSaver::new(
                Arc::clone(p),
                handshake_result.peer_id,
                handshake_result.own_epoch,
                handshake_result.peer_epoch,
                Arc::clone(&ratchet),
                Arc::clone(&outbox),
                Arc::clone(&inbox),
                Arc::clone(&pending),
            )
        });
        // Persist the starting point BEFORE any message flows, so even the
        // very first send has a saved state to roll forward from.
        if let Some(sv) = &saver {
            sv.save()?;
        }
        if was_restored {
            config.tracer.event(&TraceEvent::SessionRestored {
                peer: handshake_result.peer_id,
            });
        }

        let write_stream = Arc::new(Mutex::new(parts.writer));
        let closer: Arc<dyn Fn() + Send + Sync> = Arc::from(parts.closer);

        let session = Session {
            own_id: identity.fingerprint(),
            peer_id: Mutex::new(handshake_result.peer_id),
            own_epoch: handshake_result.own_epoch,
            peer_epoch: Mutex::new(handshake_result.peer_epoch),
            negotiated_version: Mutex::new(handshake_result.negotiated_version),
            transcript_hash: Mutex::new(handshake_result.transcript_hash),
            keys,
            write_stream,
            shutdown_handle: Mutex::new(Some(closer.clone())),
            link: Arc::new(LinkState::new(config.clock.clone(), config.tracer.clone())),
            reader_thread: Mutex::new(None),
            outbox,
            resend_ceiling,
            inbox,
            ratchet,
            control_seq,
            incoming_rx: Mutex::new(rx),
            saver,
            pending,
            restored: was_restored,
            padding_block: std::sync::atomic::AtomicU16::new(config.padding.block_size()),
        };

        session.spawn_reader(parts.reader, tx);
        session.start_keepalive(config, closer);
        session.send_resume_request()?;
        Ok(session)
    }

    /// Change how messages this side SENDS are padded, from now on. Messages
    /// already queued keep the padding they were built with. The peer needs
    /// no matching setting (see [`crate::padding`]).
    pub fn set_padding(&self, padding: Padding) {
        self.padding_block
            .store(padding.block_size(), std::sync::atomic::Ordering::Relaxed);
    }

    /// The padding currently applied to outgoing messages.
    pub fn padding(&self) -> Padding {
        Padding::from_raw(
            self.padding_block
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// `true` if this session was resumed from saved state (see
    /// [`SessionConfig::persistence`]) rather than started fresh.
    pub fn was_restored(&self) -> bool {
        self.restored
    }

    /// `false` if saving session state has started failing (disk full,
    /// permissions...). While it fails, sends are refused rather than risk
    /// reusing an encryption key after a crash.
    pub fn persistence_healthy(&self) -> bool {
        self.saver.as_ref().is_none_or(|s| !s.failing())
    }

    /// Re-establish this session on a brand new TCP connection after a
    /// disconnect, without losing any pending messages or sequence-number
    /// state, using default [`SessionConfig`] and no progress reporting.
    pub fn reconnect(
        &self,
        stream: TcpStream,
        role: Role,
        identity: &Identity,
        registry: &PeerRegistry,
    ) -> Result<()> {
        self.reconnect_with(
            stream,
            role,
            identity,
            registry,
            SessionConfig::default(),
            None,
        )
    }

    /// Re-establish this session on a brand new TCP connection after a
    /// disconnect, without losing any pending messages or sequence-number
    /// state. Performs a fresh mutual-authentication handshake (so forward
    /// secrecy still holds per-connection), then asks the peer to replay
    /// anything sent while we were apart, and replays our own backlog too.
    pub fn reconnect_with(
        &self,
        stream: TcpStream,
        role: Role,
        identity: &Identity,
        registry: &PeerRegistry,
        config: SessionConfig,
        on_progress: Option<ProgressCallback<'_>>,
    ) -> Result<()> {
        self.reconnect_over(
            Box::new(stream),
            role,
            identity,
            registry,
            config,
            on_progress,
        )
    }

    /// Like [`Session::reconnect_with`] but over any [`Connection`]. If the
    /// peer turns out to have restarted (see [`ChatError::PeerRestarted`])
    /// this fails; use [`Session::reconnect_or_replace`] to be handed a fresh
    /// session in that case instead.
    pub fn reconnect_over(
        &self,
        conn: Box<dyn Connection>,
        role: Role,
        identity: &Identity,
        registry: &PeerRegistry,
        config: SessionConfig,
        on_progress: Option<ProgressCallback<'_>>,
    ) -> Result<()> {
        self.reconnect_inner(conn, role, identity, registry, config, on_progress, false)
            .map(|_| ())
    }

    /// Reconnect after a dropped link, whatever happened to the other side.
    ///
    /// * Peer kept its session state: this session RESUMES in place
    ///   ([`Reconnected::Resumed`]); nothing is lost.
    /// * Peer restarted (new session epoch): the old ratchet can never work
    ///   again, so a brand-new session is built over this same connection and
    ///   returned ([`Reconnected::Replaced`]); the app swaps it in.
    ///
    /// Either way the peer is authenticated by the same pinned key as before
    /// (a different peer is refused with [`ChatError::PeerMismatch`]).
    pub fn reconnect_or_replace(
        &self,
        conn: Box<dyn Connection>,
        role: Role,
        identity: &Identity,
        registry: &PeerRegistry,
        config: SessionConfig,
        on_progress: Option<ProgressCallback<'_>>,
    ) -> Result<Reconnected> {
        self.reconnect_inner(conn, role, identity, registry, config, on_progress, true)
    }

    #[allow(clippy::too_many_arguments)]
    fn reconnect_inner(
        &self,
        mut conn: Box<dyn Connection>,
        role: Role,
        identity: &Identity,
        registry: &PeerRegistry,
        config: SessionConfig,
        on_progress: Option<ProgressCallback<'_>>,
        allow_replace: bool,
    ) -> Result<Reconnected> {
        // Stop the old reader thread cleanly before starting a new one, so
        // we never have two threads touching the inbox/outbox at once.
        if let Some(close_old) = self.shutdown_handle.lock().unwrap().take() {
            close_old();
        }
        if let Some(handle) = self.reader_thread.lock().unwrap().take() {
            let _ = handle.join();
        }

        let own_epoch = self.own_epoch;
        let handshake_result = traced_handshake(
            &mut conn,
            role,
            identity,
            registry,
            &own_epoch,
            &|_: &PeerId| own_epoch,
            &config,
            on_progress,
        )?;
        let parts = conn.into_parts()?;

        // The ratchet, outbox and inbox belong to ONE peer. A reconnect that
        // authenticates someone else (even someone we also trust) must not
        // be spliced onto this session.
        if handshake_result.peer_id != *self.peer_id.lock().unwrap() {
            return Err(ChatError::PeerMismatch);
        }

        // Same peer, but did it keep its session state? A different epoch
        // means it restarted: our ratchet and its (fresh) ratchet cannot
        // interoperate, so resuming would wedge both sides.
        if handshake_result.peer_epoch != *self.peer_epoch.lock().unwrap() {
            if !allow_replace {
                return Err(ChatError::PeerRestarted);
            }
            // Keep OUR epoch: the peer just recorded it from this handshake.
            let fresh = Self::from_handshake(identity, handshake_result, parts, &config, None)?;
            fresh.link.tracer.event(&TraceEvent::ReconnectReplaced);
            return Ok(Reconnected::Replaced(fresh));
        }

        *self.peer_id.lock().unwrap() = handshake_result.peer_id;
        *self.negotiated_version.lock().unwrap() = handshake_result.negotiated_version;
        *self.transcript_hash.lock().unwrap() = handshake_result.transcript_hash;
        *self.keys.lock().unwrap() = SessionKeys {
            send_key: handshake_result.send_key,
            recv_key: handshake_result.recv_key,
        };
        *self.write_stream.lock().unwrap() = parts.writer;
        // Capture AFTER the swap (see `resend_ceiling`): a send() that
        // stores a message after this point writes it to the new link.
        let ceiling = self.outbox.lock().unwrap().highest_seq();
        self.resend_ceiling
            .store(ceiling, std::sync::atomic::Ordering::SeqCst);
        let closer: Arc<dyn Fn() + Send + Sync> = Arc::from(parts.closer);
        *self.shutdown_handle.lock().unwrap() = Some(closer.clone());

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

        self.spawn_reader(parts.reader, tx);
        self.start_keepalive(&config, closer);
        self.send_resume_request()?;
        self.link.tracer.event(&TraceEvent::ReconnectResumed);
        Ok(Reconnected::Resumed)
    }

    /// Send an application payload. Returns the sequence number assigned to
    /// it. The message is durably staged in the outbox *before* it hits the
    /// socket, so even if the write fails (connection just died) it will
    /// automatically be retried the next time [`Session::reconnect`] runs.
    /// Queue `payload` for reliable delivery and return its sequence number.
    /// `Ok` means the message is in the outbox and WILL be delivered (now, or
    /// after a reconnect if the link is down); it does not mean the peer has
    /// received it - watch [`Session::pending_unacked`] for that.
    pub fn send(&self, payload: &[u8]) -> Result<u64> {
        // Ratchet-encrypt exactly once, under the ratchet lock so that ratchet
        // order always equals sequence order (the receiver's inbox delivers
        // in sequence order and the ratchet expects that). The outbox stores
        // the *ciphertext*: a retransmission must resend the identical blob,
        // because a ratchet message key can never be used twice.
        //
        // With persistence on, the new state (ratchet advanced, ciphertext in
        // the outbox) is WRITTEN before anything goes on the wire. If that
        // write fails we undo the whole send and report the error: sending
        // anyway could, after a crash, make us reuse this message key.
        let (seq, blob) = {
            let _commit = self.saver.as_ref().map(|s| s.commit.lock().unwrap());
            let mut r = self.ratchet.lock().unwrap();
            let mut ob = self.outbox.lock().unwrap();
            let before = self.saver.as_ref().map(|_| r.clone());
            let seq = ob.reserve_seq();
            // Pad inside the encryption so the wire size reveals only the
            // block the message fell in (see `crate::padding`).
            let padded = padding::pad(payload, self.padding());
            let blob = match r.encrypt(&padded) {
                Ok(b) => b,
                Err(e) => {
                    ob.rollback(seq);
                    return Err(e);
                }
            };
            ob.store(seq, blob.clone());
            if let (Some(saver), Some(before)) = (&self.saver, before) {
                if let Err(e) = saver.save_locked(&r, &ob) {
                    *r = before;
                    ob.rollback(seq);
                    return Err(e);
                }
            }
            (seq, blob)
        };
        self.link.tracer.event(&TraceEvent::MessageQueued { seq });
        // The message is now safely in the outbox. If the wire write fails
        // because the link is down, that is NOT a failed send: the reliability
        // layer re-delivers it after the next reconnect, and the broken link is
        // reported separately (`link_alive()`, and `recv()` failing). Only
        // non-I/O errors (which would be bugs) are surfaced here.
        match self.write_data_frame(seq, &blob) {
            Ok(()) => {}
            Err(ChatError::Io(_)) | Err(ChatError::ConnectionClosed) => {}
            Err(e) => return Err(e),
        }
        Ok(seq)
    }

    /// Block until the next application message - delivered strictly in
    /// order, with no gaps - is available.
    pub fn recv(&self) -> Result<Vec<u8>> {
        let msg = self
            .incoming_rx
            .lock()
            .unwrap()
            .recv()
            .map_err(|_| ChatError::ConnectionClosed)?;
        if msg.is_ok() {
            self.handed_to_app();
        }
        msg
    }

    /// The application now has the oldest queued message: drop it from the
    /// saved "decrypted but not yet read" queue (a crash before this point
    /// re-delivers it on restart: at-least-once).
    fn handed_to_app(&self) {
        if let Some(saver) = &self.saver {
            let _commit = saver.commit.lock().unwrap();
            self.pending.lock().unwrap().pop_front();
            let _ = saver.save();
        }
    }

    /// Non-blocking variant of [`Session::recv`], for tests / polling.
    pub fn try_recv(&self) -> Option<Vec<u8>> {
        let msg = self
            .incoming_rx
            .lock()
            .unwrap()
            .try_recv()
            .ok()
            .and_then(|r| r.ok());
        if msg.is_some() {
            self.handed_to_app();
        }
        msg
    }

    pub fn peer_id(&self) -> PeerId {
        *self.peer_id.lock().unwrap()
    }

    /// Our own identity's fingerprint - so a UI can show "you" alongside
    /// "peer" without needing to hold onto the `Identity` separately.
    pub fn own_id(&self) -> &PeerId {
        &self.own_id
    }

    /// The protocol version currently in use for this connection (see
    /// `handshake::negotiate_version`). Changes across a `reconnect` if the
    /// two sides end up negotiating differently (e.g. after an upgrade).
    pub fn negotiated_version(&self) -> crate::handshake::Version {
        *self.negotiated_version.lock().unwrap()
    }

    /// The hash of the handshake transcript for the current connection, as
    /// 64 lowercase hex characters. It covers both identities, both
    /// ephemeral keys and both protocol versions, so BOTH peers compute the
    /// identical value - read it aloud (or compare it in a UI) as an extra
    /// check that nobody is sitting in the middle of the connection. It is
    /// not secret, and it changes on every (re)connect.
    pub fn session_id(&self) -> String {
        self.transcript_hash
            .lock()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Non-secret snapshot of the Double Ratchet's position (counters and
    /// our current public ratchet key) - for debug UIs and tests.
    pub fn ratchet_info(&self) -> RatchetInfo {
        self.ratchet.lock().unwrap().info()
    }

    /// `false` once the current connection has ended or been declared dead
    /// (EOF, I/O error, or no authenticated traffic for
    /// [`SessionConfig::dead_after`]). The app should then reconnect.
    pub fn link_alive(&self) -> bool {
        self.link.alive.load(Ordering::SeqCst)
    }

    /// How long since anything authenticated last arrived from the peer.
    pub fn time_since_heard(&self) -> Duration {
        self.link.idle()
    }

    /// Round-trip time of the most recent answered keepalive ping, if any
    /// has completed on this connection yet.
    pub fn last_ping_rtt(&self) -> Option<Duration> {
        *self.link.last_rtt.lock().unwrap()
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
        let body = ControlMessage::ResumeRequest {
            last_contiguous_seq,
        }
        .encode();
        self.write_control_frame(&body)
    }

    fn spawn_reader(&self, mut read_stream: Box<dyn Read + Send>, tx: Sender<Result<Vec<u8>>>) {
        let keys = Arc::clone(&self.keys);
        let outbox = Arc::clone(&self.outbox);
        let resend_ceiling = Arc::clone(&self.resend_ceiling);
        let inbox = Arc::clone(&self.inbox);
        let ratchet = Arc::clone(&self.ratchet);
        let write_stream = Arc::clone(&self.write_stream);
        let control_seq = Arc::clone(&self.control_seq);
        let link = Arc::clone(&self.link);
        let saver = self.saver.clone();

        let handle = std::thread::spawn(move || {
            loop {
                let frame = match read_frame(&mut read_stream) {
                    Ok(f) => f,
                    Err(_) => {
                        link.tracer.event(&TraceEvent::LinkClosed);
                        break; // connection closed / broken - stop; reconnect() will replace us
                    }
                };
                let recv_key = keys.lock().unwrap().recv_key.clone();
                let (channel, seq, plaintext) = match decode_wire_message(&recv_key, &frame) {
                    Ok(v) => v,
                    Err(_) => {
                        link.tracer.event(&TraceEvent::FrameRejected);
                        continue; // drop unauthenticated / malformed frames
                    }
                };
                // Only a frame that AUTHENTICATED counts as proof of life, so
                // an attacker injecting junk cannot keep a dead link "alive".
                *link.last_rx.lock().unwrap() = link.clock.now();

                match channel {
                    Channel::Data => {
                        link.tracer.event(&TraceEvent::DataReceived { seq });
                        // With persistence on, "receive + decrypt + queue +
                        // save" is one atomic step with respect to snapshots
                        // taken by `send`, and the save happens BEFORE the
                        // ack below: the ack lets the peer delete its copy,
                        // so we must not ack what a crash could still lose.
                        let _commit = saver.as_ref().map(|s| s.commit.lock().unwrap());
                        let delivered = inbox.lock().unwrap().receive(seq, plaintext);
                        let mut outgoing = Vec::new();
                        for blob in delivered {
                            // The transport already authenticated this blob
                            // and the inbox ordered/deduplicated it; now peel
                            // the ratchet layer. A failure here means the two
                            // ratchets disagree (bug or active compromise) -
                            // surface it to `recv()` instead of silently
                            // dropping a message.
                            // Strip the padding straight away so everything
                            // after this (the saved queue, the app) only
                            // ever sees the real payload.
                            let msg = ratchet
                                .lock()
                                .unwrap()
                                .decrypt(&blob)
                                .and_then(padding::unpad);
                            if let (Some(sv), Ok(m)) = (&saver, &msg) {
                                sv.pending.lock().unwrap().push_back(m.clone());
                            }
                            outgoing.push(msg);
                        }
                        let saved_ok = match (&saver, outgoing.is_empty()) {
                            (Some(sv), false) => sv.save().is_ok(),
                            _ => true,
                        };
                        drop(_commit);
                        for msg in outgoing {
                            if tx.send(msg).is_err() {
                                return; // receiver side of the app dropped the session
                            }
                        }
                        if !saved_ok {
                            // Could not persist: do NOT ack. The peer keeps
                            // its copy and resends after a reconnect, where
                            // the inbox drops the duplicate.
                            continue;
                        }
                        // Let the sender know what we've got / are missing.
                        let (cumulative_ack, missing) = {
                            let ib = inbox.lock().unwrap();
                            (ib.cumulative_ack(), ib.missing_seqs())
                        };
                        let body = ControlMessage::Ack {
                            cumulative_ack,
                            missing,
                        }
                        .encode();
                        let cseq = {
                            let mut cs = control_seq.lock().unwrap();
                            let s = *cs;
                            *cs += 1;
                            s
                        };
                        let send_key = keys.lock().unwrap().send_key.clone();
                        if let Ok(wire) =
                            encode_wire_message(&send_key, Channel::Control, cseq, &body)
                        {
                            let mut w = write_stream.lock().unwrap();
                            let _ = write_frame(&mut *w, &wire);
                        }
                    }
                    Channel::Control => {
                        let Ok(control) = ControlMessage::decode(&plaintext) else {
                            continue;
                        };
                        match control {
                            ControlMessage::Ack {
                                cumulative_ack,
                                missing,
                            } => {
                                let to_resend = {
                                    let mut ob = outbox.lock().unwrap();
                                    ob.apply_ack(cumulative_ack, &missing);
                                    ob.messages_to_resend(&missing)
                                };
                                if !to_resend.is_empty() {
                                    link.tracer.event(&TraceEvent::Retransmitted {
                                        count: to_resend.len(),
                                    });
                                }
                                for (rseq, payload) in to_resend {
                                    let send_key = keys.lock().unwrap().send_key.clone();
                                    if let Ok(wire) = encode_wire_message(
                                        &send_key,
                                        Channel::Data,
                                        rseq,
                                        &payload,
                                    ) {
                                        let mut w = write_stream.lock().unwrap();
                                        let _ = write_frame(&mut *w, &wire);
                                    }
                                }
                            }
                            ControlMessage::Ping { nonce } => {
                                let _ = send_control(
                                    &keys,
                                    &control_seq,
                                    &write_stream,
                                    &ControlMessage::Pong { nonce }.encode(),
                                );
                            }
                            ControlMessage::Pong { nonce } => {
                                let mut sent = link.ping_sent.lock().unwrap();
                                if let Some((n, t0)) = *sent {
                                    if n == nonce {
                                        let rtt = link.clock.now().saturating_sub(t0);
                                        link.tracer.event(&TraceEvent::PongReceived { rtt });
                                        *link.last_rtt.lock().unwrap() = Some(rtt);
                                        *sent = None;
                                    }
                                }
                            }
                            ControlMessage::ResumeRequest {
                                last_contiguous_seq,
                            } => {
                                let ceiling =
                                    resend_ceiling.load(std::sync::atomic::Ordering::SeqCst);
                                let mut to_resend =
                                    outbox.lock().unwrap().messages_after(last_contiguous_seq);
                                // Only what existed before this link began.
                                to_resend.retain(|(rseq, _)| *rseq <= ceiling);
                                if !to_resend.is_empty() {
                                    link.tracer.event(&TraceEvent::Retransmitted {
                                        count: to_resend.len(),
                                    });
                                }
                                for (rseq, payload) in to_resend {
                                    let send_key = keys.lock().unwrap().send_key.clone();
                                    if let Ok(wire) = encode_wire_message(
                                        &send_key,
                                        Channel::Data,
                                        rseq,
                                        &payload,
                                    ) {
                                        let mut w = write_stream.lock().unwrap();
                                        let _ = write_frame(&mut *w, &wire);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Loop ended: the connection is over (EOF, error, or we closed it).
            link.alive.store(false, Ordering::SeqCst);
        });

        *self.reader_thread.lock().unwrap() = Some(handle);
    }

    /// Start the keepalive thread for the connection that was just set up.
    ///
    /// It wakes a few times per interval and: declares the link dead (and
    /// closes it) if nothing authenticated has arrived for `dead_after`;
    /// otherwise pings if the link has been quiet for `heartbeat_interval`.
    /// It exits when the connection it was started for is replaced, dies,
    /// or the `Session` is dropped.
    ///
    /// Known limit: if a write blocks indefinitely (peer vanished with a full
    /// TCP send buffer) the ping write can block too; the closer, called by
    /// reconnect/drop, unblocks it. In practice chat-sized traffic does not
    /// fill the buffer.
    fn start_keepalive(&self, config: &SessionConfig, closer: Arc<dyn Fn() + Send + Sync>) {
        let my_gen = self.link.generation.fetch_add(1, Ordering::SeqCst) + 1;
        self.link.alive.store(true, Ordering::SeqCst);
        *self.link.last_rx.lock().unwrap() = self.link.clock.now();
        *self.link.ping_sent.lock().unwrap() = None;
        *self.link.last_rtt.lock().unwrap() = None;

        let Some(interval) = config.heartbeat_interval else {
            return;
        };
        let dead_after = config.dead_after;
        let link = Arc::clone(&self.link);
        let keys = Arc::clone(&self.keys);
        let control_seq = Arc::clone(&self.control_seq);
        let write_stream = Arc::clone(&self.write_stream);
        let tick = (interval / 4).clamp(Duration::from_millis(5), Duration::from_millis(250));

        std::thread::spawn(move || {
            let mut last_ping = link.clock.now().saturating_sub(interval);
            loop {
                link.clock.sleep(tick);
                if link.generation.load(Ordering::SeqCst) != my_gen
                    || !link.alive.load(Ordering::SeqCst)
                {
                    return;
                }
                let idle = link.idle();
                if idle >= dead_after {
                    link.alive.store(false, Ordering::SeqCst);
                    link.tracer.event(&TraceEvent::LinkDead { idle });
                    closer(); // wakes the reader thread, which ends recv()
                    return;
                }
                if idle >= interval && link.clock.now().saturating_sub(last_ping) >= interval {
                    let nonce = link.ping_counter.fetch_add(1, Ordering::SeqCst);
                    *link.ping_sent.lock().unwrap() = Some((nonce, link.clock.now()));
                    last_ping = link.clock.now();
                    link.tracer.event(&TraceEvent::PingSent { nonce });
                    if send_control(
                        &keys,
                        &control_seq,
                        &write_stream,
                        &ControlMessage::Ping { nonce }.encode(),
                    )
                    .is_err()
                    {
                        link.alive.store(false, Ordering::SeqCst);
                        closer();
                        return;
                    }
                }
            }
        });
    }
}

impl Drop for Session {
    /// Dropping a session ends its connection (so the peer sees it close and
    /// background threads exit) instead of leaving a half-owned socket open.
    fn drop(&mut self) {
        self.link.generation.fetch_add(1, Ordering::SeqCst);
        self.link.alive.store(false, Ordering::SeqCst);
        if let Some(close) = self.shutdown_handle.lock().unwrap().take() {
            close();
        }
    }
}

/// [`run_handshake`] plus start/finish/failure trace events.
// Internal helper that threads the handshake inputs through; a parameter struct
// would only move the same eight values around.
#[allow(clippy::too_many_arguments)]
fn traced_handshake(
    stream: &mut Box<dyn Connection>,
    role: Role,
    identity: &Identity,
    registry: &PeerRegistry,
    initiator_epoch: &[u8; 16],
    responder_epoch: &dyn Fn(&PeerId) -> [u8; 16],
    config: &SessionConfig,
    on_progress: Option<ProgressCallback<'_>>,
) -> Result<HandshakeResult> {
    let role_name = match role {
        Role::Initiator => "initiator",
        Role::Responder => "responder",
    };
    config
        .tracer
        .event(&TraceEvent::HandshakeStarted { role: role_name });
    let r = run_handshake(
        stream,
        role,
        identity,
        registry,
        initiator_epoch,
        responder_epoch,
        config.handshake_timeout,
        on_progress,
    );
    match &r {
        Ok(h) => config
            .tracer
            .event(&TraceEvent::HandshakeCompleted { peer: h.peer_id }),
        Err(e) => config.tracer.event(&TraceEvent::HandshakeFailed {
            reason: e.to_string(),
        }),
    }
    r
}

/// Dispatch to the right handshake role, applying `timeout` (if any) as a
/// socket read timeout for the duration of the handshake only - normal
/// post-handshake operation relies on `reconnect`/background-thread logic
/// instead of a read timeout, so it's cleared again before returning.
#[allow(clippy::too_many_arguments)] // see traced_handshake
fn run_handshake(
    stream: &mut Box<dyn Connection>,
    role: Role,
    identity: &Identity,
    registry: &PeerRegistry,
    initiator_epoch: &[u8; 16],
    responder_epoch: &dyn Fn(&PeerId) -> [u8; 16],
    timeout: Option<Duration>,
    on_progress: Option<ProgressCallback<'_>>,
) -> Result<HandshakeResult> {
    // Chat traffic is many small request/response frames: disable Nagle so a
    // frame leaves immediately instead of waiting to be coalesced (latency
    // matters far more than packing efficiency here).
    stream.tune()?;
    stream.set_read_timeout(timeout)?;
    let result = match role {
        Role::Initiator => {
            handshake::run_initiator(stream, identity, registry, initiator_epoch, on_progress)
        }
        Role::Responder => {
            handshake::run_responder(stream, identity, registry, responder_epoch, on_progress)
        }
    };
    // Always clear the timeout again before handing the socket off to
    // normal operation, regardless of whether the handshake succeeded.
    let _ = stream.set_read_timeout(None);

    result.map_err(|e| match e {
        ChatError::Io(ref io_err)
            if matches!(
                io_err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
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
