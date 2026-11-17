//! Pluggable transport: how bytes actually move between two peers.
//!
//! A [`crate::session::Session`] does not care whether its bytes travel over
//! TCP, a WebSocket, Tor, QUIC, Bluetooth, a Tailscale tunnel, or an
//! in-memory pipe in a test. It only needs a [`Connection`]: an ordered,
//! reliable, bidirectional byte stream (exactly what TCP provides). Whoever
//! embeds this library decides how the connection is found and opened -
//! discovery, NAT traversal, relays and proxies are *their* concern, not the
//! protocol's.
//!
//! Two implementations ship with the crate:
//! - [`std::net::TcpStream`] (the default, used by `Session::establish`).
//! - [`MemoryConnection`] from [`memory_pair`]: an in-process pipe with
//!   optional simulated latency and a "cut the cable" switch. It exists for
//!   tests and for network simulation (no sockets, fully deterministic
//!   apart from thread scheduling).
//!
//! # What a transport must guarantee
//! Bytes arrive in order, without duplication or corruption *of framing*.
//! It does NOT need to be secure: confidentiality and authentication are
//! the protocol's job, so a hostile or buggy transport can at worst drop
//! the connection or deliver garbage that is then rejected. The tests in
//! `tests/transport_test.rs` throw garbage at the handshake to check that.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// An ordered, reliable, bidirectional byte stream between two peers.
///
/// It is used directly (as `Read + Write`) while the handshake runs, and is
/// then split into independent halves for the session's reader thread and
/// for senders.
pub trait Connection: Read + Write + Send + 'static {
    /// Called once before the handshake. Use it for transport tuning, e.g.
    /// disabling Nagle's algorithm on TCP. Default: nothing.
    fn tune(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Limit how long a single `read` may block (`Some`) or remove the
    /// limit (`None`). The session uses this only during the handshake so a
    /// silent peer cannot hang us. A timed-out read must fail with
    /// `ErrorKind::TimedOut` or `ErrorKind::WouldBlock`.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;

    /// Split into a reader half, a writer half, and a function that aborts
    /// the connection from any thread (it must wake a reader blocked in
    /// `read` so the reader thread can exit).
    fn into_parts(self: Box<Self>) -> io::Result<ConnectionParts>;
}

/// The three pieces a live session needs; see [`Connection::into_parts`].
pub struct ConnectionParts {
    /// Used only by the session's background reader thread.
    pub reader: Box<dyn Read + Send>,
    /// Shared (behind a mutex) by everything that sends.
    pub writer: Box<dyn Write + Send>,
    /// Aborts the connection; safe to call more than once.
    pub closer: Box<dyn Fn() + Send + Sync>,
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

impl Connection for TcpStream {
    fn tune(&mut self) -> io::Result<()> {
        // Chat traffic is many small request/response frames: send each one
        // immediately instead of waiting to coalesce (see `framing`).
        self.set_nodelay(true)
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn into_parts(self: Box<Self>) -> io::Result<ConnectionParts> {
        let reader = self.try_clone()?;
        let writer = self.try_clone()?;
        let closer_handle = *self;
        Ok(ConnectionParts {
            reader: Box::new(reader),
            writer: Box::new(writer),
            closer: Box::new(move || {
                let _ = closer_handle.shutdown(Shutdown::Both);
            }),
        })
    }
}

// ---------------------------------------------------------------------------
// In-memory transport (tests and simulation)
// ---------------------------------------------------------------------------

/// One write, stamped with the time it becomes readable. An EMPTY payload is
/// the end-of-stream marker.
type Chunk = (Instant, Vec<u8>);

struct MemoryReader {
    rx: Receiver<Chunk>,
    leftover: Vec<u8>,
    pos: usize,
    eof: bool,
    timeout: Option<Duration>,
    closed: Arc<AtomicBool>,
}

impl Read for MemoryReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pos < self.leftover.len() {
                let n = out.len().min(self.leftover.len() - self.pos);
                out[..n].copy_from_slice(&self.leftover[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if self.eof || self.closed.load(Ordering::SeqCst) {
                return Ok(0);
            }
            let received = match self.timeout {
                Some(t) => self.rx.recv_timeout(t),
                None => self.rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
            };
            match received {
                Ok((deliver_at, data)) => {
                    if data.is_empty() {
                        self.eof = true;
                        return Ok(0);
                    }
                    // Simulated latency: hold the data until its delivery time.
                    let now = Instant::now();
                    if deliver_at > now {
                        std::thread::sleep(deliver_at - now);
                    }
                    self.leftover = data;
                    self.pos = 0;
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "memory transport read timed out",
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.eof = true;
                    return Ok(0);
                }
            }
        }
    }
}

struct MemoryWriter {
    tx: Sender<Chunk>,
    latency: Duration,
    own_closed: Arc<AtomicBool>,
    peer_closed: Arc<AtomicBool>,
    /// While set, writes "succeed" but vanish (see [`MemoryConnection::blackhole_switch`]).
    blackhole: Arc<AtomicBool>,
}

impl Write for MemoryWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.own_closed.load(Ordering::SeqCst) || self.peer_closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "memory transport is closed",
            ));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if self.blackhole.load(Ordering::SeqCst) {
            return Ok(buf.len()); // silently dropped, like an unplugged link
        }
        self.tx
            .send((Instant::now() + self.latency, buf.to_vec()))
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "memory transport peer is gone")
            })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One end of an in-process connection created by [`memory_pair`].
pub struct MemoryConnection {
    reader: MemoryReader,
    writer: MemoryWriter,
    closer: Arc<dyn Fn() + Send + Sync>,
}

/// Shared by both ends of a [`memory_pair`]: when `true`, everything
/// written in either direction is silently discarded.
pub type BlackholeSwitch = Arc<AtomicBool>;

impl MemoryConnection {
    /// A handle that severs the link from any thread, like pulling the
    /// network cable: both ends then see end-of-stream and failed writes.
    pub fn cutter(&self) -> Arc<dyn Fn() + Send + Sync> {
        Arc::clone(&self.closer)
    }

    /// A switch that makes the link a black hole: both directions keep
    /// ACCEPTING writes (no error, no close) but deliver nothing - exactly
    /// how a dead wifi link or a vanished peer looks to TCP for minutes.
    /// This is what dead-peer detection must catch, since no I/O error will.
    pub fn blackhole_switch(&self) -> BlackholeSwitch {
        Arc::clone(&self.writer.blackhole)
    }
}

impl Read for MemoryConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Write for MemoryConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl Connection for MemoryConnection {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.timeout = timeout;
        Ok(())
    }

    fn into_parts(self: Box<Self>) -> io::Result<ConnectionParts> {
        let MemoryConnection {
            mut reader,
            writer,
            closer,
        } = *self;
        reader.timeout = None; // the handshake-only timeout does not carry over
        Ok(ConnectionParts {
            reader: Box::new(reader),
            writer: Box::new(writer),
            closer: Box::new(move || closer()),
        })
    }
}

/// Create two connected in-memory ends. `latency` is the simulated one-way
/// delay applied to everything written (so a request/response costs about
/// `2 * latency`). Use `Duration::ZERO` for an instant link.
pub fn memory_pair(latency: Duration) -> (MemoryConnection, MemoryConnection) {
    let (a_to_b_tx, a_to_b_rx) = channel::<Chunk>();
    let (b_to_a_tx, b_to_a_rx) = channel::<Chunk>();
    let a_closed = Arc::new(AtomicBool::new(false));
    let b_closed = Arc::new(AtomicBool::new(false));
    let blackhole = Arc::new(AtomicBool::new(false));

    let end = |rx: Receiver<Chunk>,
               tx: Sender<Chunk>,
               wake_own_reader: Sender<Chunk>,
               own_closed: Arc<AtomicBool>,
               peer_closed: Arc<AtomicBool>| {
        // Closing marks this end closed and pushes an end-of-stream marker
        // both to the peer (so its reader stops) and to our own reader (so
        // a thread blocked in `read` wakes up).
        let notify_peer = tx.clone();
        let own_flag = Arc::clone(&own_closed);
        let closer: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            own_flag.store(true, Ordering::SeqCst);
            let _ = notify_peer.send((Instant::now(), Vec::new()));
            let _ = wake_own_reader.send((Instant::now(), Vec::new()));
        });
        MemoryConnection {
            reader: MemoryReader {
                rx,
                leftover: Vec::new(),
                pos: 0,
                eof: false,
                timeout: None,
                closed: Arc::clone(&own_closed),
            },
            writer: MemoryWriter {
                tx,
                latency,
                own_closed,
                peer_closed,
                blackhole: Arc::clone(&blackhole),
            },
            closer,
        }
    };

    // Each end needs: the channel it reads from, the channel it writes to,
    // and a spare sender into its OWN read channel (to wake a blocked reader
    // when it closes itself).
    let a = end(
        b_to_a_rx,
        a_to_b_tx.clone(),
        b_to_a_tx.clone(),
        Arc::clone(&a_closed),
        Arc::clone(&b_closed),
    );
    let b = end(a_to_b_rx, b_to_a_tx, a_to_b_tx, b_closed, a_closed);
    (a, b)
}
