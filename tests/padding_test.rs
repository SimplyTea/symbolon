//! Padding at the session level: what an observer on the wire actually sees.
//!
//! `src/padding.rs` has the unit tests for the padding scheme itself. These
//! tests run real sessions over an in-memory link, record the size of every
//! data frame each side puts on the wire, and check that (a) the sizes follow
//! the SENDER's setting and (b) the receiver gets the exact payload back no
//! matter what either side's setting is.

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use symbolon::identity::{Identity, PeerRegistry};
use symbolon::padding::Padding;
use symbolon::session::{Role, Session, SessionConfig};
use symbolon::transport::{memory_pair, Connection, ConnectionParts};

/// Bytes added around the padded payload on the wire:
/// 4 (frame prefix) + 9 (channel + seq) + 16 (transport tag) + 40 (ratchet
/// header) + 16 (ratchet tag).
const OVERHEAD: usize = 85;

/// (total frame size, channel byte) of every frame written after the handshake.
type Sizes = Arc<Mutex<Vec<(usize, u8)>>>;

/// Wraps a connection and records each frame its WRITER half sends.
struct Recording {
    inner: Box<dyn Connection>,
    sizes: Sizes,
}

struct RecWriter {
    inner: Box<dyn Write + Send>,
    sizes: Sizes,
}

impl Read for Recording {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Write for Recording {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf) // the handshake: not recorded
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl Write for RecWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Each frame is written in one call: 4-byte length, channel byte, ...
        if buf.len() > 4 {
            self.sizes.lock().unwrap().push((buf.len(), buf[4]));
        }
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl Connection for Recording {
    fn tune(&mut self) -> io::Result<()> {
        self.inner.tune()
    }
    fn set_read_timeout(&mut self, t: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(t)
    }
    fn into_parts(self: Box<Self>) -> io::Result<ConnectionParts> {
        let parts = self.inner.into_parts()?;
        Ok(ConnectionParts {
            reader: parts.reader,
            writer: Box::new(RecWriter {
                inner: parts.writer,
                sizes: self.sizes,
            }),
            closer: parts.closer,
        })
    }
}

struct Pair {
    a: Session,
    b: Session,
    /// Frames written by `a` and by `b`.
    sent_a: Sizes,
    sent_b: Sizes,
}

fn pair(pad_a: Padding, pad_b: Padding) -> Pair {
    let (ca, cb) = memory_pair(Duration::ZERO);
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let mut reg_a = PeerRegistry::new();
    reg_a.trust(bob.public_key());
    let mut reg_b = PeerRegistry::new();
    reg_b.trust(alice.public_key());
    let sent_a: Sizes = Arc::default();
    let sent_b: Sizes = Arc::default();
    let (ra, rb) = (
        Recording {
            inner: Box::new(ca),
            sizes: sent_a.clone(),
        },
        Recording {
            inner: Box::new(cb),
            sizes: sent_b.clone(),
        },
    );
    let (a, b) = thread::scope(|s| {
        let h = s.spawn(|| {
            Session::establish_over(
                Box::new(rb),
                Role::Responder,
                &bob,
                &reg_b,
                SessionConfig {
                    padding: pad_b,
                    ..SessionConfig::default()
                },
                None,
            )
            .unwrap()
        });
        let a = Session::establish_over(
            Box::new(ra),
            Role::Initiator,
            &alice,
            &reg_a,
            SessionConfig {
                padding: pad_a,
                ..SessionConfig::default()
            },
            None,
        )
        .unwrap();
        (a, h.join().unwrap())
    });
    Pair {
        a,
        b,
        sent_a,
        sent_b,
    }
}

/// Sizes of the Data-channel frames (channel byte 0) in order.
fn data_sizes(sent: &Sizes) -> Vec<usize> {
    sent.lock()
        .unwrap()
        .iter()
        .filter(|(_, ch)| *ch == 0)
        .map(|(n, _)| *n)
        .collect()
}

/// Send each payload from `from` and check `to` receives it exactly.
fn deliver(from: &Session, to: &Session, payloads: &[Vec<u8>]) {
    for p in payloads {
        from.send(p).unwrap();
        assert_eq!(&to.recv().unwrap(), p, "payload of {} bytes", p.len());
    }
}

fn of_len(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8 + 1).collect()
}

#[test]
fn with_padding_off_the_frame_size_follows_the_message_length() {
    let p = pair(Padding::OFF, Padding::OFF);
    let lens = [1usize, 10, 20, 40, 80];
    let payloads: Vec<_> = lens.iter().map(|&n| of_len(n)).collect();
    deliver(&p.a, &p.b, &payloads);
    // payload + 1 marker byte + 85 of framing, so every length shows through.
    let expected: Vec<usize> = lens.iter().map(|n| n + 1 + OVERHEAD).collect();
    assert_eq!(data_sizes(&p.sent_a), expected);
}

#[test]
fn standard_padding_makes_short_messages_the_same_size() {
    let p = pair(Padding::STANDARD, Padding::OFF);
    let lens = [1usize, 10, 50, 100, 200, 255];
    let payloads: Vec<_> = lens.iter().map(|&n| of_len(n)).collect();
    deliver(&p.a, &p.b, &payloads);
    // All of these fit in one 256-byte block, so the wire cannot tell them apart.
    let sizes = data_sizes(&p.sent_a);
    assert_eq!(sizes.len(), lens.len());
    assert!(
        sizes.iter().all(|&n| n == 256 + OVERHEAD),
        "sizes were {sizes:?}"
    );
}

#[test]
fn longer_messages_fall_in_the_next_block() {
    let p = pair(Padding::STANDARD, Padding::STANDARD);
    // 256 bytes plus the marker no longer fits one block; 300 is in the second.
    deliver(
        &p.a,
        &p.b,
        &[of_len(256), of_len(300), of_len(511), of_len(512)],
    );
    assert_eq!(
        data_sizes(&p.sent_a),
        vec![
            512 + OVERHEAD,
            512 + OVERHEAD,
            512 + OVERHEAD,
            768 + OVERHEAD
        ]
    );
}

#[test]
fn each_side_pads_what_it_sends_and_neither_needs_the_others_setting() {
    // a pads with 1024-byte blocks, b pads nothing.
    let p = pair(Padding::STRONG, Padding::OFF);
    deliver(&p.a, &p.b, &[of_len(7), of_len(700)]);
    deliver(&p.b, &p.a, &[of_len(7), of_len(700)]);
    assert_eq!(
        data_sizes(&p.sent_a),
        vec![1024 + OVERHEAD, 1024 + OVERHEAD]
    );
    assert_eq!(
        data_sizes(&p.sent_b),
        vec![7 + 1 + OVERHEAD, 700 + 1 + OVERHEAD]
    );
}

#[test]
fn padding_can_be_changed_while_the_session_runs() {
    let p = pair(Padding::OFF, Padding::OFF);
    assert_eq!(p.a.padding(), Padding::OFF);
    deliver(&p.a, &p.b, &[of_len(10)]);
    p.a.set_padding(Padding::STANDARD);
    assert_eq!(p.a.padding(), Padding::STANDARD);
    deliver(&p.a, &p.b, &[of_len(10)]);
    p.a.set_padding(Padding::block(64).unwrap());
    deliver(&p.a, &p.b, &[of_len(10)]);
    assert_eq!(
        data_sizes(&p.sent_a),
        vec![10 + 1 + OVERHEAD, 256 + OVERHEAD, 64 + OVERHEAD]
    );
}

#[test]
fn awkward_payloads_survive_padding() {
    // Empty, all zeros, ending in zeros, ending in the marker byte, and
    // exactly one block: none of these may confuse the receiver.
    let awkward: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0; 300],
        vec![1, 2, 3, 0, 0],
        vec![9, 0x80],
        vec![0x80; 256],
        of_len(255),
        of_len(256),
    ];
    for pad in [Padding::OFF, Padding::STANDARD, Padding::block(16).unwrap()] {
        let p = pair(pad, Padding::OFF);
        deliver(&p.a, &p.b, &awkward);
    }
}
