//! Opt-in LAN discovery: "a Symbolon node is listening at this address".
//!
//! # Privacy stance (read this first)
//! Discovery is **off unless the application turns it on**. When on, an
//! announcement contains ONLY:
//!   * the product name (default `"symbolon"`),
//!   * the MAJOR version (always),
//!   * the MINOR version (only if [`Disclose::Minor`] or [`Disclose::Full`]),
//!   * the PATCH version (only if [`Disclose::Full`]),
//!   * the TCP port to dial.
//! It never contains your public key, fingerprint, group names or anything
//! else: a stable identifier on the wire would let anyone on the network
//! track you across places (see NOTES.md, "handshake oracle"). To connect to
//! a discovered address you still need that peer's key in your trust list;
//! discovery only saves you typing `host:port`.
//!
//! Why version levels? Exact versions are a target list for anyone hunting
//! known-vulnerable builds, so they are separate opt-ins. The major number
//! says which wire generation you speak; that is the least a peer needs.
//!
//! # Trust model
//! An announcement is an UNAUTHENTICATED hint: anyone on the LAN can send or
//! spoof one. Treat it exactly like a typed-in address: dial it, and let the
//! authenticated handshake decide whether the other end is who you trust.
//! Never skip or relax a check because a node "announced itself".
//!
//! # Transport
//! One small UDP datagram, repeated every `interval`. The default target is
//! the IPv4 limited broadcast address on [`DEFAULT_PORT`]; tests aim it at
//! loopback. Only one listener per host per port can bind (std has no
//! SO_REUSEADDR); that is fine for the CLI, and an app that needs more can
//! supply its own socket plumbing and use [`Announcement::encode`] /
//! [`Announcement::decode`] directly.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::clock::{Clock, SystemClock};
use crate::error::{ChatError, Result};

/// UDP port discovery uses unless told otherwise.
pub const DEFAULT_PORT: u16 = 47474;

const MAGIC: &[u8; 4] = b"SYMD";
const WIRE_VERSION: u8 = 1;
const MAX_NAME: usize = 32;
/// Largest datagram we will even look at.
const MAX_PACKET: usize = 128;

/// How much of our version to reveal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Disclose {
    /// Major only (default).
    #[default]
    Major,
    /// Major and minor.
    Minor,
    /// Major, minor and patch.
    Full,
}

/// What a node says about itself.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Announcement {
    pub name: String,
    pub major: u8,
    /// `None` unless the sender chose to disclose it.
    pub minor: Option<u8>,
    /// `None` unless the sender chose to disclose it (implies minor).
    pub patch: Option<u8>,
    /// TCP port to dial (the source IP of the datagram is the host).
    pub port: u16,
}

impl Announcement {
    /// Build from our real version, revealing only what `disclose` allows.
    pub fn new(name: &str, version: (u8, u8, u8), disclose: Disclose, port: u16) -> Result<Self> {
        if name.is_empty()
            || name.len() > MAX_NAME
            || !name.bytes().all(|b| (0x20..0x7f).contains(&b))
        {
            return Err(ChatError::MalformedMessage(
                "discovery name must be 1-32 printable ASCII bytes",
            ));
        }
        Ok(Announcement {
            name: name.to_string(),
            major: version.0,
            minor: matches!(disclose, Disclose::Minor | Disclose::Full).then_some(version.1),
            patch: matches!(disclose, Disclose::Full).then_some(version.2),
            port,
        })
    }

    /// Wire form: `"SYMD" | ver | flags | name_len | name | major | [minor] | [patch] | port(BE)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut flags = 0u8;
        if self.minor.is_some() {
            flags |= 1;
        }
        if self.patch.is_some() {
            flags |= 2;
        }
        let mut out = Vec::with_capacity(16 + self.name.len());
        out.extend_from_slice(MAGIC);
        out.push(WIRE_VERSION);
        out.push(flags);
        out.push(self.name.len() as u8);
        out.extend_from_slice(self.name.as_bytes());
        out.push(self.major);
        if let Some(m) = self.minor {
            out.push(m);
        }
        if let Some(p) = self.patch {
            out.push(p);
        }
        out.extend_from_slice(&self.port.to_be_bytes());
        out
    }

    /// Strict parser: anything unexpected (wrong magic, unknown flag bits,
    /// patch without minor, bad name bytes, trailing bytes) is an error.
    pub fn decode(b: &[u8]) -> Result<Self> {
        const BAD: ChatError = ChatError::MalformedMessage("bad discovery packet");
        if b.len() > MAX_PACKET || b.len() < 12 || &b[..4] != MAGIC || b[4] != WIRE_VERSION {
            return Err(BAD);
        }
        let flags = b[5];
        if flags & !3 != 0 || (flags & 2 != 0 && flags & 1 == 0) {
            return Err(BAD);
        }
        let name_len = b[6] as usize;
        if name_len == 0 || name_len > MAX_NAME {
            return Err(BAD);
        }
        let need = 7 + name_len + 1 + (flags & 1) as usize + ((flags >> 1) & 1) as usize + 2;
        if b.len() != need {
            return Err(BAD);
        }
        let name_bytes = &b[7..7 + name_len];
        if !name_bytes.iter().all(|c| (0x20..0x7f).contains(c)) {
            return Err(BAD);
        }
        let mut i = 7 + name_len;
        let major = b[i];
        i += 1;
        let minor = if flags & 1 != 0 {
            i += 1;
            Some(b[i - 1])
        } else {
            None
        };
        let patch = if flags & 2 != 0 {
            i += 1;
            Some(b[i - 1])
        } else {
            None
        };
        let port = u16::from_be_bytes([b[i], b[i + 1]]);
        Ok(Announcement {
            name: String::from_utf8_lossy(name_bytes).into_owned(),
            major,
            minor,
            patch,
            port,
        })
    }
}

/// Periodically sends one announcement. Stops when dropped.
pub struct Announcer {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Announcer {
    /// Start announcing to `target` every `interval`. `clock` drives the
    /// waiting (inject a [`crate::clock::ManualClock`] in tests).
    pub fn start(
        announcement: Announcement,
        target: SocketAddr,
        interval: Duration,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.set_broadcast(true)?;
        let packet = announcement.encode();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let handle = std::thread::spawn(move || {
            let mut last: Option<Duration> = None;
            while !stop2.load(Ordering::SeqCst) {
                let now = clock.now();
                if last.map_or(true, |l| now.saturating_sub(l) >= interval) {
                    let _ = sock.send_to(&packet, target); // best effort: a missed beacon is harmless
                    last = Some(now);
                }
                clock.sleep(Duration::from_millis(20));
            }
        });
        Ok(Announcer {
            stop,
            handle: Some(handle),
        })
    }

    /// Convenience: announce on the real clock to the LAN broadcast address.
    pub fn start_broadcast(announcement: Announcement, interval: Duration) -> Result<Self> {
        let target = SocketAddr::from(([255, 255, 255, 255], DEFAULT_PORT));
        Self::start(announcement, target, interval, Arc::new(SystemClock::new()))
    }
}

impl Drop for Announcer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// A node we heard, and where to dial it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovered {
    pub announcement: Announcement,
    /// Source IP of the datagram plus the announced TCP port. UNVERIFIED.
    pub dial: SocketAddr,
}

/// Receives announcements.
pub struct DiscoveryListener {
    sock: UdpSocket,
}

impl DiscoveryListener {
    /// Bind to `addr` (use `0.0.0.0:`[`DEFAULT_PORT`] on a LAN).
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        Ok(DiscoveryListener {
            sock: UdpSocket::bind(addr)?,
        })
    }

    /// The bound address (useful when binding port 0 in tests).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.sock.local_addr()?)
    }

    /// Wait up to `timeout` for the next VALID announcement; junk datagrams
    /// are dropped silently (and do not extend the wait). `None` on timeout.
    pub fn next(&self, timeout: Duration) -> Option<Discovered> {
        let deadline = std::time::Instant::now() + timeout;
        let mut buf = [0u8; MAX_PACKET + 1]; // +1 so oversize datagrams are detectable
        loop {
            let left = deadline.checked_duration_since(std::time::Instant::now())?;
            if left.is_zero() {
                return None;
            }
            self.sock.set_read_timeout(Some(left)).ok()?;
            match self.sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if let Ok(a) = Announcement::decode(&buf[..n]) {
                        let dial = SocketAddr::new(from.ip(), a.port);
                        return Some(Discovered {
                            announcement: a,
                            dial,
                        });
                    }
                }
                Err(_) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn major_only_hides_minor_and_patch() {
        let a = Announcement::new("symbolon", (1, 2, 3), Disclose::Major, 4000).unwrap();
        assert_eq!((a.minor, a.patch), (None, None));
        let d = Announcement::decode(&a.encode()).unwrap();
        assert_eq!(d, a);
        // The hidden numbers must not be on the wire at all.
        assert_eq!(a.encode().len(), 4 + 1 + 1 + 1 + 8 + 1 + 2);
    }

    #[test]
    fn minor_and_full_levels() {
        let m = Announcement::new("symbolon", (1, 2, 3), Disclose::Minor, 1).unwrap();
        assert_eq!((m.minor, m.patch), (Some(2), None));
        let f = Announcement::new("symbolon", (1, 2, 3), Disclose::Full, 1).unwrap();
        assert_eq!((f.minor, f.patch), (Some(2), Some(3)));
        for a in [m, f] {
            assert_eq!(Announcement::decode(&a.encode()).unwrap(), a);
        }
    }

    #[test]
    fn rejects_bad_names() {
        assert!(Announcement::new("", (1, 0, 0), Disclose::Major, 1).is_err());
        assert!(Announcement::new(&"x".repeat(33), (1, 0, 0), Disclose::Major, 1).is_err());
        assert!(Announcement::new("bad\nname", (1, 0, 0), Disclose::Major, 1).is_err());
    }

    #[test]
    fn decoder_is_strict() {
        let good = Announcement::new("symbolon", (1, 2, 3), Disclose::Full, 9)
            .unwrap()
            .encode();
        assert!(Announcement::decode(&good).is_ok());
        // Truncations and extensions.
        for n in 0..good.len() {
            assert!(Announcement::decode(&good[..n]).is_err(), "prefix {n}");
        }
        let mut longer = good.clone();
        longer.push(0);
        assert!(Announcement::decode(&longer).is_err());
        // Wrong magic / version / unknown flag / patch-without-minor.
        for (idx, val) in [(0usize, b'X'), (4, 9), (5, 0x80), (5, 2)] {
            let mut b = good.clone();
            b[idx] = val;
            assert!(Announcement::decode(&b).is_err(), "mutation at {idx}");
        }
        // Oversize.
        assert!(Announcement::decode(&vec![0u8; 500]).is_err());
    }

    #[test]
    fn decoder_never_panics_on_garbage() {
        // Cheap deterministic fuzz: every single-byte-flip and some patterns.
        let good = Announcement::new("symbolon", (1, 2, 3), Disclose::Full, 9)
            .unwrap()
            .encode();
        for i in 0..good.len() {
            for v in [0u8, 1, 0x7f, 0x80, 0xff] {
                let mut b = good.clone();
                b[i] = v;
                let _ = Announcement::decode(&b);
            }
        }
        for len in 0..200usize {
            let _ = Announcement::decode(&vec![0xAB; len]);
        }
    }

    #[test]
    fn announce_and_listen_over_loopback() {
        let listener = DiscoveryListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let target = listener.local_addr().unwrap();
        let a = Announcement::new("symbolon", (1, 4, 2), Disclose::Minor, 5555).unwrap();
        let _ann = Announcer::start(
            a.clone(),
            target,
            Duration::from_millis(50),
            Arc::new(SystemClock::new()),
        )
        .unwrap();
        let got = listener
            .next(Duration::from_secs(3))
            .expect("heard announcement");
        assert_eq!(got.announcement, a);
        assert_eq!(got.dial, SocketAddr::from(([127, 0, 0, 1], 5555)));
    }

    #[test]
    fn listener_ignores_junk_and_times_out() {
        let listener = DiscoveryListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.send_to(b"hello world", listener.local_addr().unwrap())
            .unwrap();
        sock.send_to(&[0u8; 400], listener.local_addr().unwrap())
            .unwrap();
        assert!(listener.next(Duration::from_millis(200)).is_none());
    }
}
