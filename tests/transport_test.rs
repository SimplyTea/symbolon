//! Tests for the pluggable transport layer (`symbolon::transport`).
//!
//! These run the real handshake, ratchet and reliability machinery over the
//! in-memory transport instead of TCP, and also feed the handshake hostile
//! bytes to confirm a bad transport can only make us fail cleanly (an `Err`),
//! never panic or hang.

use std::io::{Read, Write};
use std::thread;
use std::time::{Duration, Instant};

use symbolon::error::ChatError;
use symbolon::identity::Identity;
use symbolon::peer::PeerRegistry;
use symbolon::session::{Role, Session, SessionConfig};
use symbolon::transport::{memory_pair, Connection};

/// Two identities that pin each other (the out-of-band trust step).
fn trusting_pair() -> (Identity, PeerRegistry, Identity, PeerRegistry) {
    let a = Identity::generate();
    let b = Identity::generate();
    let mut ra = PeerRegistry::new();
    ra.trust(b.public_key());
    let mut rb = PeerRegistry::new();
    rb.trust(a.public_key());
    (a, ra, b, rb)
}

/// `Identity` is deliberately not `Clone`; rebuild one from its secret bytes.
fn dup(id: &Identity) -> Identity {
    Identity::from_bytes(&id.secret_bytes())
}

/// A registry that pins exactly one peer key.
fn pinning(id: &Identity) -> PeerRegistry {
    let mut r = PeerRegistry::new();
    r.trust(id.public_key());
    r
}

/// Run both handshake sides concurrently over the given connections.
fn establish_pair(
    ca: Box<dyn Connection>,
    cb: Box<dyn Connection>,
    a: Identity,
    ra: PeerRegistry,
    b: Identity,
    rb: PeerRegistry,
) -> (Session, Session) {
    let t = thread::spawn(move || {
        Session::establish_over(cb, Role::Responder, &b, &rb, SessionConfig::default(), None)
            .expect("responder")
    });
    let sa = Session::establish_over(ca, Role::Initiator, &a, &ra, SessionConfig::default(), None)
        .expect("initiator");
    (sa, t.join().unwrap())
}

#[test]
fn session_works_over_memory_transport_both_directions() {
    let (a, ra, b, rb) = trusting_pair();
    let (ca, cb) = memory_pair(Duration::ZERO);
    let (sa, sb) = establish_pair(Box::new(ca), Box::new(cb), a, ra, b, rb);

    assert_eq!(
        sa.session_id(),
        sb.session_id(),
        "both sides must derive the same transcript hash"
    );

    sa.send(b"hello bob").unwrap();
    assert_eq!(sb.recv().unwrap(), b"hello bob");
    sb.send(b"hello alice").unwrap();
    assert_eq!(sa.recv().unwrap(), b"hello alice");

    for i in 0..50u32 {
        sa.send(format!("a{i}").as_bytes()).unwrap();
        sb.send(format!("b{i}").as_bytes()).unwrap();
    }
    for i in 0..50u32 {
        assert_eq!(sb.recv().unwrap(), format!("a{i}").as_bytes());
        assert_eq!(sa.recv().unwrap(), format!("b{i}").as_bytes());
    }
}

#[test]
fn simulated_latency_is_visible_in_round_trip_time() {
    let latency = Duration::from_millis(40);
    let (a, ra, b, rb) = trusting_pair();
    let (ca, cb) = memory_pair(latency);
    let (sa, sb) = establish_pair(Box::new(ca), Box::new(cb), a, ra, b, rb);

    let echo = thread::spawn(move || {
        let m = sb.recv().unwrap();
        sb.send(&m).unwrap();
        sb // keep the session alive until the echo is delivered
    });
    let start = Instant::now();
    sa.send(b"ping").unwrap();
    assert_eq!(sa.recv().unwrap(), b"ping");
    let rtt = start.elapsed();
    let _sb = echo.join().unwrap();

    assert!(
        rtt >= latency * 2,
        "round trip {rtt:?} should be at least 2 x {latency:?}"
    );
    assert!(
        rtt < latency * 2 + Duration::from_millis(400),
        "round trip {rtt:?} unexpectedly slow"
    );
}

#[test]
fn cut_link_then_reconnect_loses_nothing_and_keeps_order() {
    let (a, ra, b, rb) = trusting_pair();
    let (ca, cb) = memory_pair(Duration::ZERO);
    let cut = ca.cutter();
    let (sa, sb) = establish_pair(Box::new(ca), Box::new(cb), dup(&a), ra, dup(&b), rb);

    sa.send(b"one").unwrap();
    assert_eq!(sb.recv().unwrap(), b"one");

    // Pull the cable, then keep sending: these go to the outbox.
    cut();
    thread::sleep(Duration::from_millis(50));
    let _ = sa.send(b"two");
    let _ = sa.send(b"three");

    // New link; both sides re-handshake and resume.
    let (ca2, cb2) = memory_pair(Duration::ZERO);
    let (a2, b2) = (dup(&a), dup(&b));
    let (ra2, rb2) = (pinning(&b), pinning(&a));
    let sb_ref = &sb;
    thread::scope(|s| {
        let h = s.spawn(move || {
            sb_ref
                .reconnect_over(
                    Box::new(cb2),
                    Role::Responder,
                    &b2,
                    &rb2,
                    SessionConfig::default(),
                    None,
                )
                .unwrap();
        });
        sa.reconnect_over(
            Box::new(ca2),
            Role::Initiator,
            &a2,
            &ra2,
            SessionConfig::default(),
            None,
        )
        .unwrap();
        h.join().unwrap();
    });

    assert_eq!(sb.recv().unwrap(), b"two");
    assert_eq!(sb.recv().unwrap(), b"three");
    sb.send(b"back").unwrap();
    assert_eq!(sa.recv().unwrap(), b"back");
}

/// Feed the initiator-side handshake a scripted peer that replies with junk
/// of every length 0..140 and make sure we get an Err, never a panic/hang.
#[test]
fn garbage_handshake_replies_fail_cleanly() {
    for len in 0..140usize {
        let (a, ra, _b, _rb) = trusting_pair();
        let (ca, mut evil) = memory_pair(Duration::ZERO);
        let t = thread::spawn(move || {
            // Wait for our msg1 frame, then answer with a well-framed junk payload.
            let mut hdr = [0u8; 4];
            let _ = evil.read_exact(&mut hdr);
            let n = u32::from_be_bytes(hdr) as usize;
            let mut body = vec![0u8; n];
            let _ = evil.read_exact(&mut body);
            let junk = vec![0xA5u8; len];
            let _ = evil.write_all(&(len as u32).to_be_bytes());
            let _ = evil.write_all(&junk);
        });
        let cfg = SessionConfig {
            handshake_timeout: Some(Duration::from_millis(300)),
            ..SessionConfig::default()
        };
        let r = Session::establish_over(Box::new(ca), Role::Initiator, &a, &ra, cfg, None);
        assert!(
            r.is_err(),
            "junk reply of {len} bytes must not yield a session"
        );
        let _ = t.join();
    }
}

#[test]
fn truncated_frame_fails_cleanly() {
    let (a, ra, _b, _rb) = trusting_pair();
    let (ca, mut evil) = memory_pair(Duration::ZERO);
    let t = thread::spawn(move || {
        let mut buf = [0u8; 256];
        let _ = evil.read(&mut buf);
        // Promise 130 bytes, deliver 10, then hang up.
        let _ = evil.write_all(&130u32.to_be_bytes());
        let _ = evil.write_all(&[1u8; 10]);
        (evil.cutter())();
    });
    let cfg = SessionConfig {
        handshake_timeout: Some(Duration::from_millis(500)),
        ..SessionConfig::default()
    };
    assert!(Session::establish_over(Box::new(ca), Role::Initiator, &a, &ra, cfg, None).is_err());
    t.join().unwrap();
}

#[test]
fn silent_peer_times_out() {
    let (a, ra, _b, _rb) = trusting_pair();
    let (ca, _silent) = memory_pair(Duration::ZERO);
    let cfg = SessionConfig {
        handshake_timeout: Some(Duration::from_millis(200)),
        ..SessionConfig::default()
    };
    let start = Instant::now();
    let r = Session::establish_over(Box::new(ca), Role::Initiator, &a, &ra, cfg, None);
    assert!(
        matches!(r, Err(ChatError::HandshakeTimedOut)),
        "got {:?}",
        r.err()
    );
    assert!(start.elapsed() < Duration::from_secs(3));
}
