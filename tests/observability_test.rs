//! Trace hooks and the trust store's approval queue, end to end.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use symbolon::identity::{fingerprint, Identity};
use symbolon::peer::PeerRegistry;
use symbolon::session::{Role, Session, SessionConfig};
use symbolon::trace::{CollectingTracer, TraceEvent};
use symbolon::transport::{memory_pair, Connection};
use symbolon::truststore::{MemoryTrustStore, TrustStore};

fn registry_trusting(other: &Identity) -> PeerRegistry {
    let mut r = PeerRegistry::new();
    r.trust(other.public_key());
    r
}

fn try_connect(
    a: &Identity,
    b: &Identity,
    ra: &PeerRegistry,
    rb: &PeerRegistry,
    cfg_a: SessionConfig,
    cfg_b: SessionConfig,
) -> (
    symbolon::error::Result<Session>,
    symbolon::error::Result<Session>,
) {
    let (ca, cb) = memory_pair(Duration::ZERO);
    let (ca, cb): (Box<dyn Connection>, Box<dyn Connection>) = (Box::new(ca), Box::new(cb));
    thread::scope(|s| {
        let h = s.spawn(move || Session::establish_over(cb, Role::Responder, b, rb, cfg_b, None));
        let sa = Session::establish_over(ca, Role::Initiator, a, ra, cfg_a, None);
        (sa, h.join().unwrap())
    })
}

#[test]
fn session_events_are_reported() {
    let (a, b) = (Identity::generate(), Identity::generate());
    let tr = CollectingTracer::new();
    let cfg_a = SessionConfig {
        tracer: tr.clone(),
        ..SessionConfig::default()
    };
    let (sa, sb) = try_connect(
        &a,
        &b,
        &registry_trusting(&b),
        &registry_trusting(&a),
        cfg_a,
        SessionConfig::default(),
    );
    let (sa, sb) = (sa.unwrap(), sb.unwrap());
    sa.send(b"hello").unwrap();
    assert_eq!(sb.recv().unwrap(), b"hello");
    sb.send(b"back").unwrap();
    assert_eq!(sa.recv().unwrap(), b"back");

    assert!(tr.any(|e| matches!(e, TraceEvent::HandshakeStarted { role: "initiator" })));
    assert!(tr.any(|e| *e
        == TraceEvent::HandshakeCompleted {
            peer: fingerprint(&b.public_key())
        }));
    assert!(tr.any(|e| matches!(e, TraceEvent::MessageQueued { seq: 1 })));
    assert!(tr.any(|e| matches!(e, TraceEvent::DataReceived { .. })));
}

#[test]
fn failed_handshake_is_reported_without_secrets() {
    let (a, b) = (Identity::generate(), Identity::generate());
    let tr = CollectingTracer::new();
    let cfg_b = SessionConfig {
        tracer: tr.clone(),
        handshake_timeout: Some(Duration::from_millis(300)),
        ..SessionConfig::default()
    };
    // B trusts nobody.
    let (_sa, sb) = try_connect(
        &a,
        &b,
        &registry_trusting(&b),
        &PeerRegistry::new(),
        SessionConfig {
            handshake_timeout: Some(Duration::from_millis(300)),
            ..SessionConfig::default()
        },
        cfg_b,
    );
    assert!(sb.is_err());
    assert!(tr.any(|e| matches!(e, TraceEvent::HandshakeFailed { .. })));
    // The only data in events are fingerprints/strings; make sure no raw secret leaks via Debug.
    let dump = format!("{:?}", tr.events());
    assert!(!dump.contains(&format!("{:?}", a.secret_bytes())));
}

#[test]
fn link_dead_is_traced_with_manual_clock() {
    let clock = symbolon::clock::ManualClock::new();
    let tr = CollectingTracer::new();
    let (a, b) = (Identity::generate(), Identity::generate());
    let (ca, cb) = memory_pair(Duration::ZERO);
    let hole = ca.blackhole_switch();
    let hole_b = cb.blackhole_switch();
    let cfg = SessionConfig {
        clock: clock.clone(),
        tracer: tr.clone(),
        ..SessionConfig::default()
    };
    let (ra, rb) = (registry_trusting(&b), registry_trusting(&a));
    let (sa, _sb) = thread::scope(|s| {
        let cfg_b = cfg.clone();
        let h = s.spawn(|| {
            Session::establish_over(Box::new(cb), Role::Responder, &b, &rb, cfg_b, None).unwrap()
        });
        let sa =
            Session::establish_over(Box::new(ca), Role::Initiator, &a, &ra, cfg, None).unwrap();
        (sa, h.join().unwrap())
    });
    hole.store(true, std::sync::atomic::Ordering::SeqCst);
    hole_b.store(true, std::sync::atomic::Ordering::SeqCst);
    // Step virtual time until the link dies (stepping stays correct under load).
    for _ in 0..20 {
        if !sa.link_alive() {
            break;
        }
        clock.advance(Duration::from_secs(11));
        thread::sleep(Duration::from_millis(20));
    }
    assert!(!sa.link_alive());
    assert!(sa.recv().is_err());
    assert!(tr.any(|e| matches!(e, TraceEvent::PingSent { .. })));
    assert!(tr.any(|e| matches!(e, TraceEvent::LinkDead { .. })));
}

#[test]
fn unknown_peer_is_queued_then_approved_and_connects() {
    let (a, b) = (Identity::generate(), Identity::generate());
    // B's trust store is shared so we can approve through it.
    let store = Arc::new(MemoryTrustStore::new());
    let rb = PeerRegistry::with_store(store.clone());
    let ra = registry_trusting(&b);
    let quick = || SessionConfig {
        handshake_timeout: Some(Duration::from_millis(300)),
        ..SessionConfig::default()
    };

    let (_sa, sb) = try_connect(&a, &b, &ra, &rb, quick(), quick());
    assert!(sb.is_err(), "unknown key must be rejected");
    assert_eq!(
        store.pending(),
        vec![a.public_key()],
        "attempt must be queued"
    );

    assert!(store.approve(&fingerprint(&a.public_key())).unwrap());
    let (sa, sb) = try_connect(&a, &b, &ra, &rb, quick(), quick());
    let (sa, sb) = (sa.unwrap(), sb.unwrap());
    sa.send(b"approved").unwrap();
    assert_eq!(sb.recv().unwrap(), b"approved");
}
