//! Heartbeat and dead-peer detection, over the in-memory transport so the
//! "link silently dies" case can be simulated exactly (a black hole: writes
//! succeed, nothing arrives, no error anywhere - what a vanished wifi
//! connection looks like until TCP finally gives up minutes later).

use std::thread;
use std::time::{Duration, Instant};

use symbolon::identity::Identity;
use symbolon::peer::PeerRegistry;
use symbolon::session::{Role, Session, SessionConfig};
use symbolon::transport::{memory_pair, Connection};

fn pair_of_identities() -> (Identity, Identity) {
    (Identity::generate(), Identity::generate())
}

fn registry_trusting(other: &Identity) -> PeerRegistry {
    let mut r = PeerRegistry::new();
    r.trust(other.public_key());
    r
}

/// Fast heartbeat so tests take well under a second.
fn quick() -> SessionConfig {
    SessionConfig {
        heartbeat_interval: Some(Duration::from_millis(40)),
        dead_after: Duration::from_millis(400),
        ..SessionConfig::default()
    }
}

fn connect(
    a: &Identity,
    b: &Identity,
    ca: Box<dyn Connection>,
    cb: Box<dyn Connection>,
    cfg: SessionConfig,
) -> (Session, Session) {
    let (ra, rb) = (registry_trusting(b), registry_trusting(a));
    thread::scope(|s| {
        let cfg_b = cfg.clone();
        let h = s.spawn(move || {
            Session::establish_over(cb, Role::Responder, b, &rb, cfg_b, None).unwrap()
        });
        let sa = Session::establish_over(ca, Role::Initiator, a, &ra, cfg, None).unwrap();
        (sa, h.join().unwrap())
    })
}

#[test]
fn an_idle_but_healthy_link_stays_alive_and_measures_rtt() {
    let (a, b) = pair_of_identities();
    let (ca, cb) = memory_pair(Duration::from_millis(5));
    let (sa, sb) = connect(&a, &b, Box::new(ca), Box::new(cb), quick());

    // Idle for 3x dead_after: pings must keep it alive.
    thread::sleep(Duration::from_millis(1300));
    assert!(
        sa.link_alive() && sb.link_alive(),
        "idle link was wrongly declared dead"
    );
    let rtt = sa
        .last_ping_rtt()
        .expect("a ping should have completed by now");
    assert!(
        rtt >= Duration::from_millis(10),
        "rtt {rtt:?} should reflect 2 x 5ms latency"
    );
    assert!(
        rtt < Duration::from_millis(200),
        "rtt {rtt:?} unexpectedly large"
    );
    // And it still carries messages.
    sa.send(b"still here").unwrap();
    assert_eq!(sb.recv().unwrap(), b"still here");
}

#[test]
fn a_silently_dead_link_is_detected_and_recv_fails() {
    let (a, b) = pair_of_identities();
    let (ca, cb) = memory_pair(Duration::ZERO);
    let hole = ca.blackhole_switch();
    let (sa, _sb) = connect(&a, &b, Box::new(ca), Box::new(cb), quick());
    assert!(sa.link_alive());

    hole.store(true, std::sync::atomic::Ordering::SeqCst);
    let t0 = Instant::now();
    // Without detection this recv would block forever.
    let r = sa.recv();
    let took = t0.elapsed();

    assert!(r.is_err(), "recv must fail once the link is declared dead");
    assert!(!sa.link_alive());
    assert!(
        took >= Duration::from_millis(300),
        "declared dead too early: {took:?}"
    );
    assert!(
        took < Duration::from_millis(1500),
        "took too long to notice: {took:?}"
    );
}

#[test]
fn with_the_heartbeat_disabled_a_black_hole_goes_unnoticed() {
    let (a, b) = pair_of_identities();
    let (ca, cb) = memory_pair(Duration::ZERO);
    let hole = ca.blackhole_switch();
    let cfg = SessionConfig {
        heartbeat_interval: None,
        ..quick()
    };
    let (sa, _sb) = connect(&a, &b, Box::new(ca), Box::new(cb), cfg);
    hole.store(true, std::sync::atomic::Ordering::SeqCst);
    thread::sleep(Duration::from_millis(700));
    assert!(
        sa.link_alive(),
        "no heartbeat means no detection (this documents the opt-out)"
    );
}

#[test]
fn after_a_dead_link_a_reconnect_resumes_and_nothing_is_lost() {
    let (a, b) = pair_of_identities();
    let (ca, cb) = memory_pair(Duration::ZERO);
    let hole = ca.blackhole_switch();
    let (sa, sb) = connect(&a, &b, Box::new(ca), Box::new(cb), quick());

    sa.send(b"before").unwrap();
    assert_eq!(sb.recv().unwrap(), b"before");

    hole.store(true, std::sync::atomic::Ordering::SeqCst);
    // Sent into the black hole: staged in the outbox, never delivered.
    sa.send(b"lost-on-the-wire-1").unwrap();
    sa.send(b"lost-on-the-wire-2").unwrap();
    assert!(sa.recv().is_err()); // wait for detection
    assert!(!sa.link_alive());

    let (ca2, cb2) = memory_pair(Duration::ZERO);
    let (ra, rb) = (registry_trusting(&b), registry_trusting(&a));
    thread::scope(|s| {
        let h = s.spawn(|| {
            sb.reconnect_over(Box::new(cb2), Role::Responder, &b, &rb, quick(), None)
                .unwrap()
        });
        sa.reconnect_over(Box::new(ca2), Role::Initiator, &a, &ra, quick(), None)
            .unwrap();
        h.join().unwrap();
    });

    assert!(sa.link_alive());
    assert_eq!(sb.recv().unwrap(), b"lost-on-the-wire-1");
    assert_eq!(sb.recv().unwrap(), b"lost-on-the-wire-2");
}

#[test]
fn reconnecting_as_a_different_trusted_peer_is_refused() {
    let (a, b) = pair_of_identities();
    let c = Identity::generate();
    let (ca, cb) = memory_pair(Duration::ZERO);
    let (sa, _sb) = connect(&a, &b, Box::new(ca), Box::new(cb), quick());

    // A re-dial lands on C instead of B. A trusts both, so the handshake
    // itself succeeds - the session must still refuse to adopt a new peer.
    let mut ra = PeerRegistry::new();
    ra.trust(b.public_key());
    ra.trust(c.public_key());
    let rc = registry_trusting(&a);
    let (ca2, cc2) = memory_pair(Duration::ZERO);
    let result = thread::scope(|s| {
        let h = s.spawn(|| {
            Session::establish_over(Box::new(cc2), Role::Responder, &c, &rc, quick(), None)
        });
        let r = sa.reconnect_over(Box::new(ca2), Role::Initiator, &a, &ra, quick(), None);
        let _ = h.join();
        r
    });
    assert!(
        matches!(result, Err(symbolon::ChatError::PeerMismatch)),
        "got {result:?}"
    );
}

#[test]
fn dropping_a_session_closes_the_connection_for_the_peer() {
    let (a, b) = pair_of_identities();
    let (ca, cb) = memory_pair(Duration::ZERO);
    let (sa, sb) = connect(&a, &b, Box::new(ca), Box::new(cb), quick());
    drop(sa);
    assert!(sb.recv().is_err(), "peer must see the close");
    assert!(!sb.link_alive());
}

// ---- Deterministic time: a ManualClock moves only when the test says so ----

fn manual_cfg(clock: &std::sync::Arc<symbolon::clock::ManualClock>) -> SessionConfig {
    SessionConfig {
        heartbeat_interval: Some(Duration::from_secs(10)),
        dead_after: Duration::from_secs(30),
        clock: clock.clone(),
        ..SessionConfig::default()
    }
}

/// Wait (real time, generously) for `cond`; panics if it never holds.
fn eventually(what: &str, cond: impl Fn() -> bool) {
    let t0 = Instant::now();
    while !cond() {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "timed out waiting for: {what}"
        );
        thread::sleep(Duration::from_millis(2));
    }
}

/// Advance virtual time in steps until `done`, giving background threads
/// real time to react between steps. Stepping (rather than one big jump)
/// keeps this correct under CPU load: a late-arriving frame can only delay
/// detection by one more step, never break the test.
fn advance_until(
    clock: &symbolon::clock::ManualClock,
    step: Duration,
    what: &str,
    done: impl Fn() -> bool,
) -> Duration {
    let mut total = Duration::ZERO;
    for _ in 0..20 {
        if done() {
            return total;
        }
        clock.advance(step);
        total += step;
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        done(),
        "never happened within {total:?} of virtual time: {what}"
    );
    total
}

#[test]
fn manual_clock_dead_link_detected_without_real_waiting() {
    let clock = symbolon::clock::ManualClock::new();
    let (a, b) = pair_of_identities();
    let (ca, cb) = memory_pair(Duration::ZERO);
    let hole = ca.blackhole_switch();
    let hole_b = cb.blackhole_switch(); // both directions: B's pings must not reach A either
    let (sa, _sb) = connect(&a, &b, Box::new(ca), Box::new(cb), manual_cfg(&clock));

    hole.store(true, std::sync::atomic::Ordering::SeqCst);
    hole_b.store(true, std::sync::atomic::Ordering::SeqCst);
    // Below dead_after (30s) the link must still be considered alive.
    clock.advance(Duration::from_secs(20));
    thread::sleep(Duration::from_millis(30));
    assert!(sa.link_alive(), "20s of silence is below the 30s limit");

    let total = advance_until(
        &clock,
        Duration::from_secs(11),
        "link declared dead",
        || !sa.link_alive(),
    );
    // It must NOT have died early: at least 30s of silence in total.
    assert!(Duration::from_secs(20) + total >= Duration::from_secs(30));
    assert!(sa.recv().is_err());
}

#[test]
fn manual_clock_healthy_idle_link_survives_a_virtual_hour() {
    let clock = symbolon::clock::ManualClock::new();
    let (a, b) = pair_of_identities();
    let (ca, cb) = memory_pair(Duration::ZERO);
    let (sa, sb) = connect(&a, &b, Box::new(ca), Box::new(cb), manual_cfg(&clock));

    // 360 steps of 10 virtual seconds. After each step wait (real time) for
    // the ping/pong to refresh the link, so we never outrun the exchange.
    for _ in 0..360 {
        clock.advance(Duration::from_secs(10));
        eventually("keepalive refreshed both ends", || {
            sa.time_since_heard() < Duration::from_secs(1)
                && sb.time_since_heard() < Duration::from_secs(1)
        });
        assert!(
            sa.link_alive() && sb.link_alive(),
            "healthy link was declared dead"
        );
    }
    sa.send(b"after an hour").unwrap();
    assert_eq!(sb.recv().unwrap(), b"after an hour");
}
