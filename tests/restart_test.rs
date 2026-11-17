//! What happens when the PEER RESTARTS (its app is closed and reopened) and
//! therefore has lost its ratchet/outbox/inbox. The surviving side's old
//! session can never work with the peer's new one; it must notice and start
//! over rather than reconnect "successfully" and then reject every message.

use std::thread;
use std::time::Duration;

use symbolon::identity::Identity;
use symbolon::peer::PeerRegistry;
use symbolon::session::{Reconnected, Role, Session, SessionConfig};
use symbolon::transport::memory_pair;
use symbolon::ChatError;

fn trust(other: &Identity) -> PeerRegistry {
    let mut r = PeerRegistry::new();
    r.trust(other.public_key());
    r
}

fn established(a: &Identity, b: &Identity) -> (Session, Session) {
    let (ca, cb) = memory_pair(Duration::ZERO);
    let (ra, rb) = (trust(b), trust(a));
    thread::scope(|s| {
        let h = s.spawn(|| {
            Session::establish_over(
                Box::new(cb),
                Role::Responder,
                b,
                &rb,
                SessionConfig::default(),
                None,
            )
            .unwrap()
        });
        let sa = Session::establish_over(
            Box::new(ca),
            Role::Initiator,
            a,
            &ra,
            SessionConfig::default(),
            None,
        )
        .unwrap();
        (sa, h.join().unwrap())
    })
}

#[test]
fn a_peer_that_kept_its_state_is_resumed_in_place() {
    let (a, b) = (Identity::generate(), Identity::generate());
    let (sa, sb) = established(&a, &b);
    sa.send(b"one").unwrap();
    assert_eq!(sb.recv().unwrap(), b"one");

    let (ca2, cb2) = memory_pair(Duration::ZERO);
    let (ra, rb) = (trust(&b), trust(&a));
    let outcome = thread::scope(|s| {
        let h = s.spawn(|| {
            sb.reconnect_or_replace(
                Box::new(cb2),
                Role::Responder,
                &b,
                &rb,
                SessionConfig::default(),
                None,
            )
            .unwrap()
        });
        let r = sa
            .reconnect_or_replace(
                Box::new(ca2),
                Role::Initiator,
                &a,
                &ra,
                SessionConfig::default(),
                None,
            )
            .unwrap();
        (r, h.join().unwrap())
    });
    assert!(matches!(outcome.0, Reconnected::Resumed) && matches!(outcome.1, Reconnected::Resumed));
    sa.send(b"two").unwrap();
    assert_eq!(sb.recv().unwrap(), b"two");
}

#[test]
fn a_restarted_peer_is_detected_and_a_fresh_session_is_handed_back() {
    let (a, b) = (Identity::generate(), Identity::generate());
    let (sa, sb) = established(&a, &b);
    sa.send(b"before the restart").unwrap();
    assert_eq!(sb.recv().unwrap(), b"before the restart");

    // B's app restarts: its session is gone; it makes a brand-new one.
    drop(sb);
    let (ca2, cb2) = memory_pair(Duration::ZERO);
    let (ra, rb) = (trust(&b), trust(&a));
    let (outcome, sb_new) = thread::scope(|s| {
        let h = s.spawn(|| {
            Session::establish_over(
                Box::new(cb2),
                Role::Responder,
                &b,
                &rb,
                SessionConfig::default(),
                None,
            )
            .unwrap()
        });
        let r = sa
            .reconnect_or_replace(
                Box::new(ca2),
                Role::Initiator,
                &a,
                &ra,
                SessionConfig::default(),
                None,
            )
            .unwrap();
        (r, h.join().unwrap())
    });

    let Reconnected::Replaced(sa_new) = outcome else {
        panic!("expected a replacement session, the peer restarted")
    };
    // The new pair works in both directions (it used to wedge with a ratchet error).
    sa_new.send(b"hello again").unwrap();
    assert_eq!(sb_new.recv().unwrap(), b"hello again");
    sb_new.send(b"welcome back").unwrap();
    assert_eq!(sa_new.recv().unwrap(), b"welcome back");
    assert_eq!(sa_new.session_id(), sb_new.session_id());
}

#[test]
fn the_strict_reconnect_refuses_a_restarted_peer_with_a_clear_error() {
    let (a, b) = (Identity::generate(), Identity::generate());
    let (sa, sb) = established(&a, &b);
    drop(sb);
    let (ca2, cb2) = memory_pair(Duration::ZERO);
    let (ra, rb) = (trust(&b), trust(&a));
    let result = thread::scope(|s| {
        let _h = s.spawn(|| {
            Session::establish_over(
                Box::new(cb2),
                Role::Responder,
                &b,
                &rb,
                SessionConfig::default(),
                None,
            )
        });
        sa.reconnect_over(
            Box::new(ca2),
            Role::Initiator,
            &a,
            &ra,
            SessionConfig::default(),
            None,
        )
    });
    assert!(
        matches!(result, Err(ChatError::PeerRestarted)),
        "got {result:?}"
    );
}

#[test]
fn the_surviving_side_may_be_the_listener_too() {
    // Same scenario with roles swapped: the restarted peer dials in.
    let (a, b) = (Identity::generate(), Identity::generate());
    let (sa, sb) = established(&a, &b);
    drop(sa);
    let (ca2, cb2) = memory_pair(Duration::ZERO);
    let (ra, rb) = (trust(&b), trust(&a));
    let (outcome, sa_new) = thread::scope(|s| {
        let h = s.spawn(|| {
            Session::establish_over(
                Box::new(ca2),
                Role::Initiator,
                &a,
                &ra,
                SessionConfig::default(),
                None,
            )
            .unwrap()
        });
        let r = sb
            .reconnect_or_replace(
                Box::new(cb2),
                Role::Responder,
                &b,
                &rb,
                SessionConfig::default(),
                None,
            )
            .unwrap();
        (r, h.join().unwrap())
    });
    let Reconnected::Replaced(sb_new) = outcome else {
        panic!("expected replacement")
    };
    sb_new.send(b"speaking first as responder").unwrap();
    assert_eq!(sa_new.recv().unwrap(), b"speaking first as responder");
}
