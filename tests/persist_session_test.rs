//! Saved session state: an app restart resumes the SAME session.
//!
//! "Restart" here = drop one side's Session object entirely (all in-memory
//! state gone) and bring it back from its StateStore over a new connection.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use symbolon::error::{ChatError, Result};
use symbolon::identity::Identity;
use symbolon::peer::PeerRegistry;
use symbolon::session::{Reconnected, Role, Session, SessionConfig};
use symbolon::sessionstate::SessionPersistence;
use symbolon::storage::{MemoryStateStore, StateStore};
use symbolon::trace::{CollectingTracer, TraceEvent};
use symbolon::transport::memory_pair;

fn trusting(other: &Identity) -> PeerRegistry {
    let mut r = PeerRegistry::new();
    r.trust(other.public_key());
    r
}

struct Rig {
    a: Identity,
    b: Identity,
    store_a: Arc<MemoryStateStore>,
    store_b: Arc<MemoryStateStore>,
}

impl Rig {
    fn new() -> Rig {
        Rig {
            a: Identity::generate(),
            b: Identity::generate(),
            store_a: Arc::new(MemoryStateStore::new()),
            store_b: Arc::new(MemoryStateStore::new()),
        }
    }
    fn cfg_a(&self) -> SessionConfig {
        SessionConfig {
            persistence: Some(SessionPersistence::new(self.store_a.clone(), &self.a)),
            expect_peer: Some(self.b.fingerprint()),
            ..SessionConfig::default()
        }
    }
    fn cfg_b(&self) -> SessionConfig {
        SessionConfig {
            persistence: Some(SessionPersistence::new(self.store_b.clone(), &self.b)),
            ..SessionConfig::default()
        }
    }
    /// First connection: A initiates, B responds.
    fn connect(&self) -> (Session, Session) {
        let (ca, cb) = memory_pair(Duration::ZERO);
        let (ra, rb) = (trusting(&self.b), trusting(&self.a));
        thread::scope(|s| {
            let h = s.spawn(|| {
                Session::establish_over(
                    Box::new(cb),
                    Role::Responder,
                    &self.b,
                    &rb,
                    self.cfg_b(),
                    None,
                )
                .unwrap()
            });
            let sa = Session::establish_over(
                Box::new(ca),
                Role::Initiator,
                &self.a,
                &ra,
                self.cfg_a(),
                None,
            )
            .unwrap();
            (sa, h.join().unwrap())
        })
    }
    /// After A "restarts": A comes back from its saved state, B (still
    /// running) reconnects its existing session.
    fn restart_a(&self, sb: &Session) -> (Session, Reconnected) {
        let (ca, cb) = memory_pair(Duration::ZERO);
        let (ra, rb) = (trusting(&self.b), trusting(&self.a));
        thread::scope(|s| {
            let h = s.spawn(|| {
                sb.reconnect_or_replace(
                    Box::new(cb),
                    Role::Responder,
                    &self.b,
                    &rb,
                    self.cfg_b(),
                    None,
                )
                .unwrap()
            });
            let sa = Session::establish_over(
                Box::new(ca),
                Role::Initiator,
                &self.a,
                &ra,
                self.cfg_a(),
                None,
            )
            .unwrap();
            (sa, h.join().unwrap())
        })
    }
}

fn recv_timeout(s: &Session, what: &str) -> Vec<u8> {
    let end = Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(m) = s.try_recv() {
            return m;
        }
        assert!(Instant::now() < end, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn restart_resumes_the_same_session_and_nothing_is_lost() {
    let rig = Rig::new();
    let (sa, sb) = rig.connect();
    sa.send(b"a1").unwrap();
    assert_eq!(recv_timeout(&sb, "a1"), b"a1");
    sb.send(b"b1").unwrap();
    assert_eq!(recv_timeout(&sa, "b1"), b"b1");

    let peer_a = sa.peer_id();
    drop(sa); // "app restart": every in-memory byte of A's session is gone

    // While A is down, B keeps sending: queued in B's outbox.
    sb.send(b"b2-while-down").unwrap();

    let (sa2, how) = rig.restart_a(&sb);
    assert!(
        matches!(how, Reconnected::Resumed),
        "B must see the SAME session, not a new one"
    );
    assert!(sa2.was_restored());
    assert_eq!(sa2.peer_id(), peer_a);

    assert_eq!(recv_timeout(&sa2, "queued message"), b"b2-while-down");
    // The ratchets are in sync in both directions after the restart.
    sa2.send(b"a2-after-restart").unwrap();
    assert_eq!(recv_timeout(&sb, "a2"), b"a2-after-restart");
    sb.send(b"b3").unwrap();
    assert_eq!(recv_timeout(&sa2, "b3"), b"b3");
}

#[test]
fn messages_decrypted_but_not_yet_read_survive_a_restart() {
    let rig = Rig::new();
    let (sa, sb) = rig.connect();
    for i in 0..3 {
        sb.send(format!("unread-{i}").as_bytes()).unwrap();
    }
    // Wait until A's reader has decrypted them (they sit unread in A).
    thread::sleep(Duration::from_millis(300));
    drop(sa); // A never called recv()

    let (sa2, how) = rig.restart_a(&sb);
    assert!(matches!(how, Reconnected::Resumed));
    for i in 0..3 {
        assert_eq!(
            recv_timeout(&sa2, "unread"),
            format!("unread-{i}").as_bytes()
        );
    }
    assert!(sa2.try_recv().is_none(), "no duplicates once read");
}

#[test]
fn a_message_we_sent_but_the_peer_never_got_is_resent_after_restart() {
    let rig = Rig::new();
    let (ca, cb) = memory_pair(Duration::ZERO);
    let cut = ca.cutter();
    let (ra, rb) = (trusting(&rig.b), trusting(&rig.a));
    let (sa, sb) = thread::scope(|s| {
        let h = s.spawn(|| {
            Session::establish_over(
                Box::new(cb),
                Role::Responder,
                &rig.b,
                &rb,
                rig.cfg_b(),
                None,
            )
            .unwrap()
        });
        let sa = Session::establish_over(
            Box::new(ca),
            Role::Initiator,
            &rig.a,
            &ra,
            rig.cfg_a(),
            None,
        )
        .unwrap();
        (sa, h.join().unwrap())
    });
    sa.send(b"delivered").unwrap();
    assert_eq!(recv_timeout(&sb, "delivered"), b"delivered");
    thread::sleep(Duration::from_millis(200)); // let the ack land

    cut(); // link dies; A queues a message that cannot reach B
    sa.send(b"stuck-in-outbox").unwrap();
    drop(sa); // and A restarts before it was ever delivered

    let (sa2, how) = rig.restart_a(&sb);
    assert!(matches!(how, Reconnected::Resumed));
    assert_eq!(
        recv_timeout(&sb, "resent after restart"),
        b"stuck-in-outbox"
    );
    drop(sa2);
}

#[test]
fn if_the_peer_lost_its_state_our_saved_state_is_discarded() {
    let rig = Rig::new();
    let tr = CollectingTracer::new();
    let (sa, sb) = rig.connect();
    sa.send(b"x").unwrap();
    assert_eq!(recv_timeout(&sb, "x"), b"x");
    drop(sa);
    drop(sb); // B restarts too, WITHOUT persistence: fresh epoch

    let (ca, cb) = memory_pair(Duration::ZERO);
    let (ra, rb) = (trusting(&rig.b), trusting(&rig.a));
    let cfg_a = SessionConfig {
        tracer: tr.clone(),
        ..rig.cfg_a()
    };
    let (sa2, _sb2) = thread::scope(|s| {
        let h = s.spawn(|| {
            Session::establish_over(
                Box::new(cb),
                Role::Responder,
                &rig.b,
                &rb,
                SessionConfig::default(),
                None,
            )
            .unwrap()
        });
        let sa = Session::establish_over(Box::new(ca), Role::Initiator, &rig.a, &ra, cfg_a, None)
            .unwrap();
        (sa, h.join().unwrap())
    });
    assert!(
        !sa2.was_restored(),
        "must start fresh, not resume a dead ratchet"
    );
    assert!(tr.any(|e| matches!(e, TraceEvent::SessionStateDiscarded { .. })));
    // And the fresh session works.
    sa2.send(b"fresh").unwrap();
}

#[test]
fn a_corrupted_state_file_is_not_trusted() {
    let rig = Rig::new();
    let (sa, sb) = rig.connect();
    let key = format!("session-{}", sa.peer_id());
    drop(sa);
    drop(sb);
    // Flip a byte in A's saved state.
    let mut blob = rig.store_a.get(&key).unwrap().expect("state was saved");
    let n = blob.len();
    blob[n / 2] ^= 0x01;
    rig.store_a.put(&key, &blob).unwrap();

    let tr = CollectingTracer::new();
    let (ca, cb) = memory_pair(Duration::ZERO);
    let (ra, rb) = (trusting(&rig.b), trusting(&rig.a));
    let cfg_a = SessionConfig {
        tracer: tr.clone(),
        ..rig.cfg_a()
    };
    let (sa2, _sb2) = thread::scope(|s| {
        let h = s.spawn(|| {
            Session::establish_over(
                Box::new(cb),
                Role::Responder,
                &rig.b,
                &rb,
                SessionConfig::default(),
                None,
            )
            .unwrap()
        });
        let sa = Session::establish_over(Box::new(ca), Role::Initiator, &rig.a, &ra, cfg_a, None)
            .unwrap();
        (sa, h.join().unwrap())
    });
    assert!(!sa2.was_restored());
    assert!(tr.any(|e| matches!(
        e,
        TraceEvent::SessionStateDiscarded {
            reason: "saved state unreadable",
            ..
        }
    )));
}

#[test]
fn state_is_not_readable_without_the_identity_key() {
    let rig = Rig::new();
    let (sa, _sb) = rig.connect();
    let key = format!("session-{}", sa.peer_id());
    let blob = rig.store_a.get(&key).unwrap().unwrap();
    // No plaintext ratchet key material in the file: the 32-byte secret of
    // identity A must not appear, nor the literal magic.
    assert!(!blob.windows(4).any(|w| w == b"SYMS"));
    assert!(!blob.windows(32).any(|w| w == rig.a.secret_bytes()));
}

/// A store that can be told to fail every write.
struct Flaky {
    inner: MemoryStateStore,
    fail: AtomicBool,
}
impl StateStore for Flaky {
    fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ChatError::Io(std::io::Error::other("disk full")));
        }
        self.inner.put(key, value)
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(key)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key)
    }
    fn keys(&self) -> Result<Vec<String>> {
        self.inner.keys()
    }
}

#[test]
fn a_failed_save_refuses_the_send_and_leaves_the_session_usable() {
    let (a, b) = (Identity::generate(), Identity::generate());
    let flaky = Arc::new(Flaky {
        inner: MemoryStateStore::new(),
        fail: AtomicBool::new(false),
    });
    let cfg_a = SessionConfig {
        persistence: Some(SessionPersistence::new(flaky.clone(), &a)),
        ..SessionConfig::default()
    };
    let (ca, cb) = memory_pair(Duration::ZERO);
    let (ra, rb) = (trusting(&b), trusting(&a));
    let (sa, sb) = thread::scope(|s| {
        let h = s.spawn(|| {
            Session::establish_over(
                Box::new(cb),
                Role::Responder,
                &b,
                &rb,
                SessionConfig::default(),
                None,
            )
            .unwrap()
        });
        let sa =
            Session::establish_over(Box::new(ca), Role::Initiator, &a, &ra, cfg_a, None).unwrap();
        (sa, h.join().unwrap())
    });
    sa.send(b"one").unwrap();
    assert_eq!(recv_timeout(&sb, "one"), b"one");

    flaky.fail.store(true, Ordering::SeqCst);
    assert!(
        sa.send(b"refused").is_err(),
        "must not send when the state cannot be saved"
    );
    assert!(!sa.persistence_healthy());

    flaky.fail.store(false, Ordering::SeqCst);
    // The refused send was rolled back completely: the next message is the
    // very next one in sequence and the peer's ratchet still agrees.
    sa.send(b"two").unwrap();
    assert_eq!(recv_timeout(&sb, "two"), b"two");
    assert!(sa.persistence_healthy());
    assert!(
        sb.try_recv().is_none(),
        "the refused message must never have been sent"
    );
}

#[test]
fn an_older_session_cannot_send_once_a_newer_one_owns_the_saved_state() {
    let rig = Rig::new();
    let (sa_old, sb) = rig.connect();
    sa_old.send(b"before").unwrap();
    assert_eq!(recv_timeout(&sb, "before"), b"before");

    // A second session for the same peer comes up while the first object is
    // still alive (e.g. a redial before the old one was dropped).
    let (sa_new, how) = rig.restart_a(&sb);
    assert!(matches!(how, Reconnected::Resumed));

    // Two sessions writing one saved state would fork the ratchet and reuse
    // keys, so the old one is refused.
    match sa_old.send(b"from the stale session") {
        Err(ChatError::SessionSuperseded) => {}
        other => panic!("expected SessionSuperseded, got {other:?}"),
    }
    // The new one is unaffected.
    sa_new.send(b"after").unwrap();
    assert_eq!(recv_timeout(&sb, "after"), b"after");
}
