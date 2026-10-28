//! End-to-end tests that exercise the whole stack over *real* TCP sockets
//! on loopback - no mocked transport - covering the properties asked for:
//!
//! - mutual authentication (and rejection of unpinned peers),
//! - confidentiality/integrity (tamper detection),
//! - no missing messages across a disconnect + reconnect, still in order.

use symbolon::identity::Identity;
use symbolon::peer::PeerRegistry;
use symbolon::session::{Role, Session};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

/// Spin up a listener on an OS-assigned free port and return it plus the
/// address to connect to.
fn bind_listener() -> (TcpListener, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    (listener, addr)
}

/// Two identities, each pinning the other's public key - the out-of-band
/// trust step every real deployment must do once, up front.
fn make_mutually_trusting_pair() -> (Identity, PeerRegistry, Identity, PeerRegistry) {
    let alice = Identity::generate();
    let bob = Identity::generate();

    let mut alice_registry = PeerRegistry::new();
    alice_registry.trust(bob.public_key());

    let mut bob_registry = PeerRegistry::new();
    bob_registry.trust(alice.public_key());

    (alice, alice_registry, bob, bob_registry)
}

#[test]
fn handshake_succeeds_and_both_sides_learn_the_correct_peer_fingerprint() {
    let (alice, alice_registry, bob, bob_registry) = make_mutually_trusting_pair();
    let (listener, addr) = bind_listener();

    let bob_identity_fingerprint = bob.fingerprint();
    let alice_identity_fingerprint = alice.fingerprint();

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        Session::establish(stream, Role::Responder, &bob, &bob_registry).expect("bob handshake")
    });

    let client_stream = TcpStream::connect(addr).expect("connect");
    let client_session =
        Session::establish(client_stream, Role::Initiator, &alice, &alice_registry).expect("alice handshake");

    let server_session = server.join().expect("server thread");

    // Each side should have authenticated the *other* party's identity, not
    // its own.
    assert_eq!(client_session.peer_id(), bob_identity_fingerprint);
    assert_eq!(server_session.peer_id(), alice_identity_fingerprint);
}

#[test]
fn rejects_handshake_from_a_peer_whose_key_is_not_pinned() {
    // Bob only trusts Alice; Mallory has her own, different keypair and is
    // not in anyone's registry.
    let alice = Identity::generate();
    let mallory = Identity::generate();
    let bob = Identity::generate();

    let mut bob_registry = PeerRegistry::new();
    bob_registry.trust(alice.public_key());
    let mallory_registry = PeerRegistry::new(); // Mallory trusts nobody in particular here

    let (listener, addr) = bind_listener();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        // Bob will reject Mallory before completing the handshake.
        Session::establish(stream, Role::Responder, &bob, &bob_registry)
    });

    let client_stream = TcpStream::connect(addr).expect("connect");
    let client_result = Session::establish(client_stream, Role::Initiator, &mallory, &mallory_registry);

    let server_result = server.join().expect("server thread");

    assert!(client_result.is_err(), "Mallory's handshake should be refused");
    assert!(server_result.is_err(), "Bob must refuse an untrusted identity");
}

#[test]
fn messages_are_delivered_in_order_both_directions() {
    let (alice, alice_registry, bob, bob_registry) = make_mutually_trusting_pair();
    let (listener, addr) = bind_listener();

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        Session::establish(stream, Role::Responder, &bob, &bob_registry).expect("bob handshake")
    });

    let client_stream = TcpStream::connect(addr).expect("connect");
    let alice_session =
        Session::establish(client_stream, Role::Initiator, &alice, &alice_registry).expect("alice handshake");
    let bob_session = server.join().expect("server thread");

    for i in 0..5u32 {
        alice_session.send(format!("alice says {i}").as_bytes()).unwrap();
    }
    for i in 0..5u32 {
        bob_session.send(format!("bob says {i}").as_bytes()).unwrap();
    }

    for i in 0..5u32 {
        let msg = bob_session.recv().unwrap();
        assert_eq!(msg, format!("alice says {i}").as_bytes());
    }
    for i in 0..5u32 {
        let msg = alice_session.recv().unwrap();
        assert_eq!(msg, format!("bob says {i}").as_bytes());
    }
}

/// Poll `condition` until it's true or `timeout` elapses. Used to wait for
/// asynchronous effects (like an ack arriving on the background reader
/// thread) without hard-coding a fixed sleep duration.
fn wait_until<F: Fn() -> bool>(condition: F, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if condition() {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    condition()
}

#[test]
fn no_message_is_lost_across_a_disconnect_and_reconnect() {
    // This is the core "reliability" guarantee: if a message was sent while
    // the peer was unreachable (or the ack for it never arrived before the
    // link died), reconnecting must deliver it - still in order, still
    // exactly once.
    let (alice, alice_registry, bob, bob_registry) = make_mutually_trusting_pair();
    let (listener, addr) = bind_listener();

    // --- First connection ---
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let session = Session::establish(stream, Role::Responder, &bob, &bob_registry).expect("bob handshake");
        // Hand back everything the test still needs after the handshake:
        // the live session, and the identity/registry so we can reconnect
        // later (both are needed again and neither is `Clone`, by design -
        // trust decisions shouldn't be casually duplicated).
        (session, bob, bob_registry)
    });

    let client_stream = TcpStream::connect(addr).expect("connect");
    // Keep a raw handle so the test can forcibly sever the connection,
    // independent of whatever Session does with its own clone of the fd.
    let killable_client_stream = client_stream.try_clone().expect("clone");
    let alice_session =
        Session::establish(client_stream, Role::Initiator, &alice, &alice_registry).expect("alice handshake");
    let (bob_session, bob, bob_registry) = server.join().expect("server thread");

    // Message 1 goes through normally.
    alice_session.send(b"message one").unwrap();
    assert_eq!(bob_session.recv().unwrap(), b"message one");
    // Bob delivering the message to its application layer happens slightly
    // before his ack for it makes it back across the wire and gets
    // processed by Alice's outbox - wait for that round trip to finish so
    // the next step deals only with "message two", not a race against
    // "message one"'s own ack.
    assert!(
        wait_until(|| alice_session.pending_unacked() == 0, Duration::from_secs(2)),
        "ack for message one never arrived"
    );

    // Sever the connection *before* message two is sent, so Alice's write
    // for it is guaranteed to fail / never reach Bob over this connection -
    // simulating "sent while disconnected".
    let _ = killable_client_stream.shutdown(std::net::Shutdown::Both);
    thread::sleep(Duration::from_millis(50)); // let the OS tear things down

    // This still stages the message in Alice's outbox even though the
    // write to the now-dead socket fails.
    let _ = alice_session.send(b"message two");
    assert_eq!(alice_session.pending_unacked(), 1, "message two must still be pending");

    // --- Bob comes back online: rebind a fresh listener/connection pair ---
    let (listener2, addr2) = bind_listener();

    let server2 = thread::spawn(move || {
        let (stream, _) = listener2.accept().expect("accept");
        bob_session
            .reconnect(stream, Role::Responder, &bob, &bob_registry)
            .expect("bob reconnect");
        bob_session
    });

    let new_client_stream = TcpStream::connect(addr2).expect("connect");
    alice_session
        .reconnect(new_client_stream, Role::Initiator, &alice, &alice_registry)
        .expect("alice reconnect");
    let bob_session = server2.join().expect("server2 thread");

    // Bob should now receive "message two" automatically, without Alice
    // needing to resend it manually - the reconnect handshake's resume
    // exchange takes care of it.
    let recovered = bob_session.recv().unwrap();
    assert_eq!(recovered, b"message two");

    // And normal sending still works fine afterwards, continuing the same
    // sequence-number stream (not restarting from 1).
    alice_session.send(b"message three").unwrap();
    assert_eq!(bob_session.recv().unwrap(), b"message three");
}

#[test]
fn negotiated_protocol_version_is_reported_on_both_sides() {
    let (alice, alice_registry, bob, bob_registry) = make_mutually_trusting_pair();
    let (listener, addr) = bind_listener();
    let alice_fingerprint = alice.fingerprint();
    let bob_fingerprint = bob.fingerprint();

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        Session::establish(stream, Role::Responder, &bob, &bob_registry).expect("bob handshake")
    });
    let client_stream = TcpStream::connect(addr).expect("connect");
    let alice_session =
        Session::establish(client_stream, Role::Initiator, &alice, &alice_registry).expect("alice handshake");
    let bob_session = server.join().expect("server thread");

    use symbolon::handshake::PROTOCOL_VERSION_CURRENT;
    assert_eq!(alice_session.negotiated_version(), PROTOCOL_VERSION_CURRENT);
    assert_eq!(bob_session.negotiated_version(), PROTOCOL_VERSION_CURRENT);
    // And each session knows its own identity as well as its peer's.
    assert_eq!(alice_session.own_id(), &alice_fingerprint);
    assert_eq!(bob_session.own_id(), &bob_fingerprint);
}

#[test]
fn handshake_progress_callback_reports_every_step_in_order() {
    use symbolon::handshake::HandshakeProgress;
    use symbolon::session::SessionConfig;

    let (alice, alice_registry, bob, bob_registry) = make_mutually_trusting_pair();
    let (listener, addr) = bind_listener();
    let bob_fingerprint = bob.fingerprint();

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        Session::establish(stream, Role::Responder, &bob, &bob_registry).expect("bob handshake")
    });

    let client_stream = TcpStream::connect(addr).expect("connect");
    let mut events = Vec::new();
    let mut on_progress = |e: HandshakeProgress| events.push(e);
    let alice_session = Session::establish_with(
        client_stream,
        Role::Initiator,
        &alice,
        &alice_registry,
        SessionConfig::default(),
        Some(&mut on_progress),
    )
    .expect("alice handshake");
    let _bob_session = server.join().expect("server thread");
    let _ = alice_session;

    // A UI watching this would see, in order: started, version negotiated,
    // the peer's claimed identity, that identity being in our trust store,
    // their signature checking out, and finally full completion - each
    // step strictly more "verified" than the last.
    assert!(matches!(events[0], HandshakeProgress::Started));
    assert!(matches!(events[1], HandshakeProgress::VersionNegotiated(1)));
    assert!(matches!(&events[2], HandshakeProgress::PeerIdentityClaimed(id) if *id == bob_fingerprint));
    assert!(matches!(&events[3], HandshakeProgress::PeerIdentityTrusted(id) if *id == bob_fingerprint));
    assert!(matches!(&events[4], HandshakeProgress::PeerSignatureVerified(id) if *id == bob_fingerprint));
    assert!(matches!(&events[5], HandshakeProgress::Completed { peer_id, negotiated_version: 1 } if *peer_id == bob_fingerprint));
}

#[test]
fn handshake_times_out_against_an_unresponsive_peer_instead_of_hanging_forever() {
    use symbolon::session::SessionConfig;

    let alice = Identity::generate();
    let mut alice_registry = PeerRegistry::new();
    // It doesn't even matter whether the peer is trusted - nothing is ever
    // sent, so we should time out before we'd even get to check that.
    let (listener, addr) = bind_listener();

    // A "peer" that accepts the TCP connection but then never speaks -
    // simulating an unresponsive or deliberately stalling counterpart.
    let _silent_peer = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        // Hold the connection open without ever writing anything, long
        // enough for the timeout below to fire.
        thread::sleep(Duration::from_secs(2));
        drop(stream);
    });

    let client_stream = TcpStream::connect(addr).expect("connect");
    let config = SessionConfig { handshake_timeout: Some(Duration::from_millis(200)) };
    let start = std::time::Instant::now();
    let result = Session::establish_with(client_stream, Role::Initiator, &alice, &alice_registry, config, None);
    let elapsed = start.elapsed();

    match result {
        Err(symbolon::ChatError::HandshakeTimedOut) => {}
        Err(_other) => panic!("expected a HandshakeTimedOut error, got a different error instead"),
        Ok(_) => panic!("handshake against a silent peer must fail, not succeed"),
    }
    assert!(
        elapsed < Duration::from_secs(1),
        "handshake should have timed out around 200ms, took {elapsed:?} instead"
    );
    let _ = &mut alice_registry; // keep registry alive/used for clarity
}

#[test]
fn tampered_ciphertext_is_rejected_not_silently_accepted() {
    use symbolon::crypto::{decrypt, encrypt, AeadKey, Channel};

    let key = AeadKey([9u8; 32]);
    let ciphertext = encrypt(&key, Channel::Data, 1, b"", b"transfer $10").unwrap();

    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0x01;

    // The legitimate ciphertext decrypts fine...
    assert_eq!(decrypt(&key, Channel::Data, 1, b"", &ciphertext).unwrap(), b"transfer $10");
    // ...but any bit-flip anywhere is caught, never silently "decrypted"
    // into corrupted-but-accepted plaintext.
    assert!(decrypt(&key, Channel::Data, 1, b"", &tampered).is_err());
}

/// Connect two sessions over loopback TCP; returns (initiator, responder).
fn connected_pair() -> (Session, Session) {
    let (alice, alice_registry, bob, bob_registry) = make_mutually_trusting_pair();
    let (listener, addr) = bind_listener();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        Session::establish(stream, Role::Responder, &bob, &bob_registry).expect("bob handshake")
    });
    let client = TcpStream::connect(addr).expect("connect");
    let a = Session::establish(client, Role::Initiator, &alice, &alice_registry).expect("alice handshake");
    (a, server.join().expect("server thread"))
}

#[test]
fn the_responder_can_send_before_it_has_received_anything() {
    // The textbook Double Ratchet forces the responder to wait for the first
    // message. A chat session can't, so the first chain is pre-seeded.
    let (alice, bob) = connected_pair();
    bob.send(b"bob speaks first").unwrap();
    bob.send(b"and again").unwrap();
    assert_eq!(alice.recv().unwrap(), b"bob speaks first");
    assert_eq!(alice.recv().unwrap(), b"and again");
    alice.send(b"alice answers").unwrap();
    assert_eq!(bob.recv().unwrap(), b"alice answers");
}

#[test]
fn a_long_two_way_conversation_keeps_every_ratchet_turn_in_sync_over_tcp() {
    let (alice, bob) = connected_pair();
    for i in 0..200u32 {
        let (tx, rx) = if i % 3 == 0 { (&bob, &alice) } else { (&alice, &bob) };
        let msg = format!("message {i}");
        tx.send(msg.as_bytes()).unwrap();
        assert_eq!(rx.recv().unwrap(), msg.as_bytes());
    }
}

#[test]
fn bursts_in_both_directions_at_once_do_not_desynchronise_the_ratchets() {
    let (alice, bob) = connected_pair();
    let alice = std::sync::Arc::new(alice);
    let bob = std::sync::Arc::new(bob);

    let (a2, b2) = (alice.clone(), bob.clone());
    let t1 = thread::spawn(move || {
        for i in 0..100u32 {
            a2.send(format!("a{i}").as_bytes()).unwrap();
        }
    });
    let t2 = thread::spawn(move || {
        for i in 0..100u32 {
            b2.send(format!("b{i}").as_bytes()).unwrap();
        }
    });
    for i in 0..100u32 {
        assert_eq!(bob.recv().unwrap(), format!("a{i}").as_bytes());
        assert_eq!(alice.recv().unwrap(), format!("b{i}").as_bytes());
    }
    t1.join().unwrap();
    t2.join().unwrap();
}

#[test]
fn concurrent_senders_on_one_session_still_decrypt_in_sequence_order() {
    // Two threads share one Session. The ratchet and the sequence number
    // are assigned under one lock, so whatever interleaving happens, the
    // receiver sees a consistent order and nothing fails to decrypt.
    let (alice, bob) = connected_pair();
    let alice = std::sync::Arc::new(alice);
    let mut handles = Vec::new();
    for t in 0..4u8 {
        let a = alice.clone();
        handles.push(thread::spawn(move || {
            for i in 0..50u8 {
                a.send(&[t, i]).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let mut last_seen = [None::<u8>; 4];
    for _ in 0..200 {
        let m = bob.recv().expect("every message must decrypt");
        let (t, i) = (m[0] as usize, m[1]);
        if let Some(prev) = last_seen[t] {
            assert!(i > prev, "per-thread order violated");
        }
        last_seen[t] = Some(i);
    }
}
