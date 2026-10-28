//! End-to-end group chat tests over *real* TCP connections: every member
//! pair gets its own genuine mutually-authenticated `Session` (same
//! handshake, same AEAD, same reliability as the 1:1 tests), wired together
//! full-mesh via `GroupHub`.

use symbolon::group::{GroupEvent, GroupHub, Roster};
use symbolon::identity::Identity;
use symbolon::peer::PeerRegistry;
use symbolon::session::{Role, Session};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn bind_listener() -> (TcpListener, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    (listener, addr)
}

/// Establish one real, mutually-authenticated pairwise session between two
/// identities who already trust each other's keys (out-of-band pinning,
/// same as every 1:1 test does). Uses a scoped thread so both sides can
/// borrow `a`/`b`/their registries directly - no unsafe, no cloning needed.
fn establish_pair(a: &Identity, a_registry: &PeerRegistry, b: &Identity, b_registry: &PeerRegistry) -> (Session, Session) {
    let (listener, addr) = bind_listener();
    thread::scope(|scope| {
        let server = scope.spawn(|| {
            let (stream, _) = listener.accept().expect("accept");
            Session::establish(stream, Role::Responder, b, b_registry).expect("responder handshake")
        });
        let stream = TcpStream::connect(addr).expect("connect");
        let a_session = Session::establish(stream, Role::Initiator, a, a_registry).expect("initiator handshake");
        let b_session = server.join().expect("server thread");
        (a_session, b_session)
    })
}

/// Pin every identity's key into every other identity's registry - the
/// out-of-band trust step, done once up front for the whole group.
fn mutually_trust_all(identities: &[&Identity]) -> Vec<PeerRegistry> {
    identities
        .iter()
        .map(|me| {
            let mut registry = PeerRegistry::new();
            for other in identities {
                if !std::ptr::eq(*me, *other) {
                    registry.trust(other.public_key());
                }
            }
            registry
        })
        .collect()
}

#[test]
fn three_member_group_delivers_broadcasts_to_everyone() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let carol = Identity::generate();
    let registries = mutually_trust_all(&[&alice, &bob, &carol]);
    let (alice_registry, bob_registry, carol_registry) = (&registries[0], &registries[1], &registries[2]);

    // Found the group with all three as genesis members.
    let (alice_roster, genesis) = Roster::genesis_default(&alice, vec![bob.public_key(), carol.public_key()]);
    let bob_roster = Roster::from_genesis(&genesis).expect("bob accepts genesis");
    let carol_roster = Roster::from_genesis(&genesis).expect("carol accepts genesis");

    let alice_hub = GroupHub::new(&alice, alice_roster);
    let bob_hub = GroupHub::new(&bob, bob_roster);
    let carol_hub = GroupHub::new(&carol, carol_roster);

    // Full mesh: one real pairwise session per pair (3 pairs for 3 members).
    let (a_ab, b_ab) = establish_pair(&alice, alice_registry, &bob, bob_registry);
    let (a_ac, c_ac) = establish_pair(&alice, alice_registry, &carol, carol_registry);
    let (b_bc, c_bc) = establish_pair(&bob, bob_registry, &carol, carol_registry);

    alice_hub.attach_session(bob.fingerprint(), Arc::new(a_ab));
    alice_hub.attach_session(carol.fingerprint(), Arc::new(a_ac));
    bob_hub.attach_session(alice.fingerprint(), Arc::new(b_ab));
    bob_hub.attach_session(carol.fingerprint(), Arc::new(b_bc));
    carol_hub.attach_session(alice.fingerprint(), Arc::new(c_ac));
    carol_hub.attach_session(bob.fingerprint(), Arc::new(c_bc));

    // Alice broadcasts; Bob and Carol should each receive it, correctly
    // attributed to Alice (sender authentication comes from *which*
    // authenticated session it arrived on, not a claimed field).
    alice_hub.broadcast(&alice, b"hello group").unwrap();

    match bob_hub.recv_event().unwrap() {
        GroupEvent::Message { sender, payload, .. } => {
            assert_eq!(sender, alice.fingerprint());
            assert_eq!(payload, b"hello group");
        }
        other => panic!("expected a message, got {other:?}"),
    }

    match carol_hub.recv_event().unwrap() {
        GroupEvent::Message { sender, payload, .. } => {
            assert_eq!(sender, alice.fingerprint());
            assert_eq!(payload, b"hello group");
        }
        other => panic!("expected a message, got {other:?}"),
    }

    // And messages flow the other direction too.
    bob_hub.broadcast(&bob, b"hi alice").unwrap();
    match alice_hub.recv_event().unwrap() {
        GroupEvent::Message { sender, payload, .. } => {
            assert_eq!(sender, bob.fingerprint());
            assert_eq!(payload, b"hi alice");
        }
        other => panic!("expected a message, got {other:?}"),
    }
}

#[test]
fn removed_member_loses_access_even_though_their_link_stays_open() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let carol = Identity::generate();
    let registries = mutually_trust_all(&[&alice, &bob, &carol]);
    let (alice_registry, bob_registry, carol_registry) = (&registries[0], &registries[1], &registries[2]);

    let (alice_roster, genesis) = Roster::genesis_default(&alice, vec![bob.public_key(), carol.public_key()]);
    let bob_roster = Roster::from_genesis(&genesis).unwrap();
    let carol_roster = Roster::from_genesis(&genesis).unwrap();

    let alice_hub = GroupHub::new(&alice, alice_roster);
    let bob_hub = GroupHub::new(&bob, bob_roster);
    let carol_hub = GroupHub::new(&carol, carol_roster);

    let (a_ab, b_ab) = establish_pair(&alice, alice_registry, &bob, bob_registry);
    let (a_ac, c_ac) = establish_pair(&alice, alice_registry, &carol, carol_registry);
    let (b_bc, c_bc) = establish_pair(&bob, bob_registry, &carol, carol_registry);

    alice_hub.attach_session(bob.fingerprint(), Arc::new(a_ab));
    alice_hub.attach_session(carol.fingerprint(), Arc::new(a_ac));
    bob_hub.attach_session(alice.fingerprint(), Arc::new(b_ab));
    bob_hub.attach_session(carol.fingerprint(), Arc::new(b_bc));
    carol_hub.attach_session(alice.fingerprint(), Arc::new(c_ac));
    carol_hub.attach_session(bob.fingerprint(), Arc::new(c_bc));

    // Alice removes Carol. The signed Remove op is broadcast over every
    // attached session, so Bob and (harmlessly) Carol herself both receive
    // and apply it.
    alice_hub.propose_remove(&alice, carol.fingerprint()).unwrap();

    match bob_hub.recv_event().unwrap() {
        GroupEvent::MembershipChanged { members } => {
            assert_eq!(members.len(), 2);
            assert!(!members.contains(&carol.fingerprint()));
        }
        other => panic!("expected a membership change, got {other:?}"),
    }
    assert!(!bob_hub.is_member(&carol.fingerprint()));
    assert!(!alice_hub.is_member(&carol.fingerprint()));

    // Carol's pairwise TCP links to Alice and Bob are still technically
    // open (nobody tore down the socket) - but her own hub already knows
    // she's been removed (her roster permissions dropped to `NONE`, same
    // property `removed_member_permissions_drop_to_none` checks directly
    // on `Roster`), so `post`/`broadcast` now fails *locally*, fail-fast,
    // before anything even goes out on the wire.
    //
    // Carol's hub applies the Remove op on its own background thread, so on a
    // slow machine (a Pi, or any loaded CPU) it may not have processed it yet
    // when we get here. Wait for *her* hub to catch up before asserting what
    // she can do - otherwise this test checks a race, not the permission rule.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while carol_hub.is_member(&carol.fingerprint()) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!carol_hub.is_member(&carol.fingerprint()), "Carol's hub never applied her own removal");
    let result = carol_hub.broadcast(&carol, b"can anyone still hear me?");
    assert!(matches!(result, Err(symbolon::ChatError::PermissionDenied)));

    // The group keeps working normally for everyone still in it.
    alice_hub.broadcast(&alice, b"carol is gone, group continues").unwrap();
    match bob_hub.recv_event_timeout(Duration::from_secs(2)) {
        Some(GroupEvent::Message { sender, payload, .. }) => {
            assert_eq!(sender, alice.fingerprint());
            assert_eq!(payload, b"carol is gone, group continues");
        }
        other => panic!("expected Alice's message, got {other:?}"),
    }
}

#[test]
fn offline_originators_message_reaches_a_member_via_relay_through_someone_else() {
    // The core scenario this whole redesign was for: Alice posts a
    // message. Carol has *never even connected to Alice directly* - only
    // to Bob. When Carol asks the mesh to catch her up, Bob (who has
    // Alice's message cached) relays it to her, and Carol verifies it
    // against Alice's key from her own roster - obtained at genesis,
    // without ever talking to Alice's `Session` at all.
    let alice = Identity::generate();
    let bob = Identity::generate();
    let carol = Identity::generate();

    // Deliberately asymmetric trust/connectivity: Alice and Carol never
    // pin each other's keys for a *pairwise Session*, and never establish
    // one - only Alice<->Bob and Bob<->Carol sessions exist.
    let mut alice_registry = PeerRegistry::new();
    alice_registry.trust(bob.public_key());
    let mut bob_registry = PeerRegistry::new();
    bob_registry.trust(alice.public_key());
    bob_registry.trust(carol.public_key());
    let mut carol_registry = PeerRegistry::new();
    carol_registry.trust(bob.public_key());

    // The roster still lists all three (genesis carries every founding
    // member's public key), so Carol *can* verify Alice's signature even
    // without ever having connected to her.
    let (alice_roster, genesis) = Roster::genesis_default(&alice, vec![bob.public_key(), carol.public_key()]);
    let bob_roster = Roster::from_genesis(&genesis).unwrap();
    let carol_roster = Roster::from_genesis(&genesis).unwrap();

    let alice_hub = GroupHub::new(&alice, alice_roster);
    let bob_hub = GroupHub::new(&bob, bob_roster);
    let carol_hub = GroupHub::new(&carol, carol_roster);

    let (a_ab, b_ab) = establish_pair(&alice, &alice_registry, &bob, &bob_registry);
    let (b_bc, c_bc) = establish_pair(&bob, &bob_registry, &carol, &carol_registry);

    alice_hub.attach_session(bob.fingerprint(), Arc::new(a_ab));
    bob_hub.attach_session(alice.fingerprint(), Arc::new(b_ab));
    bob_hub.attach_session(carol.fingerprint(), Arc::new(b_bc));
    carol_hub.attach_session(bob.fingerprint(), Arc::new(c_bc));
    // Note: no alice_hub <-> carol_hub session exists at all.

    // Alice posts. It can only reach Bob directly.
    alice_hub.post(&alice, b"the launch code is 4-8-15-16-23-42").unwrap();
    match bob_hub.recv_event().unwrap() {
        GroupEvent::Message { sender, payload, .. } => {
            assert_eq!(sender, alice.fingerprint());
            assert_eq!(payload, b"the launch code is 4-8-15-16-23-42");
        }
        other => panic!("expected Alice's message via Bob, got {other:?}"),
    }

    // Carol asks the mesh to catch her up. Her only link is to Bob, so the
    // request necessarily goes to him.
    carol_hub.request_catchup().unwrap();

    match carol_hub.recv_event_timeout(Duration::from_secs(2)) {
        Some(GroupEvent::Message { sender, payload, .. }) => {
            assert_eq!(sender, alice.fingerprint(), "message must be attributed to Alice, not Bob who relayed it");
            assert_eq!(payload, b"the launch code is 4-8-15-16-23-42");
        }
        other => panic!("expected Alice's relayed message via Bob, got {other:?}"),
    }
}

#[test]
fn a_member_without_write_permission_cannot_post() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let registries = mutually_trust_all(&[&alice, &bob]);
    let (alice_registry, bob_registry) = (&registries[0], &registries[1]);

    // A group where the "member" tier is read-only from the start.
    let tiers = vec![("owner".to_string(), symbolon::group::Permissions::FULL), ("member".to_string(), symbolon::group::Permissions { can_add: false, can_remove: false, can_read: true, can_write: false })];
    let (alice_roster, genesis) = Roster::genesis(&alice, tiers, vec![(alice.public_key(), "owner".to_string()), (bob.public_key(), "member".to_string())]);
    let bob_roster = Roster::from_genesis(&genesis).unwrap();

    let alice_hub = GroupHub::new(&alice, alice_roster);
    let bob_hub = GroupHub::new(&bob, bob_roster);
    let (a_ab, b_ab) = establish_pair(&alice, alice_registry, &bob, bob_registry);
    alice_hub.attach_session(bob.fingerprint(), Arc::new(a_ab));
    bob_hub.attach_session(alice.fingerprint(), Arc::new(b_ab));

    // Bob (read-only) can't post...
    let result = bob_hub.post(&bob, b"can I say something?");
    assert!(matches!(result, Err(symbolon::ChatError::PermissionDenied)));

    // ...but Alice (owner) still can, and Bob still receives it (can_read
    // is untouched).
    alice_hub.post(&alice, b"announcement: read-only channel").unwrap();
    match bob_hub.recv_event().unwrap() {
        GroupEvent::Message { sender, .. } => assert_eq!(sender, alice.fingerprint()),
        other => panic!("expected Alice's announcement, got {other:?}"),
    }
}

#[test]
fn author_can_edit_and_delete_their_own_message_and_a_moderator_can_delete_someone_elses() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let registries = mutually_trust_all(&[&alice, &bob]);
    let (alice_registry, bob_registry) = (&registries[0], &registries[1]);

    let (alice_roster, genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
    let bob_roster = Roster::from_genesis(&genesis).unwrap();
    let alice_hub = GroupHub::new(&alice, alice_roster); // alice: owner (can_remove)
    let bob_hub = GroupHub::new(&bob, bob_roster); // bob: plain member

    let (a_ab, b_ab) = establish_pair(&alice, alice_registry, &bob, bob_registry);
    alice_hub.attach_session(bob.fingerprint(), Arc::new(a_ab));
    bob_hub.attach_session(alice.fingerprint(), Arc::new(b_ab));

    // Bob posts, then edits his own message.
    let seq = bob_hub.post(&bob, b"typo: meting at 3pm").unwrap();
    match alice_hub.recv_event().unwrap() {
        GroupEvent::Message { sender, payload, seq: got_seq } => {
            assert_eq!(sender, bob.fingerprint());
            assert_eq!(payload, b"typo: meting at 3pm");
            assert_eq!(got_seq, seq);
        }
        other => panic!("expected Bob's post, got {other:?}"),
    }

    bob_hub.edit(&bob, seq, b"meeting at 3pm").unwrap();
    match alice_hub.recv_event().unwrap() {
        GroupEvent::MessageEdited { author, seq: got_seq, new_payload } => {
            assert_eq!(author, bob.fingerprint());
            assert_eq!(got_seq, seq);
            assert_eq!(new_payload, b"meeting at 3pm");
        }
        other => panic!("expected an edit event, got {other:?}"),
    }

    // Alice (owner, can_remove) moderates the message away.
    alice_hub.delete(&alice, bob.fingerprint(), seq).unwrap();
    match bob_hub.recv_event().unwrap() {
        GroupEvent::MessageDeleted { author, seq: got_seq, deleted_by } => {
            assert_eq!(author, bob.fingerprint());
            assert_eq!(got_seq, seq);
            assert_eq!(deleted_by, alice.fingerprint());
        }
        other => panic!("expected a delete event, got {other:?}"),
    }
}

#[test]
fn a_persisted_group_survives_a_full_restart() {
    use symbolon::group::GroupHubConfig;

    let alice = Identity::generate();
    let bob = Identity::generate();
    let path = std::env::temp_dir().join(format!("p2p-group-persist-test-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&path);

    // --- "First run": found the group, do some things, then drop everything ---
    {
        let (alice_roster, genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
        let alice_hub = GroupHub::create_persisted(&alice, alice_roster, &genesis, &path, GroupHubConfig::default()).unwrap();

        // No sessions attached at all - this is purely local state, no
        // network involved, which is exactly the point: persistence must
        // work independent of connectivity.
        let seq = alice_hub.post(&alice, b"first draft").unwrap();
        alice_hub.edit(&alice, seq, b"first draft, corrected").unwrap();
        alice_hub.post(&alice, b"a second message").unwrap();

        let promote = alice_hub.propose_add(&alice, bob.public_key(), "owner".to_string());
        let _ = promote; // bob is already a member via genesis; just exercising a roster op path
        alice_hub
            .propose_define_tier(&alice, "member".to_string(), symbolon::group::Permissions::READ_WRITE)
            .unwrap();

        // hub is dropped here, along with all its in-memory state.
    }

    // --- "Restart": reload purely from the encrypted log on disk ---
    let reloaded = GroupHub::load_persisted(&alice, &path, GroupHubConfig::default()).unwrap();

    assert!(reloaded.is_member(&alice.fingerprint()));
    assert!(reloaded.is_member(&bob.fingerprint()));
    assert_eq!(reloaded.tier_of(&alice.fingerprint()), Some("owner".to_string()));

    let history = reloaded.history_for(&alice.fingerprint());
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].1, b"first draft, corrected", "the edit must have been replayed, not just the original post");
    assert!(history[0].2, "message 1 should be marked edited");
    assert!(!history[0].3, "message 1 should not be marked deleted");
    assert_eq!(history[1].1, b"a second message");

    // And the group is still fully usable after reload - posting continues
    // the sequence rather than restarting it. Three prior events were
    // authored (post, edit, post), so the next one is seq 4 - `history_for`
    // shows 2 *stored messages* because the edit updated message 1 in
    // place rather than creating a new entry, but each authored event
    // still consumes its own position in the sender's chain.
    let next_seq = reloaded.post(&alice, b"continuing after restart").unwrap();
    assert_eq!(next_seq, 4);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn loading_a_persisted_group_with_the_wrong_identity_fails_closed() {
    use symbolon::group::GroupHubConfig;

    let alice = Identity::generate();
    let mallory = Identity::generate();
    let path = std::env::temp_dir().join(format!("p2p-group-persist-wrong-identity-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let (alice_roster, genesis) = Roster::genesis_default(&alice, vec![]);
    let _alice_hub = GroupHub::create_persisted(&alice, alice_roster, &genesis, &path, GroupHubConfig::default()).unwrap();

    // The storage key is derived from the owning identity's own private
    // key - a different identity (even one with no relationship to the
    // group at all) can't derive the right key and so can't decrypt the log.
    let result = GroupHub::load_persisted(&mallory, &path, GroupHubConfig::default());
    assert!(matches!(result, Err(symbolon::ChatError::DecryptionFailed)));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_non_member_cannot_construct_a_valid_roster_proposal() {
    // Mallory is never part of the group. Even holding the exact same
    // Roster state everyone else has, she can't produce a signed operation
    // that `Roster::apply` (the same check `GroupHub::recv_event` relies on
    // internally) will accept, because her key was never a member key.
    let alice = Identity::generate();
    let bob = Identity::generate();
    let mallory = Identity::generate();

    let mut alice_registry = PeerRegistry::new();
    alice_registry.trust(bob.public_key());
    let mut bob_registry = PeerRegistry::new();
    bob_registry.trust(alice.public_key());

    let (alice_roster, genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
    let bob_roster = Roster::from_genesis(&genesis).unwrap();
    let alice_hub = GroupHub::new(&alice, alice_roster);
    let bob_hub = GroupHub::new(&bob, bob_roster);

    let (a_ab, b_ab) = establish_pair(&alice, &alice_registry, &bob, &bob_registry);
    alice_hub.attach_session(bob.fingerprint(), Arc::new(a_ab));
    bob_hub.attach_session(alice.fingerprint(), Arc::new(b_ab));

    // Mallory holds her own local copy of the (public) roster state, as
    // anyone could, but attempting to propose a change with it fails
    // immediately - she was never a member, so there's no key of hers in
    // the roster to authorize anything.
    let mallory_view_of_roster = Roster::from_genesis(&genesis).unwrap();
    let result = mallory_view_of_roster.propose_remove(&mallory, bob.fingerprint());
    assert!(result.is_err(), "a non-member must not be able to build a valid roster proposal at all");

    // The real group keeps working normally throughout.
    alice_hub.broadcast(&alice, b"still just us").unwrap();
    match bob_hub.recv_event().unwrap() {
        GroupEvent::Message { sender, .. } => assert_eq!(sender, alice.fingerprint()),
        other => panic!("expected a message, got {other:?}"),
    }
}
