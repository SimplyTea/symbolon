//! A member added AFTER a group was created only holds the genesis (that is
//! all an invite contains). On connecting to anyone they must learn the
//! rest of the roster by syncing, then be able to chat normally.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use symbolon::group::{GroupHub, GroupHubConfig, Roster};
use symbolon::identity::Identity;
use symbolon::peer::PeerRegistry;
use symbolon::session::{Role, Session, SessionConfig};
use symbolon::transport::memory_pair;

fn trusting(keys: &[&Identity]) -> PeerRegistry {
    let mut r = PeerRegistry::new();
    for k in keys {
        r.trust(k.public_key());
    }
    r
}

/// Connect two hubs over an in-memory link.
fn link(a: (&Identity, &Arc<GroupHub>), b: (&Identity, &Arc<GroupHub>)) {
    let (ca, cb) = memory_pair(Duration::ZERO);
    let (ra, rb) = (trusting(&[b.0]), trusting(&[a.0]));
    let (sa, sb) = thread::scope(|s| {
        let h = s.spawn(|| {
            Session::establish_over(
                Box::new(cb),
                Role::Responder,
                b.0,
                &rb,
                SessionConfig::default(),
                None,
            )
            .unwrap()
        });
        let sa = Session::establish_over(
            Box::new(ca),
            Role::Initiator,
            a.0,
            &ra,
            SessionConfig::default(),
            None,
        )
        .unwrap();
        (sa, h.join().unwrap())
    });
    a.1.attach_session(b.0.fingerprint(), Arc::new(sa));
    b.1.attach_session(a.0.fingerprint(), Arc::new(sb));
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end {
        if f() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting for: {what}");
}

#[test]
fn a_member_added_after_creation_syncs_the_roster_and_can_chat() {
    let (alice, bob, carol, dave) = (
        Identity::generate(),
        Identity::generate(),
        Identity::generate(),
        Identity::generate(),
    );
    let (roster, genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
    let hub_a = GroupHub::with_config(
        &alice,
        Roster::from_genesis(&genesis).unwrap(),
        GroupHubConfig::default(),
    );
    let hub_b = GroupHub::with_config(&bob, roster, GroupHubConfig::default());
    link((&alice, &hub_a), (&bob, &hub_b));

    // Alice adds carol, then dave (two ops: versions 1 and 2).
    hub_a
        .propose_add(&alice, carol.public_key(), "member".into())
        .unwrap();
    hub_a
        .propose_add(&alice, dave.public_key(), "member".into())
        .unwrap();
    wait_until("bob learns both adds live", || {
        hub_b.is_member(&carol.fingerprint()) && hub_b.is_member(&dave.fingerprint())
    });

    // Carol joins holding ONLY the genesis (the invite). She is not even a
    // member in her own view yet.
    let hub_c = GroupHub::with_config(
        &carol,
        Roster::from_genesis(&genesis).unwrap(),
        GroupHubConfig::default(),
    );
    assert!(!hub_c.is_member(&carol.fingerprint()));
    link((&carol, &hub_c), (&alice, &hub_a));
    wait_until("carol syncs the roster from alice", || {
        hub_c.is_member(&carol.fingerprint()) && hub_c.is_member(&dave.fingerprint())
    });
    assert_eq!(hub_c.member_ids().len(), 4);

    // She can now talk to Alice and, once linked, to Bob as well.
    link((&carol, &hub_c), (&bob, &hub_b));
    hub_c.post(&carol, b"hi, I just joined").unwrap();
    wait_until("alice and bob receive carol's post", || {
        !hub_a.history_for(&carol.fingerprint()).is_empty()
            && !hub_b.history_for(&carol.fingerprint()).is_empty()
    });
    // And she receives theirs.
    hub_a.post(&alice, b"welcome carol").unwrap();
    wait_until("carol receives alice's post", || {
        !hub_c.history_for(&alice.fingerprint()).is_empty()
    });
}

#[test]
fn a_member_who_was_offline_catches_up_on_missed_roster_changes() {
    let (alice, bob, carol) = (
        Identity::generate(),
        Identity::generate(),
        Identity::generate(),
    );
    let (roster, genesis) =
        Roster::genesis_default(&alice, vec![bob.public_key(), carol.public_key()]);
    let hub_a = GroupHub::with_config(&alice, roster, GroupHubConfig::default());
    let hub_c = GroupHub::with_config(
        &carol,
        Roster::from_genesis(&genesis).unwrap(),
        GroupHubConfig::default(),
    );
    // Carol is offline while Alice removes Bob.
    hub_a.propose_remove(&alice, bob.fingerprint()).unwrap();
    assert!(hub_c.is_member(&bob.fingerprint()));

    link((&alice, &hub_a), (&carol, &hub_c));
    wait_until("carol learns bob was removed", || {
        !hub_c.is_member(&bob.fingerprint())
    });
}
