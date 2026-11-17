//! Existence notices, author-first fetch, and the relay policy, end to end.
//!
//! Cast: Alice authors messages; Bob holds them (he was linked to Alice);
//! Carol was never linked to Alice and learns about them from Bob.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use symbolon::group::{
    GroupHub, GroupHubConfig, GroupKind, Permissions, RelayPolicy, RelayedContent, Roster,
};
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

struct World {
    alice: Identity,
    bob: Identity,
    carol: Identity,
    a: Arc<GroupHub>,
    b: Arc<GroupHub>,
    c: Arc<GroupHub>,
}

fn world(policy: RelayPolicy, carol_cfg: GroupHubConfig) -> World {
    let (alice, bob, carol) = (
        Identity::generate(),
        Identity::generate(),
        Identity::generate(),
    );
    let tiers = vec![
        ("owner".to_string(), Permissions::FULL),
        ("member".to_string(), Permissions::READ_WRITE),
    ];
    let members = vec![
        (alice.public_key(), "owner".to_string()),
        (bob.public_key(), "member".to_string()),
        (carol.public_key(), "member".to_string()),
    ];
    let (_r, genesis) =
        Roster::genesis_with_policy(&alice, GroupKind::FullMesh, policy, tiers, members);
    let mk = |id: &Identity, cfg: GroupHubConfig| {
        GroupHub::with_config(id, Roster::from_genesis(&genesis).unwrap(), cfg)
    };
    World {
        a: mk(&alice, GroupHubConfig::default()),
        b: mk(&bob, GroupHubConfig::default()),
        c: mk(&carol, carol_cfg),
        alice,
        bob,
        carol,
    }
}

#[test]
fn author_only_group_non_authors_confirm_existence_but_not_content() {
    let w = world(RelayPolicy::AuthorOnly, GroupHubConfig::default());
    assert_eq!(w.a.relay_policy(), RelayPolicy::AuthorOnly);
    link((&w.alice, &w.a), (&w.bob, &w.b));
    w.a.post(&w.alice, b"first").unwrap();
    w.a.post(&w.alice, b"second").unwrap();
    wait_until("bob holds both", || {
        w.b.history_for(&w.alice.fingerprint()).len() == 2
    });

    // Carol meets Bob only, and asks to catch up.
    link((&w.carol, &w.c), (&w.bob, &w.b));
    w.c.request_catchup().unwrap();
    wait_until("carol learns both exist", || {
        w.c.existence_only(&w.alice.fingerprint()) == vec![1, 2]
    });
    assert!(
        w.c.history_for(&w.alice.fingerprint()).is_empty(),
        "Bob must NOT have served the content in an author-only group"
    );

    // Fetch cannot be answered by Bob either (still only a notice)...
    w.c.fetch_from_anyone(&w.alice.fingerprint(), 1).unwrap();
    thread::sleep(Duration::from_millis(300));
    assert!(w.c.history_for(&w.alice.fingerprint()).is_empty());

    // ...but once Carol reaches Alice, asking the author works.
    link((&w.carol, &w.c), (&w.alice, &w.a));
    w.c.fetch(&w.alice.fingerprint(), 1).unwrap();
    w.c.fetch(&w.alice.fingerprint(), 2).unwrap();
    wait_until("content arrives from the author", || {
        w.c.history_for(&w.alice.fingerprint()).len() == 2
    });
    let h = w.c.history_for(&w.alice.fingerprint());
    assert_eq!(h[0].1, b"first");
    assert_eq!(h[1].1, b"second");
    assert!(w.c.existence_only(&w.alice.fingerprint()).is_empty());
    assert_eq!(
        w.c.relayed_by(&w.alice.fingerprint(), 1),
        None,
        "came straight from the author"
    );
}

#[test]
fn open_group_relay_delivers_content_and_records_who_relayed_it() {
    let w = world(RelayPolicy::Open, GroupHubConfig::default());
    link((&w.alice, &w.a), (&w.bob, &w.b));
    w.a.post(&w.alice, b"hello").unwrap();
    wait_until("bob holds it", || {
        !w.b.history_for(&w.alice.fingerprint()).is_empty()
    });

    link((&w.carol, &w.c), (&w.bob, &w.b));
    w.c.request_catchup().unwrap();
    wait_until("carol gets the content via bob", || {
        !w.c.history_for(&w.alice.fingerprint()).is_empty()
    });
    assert_eq!(
        w.c.relayed_by(&w.alice.fingerprint(), 1),
        Some(w.bob.fingerprint())
    );
}

#[test]
fn existence_only_setting_refuses_relayed_content_until_the_author_sends_it() {
    let cfg = GroupHubConfig {
        relayed_content: RelayedContent::ExistenceOnly,
        ..Default::default()
    };
    let w = world(RelayPolicy::Open, cfg);
    link((&w.alice, &w.a), (&w.bob, &w.b));
    w.a.post(&w.alice, b"only-from-alice").unwrap();
    wait_until("bob holds it", || {
        !w.b.history_for(&w.alice.fingerprint()).is_empty()
    });

    link((&w.carol, &w.c), (&w.bob, &w.b));
    w.c.request_catchup().unwrap();
    wait_until("carol records existence", || {
        w.c.existence_only(&w.alice.fingerprint()) == vec![1]
    });
    // Bob sent full content (open group) but Carol's setting refused it.
    assert!(w.c.history_for(&w.alice.fingerprint()).is_empty());
    // Asking everyone still yields only relayed copies, which she ignores.
    w.c.fetch_from_anyone(&w.alice.fingerprint(), 1).unwrap();
    thread::sleep(Duration::from_millis(300));
    assert!(w.c.history_for(&w.alice.fingerprint()).is_empty());

    link((&w.carol, &w.c), (&w.alice, &w.a));
    w.c.fetch(&w.alice.fingerprint(), 1).unwrap();
    wait_until("author's copy accepted", || {
        !w.c.history_for(&w.alice.fingerprint()).is_empty()
    });
    assert_eq!(
        w.c.history_for(&w.alice.fingerprint())[0].1,
        b"only-from-alice"
    );
    assert!(w.c.existence_only(&w.alice.fingerprint()).is_empty());
}

#[test]
fn fetch_without_any_session_is_an_error_not_a_hang() {
    let w = world(RelayPolicy::Open, GroupHubConfig::default());
    assert!(w.c.fetch(&w.alice.fingerprint(), 1).is_err());
    assert!(w.c.fetch_from_anyone(&w.alice.fingerprint(), 1).is_err());
    let _ = (&w.bob, &w.b, &w.a);
}
