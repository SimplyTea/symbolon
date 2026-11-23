//! Announce-and-request forwarding (`Have`), and the read-permission checks
//! on relay/fetch requests.
//!
//! The point of `Have`: a post goes only to the members connected to its
//! author, so a member with no direct link to the author used to learn of it
//! only by asking (catch-up). Now whoever accepts it tells the other readers
//! (a few bytes) and they ask that peer for it. Nothing about other groups,
//! 1:1 sessions or who is linked to whom is ever sent.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use symbolon::group::{
    GroupHub, GroupHubConfig, GroupKind, GroupMessage, Permissions, RelayPolicy, Roster,
};
use symbolon::identity::{Identity, PeerId};
use symbolon::peer::PeerRegistry;
use symbolon::session::{Role, Session, SessionConfig};
use symbolon::trace::{CollectingTracer, TraceEvent};
use symbolon::transport::memory_pair;

fn trusting(keys: &[&Identity]) -> PeerRegistry {
    let mut r = PeerRegistry::new();
    for k in keys {
        r.trust(k.public_key());
    }
    r
}

/// Two established sessions between `a` and `b` (a = initiator).
fn session_pair(a: &Identity, b: &Identity) -> (Session, Session) {
    let (ca, cb) = memory_pair(Duration::ZERO);
    let (ra, rb) = (trusting(&[b]), trusting(&[a]));
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

/// Connect two hubs.
fn link(a: (&Identity, &Arc<GroupHub>), b: (&Identity, &Arc<GroupHub>)) {
    let (sa, sb) = session_pair(a.0, b.0);
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

struct Group {
    ids: Vec<Identity>,
    hubs: Vec<Arc<GroupHub>>,
}

/// `n` members; member 0 is the owner. `tier_of(i)` names each member's tier
/// ("owner", "member" or "blind": no read permission).
fn group(n: usize, policy: RelayPolicy, tier_of: impl Fn(usize) -> &'static str) -> Group {
    let ids: Vec<Identity> = (0..n).map(|_| Identity::generate()).collect();
    let tiers = vec![
        ("owner".to_string(), Permissions::FULL),
        ("member".to_string(), Permissions::READ_WRITE),
        (
            "blind".to_string(),
            Permissions {
                can_write: true,
                ..Permissions::NONE
            },
        ),
    ];
    let members: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| (id.public_key(), tier_of(i).to_string()))
        .collect();
    let (_r, genesis) =
        Roster::genesis_with_policy(&ids[0], GroupKind::FullMesh, policy, tiers, members);
    let hubs = ids
        .iter()
        .map(|id| {
            GroupHub::with_config(
                id,
                Roster::from_genesis(&genesis).unwrap(),
                GroupHubConfig::default(),
            )
        })
        .collect();
    Group { ids, hubs }
}

fn fp(g: &Group, i: usize) -> PeerId {
    g.ids[i].fingerprint()
}

#[test]
fn member_with_no_link_to_the_author_gets_the_post_without_asking() {
    // Alice - Bob - Carol, and NO Alice - Carol link.
    let g = group(3, RelayPolicy::Open, |i| {
        if i == 0 {
            "owner"
        } else {
            "member"
        }
    });
    link((&g.ids[0], &g.hubs[0]), (&g.ids[1], &g.hubs[1]));
    link((&g.ids[1], &g.hubs[1]), (&g.ids[2], &g.hubs[2]));
    g.hubs[0].post(&g.ids[0], b"hello carol").unwrap();
    wait_until("carol receives it with no catch-up", || {
        g.hubs[2].history_for(&fp(&g, 0)).len() == 1
    });
    assert_eq!(g.hubs[2].history_for(&fp(&g, 0))[0].1, b"hello carol");
}

#[test]
fn it_spreads_across_several_hops_and_stops() {
    // 0 - 1 - 2 - 3 - 4 in a line: the post must reach the far end.
    let g = group(5, RelayPolicy::Open, |i| {
        if i == 0 {
            "owner"
        } else {
            "member"
        }
    });
    for i in 0..4 {
        link((&g.ids[i], &g.hubs[i]), (&g.ids[i + 1], &g.hubs[i + 1]));
    }
    for k in 1..=3 {
        g.hubs[0]
            .post(&g.ids[0], format!("msg {k}").as_bytes())
            .unwrap();
    }
    wait_until("the far end has all three", || {
        g.hubs[4].history_for(&fp(&g, 0)).len() == 3
    });
    // Order and content are intact.
    let got: Vec<_> = g.hubs[4]
        .history_for(&fp(&g, 0))
        .into_iter()
        .map(|m| (m.0, String::from_utf8(m.1).unwrap()))
        .collect();
    assert_eq!(
        got,
        vec![
            (1, "msg 1".into()),
            (2, "msg 2".into()),
            (3, "msg 3".into())
        ]
    );
}

#[test]
fn full_mesh_duplicates_are_dropped_quietly_never_rejected() {
    // Everyone linked to everyone: nobody should need a forward, and the
    // announcements must not turn into repeated copies.
    let tracer = CollectingTracer::new();
    let ids: Vec<Identity> = (0..4).map(|_| Identity::generate()).collect();
    let tiers = vec![
        ("owner".to_string(), Permissions::FULL),
        ("member".to_string(), Permissions::READ_WRITE),
    ];
    let members: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            (
                id.public_key(),
                if i == 0 { "owner" } else { "member" }.to_string(),
            )
        })
        .collect();
    let (_r, genesis) = Roster::genesis_with_policy(
        &ids[0],
        GroupKind::FullMesh,
        RelayPolicy::Open,
        tiers,
        members,
    );
    let hubs: Vec<_> = ids
        .iter()
        .map(|id| {
            let cfg = GroupHubConfig {
                tracer: tracer.clone(),
                ..GroupHubConfig::default()
            };
            GroupHub::with_config(id, Roster::from_genesis(&genesis).unwrap(), cfg)
        })
        .collect();
    for i in 0..4 {
        for j in (i + 1)..4 {
            link((&ids[i], &hubs[i]), (&ids[j], &hubs[j]));
        }
    }
    for k in 0..5 {
        hubs[0].post(&ids[0], format!("m{k}").as_bytes()).unwrap();
    }
    wait_until("everyone has all five", || {
        (1..4).all(|i| hubs[i].history_for(&ids[0].fingerprint()).len() == 5)
    });
    thread::sleep(Duration::from_millis(500)); // let any stray copies land
    assert!(
        !tracer.any(|e| matches!(e, TraceEvent::GroupMessageRejected { .. })),
        "a duplicate copy must be ignored, never reported as a rejection: {:?}",
        tracer.events()
    );
    // Each message is held exactly once per member, however many copies arrived.
    for hub in &hubs[1..4] {
        assert_eq!(hub.history_for(&ids[0].fingerprint()).len(), 5);
    }
}

#[test]
fn author_only_group_forwards_existence_not_content() {
    let g = group(3, RelayPolicy::AuthorOnly, |i| {
        if i == 0 {
            "owner"
        } else {
            "member"
        }
    });
    link((&g.ids[0], &g.hubs[0]), (&g.ids[1], &g.hubs[1]));
    link((&g.ids[1], &g.hubs[1]), (&g.ids[2], &g.hubs[2]));
    g.hubs[0].post(&g.ids[0], b"secret from alice").unwrap();
    wait_until("carol learns it exists", || {
        g.hubs[2].existence_only(&fp(&g, 0)) == vec![1]
    });
    thread::sleep(Duration::from_millis(300));
    assert!(
        g.hubs[2].history_for(&fp(&g, 0)).is_empty(),
        "Bob must not have handed Alice's content to Carol in an author-only group"
    );
}

/// Drain whatever the raw peer end receives for `window`, decoded.
fn drain(session: &Session, window: Duration) -> Vec<GroupMessage> {
    let end = Instant::now() + window;
    let mut out = Vec::new();
    while Instant::now() < end {
        match session.try_recv() {
            Some(bytes) => out.push(GroupMessage::decode(&bytes).unwrap()),
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
    out
}

#[test]
fn announcements_go_only_to_members_who_may_read() {
    // Alice -> Bob (hub). Bob is also connected to Carol, whose end we hold
    // as a RAW session so we can see exactly what Bob sends her.
    for (tier, expect_have) in [("member", true), ("blind", false)] {
        let g = group(3, RelayPolicy::Open, |i| match i {
            0 => "owner",
            1 => "member",
            _ => tier,
        });
        link((&g.ids[0], &g.hubs[0]), (&g.ids[1], &g.hubs[1]));
        let (bob_side, carol_raw) = session_pair(&g.ids[1], &g.ids[2]);
        g.hubs[1].attach_session(fp(&g, 2), Arc::new(bob_side));

        g.hubs[0].post(&g.ids[0], b"x").unwrap();
        wait_until("bob has it", || {
            g.hubs[1].history_for(&fp(&g, 0)).len() == 1
        });

        let seen = drain(&carol_raw, Duration::from_millis(500));
        let have = seen
            .iter()
            .any(|m| matches!(m, GroupMessage::Have { sender, seq } if *sender == fp(&g, 0) && *seq == 1));
        assert_eq!(
            have, expect_have,
            "tier {tier}: Have announced = {have}; saw {seen:?}"
        );
        // And never anything that carries the content to a non-reader.
        if !expect_have {
            assert!(
                !seen
                    .iter()
                    .any(|m| matches!(m, GroupMessage::Application { .. })),
                "a member without can_read must never be sent content"
            );
        }
    }
}

#[test]
fn a_member_without_read_permission_cannot_pull_content_by_asking() {
    let g = group(3, RelayPolicy::Open, |i| match i {
        0 => "owner",
        1 => "member",
        _ => "blind",
    });
    link((&g.ids[0], &g.hubs[0]), (&g.ids[1], &g.hubs[1]));
    link((&g.ids[1], &g.hubs[1]), (&g.ids[2], &g.hubs[2]));
    g.hubs[0].post(&g.ids[0], b"private").unwrap();
    wait_until("bob has it", || {
        g.hubs[1].history_for(&fp(&g, 0)).len() == 1
    });

    // Carol asks every way there is.
    g.hubs[2].request_catchup().unwrap();
    g.hubs[2].fetch_from_anyone(&fp(&g, 0), 1).unwrap();
    thread::sleep(Duration::from_millis(500));
    assert!(g.hubs[2].history_for(&fp(&g, 0)).is_empty());
    assert!(g.hubs[2].existence_only(&fp(&g, 0)).is_empty());
}

#[test]
fn a_flood_of_announcements_makes_us_send_at_most_a_few_requests() {
    let g = group(3, RelayPolicy::Open, |i| {
        if i == 0 {
            "owner"
        } else {
            "member"
        }
    });
    let (bob_side, carol_raw) = session_pair(&g.ids[1], &g.ids[2]);
    g.hubs[1].attach_session(fp(&g, 2), Arc::new(bob_side));
    let _ = drain(&carol_raw, Duration::from_millis(100)); // roster-sync chatter

    // Carol (a member) claims to hold 200 different future messages of Alice.
    for seq in 1..=200u64 {
        let have = GroupMessage::Have {
            sender: fp(&g, 0),
            seq,
        }
        .encode();
        carol_raw.send(&have).unwrap();
    }
    let seen = drain(&carol_raw, Duration::from_millis(200));
    let requests = seen
        .iter()
        .filter(|m| matches!(m, GroupMessage::RelayRequest { .. }))
        .count();
    assert!(
        (1..=2).contains(&requests),
        "expected the debounce to allow ~1 request, saw {requests}"
    );
}

#[test]
fn announcements_naming_strangers_or_ourselves_are_ignored() {
    let g = group(2, RelayPolicy::Open, |i| {
        if i == 0 {
            "owner"
        } else {
            "member"
        }
    });
    let (bob_side, carol_raw) = {
        // Bob's partner here is an outsider identity that is NOT in the roster.
        let outsider = Identity::generate();
        let (a, b) = session_pair(&g.ids[1], &outsider);
        (a, (b, outsider))
    };
    g.hubs[1].attach_session(PeerId::from_bytes([0xEE; 32]), Arc::new(bob_side));
    let (raw, _o) = carol_raw;
    let _ = drain(&raw, Duration::from_millis(100));
    raw.send(
        &GroupMessage::Have {
            sender: fp(&g, 0),
            seq: 9,
        }
        .encode(),
    )
    .unwrap();
    raw.send(
        &GroupMessage::Have {
            sender: fp(&g, 1), // Bob's own id
            seq: 9,
        }
        .encode(),
    )
    .unwrap();
    let seen = drain(&raw, Duration::from_millis(300));
    assert!(
        !seen
            .iter()
            .any(|m| matches!(m, GroupMessage::RelayRequest { .. })),
        "a non-member must not be able to make us send requests: {seen:?}"
    );
}
