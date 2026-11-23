//! File sharing in a group, end to end over in-memory links.
//!
//! Cast: Alice offers a file. Bob and Carol are ordinary members; Dan is in
//! the group but his tier cannot read.

use std::io;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use symbolon::file::{
    ChunkSource, FileFrame, FileSink, MemorySource, DEFAULT_CHUNK_SIZE, MIN_CHUNK_SIZE,
};
use symbolon::group::{
    GroupEvent, GroupHub, GroupHubConfig, GroupKind, GroupMessage, Permissions, RelayPolicy, Roster,
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

/// Two raw sessions between `a` and `b`, not yet given to any hub.
fn sessions(a: &Identity, b: &Identity) -> (Session, Session) {
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

fn link(a: (&Identity, &Arc<GroupHub>), b: (&Identity, &Arc<GroupHub>)) {
    let (sa, sb) = sessions(a.0, b.0);
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

/// A sink that keeps the file in memory so the test can compare it.
#[derive(Clone, Default)]
struct MemSink(Arc<Mutex<Vec<u8>>>);

impl FileSink for MemSink {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        let mut v = self.0.lock().unwrap();
        let end = offset as usize + data.len();
        if v.len() < end {
            v.resize(end, 0);
        }
        v[offset as usize..end].copy_from_slice(data);
        Ok(())
    }
    fn finish(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct World {
    alice: Identity,
    bob: Identity,
    carol: Identity,
    dan: Identity,
    a: Arc<GroupHub>,
    b: Arc<GroupHub>,
    c: Arc<GroupHub>,
}

fn world(bob_cfg: GroupHubConfig) -> World {
    world_with(RelayPolicy::Open, bob_cfg)
}

fn world_with(policy: RelayPolicy, bob_cfg: GroupHubConfig) -> World {
    let (alice, bob, carol, dan) = (
        Identity::generate(),
        Identity::generate(),
        Identity::generate(),
        Identity::generate(),
    );
    let tiers = vec![
        ("owner".to_string(), Permissions::FULL),
        ("member".to_string(), Permissions::READ_WRITE),
        ("mute".to_string(), Permissions::NONE),
    ];
    let members = vec![
        (alice.public_key(), "owner".to_string()),
        (bob.public_key(), "member".to_string()),
        (carol.public_key(), "member".to_string()),
        (dan.public_key(), "mute".to_string()),
    ];
    let (_r, genesis) =
        Roster::genesis_with_policy(&alice, GroupKind::FullMesh, policy, tiers, members);
    let mk = |id: &Identity, cfg: GroupHubConfig| {
        GroupHub::with_config(id, Roster::from_genesis(&genesis).unwrap(), cfg)
    };
    World {
        a: mk(&alice, GroupHubConfig::default()),
        b: mk(&bob, bob_cfg),
        c: mk(&carol, GroupHubConfig::default()),
        alice,
        bob,
        carol,
        dan,
    }
}

/// A file of `n` bytes that is not all one value.
fn file_of(n: usize) -> Arc<MemorySource> {
    Arc::new(MemorySource((0..n).map(|i| (i * 31 % 251) as u8).collect()))
}

/// Wait for an event that `pick` accepts, ignoring the others.
fn event_where<T>(hub: &GroupHub, mut pick: impl FnMut(GroupEvent) -> Option<T>) -> T {
    let end = Instant::now() + Duration::from_secs(10);
    while Instant::now() < end {
        if let Some(e) = hub.recv_event_timeout(Duration::from_millis(100)) {
            if let Some(t) = pick(e) {
                return t;
            }
        }
    }
    panic!("timed out waiting for an event");
}

fn offered(hub: &GroupHub) -> (symbolon::identity::PeerId, u64, symbolon::file::FileOffer) {
    event_where(hub, |e| match e {
        GroupEvent::FileOffered { sender, seq, offer } => Some((sender, seq, offer)),
        _ => None,
    })
}

#[test]
fn a_file_is_shown_first_and_downloaded_only_when_accepted() {
    let w = world(GroupHubConfig::default());
    link((&w.alice, &w.a), (&w.bob, &w.b));
    let src = file_of(700_000); // three chunks of 256 KiB
    let want = src.0.clone();
    let seq =
        w.a.offer_file(&w.alice, src, Some("notes.bin"), DEFAULT_CHUNK_SIZE)
            .unwrap();

    let (sender, got_seq, offer) = offered(&w.b);
    assert_eq!((sender, got_seq), (w.alice.fingerprint(), seq));
    assert_eq!(offer.name.as_deref(), Some("notes.bin"));
    assert_eq!(offer.size, 700_000);
    assert_eq!(offer.prefix, want[..512].to_vec());

    // Bob has not said yes: nothing may start on its own.
    assert!(w.b.recv_event_timeout(Duration::from_millis(300)).is_none());

    let sink = MemSink::default();
    w.b.accept_file(&sender, seq, Box::new(sink.clone()))
        .unwrap();
    event_where(&w.b, |e| {
        matches!(e, GroupEvent::FileComplete { .. }).then_some(())
    });
    assert_eq!(*sink.0.lock().unwrap(), want);
}

#[test]
fn a_member_can_download_from_another_member_when_the_author_is_not_connected() {
    let w = world(GroupHubConfig::default());
    link((&w.alice, &w.a), (&w.bob, &w.b));
    let src = file_of(300_000);
    let want = src.0.clone();
    let seq =
        w.a.offer_file(&w.alice, src.clone(), None, DEFAULT_CHUNK_SIZE)
            .unwrap();
    let (author, _, _) = offered(&w.b);

    // Bob downloads it and registers it for serving (this re-hashes the file
    // and checks it against the offer).
    let bob_sink = MemSink::default();
    w.b.accept_file(&author, seq, Box::new(bob_sink.clone()))
        .unwrap();
    event_where(&w.b, |e| {
        matches!(e, GroupEvent::FileComplete { .. }).then_some(())
    });
    w.b.serve_file(
        &author,
        seq,
        Arc::new(MemorySource(bob_sink.0.lock().unwrap().clone())),
    )
    .unwrap();

    // Carol is linked to Bob only; Alice is not reachable for her.
    link((&w.carol, &w.c), (&w.bob, &w.b));
    w.c.request_catchup().unwrap();
    let (_, cseq, _) = offered(&w.c);
    assert_eq!(cseq, seq);
    let sink = MemSink::default();
    w.c.accept_file(&author, seq, Box::new(sink.clone()))
        .unwrap();
    event_where(&w.c, |e| {
        matches!(e, GroupEvent::FileComplete { .. }).then_some(())
    });
    assert_eq!(*sink.0.lock().unwrap(), want);
}

#[test]
fn serving_a_wrong_file_is_refused() {
    let w = world(GroupHubConfig::default());
    link((&w.alice, &w.a), (&w.bob, &w.b));
    let seq =
        w.a.offer_file(&w.alice, file_of(50_000), None, MIN_CHUNK_SIZE)
            .unwrap();
    let (author, _, _) = offered(&w.b);
    let wrong: Arc<dyn ChunkSource> = Arc::new(MemorySource(vec![7; 50_000]));
    assert!(w.b.serve_file(&author, seq, wrong).is_err());
}

#[test]
fn a_member_whose_tier_cannot_read_is_never_served() {
    let w = world(GroupHubConfig::default());
    // Dan's raw session, kept by the test instead of a hub.
    let (sa, sd) = sessions(&w.alice, &w.dan);
    w.a.attach_session(w.dan.fingerprint(), Arc::new(sa));
    let seq =
        w.a.offer_file(&w.alice, file_of(40_000), None, MIN_CHUNK_SIZE)
            .unwrap();
    let (offer_id, _) = {
        let o = w.a.file_offer(&w.alice.fingerprint(), seq).unwrap();
        (o.id(), ())
    };
    // Dan asks directly for the manifest and for a chunk.
    for frame in [
        FileFrame::ManifestRequest { file: offer_id },
        FileFrame::ChunkRequest {
            file: offer_id,
            indices: vec![0],
        },
    ] {
        sd.send(&GroupMessage::File(frame).encode()).unwrap();
    }
    thread::sleep(Duration::from_millis(500));
    // Anything Dan receives must not be file data (he may get the roster sync
    // request Alice's hub sends on attach).
    while let Some(bytes) = sd.try_recv() {
        match GroupMessage::decode(&bytes) {
            Ok(GroupMessage::File(_)) => panic!("a non-reader was answered with a file message"),
            Ok(GroupMessage::Application { .. }) => panic!("a non-reader received the offer"),
            _ => {}
        }
    }
}

#[test]
fn deleting_the_offer_cancels_it() {
    let w = world(GroupHubConfig::default());
    link((&w.alice, &w.a), (&w.bob, &w.b));
    let seq =
        w.a.offer_file(&w.alice, file_of(10_000), None, MIN_CHUNK_SIZE)
            .unwrap();
    let (author, _, _) = offered(&w.b);
    w.a.delete(&w.alice, w.alice.fingerprint(), seq).unwrap();
    wait_until("bob forgets the offer", || {
        w.b.file_offer(&author, seq).is_none()
    });
    assert!(w
        .b
        .accept_file(&author, seq, Box::new(MemSink::default()))
        .is_err());
    // And Alice no longer serves it either.
    assert!(w.a.file_offer(&author, seq).is_none());
}

#[test]
fn an_offer_above_the_receivers_limit_is_shown_but_cannot_be_accepted() {
    let w = world(GroupHubConfig {
        max_file_size: 1_000,
        ..GroupHubConfig::default()
    });
    link((&w.alice, &w.a), (&w.bob, &w.b));
    let seq =
        w.a.offer_file(&w.alice, file_of(5_000), None, MIN_CHUNK_SIZE)
            .unwrap();
    let (author, _, offer) = offered(&w.b);
    assert_eq!(offer.size, 5_000);
    assert!(w
        .b
        .accept_file(&author, seq, Box::new(MemSink::default()))
        .is_err());
}

#[test]
fn you_cannot_accept_your_own_offer_or_the_same_file_twice() {
    let w = world(GroupHubConfig::default());
    link((&w.alice, &w.a), (&w.bob, &w.b));
    let seq =
        w.a.offer_file(&w.alice, file_of(2_000_000), None, MIN_CHUNK_SIZE)
            .unwrap();
    assert!(w
        .a
        .accept_file(&w.alice.fingerprint(), seq, Box::new(MemSink::default()))
        .is_err());
    let (author, _, _) = offered(&w.b);
    w.b.accept_file(&author, seq, Box::new(MemSink::default()))
        .unwrap();
    assert!(w
        .b
        .accept_file(&author, seq, Box::new(MemSink::default()))
        .is_err());
}

#[test]
fn an_empty_file_transfers() {
    let w = world(GroupHubConfig::default());
    link((&w.alice, &w.a), (&w.bob, &w.b));
    let seq =
        w.a.offer_file(&w.alice, file_of(0), Some("empty"), DEFAULT_CHUNK_SIZE)
            .unwrap();
    let (author, _, _) = offered(&w.b);
    w.b.accept_file(&author, seq, Box::new(MemSink::default()))
        .unwrap();
    event_where(&w.b, |e| {
        matches!(e, GroupEvent::FileComplete { .. }).then_some(())
    });
}

#[test]
fn in_an_author_only_group_only_the_author_serves_files() {
    let w = world_with(RelayPolicy::AuthorOnly, GroupHubConfig::default());
    link((&w.alice, &w.a), (&w.bob, &w.b));
    let src = file_of(20_000);
    let seq =
        w.a.offer_file(&w.alice, src.clone(), None, MIN_CHUNK_SIZE)
            .unwrap();
    let (author, _, _) = offered(&w.b);
    // Bob may not become a second source, even with the right bytes.
    assert!(w.b.serve_file(&author, seq, src).is_err());
    // Carol is linked to Bob only. In an AuthorOnly group Bob relays just an
    // existence notice, so she never receives the offer, let alone the file.
    link((&w.carol, &w.c), (&w.bob, &w.b));
    w.c.request_catchup().unwrap();
    event_where(&w.c, |e| {
        matches!(e, GroupEvent::Existence { .. }).then_some(())
    });
    assert!(w.c.file_offer(&author, seq).is_none());
    assert!(w
        .c
        .accept_file(&author, seq, Box::new(MemSink::default()))
        .is_err());
}
