//! Receipts: delivery on by default, read opt-in, signed and verifiable.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use symbolon::group::{
    GroupHub, GroupHubConfig, Permissions, ReceiptKind, ReceiptSettings, Roster,
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

/// Alice and Bob in one group, linked. Bob's receipt settings are chosen by
/// the caller; `bob_signs` decides whether Bob's hub has a receipt signer.
fn pair(
    bob_cfg: GroupHubConfig,
    bob_signs: bool,
) -> (Identity, Identity, Arc<GroupHub>, Arc<GroupHub>) {
    let (alice, bob) = (Identity::generate(), Identity::generate());
    let tiers = vec![("owner".to_string(), Permissions::FULL)];
    let members = vec![
        (alice.public_key(), "owner".to_string()),
        (bob.public_key(), "owner".to_string()),
    ];
    let (_r, genesis) = Roster::genesis_with_policy(
        &alice,
        symbolon::group::GroupKind::FullMesh,
        Default::default(),
        tiers,
        members,
    );
    let a = GroupHub::with_config(
        &alice,
        Roster::from_genesis(&genesis).unwrap(),
        GroupHubConfig::default(),
    );
    let b = GroupHub::with_config(&bob, Roster::from_genesis(&genesis).unwrap(), bob_cfg);
    a.enable_receipts(Arc::new(Identity::from_bytes(&alice.secret_bytes())));
    if bob_signs {
        b.enable_receipts(Arc::new(Identity::from_bytes(&bob.secret_bytes())));
    }
    link((&alice, &a), (&bob, &b));
    (alice, bob, a, b)
}

#[test]
fn delivery_receipt_is_sent_by_default_and_verified() {
    let (alice, bob, a, _b) = pair(GroupHubConfig::default(), true);
    let seq = a.post(&alice, b"ping").unwrap();
    wait_until("delivery receipt", || !a.receipts_for(seq).is_empty());
    assert_eq!(
        a.receipts_for(seq),
        vec![(bob.fingerprint(), ReceiptKind::Delivered)]
    );
}

#[test]
fn no_receipt_without_a_signer_or_when_delivery_is_off() {
    let (alice, _bob, a, _b) = pair(GroupHubConfig::default(), false);
    let seq = a.post(&alice, b"x").unwrap();
    thread::sleep(Duration::from_millis(400));
    assert!(a.receipts_for(seq).is_empty(), "no signer, no receipt");

    let off = GroupHubConfig {
        receipts: ReceiptSettings {
            delivery: false,
            read: false,
        },
        ..Default::default()
    };
    let (alice, _bob, a, _b) = pair(off, true);
    let seq = a.post(&alice, b"x").unwrap();
    thread::sleep(Duration::from_millis(400));
    assert!(a.receipts_for(seq).is_empty(), "delivery receipts disabled");
}

#[test]
fn read_receipts_are_opt_in_and_upgrade_the_delivery_receipt() {
    // Default settings: mark_read does nothing.
    let (alice, _bob, a, b) = pair(GroupHubConfig::default(), true);
    let seq = a.post(&alice, b"hi").unwrap();
    wait_until("delivered", || !a.receipts_for(seq).is_empty());
    assert!(!b.mark_read(&alice.fingerprint(), seq).unwrap());
    thread::sleep(Duration::from_millis(300));
    assert_eq!(a.receipts_for(seq)[0].1, ReceiptKind::Delivered);

    // Opted in: Read replaces Delivered.
    let on = GroupHubConfig {
        receipts: ReceiptSettings {
            delivery: true,
            read: true,
        },
        ..Default::default()
    };
    let (alice, bob, a, b) = pair(on, true);
    let seq = a.post(&alice, b"hi").unwrap();
    wait_until("delivered", || !a.receipts_for(seq).is_empty());
    assert!(b.mark_read(&alice.fingerprint(), seq).unwrap());
    wait_until("read", || {
        a.receipts_for(seq).first().map(|r| r.1) == Some(ReceiptKind::Read)
    });
    assert_eq!(
        a.receipts_for(seq),
        vec![(bob.fingerprint(), ReceiptKind::Read)]
    );
}

#[test]
fn mark_read_for_a_message_we_do_not_hold_is_a_no_op() {
    let on = GroupHubConfig {
        receipts: ReceiptSettings {
            delivery: true,
            read: true,
        },
        ..Default::default()
    };
    let (alice, _bob, _a, b) = pair(on, true);
    assert!(!b.mark_read(&alice.fingerprint(), 99).unwrap());
}
