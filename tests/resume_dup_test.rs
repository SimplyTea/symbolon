//! A fresh connection must not replay a message the app just sent.
//!
//! Every new link makes BOTH sides send a resume request ("I have everything
//! up to N, send the rest"). If the app calls `send()` in the first round
//! trip, that message is written once by `send()` and, when the peer's resume
//! request arrives, would be written AGAIN as a "retransmission": same bytes,
//! the receiver drops it, but it is wasted traffic and a misleading trace
//! event. The session records a resend ceiling when a link begins so that
//! only messages that existed before the link are replayed.

use std::thread;
use std::time::Duration;

use symbolon::identity::Identity;
use symbolon::peer::PeerRegistry;
use symbolon::session::{Role, Session, SessionConfig};
use symbolon::trace::{CollectingTracer, TraceEvent};
use symbolon::transport::memory_pair;

fn pinning(id: &Identity) -> PeerRegistry {
    let mut r = PeerRegistry::new();
    r.trust(id.public_key());
    r
}

#[test]
fn a_message_sent_in_the_first_round_trip_is_not_written_twice() {
    let a = Identity::generate();
    let b = Identity::generate();
    let (ra, rb) = (pinning(&b), pinning(&a));
    // 50 ms one-way latency leaves a wide window between "establish returns"
    // and "the peer's resume request arrives".
    let (ca, cb) = memory_pair(Duration::from_millis(50));

    let tracer_a = CollectingTracer::new();
    let cfg_a = SessionConfig {
        tracer: tracer_a.clone(),
        ..SessionConfig::default()
    };
    let t = thread::spawn(move || {
        Session::establish_over(
            Box::new(cb),
            Role::Responder,
            &b,
            &rb,
            SessionConfig::default(),
            None,
        )
        .expect("responder")
    });
    let sa = Session::establish_over(Box::new(ca), Role::Initiator, &a, &ra, cfg_a, None)
        .expect("initiator");
    let sb = t.join().unwrap();

    // Immediately, before B's resume request can have reached us.
    sa.send(b"first").unwrap();
    assert_eq!(sb.recv().unwrap(), b"first");
    // Give B's resume request time to arrive and be handled.
    thread::sleep(Duration::from_millis(300));

    assert!(
        !tracer_a.any(|e| matches!(e, TraceEvent::Retransmitted { .. })),
        "a fresh link must not replay a message that send() already wrote: {:?}",
        tracer_a.events()
    );
}
