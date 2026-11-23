//! The smallest complete use of the library: two peers on one machine,
//! pinned to each other, exchanging one message each way over real TCP.
//!
//!     cargo run --example two_peers
//!
//! The README quotes this file, so it is compiled by `cargo test`/`cargo build
//! --examples` and cannot silently go stale.

use std::net::{TcpListener, TcpStream};
use std::thread;
use symbolon::identity::Identity;
use symbolon::peer::PeerRegistry;
use symbolon::session::{Role, Session};

fn main() {
    // 1. Each side has a long-term identity (an Ed25519 key pair).
    let alice = Identity::generate();
    let bob = Identity::generate();

    // 2. Each side "pins" the other's PUBLIC key. In real use you compare the
    //    fingerprints out of band (read them aloud, scan a QR code).
    let mut alice_trusts = PeerRegistry::new();
    alice_trusts.trust(bob.public_key());
    let mut bob_trusts = PeerRegistry::new();
    bob_trusts.trust(alice.public_key());

    // 3. One side listens, the other dials. After this both have proved who they are.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let bob_thread = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        Session::establish(stream, Role::Responder, &bob, &bob_trusts).unwrap()
    });
    let alice_session = Session::establish(
        TcpStream::connect(addr).unwrap(),
        Role::Initiator,
        &alice,
        &alice_trusts,
    )
    .unwrap();
    let bob_session = bob_thread.join().unwrap();

    // 4. Send and receive. Messages are encrypted, ordered and acknowledged.
    alice_session.send(b"hello bob").unwrap();
    println!(
        "bob got: {}",
        String::from_utf8_lossy(&bob_session.recv().unwrap())
    );
    bob_session.send(b"hello alice").unwrap();
    println!(
        "alice got: {}",
        String::from_utf8_lossy(&alice_session.recv().unwrap())
    );
}
