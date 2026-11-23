//! Prints REAL bytes from the library, field by field, so the layouts in
//! `docs/WIRE_FORMAT.md` can be checked against the code instead of trusted.
//!
//!     cargo run --example wire_dump
//!
//! Keys and nonces are random, so the hex differs every run; the sizes and
//! offsets never do. Every `Walker` below reads the bytes using the layout the
//! doc claims and asserts at the end that it consumed exactly the whole
//! message: if the doc's table were wrong, this program would panic.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use symbolon::discovery::{Announcement, Disclose};
use symbolon::framing::MAX_FRAME_LEN;
use symbolon::group::{GroupContent, GroupMessage, ReceiptKind, Roster, RosterOpWire};
use symbolon::handshake::{run_initiator, run_responder};
use symbolon::identity::{Identity, PeerId};
use symbolon::message::ControlMessage;
use symbolon::peer::PeerRegistry;
use symbolon::persistence::{EncryptedIdentity, KdfParams};
use symbolon::ratchet::Ratchet;
use symbolon::session::{Role, Session};
use symbolon::transport::memory_pair;

// ---------------------------------------------------------------- helpers

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Shorten long hex so tables stay readable: first 8 bytes, "...", last 4.
fn short(b: &[u8]) -> String {
    if b.len() <= 16 {
        hex(b)
    } else {
        format!("{}...{}", hex(&b[..8]), hex(&b[b.len() - 4..]))
    }
}

/// Walks a byte string field by field, printing offset, size, name, value.
struct Walker<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Walker<'a> {
    fn new(title: &str, bytes: &'a [u8]) -> Self {
        println!("\n### {title}  ({} bytes)", bytes.len());
        println!("| offset | size | field | value (hex) |");
        println!("|---:|---:|---|---|");
        Walker { bytes, at: 0 }
    }
    fn take(&mut self, name: &str, n: usize) -> &'a [u8] {
        let s = &self.bytes[self.at..self.at + n];
        println!("| {} | {} | {} | `{}` |", self.at, n, name, short(s));
        self.at += n;
        s
    }
    fn u16(&mut self, name: &str) -> usize {
        u16::from_be_bytes(self.take(name, 2).try_into().unwrap()) as usize
    }
    fn u32(&mut self, name: &str) -> usize {
        u32::from_be_bytes(self.take(name, 4).try_into().unwrap()) as usize
    }
    fn u64(&mut self, name: &str) -> u64 {
        u64::from_be_bytes(self.take(name, 8).try_into().unwrap())
    }
    fn done(self) {
        assert_eq!(
            self.at,
            self.bytes.len(),
            "layout in the doc does not cover every byte"
        );
    }
}

// ------------------------------------------------- A. a real session on TCP

/// Copies bytes both ways between two sockets and records them per direction.
fn proxy(listen: TcpListener, target: std::net::SocketAddr, log: Arc<Mutex<[Vec<u8>; 2]>>) {
    let (client, _) = listen.accept().unwrap();
    let server = TcpStream::connect(target).unwrap();
    for (dir, from, to) in [
        (
            0usize,
            client.try_clone().unwrap(),
            server.try_clone().unwrap(),
        ),
        (1usize, server, client),
    ] {
        let log = Arc::clone(&log);
        thread::spawn(move || {
            let (mut from, mut to) = (from, to);
            let mut buf = [0u8; 4096];
            while let Ok(n) = from.read(&mut buf) {
                if n == 0 {
                    break;
                }
                log.lock().unwrap()[dir].extend_from_slice(&buf[..n]);
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        });
    }
}

/// Split a recorded byte stream into length-prefixed frames.
fn frames(stream: &[u8]) -> Vec<Vec<u8>> {
    let (mut out, mut i) = (vec![], 0);
    while i + 4 <= stream.len() {
        let len = u32::from_be_bytes(stream[i..i + 4].try_into().unwrap()) as usize;
        assert!(len as u32 <= MAX_FRAME_LEN);
        out.push(stream[i..i + 4 + len].to_vec()); // keep the 4-byte prefix
        i += 4 + len;
    }
    assert_eq!(i, stream.len(), "stream ended mid-frame");
    out
}

fn part_a_session_on_the_wire() {
    println!("\n## A. A real session, captured between two sockets");
    let alice = Identity::generate();
    let bob = Identity::generate();
    let (mut ra, mut rb) = (PeerRegistry::new(), PeerRegistry::new());
    ra.trust(bob.public_key());
    rb.trust(alice.public_key());

    let bob_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bob_addr = bob_listener.local_addr().unwrap();
    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let log = Arc::new(Mutex::new([Vec::new(), Vec::new()]));
    {
        let log = Arc::clone(&log);
        thread::spawn(move || proxy(proxy_listener, bob_addr, log));
    }
    let bt = thread::spawn(move || {
        let (s, _) = bob_listener.accept().unwrap();
        Session::establish(s, Role::Responder, &bob, &rb).unwrap()
    });
    let a = Session::establish(
        TcpStream::connect(proxy_addr).unwrap(),
        Role::Initiator,
        &alice,
        &ra,
    )
    .unwrap();
    let b = bt.join().unwrap();

    a.send(b"hello bob").unwrap(); // 9 bytes
    assert_eq!(b.recv().unwrap(), b"hello bob");
    b.send(b"hi alice, this is a longer reply").unwrap(); // 32 bytes
    assert_eq!(a.recv().unwrap(), b"hi alice, this is a longer reply");
    thread::sleep(Duration::from_millis(400)); // let the acks go out
    drop((a, b));
    thread::sleep(Duration::from_millis(100));

    let log = log.lock().unwrap();
    let to_bob = frames(&log[0]);
    let to_alice = frames(&log[1]);

    // Handshake: two frames each way, in this order (the first pair are bare
    // ephemeral keys; the second pair are encrypted and hold the identities).
    assert_eq!(to_bob[0].len(), 4 + 32 + 1184);
    assert_eq!(to_alice[0].len(), 4 + 32 + 1088);
    assert_eq!(to_bob[1].len(), 4 + 118 + 16);
    assert_eq!(to_bob[2].len(), 4 + 16); // Msg5: empty plaintext + tag
    assert_eq!(to_alice[1].len(), 4 + 118 + 16);

    let f = &to_bob[0];
    let mut w = Walker::new(
        "Handshake Msg1 (initiator to responder), including the 4-byte length prefix",
        f,
    );
    w.u32("frame length");
    w.take("initiator ephemeral X25519 public key", 32);
    w.take(
        "initiator ML-KEM-768 encapsulation key (post-quantum half)",
        1184,
    );
    w.done();

    let f = &to_alice[0];
    let mut w = Walker::new("Handshake Msg2 (responder to initiator)", f);
    w.u32("frame length");
    w.take("responder ephemeral X25519 public key", 32);
    w.take(
        "ML-KEM-768 ciphertext (the encapsulated post-quantum secret)",
        1088,
    );
    w.done();

    let f = &to_bob[1];
    let mut w = Walker::new("Handshake Msg3 (initiator to responder), encrypted", f);
    w.u32("frame length");
    w.take(
        "ciphertext of: version (6) + Ed25519 public key (32) + epoch (16) + signature (64)",
        118,
    );
    w.take("authentication tag", 16);
    w.done();

    let f = &to_alice[1];
    let mut w = Walker::new("Handshake Msg4 (responder to initiator), encrypted", f);
    w.u32("frame length");
    w.take(
        "ciphertext of: version (6) + Ed25519 public key (32) + epoch (16) + signature (64)",
        118,
    );
    w.take("authentication tag", 16);
    w.done();

    let f = &to_bob[2];
    let mut w = Walker::new("Handshake Msg5 (initiator to responder), encrypted", f);
    w.u32("frame length");
    w.take(
        "authentication tag of an empty plaintext (confirmation)",
        16,
    );
    w.done();

    let hs_total: usize = to_bob[..3]
        .iter()
        .chain(to_alice[..2].iter())
        .map(|f| f.len())
        .sum();
    println!(
        "\nHandshake total on the wire: {hs_total} bytes in 5 frames. The post-quantum half \
         adds {} bytes once per connection (1184-byte key + 1088-byte ciphertext); every \
         message after the handshake is unchanged.",
        1184 + 1088
    );

    println!("\n### Every frame after the handshake (all encrypted; only the header is readable)");
    println!("| direction | frame | total bytes on wire | length prefix | channel | seq | ciphertext+tag |");
    println!("|---|---:|---:|---:|---|---:|---:|");
    let mut data_sizes = vec![];
    for (name, list, skip) in [
        ("alice to bob", &to_bob, 3usize),
        ("bob to alice", &to_alice, 2),
    ] {
        for (i, fr) in list.iter().enumerate().skip(skip) {
            let len = u32::from_be_bytes(fr[0..4].try_into().unwrap()) as usize;
            let ch = if fr[4] == 0 { "Data" } else { "Control" };
            let seq = u64::from_be_bytes(fr[5..13].try_into().unwrap());
            println!(
                "| {name} | {i} | {} | {len} | {ch} | {seq} | {} |",
                fr.len(),
                fr.len() - 13
            );
            if fr[4] == 0 {
                data_sizes.push(fr.len());
            }
        }
    }
    // Padding is off by default but its 1-byte marker is always added:
    // 9-byte message => 4 + 9 + (40 + (9 + 1) + 16) + 16 = 95;  32-byte => 118
    assert!(
        data_sizes.contains(&(9 + 86)),
        "9-byte payload should cost 86 bytes of overhead"
    );
    assert!(
        data_sizes.contains(&(32 + 86)),
        "32-byte payload should cost 86 bytes of overhead"
    );
    println!(
        "\nOverhead per data message = {} bytes (85 + the 1-byte padding marker; 9-byte payload -> {} on the wire).",
        86,
        9 + 86
    );
}

// ----------------------------------------------------------- B. the ratchet

fn part_b_ratchet() {
    println!("\n## B. The Double Ratchet layer (the blob inside each Data frame)");
    let alice = Identity::generate();
    let bob = Identity::generate();
    let (mut ra, mut rb) = (PeerRegistry::new(), PeerRegistry::new());
    ra.trust(bob.public_key());
    rb.trust(alice.public_key());
    let (mut ca, mut cb) = memory_pair(Duration::ZERO);
    let bt = thread::spawn(move || {
        run_responder(&mut cb, &bob, &rb, &|_: &PeerId| [2u8; 16], None).unwrap()
    });
    let ha = run_initiator(&mut ca, &alice, &ra, &[1u8; 16], None).unwrap();
    let hb = bt.join().unwrap();
    let mut rat_a = Ratchet::from_seed(ha.ratchet).unwrap();
    let mut rat_b = Ratchet::from_seed(hb.ratchet).unwrap();

    // Responder speaks first on the seeded chain, then the initiator replies (new DH key).
    let m1 = rat_b.encrypt(b"first").unwrap();
    rat_a.decrypt(&m1).unwrap();
    let m2 = rat_b.encrypt(b"second").unwrap();
    rat_a.decrypt(&m2).unwrap();
    let m3 = rat_a.encrypt(b"reply").unwrap();
    rat_b.decrypt(&m3).unwrap();
    for (title, m, body) in [
        ("Ratchet blob 1: responder's first message", &m1, 5usize),
        (
            "Ratchet blob 2: same chain, counter n goes up, same DH key",
            &m2,
            6,
        ),
        (
            "Ratchet blob 3: other side replies, NEW DH key, pn = length of previous chain",
            &m3,
            5,
        ),
    ] {
        let mut w = Walker::new(title, m);
        w.take("header: sender's current ratchet public key (X25519)", 32);
        let pn = w.take(
            "header: pn = messages in the previous sending chain (u32)",
            4,
        );
        let n = w.take("header: n = this message's number in the chain (u32)", 4);
        let _ = (pn, n);
        w.take("ciphertext of the payload", body);
        w.take("Poly1305 authentication tag", 16);
        w.done();
    }
}

// ----------------------------------------------------------- C. control msgs

fn part_c_control() {
    println!("\n## C. Control messages (the plaintext inside Control frames)");
    let cases: Vec<(&str, ControlMessage)> = vec![
        (
            "Ack: received everything up to 5, but 7 and 9 are missing",
            ControlMessage::Ack {
                cumulative_ack: 5,
                missing: vec![7, 9],
            },
        ),
        (
            "Ack with nothing missing",
            ControlMessage::Ack {
                cumulative_ack: 42,
                missing: vec![],
            },
        ),
        (
            "ResumeRequest",
            ControlMessage::ResumeRequest {
                last_contiguous_seq: 100,
            },
        ),
        (
            "Ping",
            ControlMessage::Ping {
                nonce: 0x1122334455667788,
            },
        ),
        (
            "Pong",
            ControlMessage::Pong {
                nonce: 0x1122334455667788,
            },
        ),
    ];
    for (title, msg) in cases {
        let b = msg.encode();
        let mut w = Walker::new(title, &b);
        match &msg {
            ControlMessage::Ack { missing, .. } => {
                w.take("tag 0x01 = Ack", 1);
                w.u64("cumulative_ack: everything up to here arrived");
                let n = w.u16("count of missing numbers");
                assert_eq!(n, missing.len());
                for _ in 0..n {
                    w.u64("a missing sequence number");
                }
            }
            ControlMessage::ResumeRequest { .. } => {
                w.take("tag 0x02 = ResumeRequest", 1);
                w.u64("last_contiguous_seq");
            }
            ControlMessage::Ping { .. } => {
                w.take("tag 0x03 = Ping", 1);
                w.u64("nonce (echoed in the Pong)");
            }
            ControlMessage::Pong { .. } => {
                w.take("tag 0x04 = Pong", 1);
                w.u64("nonce (copied from the Ping)");
            }
        }
        w.done();
    }
}

// ------------------------------------------------------------- D. group msgs

fn part_d_group() {
    println!("\n## D. Group messages (plaintext carried inside the ratchet blob)");
    let alice = Identity::generate();
    let bob = Identity::generate();
    let (_roster, genesis) = Roster::genesis_default(&alice, vec![bob.public_key()]);
    let wire = RosterOpWire::from(&genesis);
    println!(
        "\n(group id is {} raw bytes: `{}`)",
        wire.group_id.as_bytes().len(),
        short(wire.group_id.as_bytes())
    );
    let sender = alice.fingerprint(); // 32 raw bytes on the wire
    let filler_sig = [0xEEu8; 64]; // placeholder: the example cannot reach the private signing function
    let zero = [0u8; 32];

    // --- Roster (genesis)
    let b = GroupMessage::Roster(wire.clone()).encode();
    let mut w = Walker::new("Roster message carrying the Genesis operation", &b);
    w.take("tag 0x11 = Roster", 1);
    w.take("group id (raw 32 bytes)", 32);
    w.u64("roster version (0 = genesis)");
    w.take("previous roster hash (all zero at genesis)", 32);
    let oplen = w.u32("operation length");
    // Genesis op inside:
    let op_start = w.at;
    w.take("op tag 0 = Genesis", 1);
    w.take("group kind (0 = FullMesh)", 1);
    w.take("relay policy (0 = Open, 1 = AuthorOnly)", 1);
    let tiers = w.u16("number of tier definitions");
    for _ in 0..tiers {
        let l = w.u16("  tier name length");
        w.take("  tier name", l);
        w.take(
            "  permissions bitmask (add=1, remove=2, read=4, write=8)",
            1,
        );
    }
    let members = w.u16("number of members");
    for _ in 0..members {
        w.take("  member Ed25519 public key (raw 32 bytes)", 32);
        let l = w.u16("  member tier name length");
        w.take("  member tier name", l);
    }
    assert_eq!(w.at - op_start, oplen);
    w.take("proposer id (raw 32 bytes)", 32);
    w.take("proposer Ed25519 signature", 64);
    w.done();

    // --- Application (Post / Edit / Delete)
    for (title, content) in [
        (
            "Application message: Post \"hello group\"",
            GroupContent::Post {
                payload: b"hello group".to_vec(),
            },
        ),
        (
            "Application message: Edit of #1",
            GroupContent::Edit {
                target_seq: 1,
                new_payload: b"hello, group".to_vec(),
            },
        ),
        (
            "Application message: Delete of #1",
            GroupContent::Delete {
                target_sender: sender,
                target_seq: 1,
            },
        ),
    ] {
        let msg = GroupMessage::Application {
            sender,
            seq: 1,
            prev_hash: zero,
            roster_version: 0,
            content: content.clone(),
            signature: filler_sig,
        };
        let b = msg.encode();
        let mut w = Walker::new(title, &b);
        w.take("tag 0x10 = Application", 1);
        w.take("author id (raw 32 bytes: SHA-256(public key))", 32);
        w.u64("author's sequence number");
        w.take(
            "hash of this author's previous message (zero for the first)",
            32,
        );
        w.u64("roster version the author wrote under");
        let cl = w.u32("content length");
        let start = w.at;
        match content {
            GroupContent::Post { ref payload } => {
                w.take("content kind 0 = Post", 1);
                w.take("payload (your text)", payload.len());
            }
            GroupContent::Edit {
                ref new_payload, ..
            } => {
                w.take("content kind 1 = Edit", 1);
                w.u64("target sequence number being edited");
                w.take("new payload", new_payload.len());
            }
            GroupContent::Delete { .. } => {
                w.take("content kind 2 = Delete", 1);
                w.take("target author id (raw 32 bytes)", 32);
                w.u64("target sequence number");
            }
            GroupContent::File { ref offer } => {
                w.take("content kind 3 = File offer", 1);
                w.take(
                    "file offer (name, size, chunk size, root, prefix)",
                    offer.encode().len(),
                );
            }
        }
        assert_eq!(w.at - start, cl);
        w.take(
            "author Ed25519 signature (placeholder bytes 0xEE in this dump)",
            64,
        );
        w.done();
    }

    // --- Small control-style group messages
    let b = GroupMessage::Have { sender, seq: 7 }.encode();
    let mut w = Walker::new("Have: \"I hold message 7 by this author\"", &b);
    w.take("tag 0x17 = Have", 1);
    w.take("author id (raw 32 bytes)", 32);
    w.u64("sequence number");
    w.done();

    let b = GroupMessage::RelayRequest {
        sender,
        after_seq: 3,
    }
    .encode();
    let mut w = Walker::new(
        "RelayRequest: \"send me what you hold from this author after 3\"",
        &b,
    );
    w.take("tag 0x12 = RelayRequest", 1);
    w.take("author id (raw 32 bytes)", 32);
    w.u64("after_seq");
    w.done();

    let b = GroupMessage::FetchRequest { sender, seq: 4 }.encode();
    let mut w = Walker::new("FetchRequest: \"send me exactly message 4\"", &b);
    w.take("tag 0x15 = FetchRequest", 1);
    w.take("author id (raw 32 bytes)", 32);
    w.u64("sequence number");
    w.done();

    let b = GroupMessage::RosterSyncRequest { have_version: 2 }.encode();
    let mut w = Walker::new(
        "RosterSyncRequest: \"I have roster version 2, send newer\"",
        &b,
    );
    w.take("tag 0x13 = RosterSyncRequest", 1);
    w.u64("have_version");
    w.done();

    let b = GroupMessage::Existence {
        sender,
        seq: 5,
        prev_hash: zero,
        roster_version: 0,
        content_hash: [0xCDu8; 32],
        signature: filler_sig,
    }
    .encode();
    let mut w = Walker::new("Existence notice: \"message 5 exists\" (no content)", &b);
    w.take("tag 0x14 = Existence", 1);
    w.take("author id (raw 32 bytes)", 32);
    w.u64("sequence number");
    w.take("previous message hash", 32);
    w.u64("roster version");
    w.take("SHA-256 of the hidden content", 32);
    w.take("author signature (placeholder)", 64);
    w.done();

    let b = GroupMessage::Receipt {
        author: sender,
        seq: 5,
        content_hash: [0xCDu8; 32],
        kind: ReceiptKind::Delivered,
        receiver: bob.fingerprint(),
        signature: filler_sig,
    }
    .encode();
    let mut w = Walker::new("Receipt: \"I (receiver) got message 5\"", &b);
    w.take("tag 0x16 = Receipt", 1);
    w.take("author id (raw 32 bytes)", 32);
    w.u64("sequence number");
    w.take("SHA-256 of the content received", 32);
    w.take("kind (0 = delivered, 1 = read)", 1);
    w.take("receiver id (raw 32 bytes)", 32);
    w.take("receiver signature (placeholder)", 64);
    w.done();
}

// ---------------------------------------------- E. files and the LAN beacon

fn part_e_files_and_discovery() {
    println!("\n## E. Files and the discovery beacon");
    let id = Identity::generate();
    let dir = std::env::temp_dir().join(format!("symbolon-wire-dump-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("id.enc");
    EncryptedIdentity::save_with_params(&id, &path, "demo", KdfParams::insecure_fast_for_tests())
        .unwrap();
    let b = std::fs::read(&path).unwrap();
    let mut w = Walker::new("Identity file on disk (`SYMI`, format 2)", &b);
    w.take("magic \"SYMI\"", 4);
    w.take("format version (u16 = 2)", 2);
    w.take("Argon2id salt (random)", 16);
    w.take(
        "Argon2id memory cost in KiB (u32; demo uses weak test settings)",
        4,
    );
    w.take("Argon2id time cost (u32)", 4);
    w.take("Argon2id lanes (u32)", 4);
    w.take("AEAD nonce (random)", 12);
    w.take("key commitment", 32);
    w.take("encrypted 32-byte secret key", 32);
    w.take("Poly1305 tag", 16);
    w.done();
    let _ = std::fs::remove_dir_all(&dir);

    for (title, level) in [
        ("Discovery beacon, default (major only)", Disclose::Major),
        ("Discovery beacon, full version disclosed", Disclose::Full),
    ] {
        let b = Announcement::new("tea-laptop", (0, 2, 0), level, 7000)
            .unwrap()
            .encode();
        let mut w = Walker::new(title, &b);
        let _ = w.take("magic \"SYMD\"", 4);
        w.take("wire version", 1);
        let flags = w.take("flags (bit0 = minor present, bit1 = patch present)", 1)[0];
        let nl = w.take("name length", 1)[0] as usize;
        w.take("display name (ASCII)", nl);
        w.take("major version", 1);
        if flags & 1 != 0 {
            w.take("minor version", 1);
        }
        if flags & 2 != 0 {
            w.take("patch version", 1);
        }
        w.take("TCP port to dial (u16)", 2);
        w.done();
    }
}

fn main() {
    println!("# symbolon wire dump (random keys: hex changes per run, sizes do not)");
    part_a_session_on_the_wire();
    part_b_ratchet();
    part_c_control();
    part_d_group();
    part_e_files_and_discovery();
    println!("\nAll layouts matched the bytes.");
}
