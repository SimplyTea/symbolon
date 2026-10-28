//! Micro-benchmarks that print CSV (`name,param,median_us,p95_us,runs`) so
//! the numbers can be graphed or fed into a simulator as per-operation
//! costs. Run on each target device (laptop, Pi) with:
//!
//!     cargo run --release --example bench > bench_<device>.csv
//!
//! Everything measured here is *CPU cost on one machine*. Network latency is
//! deliberately excluded: add it in the simulator as a separate parameter.

use symbolon::identity::Identity;
use symbolon::peer::PeerRegistry;
use symbolon::persistence::EncryptedIdentity;
use symbolon::ratchet::Ratchet;
use symbolon::session::{Role, Session};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

/// Run `f` `runs` times and print median and 95th percentile in microseconds.
fn measure(name: &str, param: &str, runs: usize, mut f: impl FnMut()) {
    let mut samples: Vec<f64> = (0..runs)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1e6
        })
        .collect();
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = samples[samples.len() / 2];
    let p95 = samples[(samples.len() * 95 / 100).min(samples.len() - 1)];
    println!("{name},{param},{med:.2},{p95:.2},{runs}");
}

fn pair() -> (Ratchet, Ratchet) {
    Ratchet::pair_from_shared_secret(&[9u8; 32], &[3u8; 32]).unwrap()
}

fn main() {
    println!("name,param,median_us,p95_us,runs");

    // --- Identity: Ed25519 ---
    let id = Identity::generate();
    let msg = [7u8; 256];
    let sig = id.sign(&msg);
    let vk = id.public_key();
    measure("ed25519_sign", "256B", 2000, || {
        std::hint::black_box(id.sign(&msg));
    });
    measure("ed25519_verify", "256B", 2000, || {
        PeerRegistry::verify_signature(&vk, &msg, &sig).unwrap();
    });
    measure("identity_generate", "-", 500, || {
        std::hint::black_box(Identity::generate());
    });

    // --- Ratchet: steady state within one chain, by payload size ---
    for size in [64usize, 1024, 16 * 1024, 256 * 1024] {
        let payload = vec![1u8; size];
        let (mut a, mut b) = pair();
        measure("ratchet_encrypt", &format!("{size}B"), 500, || {
            std::hint::black_box(a.encrypt(&payload).unwrap());
        });
        let (mut a, mut b2) = pair();
        let wires: Vec<_> = (0..500).map(|_| a.encrypt(&payload).unwrap()).collect();
        let mut i = 0;
        measure("ratchet_decrypt", &format!("{size}B"), 500, || {
            std::hint::black_box(b2.decrypt(&wires[i]).unwrap());
            i += 1;
        });
        let _ = &mut b;
    }

    // --- Ratchet: a DH step (direction change) = 2 X25519 + 2 HKDF ---
    {
        let (mut a, mut b) = pair();
        b.decrypt(&a.encrypt(b"warm").unwrap()).unwrap();
        measure("ratchet_dh_turn_roundtrip", "64B", 500, || {
            let r = b.encrypt(b"x").unwrap();
            a.decrypt(&r).unwrap();
            let s = a.encrypt(b"y").unwrap();
            b.decrypt(&s).unwrap();
        });
    }

    // --- Ratchet: worst-case out-of-order jump (hash-chain catch-up) ---
    for gap in [10u32, 100, 1000] {
        measure("ratchet_decrypt_after_gap", &format!("gap{gap}"), 50, || {
            let (mut a, mut b) = pair();
            for _ in 0..gap {
                a.encrypt(b"x").unwrap();
            }
            let w = a.encrypt(b"y").unwrap();
            b.decrypt(&w).unwrap();
        });
    }

    // --- Session: full mutual-auth handshake over loopback TCP ---
    measure("session_handshake_loopback", "-", 30, || {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mut ar = PeerRegistry::new();
        ar.trust(bob.public_key());
        let mut br = PeerRegistry::new();
        br.trust(alice.public_key());
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            Session::establish(s, Role::Responder, &bob, &br).unwrap()
        });
        let c = TcpStream::connect(addr).unwrap();
        let a = Session::establish(c, Role::Initiator, &alice, &ar).unwrap();
        let b = h.join().unwrap();
        std::hint::black_box((a, b));
    });

    // --- Session: end-to-end send->recv on loopback (CPU + 2 threads) ---
    {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mut ar = PeerRegistry::new();
        ar.trust(bob.public_key());
        let mut br = PeerRegistry::new();
        br.trust(alice.public_key());
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            Session::establish(s, Role::Responder, &bob, &br).unwrap()
        });
        let c = TcpStream::connect(addr).unwrap();
        let a = Session::establish(c, Role::Initiator, &alice, &ar).unwrap();
        let b = h.join().unwrap();
        for size in [64usize, 1024, 64 * 1024] {
            let payload = vec![2u8; size];
            measure("session_send_recv_loopback", &format!("{size}B"), 300, || {
                a.send(&payload).unwrap();
                std::hint::black_box(b.recv().unwrap());
            });
        }
    }

    // --- Persistence: identity unlock (PBKDF2, 600k rounds by default) ---
    {
        let dir = std::env::temp_dir().join(format!("bench-id-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("id.enc");
        EncryptedIdentity::save(&id, &path, "bench passphrase").unwrap();
        measure("identity_unlock_pbkdf2", "600k", 5, || {
            std::hint::black_box(EncryptedIdentity::load(&path, "bench passphrase").unwrap());
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
