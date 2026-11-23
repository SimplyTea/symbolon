# Symbolon

A small, security-and-privacy-first **serverless peer-to-peer messaging
library** in Rust. No servers, no accounts, no certificate authority. Peers
connect directly, prove who they are with keys they already pinned, and
exchange messages that are encrypted, tamper-evident and not silently lost
across disconnects. Groups are built on top of the same pairwise protocol.

It is a **library, not a framework**: few dependencies, no async runtime,
everything commented so it can be read end to end. It is **unreleased and not
audited**; do not protect anything important with it yet
([Threat model](docs/THREAT_MODEL.md)).

## If you are new, read in this order

1. This page (what it does, and a tiny example).
2. [Glossary](docs/GLOSSARY.md): every term in plain words.
3. The topic pages below, in any order. Each starts "in plain words", lists
   the **options with trade-offs**, then says what we chose.
4. [Plan](docs/PLAN.md): what is built, planned, parked and rejected.

## Guide to the docs

| Page | Answers |
|---|---|
| [Identity and trust](docs/IDENTITY_AND_TRUST.md) | Who is who without a server? Why pinning, not TOFU or a CA? |
| [Handshake and versioning](docs/HANDSHAKE_AND_VERSIONING.md) | How two peers prove themselves; what happens if versions differ; the oracle |
| [Wire format](docs/WIRE_FORMAT.md) | Every byte on the wire and on disk: field sizes, types, the reason for each, real hex dumps, what an eavesdropper sees |
| [Sessions](docs/SESSIONS.md) | Encryption layers, the Double Ratchet, reliable delivery, heartbeat, surviving restarts |
| [Groups](docs/GROUPS.md) | Signed roster, tiers, group type, full mesh versus tree versus sender keys |
| [Messages](docs/MESSAGES.md) | Author chains, relay policy, existence notices, receipts, `Have` forwarding |
| [Bots](docs/BOTS.md) | Bot members, sponsors, scripting |
| [Ordering](docs/ORDERING.md) | Why there is no global order; Lamport clock and other options |
| [Storage and plug-ins](docs/STORAGE_AND_PLUGINS.md) | The traits you can replace; encryption at rest |
| [File transfer](docs/FILES.md) | Offers shown before download, hash-checked chunks, limits, what is built so far |
| [Discovery](docs/DISCOVERY.md) | Finding peers on a LAN, and what it costs in privacy |
| [Future crypto](docs/FUTURE_CRYPTO.md) | Post-quantum, MLS, and why not sender keys |
| [Threat model](docs/THREAT_MODEL.md) | Who we defend against, metadata, known gaps |
| [Library vs app](docs/LIBRARY_VS_APP.md) | What the library promises and what an app must decide |
| [Plan](docs/PLAN.md) | Roadmap, parked ideas, rejected ideas, defaults |
| [Glossary](docs/GLOSSARY.md) | Terms |

## What you get today

- **Mutual authentication** with pinned Ed25519 identities; unknown keys are
  refused and queued for approval.
- **Confidentiality, integrity, forward secrecy**: ephemeral X25519 handshake,
  ChaCha20-Poly1305, and a Double Ratchet inside the transport encryption.
- **No silently lost messages**: sequence numbers, acks, gap detection, resume
  after disconnect, and saved state across restarts (at-least-once).
- **Liveness** by pinging only when idle.
- **Groups**: a signed hash-chained roster, named permission tiers (add,
  remove, read, write), an immutable group type, per-author hash chains that
  expose equivocation, edits and deletes, relay policy (Open or AuthorOnly),
  existence notices, delivery/read receipts, announce-and-request forwarding,
  and bot members with sponsors.
- **Plug-ins** for transport, storage, trust, clock and tracing; identity file
  protected by Argon2id.
- **Version rule**: crate version = protocol version; major and minor must
  match to connect.

## Example

Two peers on one machine, pinned to each other, exchanging a message each way.
Condensed from the compiled file `examples/two_peers.rs` (imports and prints omitted):

```rust
let alice = Identity::generate();
let bob = Identity::generate();

// Each side pins the other's public key (verify fingerprints out of band!).
let mut alice_trusts = PeerRegistry::new();
alice_trusts.trust(bob.public_key());
let mut bob_trusts = PeerRegistry::new();
bob_trusts.trust(alice.public_key());

// One side listens, the other dials; both prove who they are.
let listener = TcpListener::bind("127.0.0.1:0").unwrap();
let addr = listener.local_addr().unwrap();
let bob_thread = thread::spawn(move || {
    let (stream, _) = listener.accept().unwrap();
    Session::establish(stream, Role::Responder, &bob, &bob_trusts).unwrap()
});
let alice_session = Session::establish(
    TcpStream::connect(addr).unwrap(), Role::Initiator, &alice, &alice_trusts,
).unwrap();
let bob_session = bob_thread.join().unwrap();

alice_session.send(b"hello bob").unwrap();
let received = bob_session.recv().unwrap(); // b"hello bob"
```

Run it with `cargo run --example two_peers`. For groups see
`tests/group_integration_test.rs` and [Groups](docs/GROUPS.md).

## Code map

| Module | Role |
|---|---|
| `identity`, `peer`, `truststore` | Keys, fingerprints, pinned-peer registry, approval queue |
| `handshake` | Mutual authentication, key exchange, `Version` negotiation |
| `crypto`, `ratchet` | AEAD and the Double Ratchet |
| `framing`, `message`, `reliability` | Length-prefixed frames, control messages, sequence/ack/gap logic |
| `session`, `sessionstate` | The send/recv API; saved state |
| `group` | Roster, tiers, author chains, relay, receipts, `GroupHub` |
| `storage`, `persistence` | Storage traits and defaults; encrypted identity file |
| `transport`, `clock`, `trace`, `discovery` | Pluggable byte transport, time, tracing, LAN hints |
| `error` | The crate's error type |

## Tests and tools

```
cargo test                       # 269 tests: unit plus real-TCP integration
cargo run --release --example bench > bench.csv   # per-operation CPU costs
cargo run --example wire_dump    # real bytes of every message, field by field
```

Integration tests cover tampering, disconnect and resume, restart, heartbeat,
group roster sync, receipts, existence notices and forwarding. They double as
executable documentation. `NOTES.md` is the running development log with the
reasons behind each decision.

`scripts/e2e/run_all.sh` additionally drives the real `symbolon` program as separate
processes (see `scripts/e2e/README.md`).

A command-line app (`src/bin/symbolon`) exists for manual testing and is not
documented here; the docs describe the library.

## Dependencies

Narrow and well known: `ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`,
`hkdf`, `sha2`, `rand_core`, `argon2`, `zeroize` and `ml-kem` (the RustCrypto
ML-KEM, which has not been independently audited; see the
[Threat model](docs/THREAT_MODEL.md)). Some transitive crates are pinned, noted in
`Cargo.toml`. Everything else, including framing,
threads and the TCP transport, is on `std`.

## What this is not

Not audited, not released, post-quantum key exchange but classical signatures
and identities, no key rotation, and groups
are a full mesh (cost grows with the square of group size) until the
tree-based design in the [Plan](docs/PLAN.md) lands.
