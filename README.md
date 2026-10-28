# symbolon

A small, dependency-light peer-to-peer secure messaging library written in
Rust. No server, no UI - two peers connect directly over TCP, mutually
authenticate, and exchange messages that are encrypted, tamper-evident, and
guaranteed not to go missing across a disconnect/reconnect.

There is no CLI or terminal input here on purpose (per the request this was
built for) - the intended entry points are the library API (`src/`) and the
test suite (`cargo test`), which doubles as executable documentation of every
security property below.

## Security properties, concretely

- **Mutual authentication.** Each peer has a long-term Ed25519 identity
  keypair. Before two peers can talk, each must already have the other's
  public key "pinned" (see Trust model below). The handshake
  (`src/handshake.rs`) makes both sides *prove*, via signatures over a shared
  transcript, that they hold the private key matching their pinned identity.
  This is symmetric - unlike TLS, there's no client/server asymmetry; both
  sides authenticate each other before a single byte of application data
  moves.
- **Confidentiality and integrity.** Every message (including the internal
  acknowledgement/control traffic) is encrypted with ChaCha20-Poly1305
  (`src/crypto.rs`). Any bit-flip, truncation, or tampering is rejected by
  the authentication tag - see
  `tests/integration_test.rs::tampered_ciphertext_is_rejected_not_silently_accepted`.
- **Forward secrecy.** Session encryption keys come from a fresh ephemeral
  X25519 Diffie-Hellman exchange every single connection - never from the
  long-term identity keys directly. If a long-term private key leaks later,
  past traffic recorded by an eavesdropper still can't be decrypted.
- **No silently missing messages.** Every message is sequence-numbered,
  durably staged in a per-peer outbox until acknowledged, and the receiver
  tracks gaps explicitly (`src/reliability.rs`). If a connection drops before
  a message is acknowledged, reconnecting automatically triggers a resend of
  exactly what's missing - see
  `tests/integration_test.rs::no_message_is_lost_across_a_disconnect_and_reconnect`.
- **In-order delivery.** The receiver buffers out-of-order arrivals and only
  ever hands messages to the application in strict sequence order, so a gap
  can never be silently skipped over.

## Trust model (read this before using it for anything real)

There is no certificate authority. In a genuine P2P setting there usually
isn't one to trust anyway. Instead, exactly like SSH's `known_hosts` or
Signal's "safety numbers", **you must exchange and verify each peer's public
key fingerprint out of band** before connecting - read it aloud on a call,
scan a QR code in person, etc. `PeerRegistry` (`src/identity.rs`) is a
simple pinned-key allow-list; connections from/to identities that aren't
pinned are refused before any application data is exchanged. This library
deliberately does **not** implement Trust-On-First-Use by default, since that
would let an attacker who's on-path for the very first connection plant
themselves permanently.

## Module map

| Module | Responsibility |
|---|---|
| `identity` | Long-term Ed25519 keypairs, peer fingerprints, the pinned-peer trust registry |
| `handshake` | Mutual-authentication + ephemeral key exchange protocol |
| `crypto` | AEAD encryption primitives, per-direction keys, nonce management |
| `framing` | Length-prefixed message framing over a raw byte stream |
| `message` | Wire encoding for control messages (Ack, ResumeRequest) |
| `reliability` | Sequence numbering, acknowledgement, gap detection/recovery |
| `session` | Ties it all together: the public send/recv API, reconnect support |
| `group` | Group chat: signed roster + full-mesh of `Session`s + equivocation-detecting sender chains |
| `error` | The crate's error type |

## Dependencies

Deliberately minimal, all narrowly-scoped, widely-used cryptography crates -
no web/async framework, no heavy serialization framework:

- `ed25519-dalek`, `x25519-dalek` - the two curve25519 primitives
- `chacha20poly1305` - AEAD encryption
- `hkdf`, `sha2` - key derivation / hashing
- `rand_core` - CSPRNG source

Everything else (TCP transport, wire framing, message parsing) is hand-rolled
on top of `std::net` / `std::thread` - no async runtime.

## Group chat

Group chat is built as a layer *on top of* the pairwise protocol above,
not a separate one - see `src/group.rs` for the full design rationale.
Short version: every member keeps one ordinary, mutually-authenticated
`Session` with every other member (full mesh), and a `GroupHub` wires them
together, adding exactly two things full-mesh doesn't give you for free:

- **A signed, hash-chained membership roster** (`Roster`) - every Add/Remove
  must be signed by a *current* member and must build on the exact previous
  roster state, so a non-member can't forge a membership change, and a
  removed member can't keep participating just because their TCP link is
  still technically open.
- **Per-sender hash chains** (`SenderChainState`/`OwnChainState`) - so that
  if a malicious sender told two different members two different things
  under the same message number (equivocation), that's detectable by
  comparing the two members' independently-derived tip hashes for that
  sender, even though plain full-mesh AEAD alone would never catch it.

A group's "type" is fixed forever at creation (`Roster::genesis`) - there is
no operation that turns a group into a 1:1 session or back, and no code
path branches on live member count. A group that shrinks to two members via
`Remove` is still, structurally, an ordinary group.

See `tests/group_integration_test.rs` for the full end-to-end
demonstration (real TCP full mesh, broadcasting, and removing a member).

## Running the tests

```
cargo test
```

30 unit tests cover each module in isolation (nonce/channel separation,
tamper detection, gap-buffering logic, wire encoding round-trips, roster
signature/fork rejection, equivocation detection). 8 integration tests
(`tests/integration_test.rs`, `tests/group_integration_test.rs`) exercise
the whole stack over real TCP loopback connections, including a full
disconnect + reconnect scenario and a 3-member group with a member removal.

## What this is not

This is a demonstration/reference implementation, not an audited production
security library. In particular: it doesn't persist the outbox/inbox to
disk (a process restart, as opposed to a network disconnect, currently loses
in-flight state), doesn't implement identity key persistence/rotation
tooling, and hasn't been through third-party cryptographic review.

The group chat layer specifically is full-mesh (O(N) links and O(N) work per
broadcast per sender) rather than MLS/TreeKEM-style (O(log N)), and it does
*not* rekey group encryption on membership changes the way MLS does -
removing a member stops their messages from being *accepted* (enforced by
the roster check on every recipient) but their pairwise `Session`s aren't
automatically re-derived with fresh keys, and there's no tree-based
post-compromise "healing" within a session. For groups large enough for
O(log N) rekeying to matter, or for that stronger healing property, MLS
(via `openmls`/`mls-rs`) is the right tool - see the design discussion this
module grew out of for the full trade-off.
