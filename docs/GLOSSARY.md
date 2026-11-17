# Glossary

Every term the other docs use, in plain words. If you are new to this, read the
[README](../README.md) first, then come here whenever a word is unfamiliar.
Each entry links to the doc that explains it in depth.

## Cryptography words

**AEAD (authenticated encryption)**
Encryption that also proves the message was not changed. If even one bit is
flipped in transit, decryption fails instead of giving you garbage. We use
ChaCha20-Poly1305. See [Sessions](SESSIONS.md).

**Argon2id**
A deliberately slow, memory-hungry way of turning a passphrase into a key, so
that guessing passphrases is expensive. Protects the identity file on disk.
See [Storage](STORAGE_AND_PLUGINS.md).

**Ed25519**
A digital-signature scheme. A *private key* signs; anyone with the matching
*public key* can verify the signature but cannot forge one. Our identities are
Ed25519 key pairs. See [Identity and trust](IDENTITY_AND_TRUST.md).

**Ephemeral key**
A key made fresh for one connection and thrown away afterwards. Because it is
never stored, stealing your long-term key later does not reveal past traffic.
See [Handshake](HANDSHAKE_AND_VERSIONING.md).

**Fingerprint**
A short summary (SHA-256 hash, shown in hex) of a public key. Humans compare
fingerprints to check they have the right key. See
[Identity and trust](IDENTITY_AND_TRUST.md).

**Forward secrecy**
If a key is stolen today, messages recorded in the past still cannot be read.
Achieved here twice: per connection (ephemeral keys) and per message (the
ratchet). See [Sessions](SESSIONS.md).

**Harvest-now-decrypt-later**
An attacker records encrypted traffic today and waits for a future quantum
computer to break it. The reason post-quantum matters even before such
computers exist. See [Future crypto](FUTURE_CRYPTO.md).

**HKDF**
A standard way to turn one secret into several independent keys.

**Double Ratchet**
The algorithm (from Signal) that changes the encryption key after every
message, so a stolen key exposes at most one message, and "heals" after one
round trip. See [Sessions](SESSIONS.md).

**ML-KEM (Kyber), ML-DSA**
Post-quantum key-exchange and signature algorithms standardised by NIST.
Planned, not built. See [Future crypto](FUTURE_CRYPTO.md).

**Nonce**
A number used once per encryption under a key. Reusing one breaks the cipher,
so the design makes reuse impossible. See [Sessions](SESSIONS.md).

**Pinning**
Remembering "this exact public key is this person" and refusing any other key,
like SSH's `known_hosts`. There is no certificate authority. See
[Identity and trust](IDENTITY_AND_TRUST.md).

**Post-compromise security (healing)**
After an attacker steals your state once, you become safe again after a fresh
key exchange, as long as they do not keep stealing. See
[Sessions](SESSIONS.md).

**Post-quantum (PQ)**
Algorithms believed to resist quantum computers. See
[Future crypto](FUTURE_CRYPTO.md).

**X25519**
A Diffie-Hellman key exchange: two sides each send a public value and both
compute the same secret that an eavesdropper cannot. See
[Handshake](HANDSHAKE_AND_VERSIONING.md).

## Connection and delivery words

**Ack (acknowledgement)**
"I received message N." The sender keeps a message in its outbox until acked.
See [Sessions](SESSIONS.md).

**At-least-once delivery**
A message may arrive twice after a crash but never zero times; duplicates are
filtered out. See [Sessions](SESSIONS.md).

**Handshake**
The opening exchange where both sides prove who they are and agree on keys,
before any message moves. See [Handshake](HANDSHAKE_AND_VERSIONING.md).

**Heartbeat / ping**
A tiny "are you there?" sent only after a quiet period. Any message received
already proves the link is alive. See [Sessions](SESSIONS.md).

**Outbox / inbox**
The queues of sent-but-unacked and received-but-not-yet-read messages, with
sequence numbers. See [Sessions](SESSIONS.md).

**Session**
One authenticated, encrypted, reliable connection between two peers that can
survive disconnects. See [Sessions](SESSIONS.md).

**Transport**
How raw bytes move (TCP by default, in-memory for tests). The app chooses it.
See [Storage and plug-ins](STORAGE_AND_PLUGINS.md).

## Group words

**Author chain**
Each member's messages form a chain where every message includes the hash of
the previous one, so lying to different people differently is detectable. See
[Messages](MESSAGES.md).

**Bot**
A group member run by a program, always labelled as a bot, with limited
powers and a human sponsor. See [Bots](BOTS.md).

**Equivocation**
Telling two members two different things under the same message number. The
author chains make this detectable. See [Messages](MESSAGES.md).

**Existence notice**
"A message by X with number N exists" without the content. Used when a group
only lets the author hand out content. See [Messages](MESSAGES.md).

**Full mesh**
Everyone keeps a direct connection to everyone else. Simple and private, but
the number of links grows with the square of the group size. See
[Groups](GROUPS.md).

**Group type (kind)**
Fixed at creation and never changed. Currently only full mesh exists. See
[Groups](GROUPS.md).

**Have (announcement)**
"I now hold message N from X" sent to other group readers so they can ask for
it if they lack it. See [Messages](MESSAGES.md).

**Relay policy**
A group-wide rule, set at creation: *Open* (any holder may serve a message) or
*AuthorOnly* (only the author serves content; others serve existence
notices). See [Messages](MESSAGES.md).

**Receipt**
A signed "I got it" (delivery, on by default) or "I read it" (opt-in). See
[Messages](MESSAGES.md).

**Roster**
The signed, hash-chained list of who is in the group and at which tier. See
[Groups](GROUPS.md).

**Sponsor**
The member who added a bot. Remove the sponsor and their bots go too. See
[Bots](BOTS.md).

**Tier**
A named bundle of four permissions (add, remove, read, write), defined per
group. See [Groups](GROUPS.md).

## Design words

**Library vs app**
What this crate guarantees versus what the program built on it must decide.
See [Library vs app](LIBRARY_VS_APP.md).

**Lamport clock**
A counter that gives events a consistent order without wall-clock time.
Considered and shelved. See [Ordering](ORDERING.md).

**MLS (Messaging Layer Security)**
An IETF standard for large-group encryption using a key tree. Wanted later.
See [Future crypto](FUTURE_CRYPTO.md).

**Metadata**
Who talks to whom, when, how often, and how big. Often more revealing than
content. See [Threat model](THREAT_MODEL.md).

**Oracle (handshake)**
Anything that lets an outsider learn a fact by probing. Ours reveals that two
nodes may know each other. See [Handshake](HANDSHAKE_AND_VERSIONING.md).

**Sender key**
A group design where each sender uses one key for everyone. Considered and
rejected. See [Future crypto](FUTURE_CRYPTO.md).

**TreeKEM**
The tree structure inside MLS. See [Future crypto](FUTURE_CRYPTO.md).
