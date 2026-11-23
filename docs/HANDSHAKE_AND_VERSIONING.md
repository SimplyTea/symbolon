# Handshake and versioning

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

## In plain words

Before two peers exchange a single message they run a short **handshake**.
Its job is threefold: each side proves it holds the private key for the public
key the other side pinned ([Identity and trust](IDENTITY_AND_TRUST.md)), both
agree on fresh secret keys for this connection, and both confirm they speak
compatible versions of the protocol.

## How it works here

1. Each side contributes key material for a **hybrid** exchange: an
   **ephemeral** X25519 key from each side, plus ML-KEM-768 (the standardized
   post-quantum KEM, formerly Kyber). The initiator sends its X25519 key and an
   ML-KEM public key (Msg1); the responder answers with its X25519 key and an
   ML-KEM ciphertext (Msg2). Nobody has said who they are yet.
2. Both compute the same two secrets and mix them into one (HKDF), then derive
   **handshake keys** from it. An eavesdropper has seen only public halves, and
   would need to break **both** X25519 and ML-KEM to recover the secret. That is
   what protects a recording against a future quantum computer ("harvest now,
   decrypt later").
3. The initiator sends, **encrypted**, its version, identity key, a random
   16-byte epoch and a signature (Msg3). The responder checks that the caller
   really holds the key it names, and then that the key is pinned. If not, it
   closes without a word.
4. Only then does the responder send its own version, identity key, epoch and
   signature, encrypted (Msg4). The signature covers a *transcript*: a hash of
   everything said, including the initiator's signature. An attacker cannot
   swap pieces between conversations or downgrade anything undetected.
5. The initiator checks everything and sends a tiny encrypted confirmation
   (Msg5). The responder creates a session only when it arrives.
6. From the shared secret, **HKDF** derives separate session keys for each
   direction. Those seed the [Double Ratchet](SESSIONS.md).
7. The initiator only trusts the peer it *meant* to dial. If it reaches the
   wrong machine it stops before Msg5, so the wrong machine never attaches a
   session.
   (Found in the first LAN test and fixed.)

This is the same idea TLS 1.3 uses (it exchanges key shares first and sends the
certificates encrypted), and Noise-style handshakes work the same way.

The exact bytes of each message, with sizes and the reason for every field, are
in [Wire format](WIRE_FORMAT.md). The post-quantum half costs 2272 bytes once
per connection (1184 + 1088); messages after the handshake are unchanged. Who can
see what: a passive observer sees two blocks of random-looking key material and
two encrypted blobs, so **no identity, version or
epoch**. An active attacker who intercepts the exchange learns the *dialler's*
identity (it speaks first) but cannot authenticate and never learns the
listener's. Hiding the dialler from active attackers too would need the
listener's key known in advance (as in Noise IK); not done yet.

Because keys are ephemeral, stealing a long-term key later does not reveal past
traffic. That property is **forward secrecy**.

## Versioning

The crate version *is* the protocol version (`x.y.z`, from `Cargo.toml`).

- Two nodes can connect if **major and minor are equal**. Patch may differ.
- Therefore any change to a wire or signed format must bump the minor (while
  we are on 0.x) or the major (from 1.0). A patch bump promises "no wire
  change". This is a discipline rule, recorded in `NOTES.md`.
- A responder that sees a mismatched version closes the connection silently
  and logs both versions locally. Replying would tell a stranger which version
  we run.

| Option | Good | Bad |
|---|---|---|
| Single protocol number separate from crate version | Library can change without protocol changes | Two numbers to keep in sync; easy to forget |
| **Crate version is the protocol version** (**chosen**) | One number, impossible to drift; tooling shows it | A harmless refactor release still changes the visible version |
| Capability negotiation (feature flags) | Mixed versions interoperate more | Large attack surface; downgrade attacks; complicated to test |
| Always accept anything | Maximum connectivity | Parsing unknown formats is exactly where bugs live |

We chose the single number plus strict equality of major.minor. The cost is
that two friends on 0.1 and 0.2 cannot talk until one upgrades. For an
unreleased security library, a loud failure beats a quiet downgrade.

## The "oracle" (fixed in 0.3.0)

In 0.2 a node that held a trusted key could probe another node and learn that
it exists, which identity answers, that its signature verifies, and which
version it runs. That meant a handshake could reveal that **two nodes may know
each other**.

Now the responder reveals nothing until the caller has proved it holds a key
the responder has pinned. An unknown caller, a stranger probing, or a caller
with a bad signature all get the same thing: a bare ephemeral key (which says
nothing), then silence. A caller that proved its key but is not yet pinned is
recorded for approval, so you can still approve a new friend. Keys that did
not sign are never recorded, so a stranger cannot flood the approval list.

Trade-off: on a version mismatch the dialler can no longer be told why. The
listener refuses silently and logs both versions; the dialler just sees the
connection close.

## What the app handles

Choosing who to dial, retry timing, and what to tell a user when a peer is on a
newer version. The library reports `VersionMismatch{ours, theirs}`.

## Related

[Wire format](WIRE_FORMAT.md) · [Identity and trust](IDENTITY_AND_TRUST.md) · [Sessions](SESSIONS.md) ·
[Future crypto](FUTURE_CRYPTO.md) · [Threat model](THREAT_MODEL.md)
