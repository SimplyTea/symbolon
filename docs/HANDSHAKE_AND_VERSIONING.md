# Handshake and versioning

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

## In plain words

Before two peers exchange a single message they run a short **handshake**.
Its job is threefold: each side proves it holds the private key for the public
key the other side pinned ([Identity and trust](IDENTITY_AND_TRUST.md)), both
agree on fresh secret keys for this connection, and both confirm they speak
compatible versions of the protocol.

## How it works here

1. Each side generates an **ephemeral** X25519 key and a random 16-byte epoch.
2. They exchange these plus their identity public keys and versions.
3. Each side signs a *transcript* (a hash of everything said so far: versions,
   identities, ephemeral keys, epochs) with its Ed25519 identity key. Because
   the signature covers everything, an attacker cannot swap pieces between
   conversations or downgrade anything undetected.
4. From the shared X25519 secret, **HKDF** derives separate keys for each
   direction. Those seed the [Double Ratchet](SESSIONS.md).
5. The initiator only trusts the peer it *meant* to dial. If it reaches the
   wrong machine it stops before sending its final message, so the wrong
   machine never attaches a session. (Found in the first LAN test and fixed.)

The exact bytes of each message, with sizes and the reason for every field, are
in [Wire format](WIRE_FORMAT.md). One thing to know now: the identity keys in
the first two messages are sent **unencrypted**, so a network observer can see
which identities connect.

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

## The "oracle" (known, low priority)

A node that holds a trusted key and probes another node can learn that the
other node exists, which identity answers, that its signature verifies, and
which version it runs. That means a handshake can reveal that **two nodes may
know each other**. It does not reveal message content or who else is in a
group.

Options: leave it (cheap, a small metadata leak), or redesign the handshake so
the responder reveals nothing until the initiator has proved knowledge of a
shared secret first (stronger, but it changes the message flow). We decided to
**bundle the fix with the post-quantum handshake**, since that handshake is
being redesigned anyway. See [Future crypto](FUTURE_CRYPTO.md) and
[Plan](PLAN.md).

## What the app handles

Choosing who to dial, retry timing, and what to tell a user when a peer is on a
newer version. The library reports `VersionMismatch{ours, theirs}`.

## Related

[Wire format](WIRE_FORMAT.md) · [Identity and trust](IDENTITY_AND_TRUST.md) · [Sessions](SESSIONS.md) ·
[Future crypto](FUTURE_CRYPTO.md) · [Threat model](THREAT_MODEL.md)
