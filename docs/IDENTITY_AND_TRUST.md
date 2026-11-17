# Identity and trust

*Part of the Symbolon docs. Words in **bold** are explained in the
[Glossary](GLOSSARY.md).*

## In plain words

There is no server and no account system, so "who are you?" has to be answered
by mathematics. Every participant has an **identity**: a pair of keys. The
*private* key never leaves your device and is used to sign things. The *public*
key is shared freely and lets others check your signatures. Your **fingerprint**
is a short hash of the public key, convenient for humans to compare.

"Trust" then means one thing: *I have recorded that this exact public key
belongs to that person, and I will refuse anything else.* This is called
**pinning**.

## How it works here

- Identity: an **Ed25519** key pair (`identity.rs`). Fingerprint = SHA-256 of
  the public key, shown as hex.
- Trust: a `PeerRegistry` holds the keys you trust. A connection from or to a
  key that is not in it is refused before any application data moves.
- You obtain a friend's key out of band: read the fingerprint aloud on a call,
  scan a QR code in person, and so on. Nothing on the network is trusted to
  tell you who someone is.
- The identity file on disk is encrypted with a passphrase using **Argon2id**
  (see [Storage](STORAGE_AND_PLUGINS.md)).
- The registry is backed by a pluggable `TrustStore`. The default behaviour is
  *reject and record*: an unknown key that tries to connect is refused, and its
  key goes into a pending list (capped at 64) that the app can show to the
  user, who may then approve it. Approving a key never happens automatically.

## Options for establishing trust

| Option | How it works | Good | Bad |
|---|---|---|---|
| **Certificate authority** (like web HTTPS) | A central body vouches for keys | Scales to strangers | Needs a trusted third party; contradicts "no server"; the CA can lie or be breached |
| **Trust on first use (TOFU)** | Accept whatever key shows up first, remember it | Zero effort | Anyone on the network path during the first contact can plant themselves permanently |
| **Pinning with out-of-band check** (**chosen**) | You verify the fingerprint through another channel before trusting | No third party; an on-path attacker cannot get in | The humans have to do the check; awkward for strangers |
| **Web of trust** | Friends vouch for friends' keys | Scales without a CA | Complex, leaks who knows whom, notoriously hard for users |
| **Key transparency log** | Public append-only log of keys | Detects a server lying about keys | Needs a log operator, which this design does not have |

## What we chose and what it costs

We chose **pinning**, with an approval queue so that "someone tried to connect"
is visible rather than silently dropped.

Costs we accept:

- Onboarding needs a human step. This is the price of having no authority.
- If you lose your identity file you become a new person and everyone must
  re-pin you. There is no key rotation or recovery tooling yet.
- The pending list reveals to the *local* user that a stranger knocked; it
  reveals nothing to the stranger (see the oracle note in
  [Handshake](HANDSHAKE_AND_VERSIONING.md)).

## What the app handles

The library gives you the registry, the approval queue and the fingerprint.
The **app** decides how a human actually verifies a fingerprint (QR code,
voice call, in-person), how to present the approval prompt, and how to back up
the identity. See [Library vs app](LIBRARY_VS_APP.md).

## Planned

- Identity key rotation and signed "I am now this new key" statements: not
  designed yet. See [Plan](PLAN.md).
- Post-quantum signatures (ML-DSA) later: see [Future crypto](FUTURE_CRYPTO.md).

## Related

[Handshake](HANDSHAKE_AND_VERSIONING.md) · [Storage](STORAGE_AND_PLUGINS.md) ·
[Threat model](THREAT_MODEL.md)
