# Storage, plug-in points and at-rest protection

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

## In plain words

A library should not decide where your data lives or how the network works.
Symbolon therefore defines small **traits** (interfaces) for the parts an app
may want to replace, and ships simple defaults.

## The plug-in points

| Trait | What it is for | Default |
|---|---|---|
| `Connection` / transport | Moves bytes between peers | TCP; in-memory pair for tests and simulation (with latency, cuts and blackholes) |
| `EventStore` | The group's message log | File store; in-memory store |
| `StateStore` | Saved session and group state (see [Sessions](SESSIONS.md)) | File store (atomic write with a unique temp name); in-memory |
| `KeyStore` | Where the identity secret lives | Encrypted file; the app may use an OS keychain or hardware key |
| `TrustStore` | Which public keys are trusted and the pending queue ([Identity](IDENTITY_AND_TRUST.md)) | File-backed store; in-memory store |
| `Clock` | Time source | System clock; injectable fake for tests |
| `Tracer` | Receives `TraceEvent`s for debugging and the planned simulation graph | Discards events |

**Randomness is deliberately not pluggable.** An injectable random source is
the classic way to introduce a catastrophic key-generation bug, so the library
always uses the operating system's generator.

## What is protected at rest

- **Identity file** (`SYMI`, format 2): the secret key encrypted with a key
  derived from your passphrase by **Argon2id** (default 64 MiB memory, time
  cost 3). The file is *key-committing*, meaning a wrong key can never
  "successfully" decrypt to something else. Loading rejects absurd cost
  settings (more than 1 GiB or time cost over 64) so a tampered file cannot
  freeze the machine.
- **Event log and state blobs**: the library *seals* (encrypts) them before the
  store sees them. A store, even a cloud one, only holds ciphertext.
- Honest limit: file *names*, sizes and modification times are still visible
  to anyone with disk access. See [Threat model](THREAT_MODEL.md).

| Option | Good | Bad |
|---|---|---|
| Library writes files directly, fixed layout | Simple | Unusable on mobile, browsers, or encrypted-volume setups; hard to test |
| **Traits with defaults** (**chosen**) | App controls location and custody; testable | Callers must wire things; more public surface to keep stable |
| Library depends on a database crate | Rich queries | Heavy dependency; constrains every app |

## What we do not ship

No async runtime: sessions use plain threads, and `GroupHubConfig.auto_pump =
false` lets an app with its own executor feed messages in itself. No
compression yet (see [Plan](PLAN.md): opt-in later, because compressing before
encrypting can leak message content through length, the CRIME/BREACH family of
attacks).

## Library vs app

Library: the traits, sealing, and the defaults. App: which store to use, key
custody UX (keychain, hardware key), backups, and retention. Outbox and
history limits default to **unlimited**; trimming is the app's job. See
[Library vs app](LIBRARY_VS_APP.md).

## Related

[Sessions](SESSIONS.md) · [Identity](IDENTITY_AND_TRUST.md) ·
[Threat model](THREAT_MODEL.md)
