# Library versus app: who decides what

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

Symbolon is a **library, not a framework**: it gives you parts and guarantees,
and does not run your program for you. The command-line tool in `src/bin/` is
one *app* built on it, and is intentionally not documented here. This page
draws the line between what the library promises and what an app built on it
must decide.

## The rule of thumb

If getting it wrong breaks a **security or correctness guarantee**, the library
owns it. If it is a **preference, policy or presentation**, the app owns it.

## The split

| Topic | Library | App |
|---|---|---|
| Identity | Key generation, signing, fingerprints, encrypted file ([Identity](IDENTITY_AND_TRUST.md)) | How a human verifies a fingerprint; backups; keychain or hardware key use |
| Trust | Pinning, the pending-approval queue | The approval prompt and its wording |
| Handshake and versions | Mutual authentication, version check, `VersionMismatch` | "Your friend needs to update" messaging |
| Reliability | Ordering, acks, resume, saved state ([Sessions](SESSIONS.md)) | Offline indicators, retry policy, timing values |
| Retention | Nothing: limits default to unlimited | How long to keep history, when to trim the outbox |
| Groups | Roster signing and checks, tiers, `can_read` enforcement ([Groups](GROUPS.md)) | Names and invites, default tiers, "you were removed" UX |
| Relay | Policy enforcement, `relayed_by` | Whether to show relayed content, whether to warn |
| Receipts | Producing and verifying signed receipts | Showing delivered/read, offering the read-receipt toggle |
| Ordering | Per-author order ([Ordering](ORDERING.md)) | Merged timeline, replies, typing indicators, notifications |
| Bots | Membership rules, sponsor cascade ([Bots](BOTS.md)) | What a bot does; rate limits; badges |
| Storage | The traits, sealing, defaults ([Storage](STORAGE_AND_PLUGINS.md)) | Which store; encryption of the device; backup |
| Discovery | Optional LAN hint ([Discovery](DISCOVERY.md)) | Whether to enable it; NAT traversal; internet rendezvous; choosing the transport |
| Compression | Nothing yet | If added later, whether to enable it per group |
| Random numbers | OS generator, not replaceable | Nothing |

## Why not put more in the library?

- **Policy bakes in assumptions.** A "retain 30 days" default would be wrong for
  half of apps and silently delete data.
- **More code is more attack surface.** Keeping the library small keeps it
  reviewable. The source is meant to be read end to end; fewer features means
  fewer lines to trust.
- **UI semantics vary.** Typing indicators, read-state and reply threading mean
  different things in different products.

## Why not put less?

Anything that can break security if misused needs a safe default in the
library: sealing storage, bounding sizes and counts, refusing unpinned peers,
and checking permissions. Those are never left to the app.

## Related

[Plan](PLAN.md) · [Threat model](THREAT_MODEL.md)
