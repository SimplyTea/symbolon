# Plan: built, planned, parked, and rejected

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

Each item says what it is, the options that exist with trade-offs, which one
we picked (or lean to), and why. Details live in the linked topic page.

## Status at a glance

| Status | Items |
|---|---|
| **Built** | Pinned identities, handshake with version check, Double Ratchet, reliable sessions, heartbeat, saved state, signed-roster groups with tiers, per-author chains, relay policy, existence notices, receipts, `Have` forwarding, bots, discovery, storage/trust/clock/trace plug-ins |
| **Planned** | Hybrid post-quantum handshake (+ oracle fix), tree-based groups, state journal, receipt queueing, backdating fix, session teardown on removal, simulation graph, more tests (LAN, groups, out of network) |
| **Parked** (idea, not scheduled) | Reply-to, group-wide ordering, typing indicator, compression, multi-device |
| **Rejected** | Sender keys, trust on first use, bot plug-in code, an `--exec` bot, periodic catch-up as the default, link-state routing hints, wall-clock timestamps, injectable RNG |

## Planned

### Hybrid post-quantum handshake (and the oracle fix)
Options and trade-offs are in [Future crypto](FUTURE_CRYPTO.md). **Plan:**
X25519 + ML-KEM-768 hybrid. *Trade-off accepted:* about 1 KB more per handshake
and a minor-version bump, in exchange for protection from
harvest-now-decrypt-later. The [handshake oracle](HANDSHAKE_AND_VERSIONING.md)
fix rides along because the flow is being rewritten anyway.

### Identity-hiding handshake and smaller wire format
Found while documenting the bytes ([Wire format](WIRE_FORMAT.md)): both identity
public keys cross the network unencrypted in the handshake, and ids are sent as
64 ASCII characters instead of 32 raw bytes.
- *Identity hiding* options: leave it (simple, but observers see who connects);
  **encrypt the identities under the ephemeral key after the first exchange**
  (like Noise or SIGMA-I handshakes: an observer sees only random-looking
  bytes, at the cost of one more round trip or a reordered flow and a careful
  redesign); or use a rendezvous secret (hides more, needs shared setup).
  **Leaning:** encrypt after the ephemeral exchange, done together with the
  post-quantum handshake and oracle fix so the handshake changes once.
- *Wire-size* options: keep hex ids (readable); **raw 32-byte ids** (half the
  size, minor bump); member-index ids (smallest, but unreadable without the
  roster). **Leaning:** raw ids, in the same format break. Not decided.

### Tree-based groups (MLS-style)
Options: full mesh (today), sender keys, MLS/TreeKEM, server fan-out; see
[Groups](GROUPS.md) and [Future crypto](FUTURE_CRYPTO.md). **Plan:** tree-based.
*Blocked on one decision:* how to order membership commits without a server.
Recommendation: **owner-ordered**. *Trade-off:* simple and deterministic, but
membership changes need the owner online. Alternative is epoch-with-retry,
which has no single owner but is subtler.

### Save-state journal
Today the state file is rewritten per message ([Sessions](SESSIONS.md)).
Options: keep rewriting (simple, wasteful), **append-only journal with
compaction** (cheap writes, more recovery code), or a database (heavy
dependency). **Plan:** journal. *Trade-off:* more complex crash recovery.

### Receipt queueing
Receipts only reach a currently connected author ([Messages](MESSAGES.md)).
Options: drop (today), **queue and send on reconnect** (reliable, slightly more
state), or route via other members (leaks who read what). **Plan:** queue.

### Backdating fix and session teardown after removal
See [Threat model](THREAT_MODEL.md). Backdating options: ignore, or **record the
remover's last-seen sequence in the `Remove` operation** (candidate; changes
the signed format). Teardown: dropping the removed member's session is easy but
you want to *observe* both behaviours in a debugger first. **Low priority.**

### Tests and the simulation graph
Order: more LAN tests, then group tests, then out-of-network (laptop, Pi, a
friend's laptop). The `Tracer` and the benchmark (`examples/bench.rs`) feed a
planned simulation that graphs cost against group size. *Trade-off:* the
benchmark ignores network latency on purpose; the simulator adds it as a
parameter.

### Smaller backlog
Tidying a duplicate send on attach; roughly a dozen Clippy warnings; comments throughout
`group.rs`; release-profile choices (strip, LTO), still undecided because they
trade binary size against build time and debuggability.

## Parked: ideas we are keeping but not building

| Idea | Options | Why parked |
|---|---|---|
| **Reply-to** | Reference (author, seq) of the message answered | "Sounds alright", but depends on how ordering is handled; see [Ordering](ORDERING.md) |
| **Group-wide ordering** | Lamport clock; cross-linked chains; arrival order; consensus | Complexity felt wrong for the benefit; per-author order is correct and verifiable |
| **Typing indicator** | App-only; or an ephemeral library channel | Mainly an app concern; also a privacy preference to ask users about |
| **Compression** | Never; always; **opt-in per group** | Length leaks content (CRIME/BREACH); only worth it if someone needs it |
| **Multi-device** | Same key on every device; one key per device; devices behind one gateway | Hard to do safely; skipped for now. Likely a service-level idea (several devices behind one gateway) |

## Rejected, with reasons

| Idea | Why not |
|---|---|
| **Sender keys** | Weaker post-compromise security; more rekeying on removal ([Future crypto](FUTURE_CRYPTO.md)) |
| **Trust on first use** | An on-path attacker at first contact wins permanently ([Identity](IDENTITY_AND_TRUST.md)) |
| **Periodic catch-up timer as default** | Polling is noisy and hides real delivery bugs; replaced by `Have` ([Messages](MESSAGES.md)) |
| **Link-state hints** | Tells every member who is connected to whom |
| **Flood-forwarding full messages** | O(N²) copies; breaks author-only relay policy |
| **Wall-clock timestamps for order** | Clocks lie; a member can backdate |
| **Plug-in code or `--exec` for bots** | Chat text must never become code execution ([Bots](BOTS.md)) |
| **Injectable RNG** | The easiest way to break key generation; OS source only |
| **Heavy dependencies or an async runtime** | Library, not framework: smaller review surface |

## Defaults we picked (so you can find them)

| Setting | Default | Page |
|---|---|---|
| Relay policy | Chosen per group at creation (Open or AuthorOnly) | [Messages](MESSAGES.md) |
| Relayed content | Deliver (app may switch to ExistenceOnly) | [Messages](MESSAGES.md) |
| Delivery / read receipts | On / off | [Messages](MESSAGES.md) |
| Relay cache | 256 messages per sender | [Messages](MESSAGES.md) |
| Heartbeat / dead after / handshake timeout | 10 s / 30 s / 10 s | [Sessions](SESSIONS.md) |
| Outbox and history limits | Unlimited | [Library vs app](LIBRARY_VS_APP.md) |
| Discovery | Off; name + major version when on | [Discovery](DISCOVERY.md) |
| Group type | Immutable; only full mesh exists | [Groups](GROUPS.md) |

## Versioning rule

The crate version is the protocol version. Every wire or signed-format change
bumps the minor. `Have` (a new message) and the stricter read checks were such a
change, so the crate is now **0.2.0**; a 0.1.x build refuses to talk to it.
See [Handshake](HANDSHAKE_AND_VERSIONING.md).
