# Plan: built, planned, parked, and rejected

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

Each item says what it is, the options that exist with trade-offs, which one
we picked (or lean to), and why. Details live in the linked topic page.

## Status at a glance

| Status | Items |
|---|---|
| **Built** | Pinned identities, handshake with version check, Double Ratchet, reliable sessions, heartbeat, saved state, signed-roster groups with tiers, per-author chains, relay policy, existence notices, receipts, `Have` forwarding, bots, discovery, storage/trust/clock/trace plug-ins, identity-hiding handshake, raw 32-byte ids, hybrid X25519 + ML-KEM-768 key exchange, optional padding |
| **Planned** | File sending (in progress), device certificates for one account on several devices (after 1.0), post-quantum signatures and ratchet healing (1.0.0), tree-based groups, state journal, receipt queueing, backdating fix, session teardown on removal, simulation graph, more tests (LAN, groups, out of network) |
| **Parked** (idea, not scheduled) | Reply-to, group-wide ordering, typing indicator, compression |
| **Rejected** | Sender keys, trust on first use, bot plug-in code, an `--exec` bot, periodic catch-up as the default, link-state routing hints, wall-clock timestamps, injectable RNG |

## Planned

### Hybrid post-quantum handshake (BUILT in 0.3.0) and the oracle fix
Options and trade-offs are in [Future crypto](FUTURE_CRYPTO.md). **Built:**
X25519 + ML-KEM-768 hybrid. *Trade-off accepted:* 2272 bytes more per handshake
(once per connection; messages are unchanged) and a minor-version bump, in
exchange for protection from harvest-now-decrypt-later. The
[handshake oracle](HANDSHAKE_AND_VERSIONING.md) fix is done with the
identity-hiding rewrite. Still classical, and planned for **1.0.0**: Ed25519
signatures (hybrid ML-DSA, designed so it does not put a 3 KB signature on every
message) and ratchet healing (periodic re-handshake or a post-quantum ratchet).
See the [Post-quantum status](THREAT_MODEL.md#post-quantum-status) table. Any
tree-based group design must be post-quantum from day one, either with a hybrid
KEM at the tree nodes or by mixing in a secret delivered over the pairwise
hybrid sessions.

### Identity-hiding handshake (BUILT in 0.3.0) and smaller wire format
Done: both identity keys, versions and epochs are now encrypted after an
anonymous ephemeral exchange, and the responder answers only pinned callers
(this also closes the handshake oracle). See [Wire format](WIRE_FORMAT.md) and
[Handshake](HANDSHAKE_AND_VERSIONING.md). Remaining in the same release:
- *Wire-size:* **BUILT** — ids are raw 32-byte values (`PeerId`, `GroupId`)
  instead of 64 hex characters; an 11-byte post went from 280 to 246 bytes.
- *Post-quantum:* **BUILT** — the hybrid X25519 + ML-KEM-768 exchange (above).
- *Padding:* **BUILT** — optional, default off. Presets Standard (256-byte blocks) and
  Strong (1024) plus a custom size (16 to 65535). *Trade-offs accepted:* padding grows
  every message by about half a block on average, and it does not hide timing or
  message counts. The padding sits inside the encryption behind an always-present
  1-byte marker (`0x80`), so the receiver needs no setting, flag or length field
  and each side chooses what it sends; the cost of that simplicity is one byte on
  every message even with padding off. Rejected: a per-message flags byte or
  length field (the flags header is on hold), and negotiating padding in the
  handshake (more state for no gain). Details in
  [Wire format 5.1](WIRE_FORMAT.md#51-optional-padding-inside-the-encrypted-plaintext).

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
Comments throughout
`group.rs`; release-profile choices (strip, LTO), still undecided because they
trade binary size against build time and debuggability.

## Roadmap by release (current thinking, not a promise)

| Release | Contents |
|---|---|
| **0.3.0** | Identity-hiding handshake (built), raw 32-byte ids (built), hybrid X25519 + ML-KEM-768 handshake (built), optional padding (built, default off) |
| **0.4.0** | File sending (core built, wiring next; see [File transfer](FILES.md)); a small API to derive extra keys from a live session (needed by add-ons) |
| **Demo app** | A real app written against the library, to find API gaps before the format is frozen |
| **1.0.0** | Format frozen. Post-quantum healing (periodic re-handshake or a post-quantum ratchet), ML-DSA signatures, key rotation, tree-based groups if the design is settled |
| **~1.2.0** | Transports: write down the contract ("any reliable, ordered byte stream"), then add-on crates for other transports (a QUIC wrapper, a small reliable-UDP shim). Optional unreliable encrypted datagram channel next to the session |
| **Add-ons (any time after 1.0.0)** | Voice chat (on the datagram channel), verification codes, disappearing messages, reactions, backup and export |

## Parked: ideas we are keeping but not building

| Idea | Options | Why parked |
|---|---|---|
| **Reply-to** | Reference (author, seq) of the message answered | "Sounds alright", but depends on how ordering is handled; see [Ordering](ORDERING.md) |
| **Group-wide ordering** | Lamport clock; cross-linked chains; arrival order; consensus | Complexity felt wrong for the benefit; per-author order is correct and verifiable |
| **Typing indicator** | App-only; or an ephemeral library channel | Mainly an app concern; also a privacy preference to ask users about |
| **Compression** | Never; always; **opt-in per group** | Length leaks content (CRIME/BREACH); only worth it if someone needs it |
| **Multi-device** | Same key on every device; one key per device; devices behind one gateway | Same key everywhere is unsafe (ratchet state cannot be shared), so it was skipped. Now PLANNED, after 1.0: one key per device, each certified by the account key (like bot sponsor certificates); a home-node gateway is the cheap fallback |

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
change, so the crate is now **0.3.0** (new handshake); older builds refuse to talk to it.
See [Handshake](HANDSHAKE_AND_VERSIONING.md).
