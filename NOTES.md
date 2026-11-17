# Symbolon - roadmap notes (not the README)

Name: Greek *symbolon* (σύμβολον), a token split in two halves; each party kept one half and
matching the halves later proved who you were - i.e. pinned mutual verification.

**Legacy labels:** the on-wire domain-separation strings still read `p2p-secure-chat/...`
(handshake transcript, ratchet KDF labels). Renaming them changes the protocol, so builds
would stop interoperating. Do it at the first deliberate protocol bump (e.g. adding ML-KEM).
The default identity folder moved to `~/.symbolon`; an older `~/.p2pchat` is still honoured.

Working notes on what is deliberately NOT built yet. Newest decisions first.

## Post-quantum (decided: later, as an OPTION, not now)
Names, since they are easy to forget (all NIST-standardised, FIPS 203/204/205):
- **ML-KEM** (was "Kyber", FIPS 203): key exchange. Plan: HYBRID with X25519, i.e. mix the
  ML-KEM shared secret into the same HKDF as today's X25519 secret, so we are never weaker
  than classical. Protects against "record now, decrypt later".
- **ML-DSA** (was "Dilithium", FIPS 204): signatures. Replaces/augments Ed25519 identities,
  so authentication (not just confidentiality) survives a quantum attacker. Bigger keys/sigs.
- **SLH-DSA** (was "SPHINCS+", FIPS 205): hash-based signatures, conservative, large/slow.
- HQC: a second, code-based KEM NIST picked as a backup to ML-KEM (check current status).
Open questions: which pure-Rust crate (size, audit history, maintenance) given the
"no heavy crates" rule; ship behind a cargo feature flag; wire/protocol version bump.

## Next up
1. Heartbeat (encrypted ping on the control channel) + dead-peer detection + reconnect loop.
2. CLI group mode (needed for the cross-network group test).
3. Signed headers (header + content hash) -> existence notices, author-first fetch with
   relay fallback, delivered receipts / signed cursors, opt-in read receipts.
4. Persist ratchet + session state; derive the group-log key independently of the identity key.

## Known gaps
Argon2id instead of PBKDF2; key-committing AEAD for identity file; bounded outbox/message
store; permission snapshot at send time; bots via delegation certificates; multi-device
(device certificates, same idea as bots); compression (opt-in only, CRIME/BREACH-style
length leaks); NAT traversal / discovery (use Tailscale/WireGuard or port-forward meanwhile).

## Decisions (2026-10-29)
- **Sender keys**: possible OPTIONAL group mode later (encrypt once, bit-identical relays; costs:
  no post-compromise healing, rotate + redistribute on every removal). Pairwise mesh stays the
  default. Group type must be fixed at creation; switching = "move to a new group" with a
  signed pointer. TODO: add a group-kind field to the genesis op now so the format can carry it.
- **Multi-device: skipped for now.** If ever done, prefer a "home node / bouncer" model
  (one gateway holds the account key and peers talk only to it; the user's other devices
  connect to the gateway) - that is a service built on the protocol, not a protocol feature.
- **Plug-in points to add (library, not framework)**, in priority order:
  1. Transport trait (Session currently hard-wired to TcpStream) -> Tor/QUIC/WebSocket/in-memory sim.
  2. Storage traits: EventStore (group log), KeyStore (identity custody: file/keychain/HSM),
     StateStore (ratchet/session state), optional HistoryStore. FileStore = default impl.
  3. TrustStore + connection-approval callback (PeerRegistry as a trait; contacts are app-level).
  4. Clock + RNG injection (deterministic simulation, heartbeat tests).
  5. Wire-level trace/event hooks (so tools can show raw frames without the library printing).
  6. Payload codec hook (app-side compression/padding, opt-in).
  Resource limits (outbox, inbox window, history) become config with DEFAULT = unlimited.

## 2026-10-29: Transport plug-in done
- `src/transport.rs`: `Connection` trait (tune / set_read_timeout / into_parts), TcpStream impl, in-memory transport (`memory_pair(latency)`, `cutter()`).
- `Session::establish_over` / `reconnect_over` take any `Connection`; `establish`/`establish_with`/`reconnect*` TcpStream wrappers kept.
- `tests/transport_test.rs` (6 tests): both directions, latency, cut + reconnect, garbage/truncated handshake, silent peer. Suite stable under CPU load (15 runs, 0 failures).
- Next: Storage traits, TrustStore + approval, trace hooks.

## 2026-11-09: Storage traits done
- `src/storage.rs`: `EventStore` (+File/Memory/`SealedEventStore`), `KeyStore` (+File/Memory), `StateStore` (+File/Memory), `seal`/`open` helpers.
- Library encrypts event-log records and state blobs BEFORE the store sees them; KeyStore owns identity protection.
- `GroupHub::create_with_store` / `load_with_store`; path-based `create_persisted`/`load_persisted` now wrap `FileEventStore` (same on-disk format, old logs still load).
- `GroupHub::persistence_healthy()`: a failed append is no longer silently dropped.
- NOT done: ratchet/session state serialization (so StateStore is not yet used by `Session`); optional HistoryStore; old `persistence::EventLog` kept but unused by the hub.

## 2026-11-13: Bundled format bump + Argon2id identity file (no backward compat, by decision)
- Group: `GroupKind` (FullMesh only; unknown rejected) in the genesis op and group id; messages carry a signed `roster_version`;
  signature + hash chain are over a HEADER that commits to content by SHA-256 (enables existence notices / header-only chain
  extension later); an author's claimed roster version may never decrease along their chain (limits backdating).
- Permission check is now AS OF the author's signed roster version (`Roster::permissions_at`, `key_ever`), so a removed member's
  earlier messages stay valid and post-removal ones don't. Messages claiming a version we haven't reached are parked
  (`pending_ahead`, cap 1000) and retried after each applied roster op.
- KNOWN LIMIT: a removed member can still BACKDATE by claiming their last valid version forever (monotonic rule only stops going
  down). Candidate fix (not built): Remove op records the remover's last-seen seq for the target; later seqs rejected. Trade-off:
  can drop legitimately-sent-but-unseen messages. Needs a decision.
- Identity file v2: magic SYMI, Argon2id (default 64 MiB, t=3, p=1; params in header, sanity-capped on load) + HKDF-derived AEAD key and
  32-byte key commitment (checked constant-time before decrypt). PBKDF2 and `EventLog` removed. Sandbox unlock ~100 ms (expect ~0.7 s on Pi).
- All legacy `p2p-*` domain labels renamed to `symbolon/...`.
- Not yet: existence notices / author-first fetch / receipts (header format is ready for them), group-kind switch pointer.

## 2026-11-14: Heartbeat, dead-peer detection, reconnect, session epoch, CLI group mode
- `SessionConfig`: `heartbeat_interval` (default 10 s) + `dead_after` (default 30 s). Encrypted Ping/Pong on the control channel; pings only when idle.
  Dead link => reader closed => `recv()` fails; `link_alive()`, `time_since_heard()`, `last_ping_rtt()`. `Session` Drop closes the connection.
  Limit: a write that blocks forever (full send buffer to a vanished peer) can stall the keepalive thread until closed.
- `MemoryConnection::blackhole_switch()` simulates a silently dead link (used by tests/heartbeat_test.rs).
- BUG FIXED: `reconnect` accepted any trusted peer (now `PeerMismatch`).
- BUG FIXED: after a peer APP RESTART the surviving side's old session reconnected "successfully" but ratchets mismatched (every message rejected).
  Handshake now carries a signed 16-byte SESSION EPOCH; `reconnect_or_replace` -> `Reconnected::Resumed | Replaced(new Session)`;
  strict `reconnect_over` errors with `PeerRestarted`. Handshake msgs are now 82 / 146 bytes. Messages the old session hadn't delivered are lost on Replace
  (peer has no state to receive them) - app-level history/outbox persistence (ratchet serialization) would be needed to avoid that.
- `Session::send` now returns Ok when the message is queued in the outbox even if the wire write failed (link down); delivery happens after reconnect.
- CLI: auto-reconnect for listen/connect (`--no-reconnect` to exit instead); `group-new` / `group-run` (full mesh over TCP; smaller fingerprint dials);
  `src/bin/symbolon/{main,group}.rs`. Verified with real processes: 3-node group, restart + catch-up, edit propagation, link cut + same-session resume, peer restart.
- Group CLI limitation: membership fixed at creation (late joiners need roster-history sync, not built).

## 2026-11-14 (later) - roster sync, trust store, clock, trace

**Roster sync.** Each hub keeps the ordered roster op log (`Roster.ops`, `ops_after(version)`).
`attach_session` sends `RosterSyncRequest{have_version}` (tag 0x13); anyone can answer with the
missing ops. Ops are self-verifying (signed, hash-chained), so the answerer need not be trusted.
A late-added member or an offline member catches up automatically. Tests: `roster_sync_test`.

**Trust store** (`src/truststore.rs`). `TrustStore` trait; `MemoryTrustStore`; `FileTrustStore`
(sealed with a key derived from our identity, so a local attacker cannot add a key; tampering
fails the open). `PeerRegistry` is now a thin wrapper (`with_store`); `new()`/`trust()` unchanged.
Unknown keys are rejected immediately and recorded in a bounded (64), de-duplicated approval
queue (`pending()`, `approve(id)`, `dismiss(id)`). Entries are *claims* (checked before the
signature), so verify the fingerprint out-of-band. We reject-and-record rather than holding the
handshake open (a held handshake lets strangers tie up threads). Revoking a key does not tear
down live sessions (item 10, still open).

**Clock** (`src/clock.rs`). `Clock` trait (`now()` monotonic Duration, `sleep`), `SystemClock`,
`ManualClock`. Used by keepalive, dead-link detection and RTT. In `SessionConfig.clock`; fixed
at first session creation. RNG injection deliberately NOT public (predictable RNG = hole).
Test pitfall learned: advance manual time in steps and wait for BOTH ends to refresh; a single
big jump or waiting on one end is racy under CPU load.

**Trace hooks** (`src/trace.rs`). `Tracer` trait + `TraceEvent` enum (session and group events).
Events carry only fingerprints, seqs, counts, durations and static reasons: no keys/plaintext.
`SessionConfig.tracer`, `GroupHubConfig.tracer`; CLI `--debug` prints them. Tracers run on
library threads: keep them fast; rate-limit `FrameRejected` (attacker-triggerable).

Open: backdating after removal (needs your decision), item 10, existence notices/receipts,
ratchet state persistence, PQ hybrid, README last.

## 2026-11-15 discovery, existence notices, receipts, session persistence

### Discovery (src/discovery.rs)
- Opt-in only (`--announce`, `symbolon discover`). Unauthenticated UDP hint, magic `SYMD`.
- Announces name + major version by default; minor and patch are separate opt-ins (`Disclose`).
- Never carries a key by default. Treat what it hears as a hint, never as identity.
- Limit: `--announce` on a loopback bind advertises an address nobody can dial.

### Existence notices and relay policy (src/group.rs)
- A notice is an Application message whose content is replaced by its SHA-256. The author's
  signature covers the header, so anyone can verify it and it advances the author chain.
- At notice time only `can_write || can_remove` can be checked; the full per-kind check
  runs when the content fills in. Filling content must hash to the notice hash.
- Relay policy is set at genesis (`genesis_with_policy`, `--relay`). Denied relays send a notice.
- `--hide-relayed` converts relayed content to notices on receipt. `/fetch` and `/pending` in the CLI.

### Receipts
- Signed, name the content hash. Delivery receipts default on, read receipts opt-in (`--read-receipts`,
  `--no-receipts`). Signing goes through a `ReceiptSigner` closure so the hub never holds the identity key.
- Limit: receipts go only to the author's attached session; there is no queue for offline authors.

### Session persistence (src/sessionstate.rs, session.rs)
- Ratchet + outbox + inbox + pending queue saved per peer, sealed with an identity-derived key.
- Send is write-ahead (save before wire write, roll back on failure).
- Receive: decrypt, queue to pending, save, THEN ack. Delivery is at-least-once across a crash.
- Lock order: commit, ratchet, outbox, inbox, pending.
- Responder picks its epoch after learning the caller. Initiator must set `expect_peer` to resume.
- Supersede guard: process-wide ownership tickets keyed by (store Arc pointer, peer). Two separately
  opened stores on one directory are NOT detected.
- Limits: every send/receive rewrites the whole state file (a journal is the optimisation).
- Disable with `--no-session-state`.

### Backlog
Backdating fix (observe first), drop removed member's session, handshake oracle (bundle with PQ),
receipt queueing, state journal, clippy (~13), comments pass on group.rs, README last, out-of-network tests, simulation graph.

## 2026-11-15 bots, and why MLS is not built yet

### Bots (src/group.rs, CLI bot-new / bot-run)
- `MemberKind::{Person, Bot}`, fixed when the member is added (new signed op `AddBot`, tag 5).
  A bot has its own key and pairwise sessions like anyone; only governance differs.
- A bot may only hold tiers with neither `can_add` nor `can_remove`: enforced at AddBot,
  at ChangeTier (no promotion) and at DefineTier (a tier holding a bot can't be widened).
- Every bot has a SPONSOR (the member who added it). Removing/leaving sponsor removes their
  bots in the same roster step on every node. Re-adding a current member is refused, so a
  bot can't be turned into a "person" by an Add.
- CLI: `bot-new --id F` (own identity file, prints the /addbot line), `bot-run` (listen =
  events on stdout, `--format tsv` is one escaped record per event; write = `--say TEXT`
  and stdin lines posted VERBATIM, `--commands` to opt into /commands; `--listen-only`,
  `--seconds N`), `--pass-file F` (must be mode 600). In-session: /addbot /bots /tier /deftier.
  group-new now defines tiers "bot" (read+write) and "listener" (read only).
- Not built: bot-specific rate limits, bot-only moderation (can_remove is refused), a UI marker
  beyond `[bot]` in /members. A bot's key sits on a server: treat its loss as the sponsor's loss.

### MLS: decision
Not started. Goal accepted (tree-based group key, O(log N) membership change, post-compromise
security for the whole group). Blocker is design, not code: MLS needs a total order on
commits, and Symbolon has no server. Needs a decision first on how concurrent commits are
ordered (see the conversation notes) before any TreeKEM code.

## 2026-11-15 protocol version = crate version
- `handshake::Version {major, minor, patch}`; `PROTOCOL_VERSION_CURRENT` is read from Cargo.toml at
  compile time, so the crate version and protocol version cannot drift. Sent as 3 x u16 in msg1/msg2
  (handshake msgs are now 86 / 150 bytes) and bound into the signed transcript (domain "handshake/v2").
- Rule (`negotiate_version`): major AND minor must match; patch may differ; session is labelled with
  the lower patch. Else `ChatError::VersionMismatch {ours, theirs}`.
- DISCIPLINE: any change to a wire/signed format must bump minor (0.x) or major (1.x+) in Cargo.toml.
  A patch bump promises no wire change.
- A responder refuses a mismatched caller silently (no reply to an unproven peer), so the INITIATOR sees
  a closed connection; the responder's log names both versions. Replying would tell strangers our version.
- `run_initiator_as` / `run_responder_as` take an explicit version (used by tests).

## 2026-11-15 fixes from the first real LAN test
- `FileStateStore::put` used ONE fixed temp name per key, so two simultaneous saves of the same
  key (two sessions with one peer) raced and one got "No such file or directory". Now a unique
  temp name per write; test `concurrent_puts_to_one_key_never_fail`.
- Dialling the wrong address (e.g. 127.0.0.1 on the wrong machine) used to complete the
  handshake on the OTHER side (it attached a session that replaced a good one) and only then fail
  on the dialler (PeerMismatch). The dialler now trusts ONLY the peer it meant to dial, so it
  refuses at msg2, before sending msg3; the other side never attaches.
- Repeated `--peer` / `/peer` for the same member started duplicate dial loops (two sessions, the
  second replacing the first). One dial loop per peer now; repeats are ignored with a note.
- `bot-run --say` now waits until the bot has learned (by roster sync) that it is a bot member,
  instead of posting as soon as it is connected (which was rejected).
- Still open: a dial that hangs prints nothing (no connect timeout / "dialling" line yet).

## 2026-11-15 late: periodic catch-up, /history order
- A post reaches only the members CONNECTED to its author at that moment. A member with no direct
  link to the author (bot on another machine, missing mesh link) only learned of it by asking, i.e.
  /catchup or at connect. Reproduced deterministically (bot fingerprint smaller than B's, so the bot
  must dial B and B cannot dial it): with --catchup 0 B misses the post until /catchup, then gets it
  relayed by A; with --catchup 3 B gets it automatically.
- `group-run` / `bot-run` now call `request_catchup` every `--catchup S` seconds (default 15, 0 = off).
  Cost: a few small RelayRequests per interval per connection. Library unchanged (hub.request_catchup).
- Not done: push-forwarding (relay a newly accepted message to peers not connected to its author).
  Pull is bounded and fits "author first, fall back to holders"; forwarding is O(N^2) and has to
  respect relay policy (author-only groups would forward existence notices only).
- /history: grouped by author (now sorted by fingerprint; it used to follow HashMap order, which
  differs per run), each author's messages in that author's own seq order. `#seq` is per author.
  There is no group-wide sequence or trusted timestamp; a merged timeline could only use local arrival
  order, which differs between nodes.

## 2026-11-15 night: announce-and-request forwarding (`Have`), read check on pulls, scripted bots
- NEW `GroupMessage::Have {sender, seq}` (tag 0x17). After a node ACCEPTS a message (first time only;
  duplicates are rejected earlier, so no loops) it sends `Have` to the other members who currently have
  `can_read`, except the peer it came from and the author. A receiver that lacks it sends ONE
  `RelayRequest` to that peer; the normal relay policy decides what is served (author-only groups
  serve existence notices). Debounced to one request per author per 300 ms; ignored unless the
  announcer is a current reader and the author is a known member (past or present).
- Privacy by construction: only sessions attached to THIS hub (this group), only readers; contains no
  link information, nothing about other groups or 1:1 sessions. A full mesh produces no extra copies
  (everyone already has it, so nobody asks). Rejected design: link-state hints (would tell members
  who is connected to whom).
- The 15 s periodic catch-up is now OFF by default (`--catchup S` is an opt-in safety net).
  Real-process check: bot with no link to the Pi, no timer: 5/5 delivered (3/3 missed before).
- SECURITY FIX found while testing: `RelayRequest` and `FetchRequest` were answered without checking the
  requester's `can_read`, so a member without read permission could pull content by asking. Both now
  require `can_read`. Test: `a_member_without_read_permission_cannot_pull_content_by_asking`.
- tests/forward_test.rs: 8 tests (no-link member, 4-hop line, full mesh no duplicates, author-only,
  announcements only to readers, non-reader can't pull, flood debounce, strangers ignored).
- Scripted bot: `scripts/echo_bot.py` drives `bot-run --format tsv` over pipes (answers !ping / !echo).
  Tested against real nodes. Message text is untrusted input; no `--exec` by design.
- Decided NOT to build now: Lamport clock / cross-linked chains for a group-wide order; typing
  indicator (idea only, ask the group). reply-to still wanted when ordering is revisited.
- NOTE for 0.2.0: `Have` is a new wire message and the read check changes behaviour; per the version
  rule the minor should be bumped before anyone outside the LAN tests runs a mixed set of builds.

## 2026-11-16 documentation set
- README rewritten; `docs/` added: GLOSSARY, PLAN, IDENTITY_AND_TRUST, HANDSHAKE_AND_VERSIONING, SESSIONS, GROUPS,
  MESSAGES, BOTS, ORDERING, STORAGE_AND_PLUGINS, DISCOVERY, FUTURE_CRYPTO, THREAT_MODEL, LIBRARY_VS_APP.
  Each topic page: plain-words intro, options table with trade-offs, what we chose, library-vs-app note.
- New `examples/two_peers.rs` (compiled; README snippet is condensed from it). All relative links checked.
- Docs describe the library only; the CLI is deliberately not documented there.
- Docs state 0.2.0 should be the next version others run (Have + read check are wire/behaviour changes).

## 2026-11-16 0.2.0, connect timeout, timing flags
- Version bumped to 0.2.0 (Have + read checks). Verified with real processes: a 0.2.0 node refuses a 0.1.0 dialler;
  its log says "this build is 0.2.0, the peer is 0.1.0"; the 0.1.0 side only sees "connection closed unexpectedly" (by design).
- CLI: `dial()` uses connect_timeout (default 10 s, `--connect-timeout`), "[dialling ADDR ...]" line,
  `--heartbeat`, `--dead-after` (must be >= 2x heartbeat), `--handshake-timeout` (0 = off), `--relay-cache`.
- Not exercised here: a real blackholed address (the sandbox answers "refused" at once), so the timeout path itself is untested.
- Duplicate send on attach: NOT done (not reproduced yet).
- Kept a 0.1.0 source tarball and linux-x86_64 binary in outputs for old-vs-new tests.
