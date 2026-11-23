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

## 2026-11-17 wire format doc
- NEW docs/WIRE_FORMAT.md + examples/wire_dump.rs (captures a real TCP session through a recording proxy, a ratchet pair,
  and every group/control/file/beacon layout; Walker asserts each layout covers every byte). Re-run after ANY wire change.
- Measured: data overhead below the group layer = 85 bytes (4 prefix + 9 channel/seq + 16 transport tag + 40 ratchet header + 16 ratchet tag).
  A group post of 11 bytes of text = 195 byte group msg = 280 bytes on the wire.
- FINDINGS: (1) both Ed25519 identity keys, version and epochs are sent UNENCRYPTED in handshake Msg1/Msg2, so an observer sees which
  identities connect (added to THREAT_MODEL and PLAN; fix belongs with the PQ handshake). (2) peer/author/group ids are 64 ASCII hex chars on
  the wire (2x the raw 32 bytes). Candidate for the same format break. Neither is decided.

## 2026-11-18 clippy, e2e scripts, two real bugs found by a flaky test
- scripts/e2e/: 8 real-process scripts + run_all.sh (a script passes only if exit 0, no FAIL line, at least one PASS line;
  most scripts print PASS/FAIL rather than setting an exit code).
- Clippy clean (allow() with reasons on Reconnected size and two 8-arg internal fns); cargo fmt applied.
- forward_test was flaky (about 1 in 3 on a 2-core box; passed earlier by luck). Two REAL bugs:
  1. Duplicate copy (author's own + a Have-prompted fetch) was reported as a "chain violation" rejection. Now: identical content =
     GroupMessageDuplicate (ignored); different content under a held seq = rejected as conflict (equivocation). 2 new unit tests.
  2. Lost wake-up: a Have inside the 300 ms request window was DROPPED, so the last announcement could stall forever. Now one
     event-triggered follow-up per author asks for the HIGHEST announced seq (first version used the first seq: still stalled 1/26).
  Verified: 70 runs sequential + 30 under parallel load, 0 failures. Tests: 209.

## 2026-11-18 duplicate send on attach: analysis so far (PAUSED, not fixed)
- Cause (from reading session.rs; NOT yet reproduced by a test): every new connection, including a brand-new session, makes BOTH
  sides send a ResumeRequest (we saw control seq 1 = 9-byte plaintext in wire_dump). The peer's ResumeRequest handler resends
  `outbox.messages_after(last_contiguous)`. If the app already send()-wrote a message in the first round trip, that message is
  still unacked, so it goes out twice (original write + "Retransmitted"). Receiver's inbox drops the duplicate; same key, same
  nonce, same plaintext => identical bytes, so no secrecy harm, just wasted frames and a Retransmitted trace event.
- Planned repro: memory_pair with ~50 ms latency, A sends right after establish, tracer must show no Retransmitted on a fresh link.
- Planned fix: `resend_ceiling` = highest outbox seq at the moment the current connection began (captured AFTER swapping
  write_stream, line ~677; set from the restored outbox on state restore). ResumeRequest resends only seq <= ceiling. Messages
  stored after the swap are written by send() on the new link. A message stored before the capture but written after the swap is
  at worst sent twice, never lost. Do NOT use "skip if written on this link" without that ordering: a send stored after capture but
  written to the old dead link would never be retransmitted. Keep the Ack(missing) retransmit path unchanged.

## 2026-11-19 duplicate send on attach: FIXED
- Reproduced with tests/resume_dup_test.rs (memory_pair, 50 ms latency, send right after establish): before the fix the tracer showed
  `MessageQueued{1}` then `Retransmitted{count:1}` on a fresh link; after, no Retransmitted.
- Fix: `Outbox::highest_seq()`; `Session.resend_ceiling` (AtomicU64) seeded from the (restored) outbox in from_handshake and re-captured in
  reconnect AFTER the write_stream swap; the ResumeRequest handler retains only seq <= ceiling. Ack(missing) retransmit path unchanged.
- Verified: 210 tests pass, clippy clean, 8 e2e scripts pass (use an ABSOLUTE SYMBOLON_BIN path). Docs: SESSIONS.md section 3, PLAN backlog.
- Presentation: Slides artifact built (Hack and Tell), 19+ slides with exchange-band and packing diagrams and sketch snippets.

## 2026-11-19 0.3.0 step 1: identity-hiding handshake (BUILT)
- New flow (5 frames): Msg1/Msg2 = bare ephemeral X25519 keys (32 B each); handshake keys = HKDF(salt = H("symbolon/handshake/v3/eph" ||
  epub_i || epub_r), shared); Msg3 (I->R) and Msg4 (R->I) = AEAD{version(6) idpub(32) epoch(16) sig(64)} (134 B each incl. tag);
  Msg5 (I->R) = AEAD(empty) with the full transcript as AAD. Responder replies (Msg4) ONLY after the initiator proved its key AND is pinned.
- Initiator signs H("symbolon/handshake/v3/initiator" || epubs || version_i || idpub_i || epoch_i); responder signs the FULL transcript
  (includes sig_i). Session keys + ratchet seed derive from (shared, full transcript) as before.
- Why Msg5: first version had no confirmation; dialling a wrong machine left a half-open session on it (bot_wrong_addr e2e caught it).
  New unit test dialling_the_wrong_machine_leaves_no_session_on_that_machine.
- Only keys that SIGNED are recorded for approval (stranger cannot flood the queue). Old 86-byte Msg1 gets a clear VersionMismatch (logged).
- Known limit: an ACTIVE MITM learns the DIALLER's identity (it speaks first); listener's stays hidden. Fix would need the listener's key known in
  advance (Noise IK). Version mismatch now only visible to the listener (dialler sees closed connection).
- Crate is 0.3.0. 215 tests, 8 e2e pass, wire_dump updated ("All layouts matched the bytes").
- DECISIONS (Tea): expiry field NOT in the header (disappearing messages = app/add-on, maybe a later wire change); flags byte on HOLD (may
  need TLV-style options if app-type headers come); padding optional default off; raw ids + ml-kem still to do in 0.3.0.
- TODO next in 0.3.0: raw 32-byte PeerId type; hybrid ML-KEM-768 (approved crate: ml-kem, builds on 1.97); optional padding.

## 2026-11-20 0.3.0 step 2: raw 32-byte ids (BUILT)
- New src/ids.rs: PeerId / GroupId newtypes ([u8;32], Copy). Wire carries raw bytes (no u16 length, no hex); hex only in Display/Debug/CLI.
- Saved session state SYMS format 2 (raw peer id). Signed/hashed group data now uses raw ids.
- 11-byte post: 195 -> 161 byte group message; 280 -> 246 bytes on the wire. Delete 190, Receipt 170, Have 41, Roster(genesis, 2 members) 276.
- 217 tests pass, clippy clean (after removing clone-on-Copy and unused hex_encode), wire_dump matches all layouts.
- Docs updated: WIRE_FORMAT (sections 1, 6, 9), PLAN.
- Remaining in 0.3.0: hybrid X25519 + ML-KEM-768 (ml-kem crate), optional padding (default off).
- Tea asked: handshake size and comparison with Signal. Correct number: ML-KEM-768 adds ~2.3 KB once per connection
  (1184 B encapsulation key + 1088 B ciphertext); per-message overhead unchanged (85 B).

## 2026-11-20 roadmap discussion
- Added "Roadmap by release" to docs/PLAN.md. Transports (TCP/UDP-style choice, possibly both listening) planned ~1.2.0 as add-ons;
  library already runs over any reliable ordered stream, so apps can attach other streams today. Raw UDP is not such a stream.
- PQ ratchet / re-handshake / ML-DSA -> 1.0.0. Voice -> post-1.0.0 add-on.
- ml-kem dependency line already added to Cargo.toml (Cargo.lock changed), NOT yet used. Handshake work starts next session.

## 2026-11-20 file sending design (agreed, not built; planned 0.4.0)
- Offer = new content kind in the signed application message: optional name, u64 size, whole-file hash (Merkle root), 512-byte prefix (optional).
- Receiver-driven: library raises FileOffered event; app calls accept_file(offer, writer) / decline_file(offer). Default policy = always ask; decline is local and silent.
- Chunks 256 KiB, Merkle-verified, windowed (a few in flight), resumable, streamed to temp file then renamed after hash check. New group tags FileRequest/FileChunk.
- Default cap 1 GiB, configurable, higher hard cap; reject sender that exceeds declared size. Magic bytes are a claim: verify prefix against received file; no file-type database in core.
- Test binary: y/n prompt plus --auto-accept / --auto-deny flags for e2e scripts and bots.
- Open: files in 1:1 chats as well as groups (leaning: one mechanism for both).

## 2026-11-20 0.3.0 step 3: hybrid X25519 + ML-KEM-768 handshake (BUILT)
- Crate: ml-kem 0.3.4 (RustCrypto; its README says NOT independently audited; noted in THREAT_MODEL). Features getrandom + zeroize.
  Needed `cargo update -p zeroize` and a direct `zeroize = "1.8"` dependency; dropped the old zeroize/zeroize_derive exact pins
  (ml-kem needs Rust 1.85+ anyway, so the pins for old compilers no longer help).
- Msg1 = epub_i (32) || ML-KEM encapsulation key (1184) = 1216; Msg2 = epub_r (32) || ciphertext (1088) = 1120.
  eph = SHA-256("symbolon/handshake/v4/eph" || Msg1 || Msg2) salts the combiner and is bound into both signatures (labels now v4).
  combined = HKDF(salt = eph, ikm = ss_mlkem || ss_x25519, info "symbolon/hybrid/v1 x25519+ml-kem-768"); it replaces the raw DH secret everywhere
  (handshake keys, session keys, ratchet seed). Msg3/Msg4 are therefore protected by the PQ secret too.
- Measured: handshake = 2640 bytes in 5 frames (was 368); +2272 once per connection; per-message overhead unchanged (85 B).
- Responder validates the ML-KEM key (FIPS 203 modulus check) before replying; a 32-byte (pre-hybrid draft) first message gets MalformedMessage;
  86-byte 0.2 message still gets VersionMismatch. ML-KEM implicit rejection means a tampered ciphertext shows up as a failed Msg3 decrypt.
- 7 new tests (sizes, combiner needs both inputs, tampered ciphertext, tampered X25519 half, control run, malformed key, old 32-byte msg1).
  224 tests pass, clippy clean, wire_dump matches.
- Docs: WIRE_FORMAT section 3, HANDSHAKE_AND_VERSIONING, THREAT_MODEL (new Post-quantum status table), FUTURE_CRYPTO, PLAN, README.
- Decided with Tea: PQ ratchet / periodic re-handshake / ML-DSA wait for 1.0.0. Any tree group design must be PQ from day one
  (hybrid KEM at nodes, or a secret mixed in from the pairwise hybrid sessions).
- Remaining in 0.3.0: optional padding (default off, selectable block sizes). Then file sending (0.4.0).

## 2026-11-21 0.3.0 step 4: optional padding (BUILT) — 0.3.0 bundle complete
- New src/padding.rs: `Padding` (OFF default, STANDARD 256, STRONG 1024, `Padding::block(16..=65535)`), `pad()` / `unpad()`.
  Scheme: payload || 0x80 || zeros up to a multiple of the block. Receiver ALWAYS unpads (drop trailing zeros, require 0x80),
  so no setting, flag or negotiation is needed and each side pads only what it sends. Marker is always present: padding off costs exactly 1 byte/message.
- Wired in Session::send (pad before ratchet encrypt) and the reader thread (unpad right after decrypt, before the saved queue).
  `SessionConfig.padding`, `Session::set_padding()` / `padding()` (atomic, changeable at runtime). New `ChatError::InvalidConfig`.
- CLI: `--padding off|standard|strong|BYTES`. New e2e script scripts/e2e/padding_e2e.py (one side padded, one not), added to run_all.sh.
- Fixed overhead below the group layer is now 86 bytes (85 + marker). 11-byte "hello group" post: 247 bytes on the wire off, 341 with Standard.
- 14 new tests (8 unit in padding.rs, 6 in tests/padding_test.rs that record real frame sizes). 238 tests total, clippy clean, wire_dump matches.
- Docs: WIRE_FORMAT 5.1 plus updated numbers, THREAT_MODEL metadata, PLAN, README.
- Padding does not hide timing, message counts or the Data/Control channel byte.
- NEXT: file sending (0.4.0), a key-derivation API for add-ons, demo app. Open: files in 1:1 chats too (leaning yes, one mechanism).

## 2026-11-22 0.4.0 file sending, stage 1: core module (BUILT)
- Tea decided: default size limit 1 GiB (configurable, hard max 4 GiB); files in 1:1 chats too, one mechanism for both.
- New src/file.rs (+ docs/FILES.md): FileOffer (optional name, u64 size, chunk size, root, 512-byte prefix), Manifest (flat list of per-chunk
  hashes, NOT a Merkle tree: receiver always fetches the whole list first, so per-chunk proofs buy nothing; rationale in FILES.md),
  prepare(), ChunkSource (FileSource, MemorySource), FileServer (re-verifies each chunk so a file changed on disk is not served),
  FileSink (PartFileSink writes <name>.part and renames when complete, never overwrites), FileReceiver (windowed requests, any order,
  duplicates ignored, bad chunk rejected unwritten, prefix lie caught on chunk 0, save/restore of verified chunks), FileFrame (5 messages),
  sanitize_name. New ChatError::FileTransfer. Constants: chunk 256 KiB default (16 KiB..1 MiB), max 65536 chunks, prefix 512, window requests <= 64.
- Root = SHA-256("symbolon/file/root/v1" || size || chunk_size || all leaf hashes); leaf = SHA-256("symbolon/file/leaf/v1" || chunk).
- Measured (256 MiB in memory): prepare 1.1 GiB/s, serve+verify+write 0.6 GiB/s.
- 19 new tests; 257 total, clippy clean. Not yet wired into sessions/groups/CLI; no wire format section yet (added with the wiring).
- NEXT (stage 2): group wiring (content kind for the offer, tags 0x18+ for requests/chunks, author-first then holders, only members may request);
  stage 3: 1:1 envelope so a Session can carry text and file messages (decide how; current 1:1 payloads are raw app bytes);
  stage 4: hub/session events + accept_file/decline_file, policy hook, CLI y/n and --auto-accept/--auto-deny, e2e script.

## 2026-11-22 file transfer: security fix, full checks list, number theory / quantum note
- FOUND WHILE LISTING CHECKS: PartFileSink::create truncated an existing `<name>.part` (would follow a planted symlink) and finish() used rename
  (silently replaces a file that appeared meanwhile). FIXED: `.part` is created with create_new (refuses anything existing, incl. symlinks); finish()
  uses hard_link (fails if destination exists) with a check-then-rename fallback; new `PartFileSink::resume` (plain file of exact size, no links).
  3 new tests (mid-download destination, stale part + resume, symlink on unix). 22 file tests, 260 total.
- docs/FILES.md: complete numbered list of every check (44 built, grouped), planned checks for the wiring stage, and known gaps.
  docs/THREAT_MODEL.md: new "File transfer" and "Number theory, Riemann and quantum algorithms" sections; FUTURE_CRYPTO points at it.
- Riemann news (as reported 22 Nov 2026): two claimed proofs (Anthropic number theorist + Claude with Lean code; Stanford postdoc, no AI).
  UNVERIFIED, no peer review. Conclusion recorded: RH does not affect any primitive we use (we use fixed standardized parameters, ECDLP / lattice / hash);
  Shor does (Ed25519 + X25519), and Google Quantum AI's reported estimate (<1200 logical, <500k physical qubits for ECDLP-256) is a reason to keep
  the 1.0.0 hybrid-signature work on schedule.
- Tea asked about "device support": multi-device was decided SKIPPED (home-node/bouncer idea only); laptop + Raspberry Pi runs are done (LAN tested).

## Stage 2 of file sending: wired into groups (269 tests)

- Offer = content kind 3 in the signed author chain; bytes = group tag 0x18 carrying a `FileFrame`. New module `src/group/files.rs` (child of `group` so it can use hub state).
- API: `offer_file`, `accept_file`, `decline_file`, `try_another_source`, `serve_file`, `file_offer`. Events: `FileOffered`, `FileProgress`, `FileComplete`, `FileFailed`. Config: `max_file_size` (1 GiB), `max_concurrent_downloads` (4).
- Author first, then other connected readers; AuthorOnly groups: author only. Non-readers get no answer (mutation-checked: removing the check fails the test).
- Caught while writing: a `cargo fmt` reformat made two scripted edits silently not apply (the AuthorOnly guard in `serve_file`); the new AuthorOnly test caught it. Lesson: verify scripted edits landed.
- In AuthorOnly groups a relaying member sends only an existence notice, so a member not linked to the author never sees the offer. That is the policy working, not a bug.
- Known gaps recorded in docs/FILES.md: no stall timer (app calls `try_another_source`), disk reads on the processing thread, no resume across restarts.
- Multi-device (device certificates, after 1.0) moved from Parked to Planned in docs/PLAN.md.
- Next: stage 3 (1:1 envelope; options to Tea first), then stage 4 (app calls, CLI y/n, `--auto-accept`/`--auto-deny`, e2e).
