# Sessions: encryption, reliability, liveness, saved state

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

A **session** is the library's name for one authenticated, encrypted, reliable
conversation between two peers. It is built in layers; this page walks through
them from the bottom.

## 1. Framing

TCP is a stream of bytes with no message boundaries. We prefix each message
with its length (`framing.rs`). Frames larger than 4 MiB are refused so a
stranger cannot make us allocate gigabytes.

## 2. Encryption: two layers

- **Transport layer.** After the [handshake](HANDSHAKE_AND_VERSIONING.md) each
  direction has its own key. Everything, including acknowledgements, is
  encrypted with ChaCha20-Poly1305 (**AEAD**). Separate keys per direction and
  a never-repeating counter make **nonce** reuse impossible by construction.
- **Message layer: the Double Ratchet.** Inside the transport layer, every
  message gets its own one-time key derived from a hash chain, and the old
  key is deleted. Every change of conversation direction mixes in a fresh
  X25519 exchange.

What the ratchet buys you:

| Property | Meaning |
|---|---|
| Per-message forward secrecy | Stealing the current state reveals nothing about messages already processed |
| Post-compromise security | After one round trip the attacker is locked out again, unless they keep stealing state |

Details worth knowing: the ratchet header is 40 bytes (authenticated, not
secret). Out-of-order messages are handled by caching skipped keys, capped at
1000 per jump and 2000 stored in total, so a lying peer cannot burn our CPU or
memory. Decryption runs on a *copy* of the state and commits only if the tag
verifies, so a forged message cannot corrupt the real state.

| Option | Good | Bad |
|---|---|---|
| Transport encryption only (like TLS) | Simple | One leaked key exposes the whole connection, past and future |
| **Transport plus Double Ratchet** (**chosen**) | Leak of a key exposes one message; heals itself | More code, more state to save, small per-message overhead |
| Hand-rolled "rekey every N minutes" | Less code | Weaker, and easy to get wrong |

## 3. Reliability: no silently missing messages

Every message has a sequence number and sits in the sender's **outbox** until
the receiver **acks** it. The receiver keeps an **inbox** that notices gaps and
delivers strictly in order. After a disconnect the two sides compare what they
have and resend exactly what is missing (`reliability.rs`).

Reconnect outcomes are explicit: `Reconnected::Resumed` (same conversation
continued) or `Reconnected::Replaced` (the other side restarted without state;
you start a new conversation). A reconnect from the wrong identity yields
`PeerMismatch`; a newer session taking over yields `SessionSuperseded`.

## 4. Liveness: the heartbeat

TCP can stay "open" for a long time after the other side vanished. We send a
small **ping** only after `heartbeat_interval` (default 10 s) of silence, and
consider the link dead after `dead_after` (default 30 s) with nothing heard.
The handshake itself times out at 10 s. **Any** authenticated frame received
counts as proof of life, so a busy conversation sends no pings at all.

| Option | Good | Bad |
|---|---|---|
| Fixed-interval ping | Simplest | Constant background traffic; reveals activity pattern; wastes battery |
| Application-level catch-up timer | Also repairs missed messages | Hacky; polls forever; we removed it as a default |
| **Ping only when idle** (**chosen**) | Zero overhead when busy | Dead peers take up to `dead_after` to notice |
| TCP keepalive only | No code | Defaults are minutes to hours; not authenticated |

## 5. Saved state across restarts

Reconnecting after a *network* drop is easy: the process still holds the
queues. Surviving a *process restart* needs the queues and ratchet saved to a
`StateStore` (`sessionstate.rs`, file magic `SYMS`). The rules:

- **Write-ahead on send**: save before putting bytes on the wire.
- **On receive**: decrypt, queue, save, *then* ack. A crash in between means
  the peer resends, so delivery is **at-least-once**, with duplicates dropped.
- Saved blobs are sealed (encrypted) by the library before the store sees them.
- A commit lock and process-wide ownership tickets stop two sessions to the
  same peer from corrupting each other's file.
- To resume after restart, the initiating side must name the peer it expects
  (`expect_peer`).

**Known cost:** the whole state file is rewritten on every send or receive. A
journal (append-only log plus compaction) would avoid that. It is on the
[Plan](PLAN.md).

## Library vs app

Library: all of the above. App: choosing timing values, what "offline" looks
like in the UI, and how much history to keep. Outbox limits default to
unlimited; deciding retention is the app's job. See
[Library vs app](LIBRARY_VS_APP.md).

## Related

[Handshake](HANDSHAKE_AND_VERSIONING.md) · [Groups](GROUPS.md) ·
[Storage](STORAGE_AND_PLUGINS.md) · [Threat model](THREAT_MODEL.md)
