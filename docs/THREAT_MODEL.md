# Threat model: what we defend against, and what we do not

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

Security claims mean nothing without saying *against whom*. This page lists
the attackers we considered and the honest limits.

## Attackers and outcomes

| Attacker | Can they read messages? | Can they forge or alter? | Notes |
|---|---|---|---|
| Passive eavesdropper on the network | No | No | Everything is AEAD-encrypted ([Sessions](SESSIONS.md)) |
| Active man-in-the-middle | No | No | Both sides sign the handshake transcript with pinned keys ([Handshake](HANDSHAKE_AND_VERSIONING.md)); they can only drop or delay traffic |
| Stranger who knows an address | No | No | Refused before any application data; sees only that a port answers |
| Someone who steals a long-term key later | Not past traffic | Can impersonate from then on | Forward secrecy per connection and per message |
| Someone who steals session state once | Only until the next round trip | - | Double Ratchet healing |
| Malicious group member | Reads what they are allowed | Cannot forge others; **cannot equivocate undetected** | [Author chains](MESSAGES.md) |
| Removed member | Not new traffic | Their new messages are rejected | They keep what they already received; see limits below |
| Malicious bot | Only what its tier reads | Cannot add or remove | [Bots](BOTS.md) |
| Quantum computer, later | Recorded traffic is at risk | Signatures at risk | **Not defended yet**; see [Future crypto](FUTURE_CRYPTO.md) |

## Metadata: what still leaks

Content is the easy part. **Metadata** is who talks to whom, when, how much.

- A network observer sees who connects to whom (IP addresses), when, and
  roughly how large messages are. We do not hide that, and do not pad sizes.
- **Identities are visible in the handshake.** Both Ed25519 public keys, the
  version and the epochs are sent unencrypted in the first two handshake
  messages ([Wire format](WIRE_FORMAT.md#3-layer-2-the-handshake-the-only-unencrypted-part)).
  Anyone watching the network can therefore see *which identities* connect to
  each other, not just which IP addresses. The oracle fix alone does not remove
  this; a handshake that encrypts the identities after the ephemeral exchange
  would (see [Plan](PLAN.md)).
- Frame length prefixes, the channel byte and sequence numbers are visible too,
  so message sizes and counts leak ([Wire format](WIRE_FORMAT.md#8-what-an-eavesdropper-sees)).
- Idle heartbeats only occur during silence, which shows when two peers are
  *not* talking; they are encrypted but their timing is visible.
- Group members learn the full member list. Membership is not hidden from
  members.
- Delivery receipts tell an author when you were online. Read receipts are
  opt-in for this reason ([Messages](MESSAGES.md)).
- The handshake oracle ([Handshake](HANDSHAKE_AND_VERSIONING.md)) lets a key
  holder learn that another node may know them.
- Discovery broadcasts reveal your name and presence to the LAN, which is why
  they are opt-in ([Discovery](DISCOVERY.md)).
- Disk: file names, sizes and times are visible to someone with the disk
  ([Storage](STORAGE_AND_PLUGINS.md)).

## Known gaps (tracked in the [Plan](PLAN.md))

1. **Backdating after removal.** A removed member may be able to author
   messages that claim an earlier roster version, and later deliver them to
   someone who has not yet seen the removal. Candidate fix: the `Remove`
   operation records the removed member's last-seen sequence, so anything
   past that is invalid. Low priority; wanted for observation in a debugger.
2. **A removed member's sessions are not torn down.** Their messages are
   rejected, but the connections stay open. Low priority.
3. **No post-quantum protection.**
4. **No key rotation or recovery.**
5. **State rewrite on every message** (performance, not secrecy).
6. **Not audited.** This is a research and learning implementation. It has not
   had third-party cryptographic review. Do not protect anything that matters
   with it yet.

## Out of scope

- A compromised device. If malware runs as you, it reads the same memory the
  app does.
- Denial of service by a determined network attacker (they can always drop
  packets). We cap sizes and counts so one peer cannot exhaust memory.
- Deciding whether your friend is who they say they are. That is the
  out-of-band step ([Identity and trust](IDENTITY_AND_TRUST.md)).

## Related

[Wire format](WIRE_FORMAT.md) · [Library vs app](LIBRARY_VS_APP.md) · [Future crypto](FUTURE_CRYPTO.md)
