# The wire format: every byte, what it is and why

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

This page shows **exactly what is sent**, field by field, with sizes, types and
the reason each field exists. Every table was produced by running
`cargo run --example wire_dump`, which captures real bytes from a live
connection and checks that the layouts below cover every byte. If a table here
were wrong, that program would stop with an error. Keys and nonces are random,
so the hex values differ on every run; the **sizes and offsets never change**.

## 0. Conventions

| Term | Meaning |
|---|---|
| **u8 / u16 / u32 / u64** | Unsigned whole numbers of 1, 2, 4 or 8 bytes |
| **Big-endian** | The most significant byte comes first, so `0x0102` is sent as `01 02`. Every number on the wire is big-endian (also called network order) so both machines read it the same way |
| **Length prefix** | A number saying how many bytes follow, so a reader knows where a variable-sized field ends |
| **Tag** | A one-byte label saying which kind of message follows |
| **Ed25519 public key** | 32 raw bytes. **Signature**: 64 bytes. **X25519 public key**: 32 bytes |
| **Poly1305 tag** | 16 bytes appended by the encryption, proving nothing was changed |
| **Peer id / author id** | The fingerprint: SHA-256 of a public key. On the wire it is sent as **64 ASCII characters** (hex text), not 32 raw bytes. See [section 9](#9-the-size-bill-and-what-we-could-trim) |
| **Hex dump values** | Shown as lowercase hex. Long values are shortened to `first 8 bytes...last 4 bytes` |

## 1. The layer cake

Nothing is sent "raw". A chat message is wrapped five times on its way out:

```text
 you type:   hello group                                          11 bytes
                │
 group       ▼  tag, author id, seq, hashes, content, signature  195 bytes   (section 6)
 message
                │
 ratchet     ▼  + 40-byte header + 16-byte tag                   251 bytes   (section 5)
 blob
                │
 transport   ▼  + channel(1) + seq(8) + 16-byte tag              276 bytes   (section 4)
 message
                │
 frame       ▼  + 4-byte length prefix                           280 bytes   (section 2)
                │
 TCP         ▼  280 bytes leave the machine
```

The 4 + 9 + 16 + 40 + 16 = **85 bytes** of overhead added below the group layer
is the same for every data message, whatever its size. The capture in section 3
confirms it: a 9-byte payload became 94 bytes on the wire, a 32-byte payload
became 117. The group layer adds its own overhead on top of that (section 6).

Control traffic (acknowledgements, pings) skips the ratchet and the group
layer: it is only wrapped in the transport message and the frame.

## 2. Layer 1: the frame

TCP delivers a stream of bytes with no message boundaries, so every message is
preceded by its length.

| Offset | Size | Type | Field | Why |
|---:|---:|---|---|---|
| 0 | 4 | u32 | Length N of what follows | A reader needs to know where this message ends and the next begins |
| 4 | N | bytes | Payload | The handshake message or transport message |

- **Why 4 bytes?** A u16 would cap messages at 64 KiB, too small; a u64 wastes
  four bytes on every message.
- **Why a cap?** A reader refuses any N above **4 MiB** (4,194,304) before
  allocating anything, so a stranger cannot make you reserve gigabytes with one
  forged length. See [Threat model](THREAT_MODEL.md).
- **Why one write?** The length and payload are sent in a single `write`. Two
  small writes interact badly with TCP's delay timers and added tens of
  milliseconds to the handshake.

## 3. Layer 2: the handshake (the only unencrypted part)

Three frames, sent before any key exists. Purpose and reasoning are in
[Handshake and versioning](HANDSHAKE_AND_VERSIONING.md); this is what the bytes
are. Real capture:

**Msg1: initiator to responder** (90 bytes on the wire = 4 prefix + 86)

| Offset | Size | Field | Example (this run) | Why |
|---:|---:|---|---|---|
| 0 | 4 | frame length = 86 | `00000056` | section 2 |
| 4 | 6 | version: major, minor, patch as three u16 | `000000020000` (= 0.2.0) | Both sides must speak a compatible version; it is also signed into the transcript so it cannot be rewritten |
| 10 | 32 | initiator's Ed25519 identity public key | `43a926034bc6f24e...b756c4c4` | The responder checks it is pinned; it is signed into the transcript |
| 42 | 32 | initiator's ephemeral X25519 public key | `9b757fe45ae67fc5...96c6d23d` | Half of the Diffie-Hellman exchange; thrown away after this connection (forward secrecy) |
| 74 | 16 | initiator's epoch (random) | `438e6f9da6ad0649...` | Identifies "this conversation" so a reconnect can tell resume from restart ([Sessions](SESSIONS.md)) |

**Msg2: responder to initiator** (154 bytes on the wire)

| Offset | Size | Field | Example | Why |
|---:|---:|---|---|---|
| 0 | 4 | frame length = 150 | `00000096` | |
| 4 | 6 | version | `000000020000` | Same as above |
| 10 | 32 | responder's Ed25519 public key | `3090aa09143999b5...01ecd1fd` | The initiator checks it is the peer it meant to dial |
| 42 | 32 | responder's ephemeral X25519 public key | `835321fbe08e39c5...973e896a` | Other half of the DH |
| 74 | 16 | responder's epoch | `b2146723e1e1fd70...` | As above |
| 90 | 64 | responder's signature over the transcript | `23b3d725ddc81aff...c2fc830c` | Proves the responder holds the private key for the identity it sent |

**Msg3: initiator to responder** (68 bytes on the wire)

| Offset | Size | Field | Example | Why |
|---:|---:|---|---|---|
| 0 | 4 | frame length = 64 | `00000040` | |
| 4 | 64 | initiator's signature over the transcript | `11f72218b27d78db...858ed90a` | Proves the initiator holds its private key |

**What gets signed.** The *transcript* is
`SHA-256("symbolon/handshake/v2" ‖ version_i ‖ idpub_i ‖ epub_i ‖ epoch_i ‖
version_r ‖ idpub_r ‖ epub_r ‖ epoch_r)`: a 21-byte label followed by each
side's 86 bytes (6 + 32 + 32 + 16), initiator first, 193 bytes hashed in all.
Both signatures cover this one hash. The label is **domain separation**: a
signature made for the handshake can never be mistaken for a signature in some
other part of the protocol.

**What is derived (never sent).** Both sides compute the X25519 shared secret,
then `HKDF-SHA256(salt = transcript, input = shared secret)` expanded under the
labels `"initiator-to-responder"` and `"responder-to-initiator"` into two
independent 32-byte keys, one per direction. A third derivation seeds the
[ratchet](SESSIONS.md).

**Who can see this.** Everyone on the network path. Note especially that both
**identity public keys travel in the clear** in Msg1 and Msg2, as do the
version and the epochs. See [Threat model](THREAT_MODEL.md); it is a known
metadata cost with options in [Plan](PLAN.md).

## 4. Layer 3: the transport message (every frame after the handshake)

Once the keys exist, every frame payload looks like this:

| Offset | Size | Type | Field | Why |
|---:|---:|---|---|---|
| 0 | 1 | u8 | **Channel**: 0 = Data, 1 = Control | Lets data and control traffic each keep a simple counter without ever reusing a nonce |
| 1 | 8 | u64 | **Sequence number** | Orders messages and builds the nonce; per channel, per direction, starts at 1 |
| 9 | M | bytes | **Ciphertext + 16-byte Poly1305 tag** | The encrypted content |

- **Nonce** (12 bytes, never sent, rebuilt by the receiver): byte 0 = channel,
  bytes 1 to 3 = zero, bytes 4 to 11 = the sequence number. Two directions use
  two different keys, and each counter only goes up, so a (key, nonce) pair is
  never repeated; repeating one would break ChaCha20-Poly1305 completely.
- **Associated data** (authenticated but not encrypted): the channel byte and
  the sequence number (9 bytes). They are visible on the wire, so they are
  *bound into the tag*: changing either makes decryption fail.
- Real capture, after the handshake, from the same run:

| Direction | Frame | Bytes on wire | Length prefix | Channel | Seq | Ciphertext + tag |
|---|---:|---:|---:|---|---:|---:|
| alice to bob | 2 | 38 | 34 | Control | 1 | 25 |
| alice to bob | 3 | 94 | 90 | Data | 1 | 81 |
| alice to bob | 4 | 40 | 36 | Control | 2 | 27 |
| bob to alice | 1 | 38 | 34 | Control | 1 | 25 |
| bob to alice | 2 | 40 | 36 | Control | 2 | 27 |
| bob to alice | 3 | 117 | 113 | Data | 1 | 104 |

Reading it: the 25-byte control ciphertexts are 9 bytes of plaintext plus the
16-byte tag, the size of a *ResumeRequest*; the 27-byte ones are 11 + 16, the
size of an *Ack* with nothing missing. (The capture cannot decrypt them, so
this is inferred from the sizes, which match section 4.1 exactly.) The Data
frames carry the ratchet blob. For the 9-byte payload: blob = 40 + 9 + 16 = 65,
plus the 16-byte transport tag = 81 (the last column), plus channel and seq (9)
plus the 4-byte prefix = 94.

### 4.1 Control messages (plaintext before encryption)

All numbers big-endian. Sent on the Control channel.

**Ack** (11 bytes, plus 8 per missing number)

| Offset | Size | Field | Why |
|---:|---:|---|---|
| 0 | 1 | tag `0x01` | Kind of control message |
| 1 | 8 | `cumulative_ack`: everything up to and including this arrived | Lets the sender delete those from its outbox |
| 9 | 2 | count of missing numbers | Length of the list that follows |
| 11 | 8 each | a sequence number that is missing | Tells the sender exactly what to resend |

Example: "got everything to 5, missing 7 and 9" is 27 bytes:
`01 0000000000000005 0002 0000000000000007 0000000000000009`.

**ResumeRequest** (9 bytes): tag `0x02`, then u64 `last_contiguous_seq`. Sent on
reconnect: "the last message I have in an unbroken run is N; resend after it."

**Ping** (9 bytes): tag `0x03`, then u64 nonce. **Pong** (9 bytes): tag `0x04`,
then the same nonce copied back. The nonce lets the pinger match a Pong to its
Ping and measure the round-trip time.

## 5. Layer 4: the ratchet blob (inside a Data transport message)

This is what the [Double Ratchet](SESSIONS.md) produces. It is the plaintext
that the transport layer then encrypts again.

| Offset | Size | Type | Field | Why |
|---:|---:|---|---|---|
| 0 | 32 | X25519 public key | Sender's **current ratchet public key** | The receiver mixes it into the next key step; it changes whenever the conversation changes direction |
| 32 | 4 | u32 | **pn**: how many messages the sender sent in its previous chain | Lets the receiver compute and cache any keys it never saw, so late messages still decrypt |
| 36 | 4 | u32 | **n**: this message's number in the current chain | Which one-time message key to derive |
| 40 | len | bytes | Ciphertext of the payload | Same length as the plaintext |
| 40 + len | 16 | bytes | Poly1305 tag | Covers the ciphertext **and the 40-byte header** |

Real capture from a ratchet pair:

| Message | Header key | pn | n | Payload | Total |
|---|---|---:|---:|---|---:|
| 1: responder's first, "first" | `4bacdc20...83dafd70` | 0 | 0 | 5 bytes | 61 |
| 2: same sender again, "second" | **same** `4bacdc20...83dafd70` | 0 | **1** | 6 bytes | 62 |
| 3: the other side replies, "reply" | **new** `f3031d8a...c74dd900` | 0 | 0 | 5 bytes | 61 |

Notice message 2 only counts `n` up (same chain), while message 3, sent by the
other person, carries a **new key**. That fresh key is the "DH ratchet step"
that locks out someone who stole an old state. Every message's cipher key is
derived and used **once**, then deleted.

## 6. Layer 5: group messages (inside the ratchet blob)

A group message is one-byte-tagged, then fields. Peer ids are length-prefixed
ASCII (`0040` = 64 characters). All captured from `wire_dump` with real ids; the
signature bytes in the application, existence and receipt dumps are
**placeholder filler** because the example cannot reach the private signing
function, but the sizes are exact.

### 6.1 Tags

| Tag | Message | Purpose |
|---|---|---|
| `0x10` | Application | A post, edit or delete |
| `0x11` | Roster | A signed membership change |
| `0x12` | RelayRequest | "Send me what you hold from this author after N" |
| `0x13` | RosterSyncRequest | "I have roster version V, send newer" |
| `0x14` | Existence | "Message N exists" without its content |
| `0x15` | FetchRequest | "Send me exactly message N" |
| `0x16` | Receipt | Signed "I received (or read) message N" |
| `0x17` | Have | "I hold message N by this author" |

### 6.2 Application message: a post (195 bytes for "hello group")

| Offset | Size | Type | Field | Why |
|---:|---:|---|---|---|
| 0 | 1 | u8 | tag `0x10` | |
| 1 | 2 | u16 | author id length (= 64) | |
| 3 | 64 | ASCII | author id (hex of SHA-256 of the public key) | Who wrote it |
| 67 | 8 | u64 | author's **sequence number** (starts at 1) | Position in this author's own chain |
| 75 | 32 | bytes | **prev_hash**: the author's chain tip before this message (zeros for #1) | Links this message to the one before; this is the hash chain ([Messages](MESSAGES.md)) |
| 107 | 8 | u64 | **roster version** the author wrote under | Lets a receiver judge permission as of that version ([Groups](GROUPS.md)) |
| 115 | 4 | u32 | content length (= 12) | |
| 119 | 1 | u8 | content kind: 0 Post, 1 Edit, 2 Delete | |
| 120 | 11 | bytes | the payload (your text) | The only part you typed |
| 131 | 64 | bytes | author's **Ed25519 signature** | Proves authorship |

**Edit** (204 bytes in the example): after the content kind `01`, an 8-byte
`target_seq` (which of your messages), then the new payload. **Delete**
(258 bytes): kind `02`, a u16 length + the 64-character target author id, then
the 8-byte target sequence number. An edit or delete is a new entry in the
author's chain, not a change to history.

**The hash chain, exactly.** The author keeps a running *tip*, 32 zero bytes
before message 1. For each message:

1. `header = [u16 id length][id][u64 seq][prev_hash][u64 roster_version][SHA-256(content)]`
2. new tip = `SHA-256(old tip ‖ header)`
3. The next message's `prev_hash` is that new tip.

Receivers recompute this; a message whose `prev_hash` or `seq` does not fit is
rejected as a broken chain. The header holds the **hash** of the content, not
the content, so an [existence notice](MESSAGES.md) (which carries only the hash)
fits the same chain.

**What is signed:** `"symbolon/group/application/v2" ‖ u16 group-id length ‖
group id ‖ header`. The group id is included so a signed message cannot be
replayed into a different group; the label separates it from other signatures.

### 6.3 Roster message carrying the genesis operation (344 bytes, 2 members)

| Offset | Size | Field | Why |
|---:|---:|---|---|
| 0 | 1 | tag `0x11` | |
| 1 | 2 | group id length (64) | |
| 3 | 64 | **group id**: hex of `SHA-256("symbolon/group/id/v1" ‖ kind ‖ relay ‖ creator key ‖ sorted member fingerprints)` | The id commits to the founding members, kind and policy, so nobody can claim an existing id for a different group |
| 67 | 8 | roster version (0 for genesis) | Orders the roster history |
| 75 | 32 | previous roster hash (zeros at genesis) | Chains each change to the last |
| 107 | 4 | operation length (103) | |
| 111 | 1 | op tag: 0 Genesis | Later ops: 1 Add, 2 Remove, 3 ChangeTier, 4 DefineTier, 5 AddBot |
| 112 | 1 | group kind (0 = FullMesh) | Immutable ([Groups](GROUPS.md)) |
| 113 | 1 | relay policy (0 Open, 1 AuthorOnly) | Immutable ([Messages](MESSAGES.md)) |
| 114 | 2 | number of tier definitions (2) | |
| 116 | 2 + 5 + 1 | tier `owner`: name length, name, **permission bitmask `0f`** | Bitmask: add=1, remove=2, read=4, write=8. `0f` = all four |
| 124 | 2 + 6 + 1 | tier `member`: bitmask `0c` | `0c` = read + write |
| 133 | 2 | number of members (2) | |
| 135 | 32 + 2 + 5 | member 1: raw public key, tier name length, `owner` | Genesis lists raw keys so everyone can verify signatures from the start |
| 174 | 32 + 2 + 6 | member 2: raw public key, tier `member` | |
| 214 | 2 + 64 | proposer id length and id | Who signed |
| 280 | 64 | proposer's Ed25519 signature | Over `"symbolon/group/roster-op/v1" ‖ group id ‖ version ‖ prev hash ‖ op bytes` |

Later roster operations reuse the same outer shell (version, previous hash,
operation bytes, proposer, signature) with a different op body. An `Add` is a
raw 32-byte key plus a tier name; a `Remove` is a length-prefixed target id.

### 6.4 The small messages

| Message | Total | Fields after the tag |
|---|---:|---|
| **Have** `0x17` | 75 | author id (u16 length + 64), u64 seq |
| **RelayRequest** `0x12` | 75 | author id (u16 length + 64), u64 `after_seq` |
| **FetchRequest** `0x15` | 75 | author id (u16 length + 64), u64 seq |
| **RosterSyncRequest** `0x13` | 9 | u64 `have_version` |
| **Existence** `0x14` | 211 | author id, u64 seq, 32-byte prev_hash, u64 roster version, **32-byte content hash**, 64-byte signature |
| **Receipt** `0x16` | 238 | author id, u64 seq, 32-byte content hash, 1-byte kind (0 delivered, 1 read), receiver id (u16 + 64), 64-byte signature |

An **Existence** notice is exactly an Application message with the content
replaced by its 32-byte hash, so it can be checked against the same chain and
signature. A **Receipt** includes the content hash so it proves *which* bytes
were received, not just "something with that number".

## 7. At rest: the files

### 7.1 Identity file (126 bytes, magic `SYMI`)

| Offset | Size | Field | Why |
|---:|---:|---|---|
| 0 | 4 | magic `SYMI` | Identifies the file type |
| 4 | 2 | format version (2) | Lets the loader refuse formats it does not know |
| 6 | 16 | Argon2id salt (random) | Makes every file's key unique |
| 22 | 4 | Argon2id memory cost in KiB (default 65536 = 64 MiB; the dump uses weak test settings) | Stored so the file says how to unlock itself |
| 26 | 4 | Argon2id time cost (default 3) | |
| 30 | 4 | Argon2id lanes | |
| 34 | 12 | AEAD nonce (random) | |
| 46 | 32 | **key commitment** | Binds the file to exactly one passphrase-derived key, checked *before* decrypting |
| 78 | 32 | encrypted secret key | |
| 110 | 16 | Poly1305 tag | Covers the ciphertext **and the whole 78-byte header** as associated data, so no field can be edited |

### 7.2 A sealed record (event log entries and state files)

`nonce (12, random) ‖ ciphertext ‖ tag (16)`: 28 bytes of overhead. Every
record in the group log and every saved state blob has this form, so a store
(even a cloud one) holds only ciphertext. See
[Storage](STORAGE_AND_PLUGINS.md).

### 7.3 Saved session state (plaintext, before it is sealed)

Magic `SYMS`, format byte `01`, then length-prefixed (u32) blobs in this order:
peer id; 16-byte own epoch; 16-byte peer epoch; the **ratchet state** (all
secret keys, chain counters and cached skipped keys); the **outbox** (next
sequence number, then each unacknowledged message as seq + length + bytes); the
**inbox** (next expected number, then buffered out-of-order messages); and the
queue of decrypted-but-not-yet-delivered messages. It is sealed under a key
derived from your identity, so it is exactly as exposed as your identity file.
Transport keys are **not** saved: every connection performs a fresh handshake.

### 7.4 Discovery beacon (20 bytes, or 22 with full version)

| Offset | Size | Field | Why |
|---:|---:|---|---|
| 0 | 4 | magic `SYMD` | Ignore unrelated UDP traffic |
| 4 | 1 | wire version (1) | |
| 5 | 1 | flags: bit 0 = minor present, bit 1 = patch present | Minor and patch are separate opt-ins ([Discovery](DISCOVERY.md)) |
| 6 | 1 | name length | |
| 7 | n | display name (ASCII, at most 32) | What others see |
| 7 + n | 1 | major version | Always sent |
| next | 0 or 1 | minor version | Only if disclosed |
| next | 0 or 1 | patch version | Only if disclosed |
| last | 2 | TCP port (u16) | Where to dial; the host is the packet's source address |

The parser is strict: wrong magic, unknown flag bits, a patch without a minor or
extra trailing bytes all reject the packet.

## 8. What an eavesdropper sees

| Item | Visible on the network? |
|---|---|
| IP addresses, ports, timing, packet sizes | **Yes** |
| Handshake: both identity public keys, version, epochs, ephemeral keys, signatures | **Yes** (Msg1 to Msg3 are unencrypted) |
| Frame length prefix | **Yes** (so message sizes leak) |
| Channel byte (Data or Control) and sequence number | **Yes** (authenticated, not hidden) |
| Ratchet header (key, pn, n) | No (inside the transport encryption) |
| Group message type, author, content, signatures | No |
| Whether a message is a post or a ping | Only roughly, from size and channel |

## 9. The size bill, and what we could trim

For one post "hello group" (11 bytes of text) the cost is 280 bytes on the wire,
about 4% useful. Where it goes:

| Part | Bytes | Share of the 280 |
|---|---:|---:|
| Your text | 11 | 4% |
| Author id as 64 ASCII characters (+2 length) | 66 | 24% |
| Author signature | 64 | 23% |
| prev_hash | 32 | 11% |
| Ratchet header + tag | 56 | 20% |
| Transport (channel, seq, tag) + frame prefix | 29 | 10% |
| Seq, roster version, content length, kind, tag | 22 | 8% |

Options for the largest avoidable cost, the author id:

| Option | Saves | Good | Bad |
|---|---:|---|---|
| **Keep ASCII hex ids** (today) | 0 | Human-readable in dumps and logs; one string type everywhere; no conversion bugs | Doubles the id's size; repeated per message |
| Send raw 32-byte ids | 32 per id (a Delete or Receipt carries two) | Half the size; trivial to do | Wire change (minor bump); code that treats ids as strings needs a conversion layer |
| Send a small member index (u16) from the roster | about 62 per id | Tiny | The receiver needs the roster to read any message; a message from an unknown member becomes unreadable instead of rejectable |
| Compress | varies | Easy | Not for random hex or signatures, and unsafe in general ([Plan](PLAN.md)) |

Raw 32-byte ids look like the sensible next step, because they cost nothing in
security. It is **not decided**; it belongs with the next wire-format change
(the post-quantum handshake), so we only break compatibility once. Signatures
(64) and hashes (32) cannot be shrunk without weakening the design. See
[Plan](PLAN.md).

## Reproducing this page

```
cargo run --example wire_dump
```

prints every table above from live bytes (fresh keys each time).

## Related

[Sessions](SESSIONS.md) · [Handshake and versioning](HANDSHAKE_AND_VERSIONING.md) ·
[Groups](GROUPS.md) · [Messages](MESSAGES.md) · [Storage](STORAGE_AND_PLUGINS.md) ·
[Threat model](THREAT_MODEL.md) · [Plan](PLAN.md)
