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
| **Peer id / author id** | The fingerprint: SHA-256 of a public key. On the wire it is the **32 raw bytes** (since 0.3.0; earlier builds sent 64 hex characters with a length prefix). Hex appears only in logs, dumps and the CLI. See [section 9](#9-the-size-bill-and-what-we-could-trim) |
| **Hex dump values** | Shown as lowercase hex. Long values are shortened to `first 8 bytes...last 4 bytes` |

## 1. The layer cake

Nothing is sent "raw". A chat message is wrapped five times on its way out:

```text
 you type:   hello group                                          11 bytes
                │
 group       ▼  tag, author id, seq, hashes, content, signature  161 bytes   (section 6)
 message
                │
 ratchet     ▼  + 1-byte padding marker, 40-byte header, 16-byte tag   218 bytes   (section 5)
 blob
                │
 transport   ▼  + channel(1) + seq(8) + 16-byte tag              243 bytes   (section 4)
 message
                │
 frame       ▼  + 4-byte length prefix                           247 bytes   (section 2)
                │
 TCP         ▼  247 bytes leave the machine
```

The 4 + 9 + 16 + 40 + 16 = **85 bytes** of framing added below the group layer,
plus **1 byte** for the padding marker (section 5.1), is **86 bytes** for every
data message, whatever its size (with optional padding turned on, the payload is
rounded up to a block, so this is no longer exact). The capture in section 4
confirms it: a 9-byte payload became 95 bytes on the wire, a 32-byte payload
became 118. The group layer adds its own overhead on top of that (section 6).

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

## 3. Layer 2: the handshake (only two bare key bundles are visible)

Five frames. The first two carry nothing but key material, so the two sides can
agree on a secret **before anyone has said who they are**. The key exchange is a
**hybrid**: classical X25519 plus the post-quantum **ML-KEM-768** (FIPS 203,
the standardized form of Kyber), so an attacker must break both. The next two
frames are encrypted under the combined secret and carry the identities, and a
short confirmation closes it. Purpose and reasoning are in
[Handshake and versioning](HANDSHAKE_AND_VERSIONING.md); this is what the bytes
are. The whole handshake is **2640 bytes** on the wire, of which **2272** are the
post-quantum half; it is paid once per connection, and every message after it is
unchanged. Real capture:

**Msg1: initiator to responder** (1220 bytes on the wire = 4 prefix + 32 + 1184)

| Offset | Size | Field | Example (this run) | Why |
|---:|---:|---|---|---|
| 0 | 4 | frame length = 1216 | `000004c0` | section 2 |
| 4 | 32 | initiator's ephemeral X25519 public key | `5059ec45a0091702...fccb3725` | Half of the Diffie-Hellman exchange; thrown away after this connection (forward secrecy) |
| 36 | 1184 | initiator's **ML-KEM-768 encapsulation key** | `158c99006a2af540...47db5d90` | The public half of a fresh post-quantum keypair, used for this connection only. The responder validates it (FIPS 203 modulus check) and refuses a malformed key |

**Msg2: responder to initiator** (1124 bytes on the wire = 4 + 32 + 1088)

| Offset | Size | Field | Example | Why |
|---:|---:|---|---|---|
| 0 | 4 | frame length = 1120 | `00000460` | |
| 4 | 32 | responder's ephemeral X25519 public key | `996dbed624234b05...ff4d7765` | Other half of the DH |
| 36 | 1088 | **ML-KEM-768 ciphertext** | `6cff3e7683b2d4a4...88e6338d` | A fresh random secret, encapsulated to the initiator's key. Only the initiator's private key recovers it. Anyone who sends a well-formed Msg1 gets this; it says nothing about who the responder is |

Neither message contains an identity, version or epoch. Both sides now have
two shared secrets, the X25519 one and the ML-KEM one, and combine them:

```text
eph      = SHA-256("symbolon/handshake/v4/eph" ‖ Msg1 ‖ Msg2)   all the bytes above
combined = HKDF-SHA256(salt = eph, input = ss_mlkem ‖ ss_x25519)  expanded under
           "symbolon/hybrid/v1 x25519+ml-kem-768" to 32 bytes
```

Both secrets are inputs, so the result is unpredictable unless an attacker
knows **both**. Two **handshake keys** (one per direction) come from
`HKDF-SHA256(salt = eph, input = combined)`, and everything below is encrypted
with them. That means the identities in Msg3 and Msg4 are protected by the
post-quantum secret too: a recording of the handshake does not reveal who
connected, even to a future quantum computer. ML-KEM never reports a bad
ciphertext; it returns an unrelated secret ("implicit rejection"), so a tampered
Msg2 shows up as Msg3 failing to decrypt (a unit test flips one bit in the
ciphertext and in the X25519 key and checks that no session results).

**Msg3: initiator to responder** (138 bytes on the wire = 4 + 118 + 16 tag)

| Offset | Size | Field | Example | Why |
|---:|---:|---|---|---|
| 0 | 4 | frame length = 134 | `00000086` | |
| 4 | 6 | *(encrypted)* version: major, minor, patch as three u16 | | Both sides must speak a compatible version; it is signed so it cannot be rewritten |
| 10 | 32 | *(encrypted)* initiator's Ed25519 identity public key | | The responder checks it is pinned |
| 42 | 16 | *(encrypted)* initiator's epoch (random) | | Identifies "this conversation" so a reconnect can tell resume from restart ([Sessions](SESSIONS.md)) |
| 58 | 64 | *(encrypted)* initiator's signature | | Proves the initiator holds the private key for the identity it just named |
| 122 | 16 | authentication tag | `5e33c24c583ca8f6...` | Detects any change to the ciphertext |

The visible bytes on the wire are the length and 134 random-looking bytes
(`d9ade08af7b9b4b6...b256907c` in this run).

**Msg4: responder to initiator** (138 bytes on the wire)

Same layout and size as Msg3, with the responder's version, identity public key,
epoch and signature. **The responder sends it only if it trusts the initiator.**
An unknown caller gets nothing back, so it learns neither the responder's
identity, version nor epoch (this closes the "oracle", see
[Handshake](HANDSHAKE_AND_VERSIONING.md)).

**Msg5: initiator to responder** (20 bytes on the wire = 4 prefix + 16 tag)

An encrypted *empty* message: only its authentication tag, computed with the
full transcript as associated data. The initiator sends it only after it has
checked everything in Msg4 (including that this is the peer it meant to dial).
The responder waits for it before it creates a session, so dialling the wrong
machine never leaves a half-open session on that machine.

**What gets signed.** Two hashes, each starting with its own label
(**domain separation**: a handshake signature can never be mistaken for a
signature elsewhere in the protocol):
- The initiator signs `SHA-256("symbolon/handshake/v4/initiator" ‖ eph ‖
  version_i ‖ idpub_i ‖ epoch_i)`.
- The responder signs the **full transcript**
  `SHA-256("symbolon/handshake/v4/transcript" ‖ eph ‖ version_i ‖ idpub_i ‖
  epoch_i ‖ sig_i ‖ version_r ‖ idpub_r ‖ epoch_r)`, which includes the
  initiator's own signature, so its proof covers the whole conversation.

`eph` hashes all of Msg1 and Msg2, so both signatures also cover the ML-KEM
key and ciphertext; none of the key exchange can be swapped without detection.

**What is derived (never sent).** The session keys are
`HKDF-SHA256(salt = full transcript, input = combined secret)` expanded under the
labels `"initiator-to-responder"` and `"responder-to-initiator"` into two
independent 32-byte keys, one per direction. A third derivation seeds the
[ratchet](SESSIONS.md).

**Who can see what.** A passive eavesdropper sees two blocks of key material
(random-looking) and then two encrypted blobs: no identity, version or epoch (a unit test
asserts none of those byte strings appear on the wire). An **active**
man-in-the-middle can run its own key exchange with the dialler and read Msg3,
so it learns the *dialler's* identity, but it cannot pass authentication
(the signature covers all of Msg1 and Msg2) and it never learns the listener's.

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
| alice to bob | 4 | 95 | 91 | Data | 1 | 82 |
| alice to bob | 4 | 40 | 36 | Control | 2 | 27 |
| bob to alice | 1 | 38 | 34 | Control | 1 | 25 |
| bob to alice | 2 | 40 | 36 | Control | 2 | 27 |
| bob to alice | 4 | 118 | 114 | Data | 1 | 105 |

Reading it: the 25-byte control ciphertexts are 9 bytes of plaintext plus the
16-byte tag, the size of a *ResumeRequest*; the 27-byte ones are 11 + 16, the
size of an *Ack* with nothing missing. (The capture cannot decrypt them, so
this is inferred from the sizes, which match section 4.1 exactly.) The Data
frames carry the ratchet blob. For the 9-byte payload: the plaintext is the
payload plus the 1-byte padding marker (10), so blob = 40 + 10 + 16 = 66, plus
the 16-byte transport tag = 82 (the last column), plus channel and seq (9) plus
the 4-byte prefix = 95.

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

(This capture drives the ratchet directly, so its payloads are the raw bytes.
In a real session the session layer pads first, section 5.1, so each plaintext
is one byte longer, or a whole block longer with padding on.)

### 5.1 Optional padding (inside the encrypted plaintext)

Before a message goes into the ratchet, the session adds a **marker byte
`0x80`** and then, if padding is on, **zero bytes up to the next multiple of the
block size**:

```text
plaintext = payload ‖ 0x80 ‖ 00 00 ... 00        total = a multiple of the block size
```

| Setting | Block | What an observer sees | Cost per message |
|---|---:|---|---|
| **Off** (default) | none | the exact length | 1 byte (the marker) |
| **Standard** | 256 B | which 256-byte block; all messages up to about 255 bytes look identical | about 128 bytes on average |
| **Strong** | 1024 B | which 1 KB block | about 512 bytes on average |
| Custom | 16 to 65535 B | which block | about half a block |

Why this design: the receiver strips it the same way every time (drop trailing
zeros, require the `0x80` before them), so it needs **no setting, flag or length
field**, and padded and unpadded messages mix freely. Each side chooses the
padding for what it **sends**; a peer on a different setting still works. A
payload that ends in zeros or `0x80` is safe, because the marker is added after
it and stripping starts from the end. The padding is inside the encryption, so
the wire shows only the total size. For the 11-byte "hello group" post
(161 bytes at the group layer) Standard padding makes the data frame 341 bytes
on the wire instead of 247. It does **not** hide when you send, how many
messages you send, or which channel a frame is on (Data versus Control, visible
and authenticated). Rationale and trade-offs: [Plan](PLAN.md).

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
| `0x18` | File | One step of a file transfer (see 6.5) |

### 6.2 Application message: a post (161 bytes for "hello group")

| Offset | Size | Type | Field | Why |
|---:|---:|---|---|---|
| 0 | 1 | u8 | tag `0x10` | |
| 1 | 32 | bytes | author id (raw SHA-256 of the public key) | Who wrote it |
| 33 | 8 | u64 | author's **sequence number** (starts at 1) | Position in this author's own chain |
| 41 | 32 | bytes | **prev_hash**: the author's chain tip before this message (zeros for #1) | Links this message to the one before; this is the hash chain ([Messages](MESSAGES.md)) |
| 73 | 8 | u64 | **roster version** the author wrote under | Lets a receiver judge permission as of that version ([Groups](GROUPS.md)) |
| 81 | 4 | u32 | content length (= 12) | |
| 85 | 1 | u8 | content kind: 0 Post, 1 Edit, 2 Delete, 3 File offer | |
| 86 | 11 | bytes | the payload (your text) | The only part you typed |
| 97 | 64 | bytes | author's **Ed25519 signature** | Proves authorship |

**Edit** (170 bytes in the example): after the content kind `01`, an 8-byte
`target_seq` (which of your messages), then the new payload. **Delete**
(190 bytes): kind `02`, the raw 32-byte target author id, then
the 8-byte target sequence number. An edit or delete is a new entry in the
author's chain, not a change to history.

**The hash chain, exactly.** The author keeps a running *tip*, 32 zero bytes
before message 1. For each message:

1. `header = [id (32)][u64 seq][prev_hash][u64 roster_version][SHA-256(content)]`
2. new tip = `SHA-256(old tip ‖ header)`
3. The next message's `prev_hash` is that new tip.

Receivers recompute this; a message whose `prev_hash` or `seq` does not fit is
rejected as a broken chain. The header holds the **hash** of the content, not
the content, so an [existence notice](MESSAGES.md) (which carries only the hash)
fits the same chain.

**What is signed:** `"symbolon/group/application/v2" ‖ group id (32) ‖ header`. The group id is included so a signed message cannot be
replayed into a different group; the label separates it from other signatures.

### 6.3 Roster message carrying the genesis operation (276 bytes, 2 members)

| Offset | Size | Field | Why |
|---:|---:|---|---|
| 0 | 1 | tag `0x11` | |
| 1 | 32 | **group id**: `SHA-256("symbolon/group/id/v1" ‖ kind ‖ relay ‖ creator key ‖ sorted member fingerprints)` | The id commits to the founding members, kind and policy, so nobody can claim an existing id for a different group |
| 33 | 8 | roster version (0 for genesis) | Orders the roster history |
| 41 | 32 | previous roster hash (zeros at genesis) | Chains each change to the last |
| 73 | 4 | operation length (103) | |
| 77 | 1 | op tag: 0 Genesis | Later ops: 1 Add, 2 Remove, 3 ChangeTier, 4 DefineTier, 5 AddBot |
| 78 | 1 | group kind (0 = FullMesh) | Immutable ([Groups](GROUPS.md)) |
| 79 | 1 | relay policy (0 Open, 1 AuthorOnly) | Immutable ([Messages](MESSAGES.md)) |
| 80 | 2 | number of tier definitions (2) | |
| 82 | 2 + 5 + 1 | tier `owner`: name length, name, **permission bitmask `0f`** | Bitmask: add=1, remove=2, read=4, write=8. `0f` = all four |
| 90 | 2 + 6 + 1 | tier `member`: bitmask `0c` | `0c` = read + write |
| 99 | 2 | number of members (2) | |
| 101 | 32 + 2 + 5 | member 1: raw public key, tier name length, `owner` | Genesis lists raw keys so everyone can verify signatures from the start |
| 140 | 32 + 2 + 6 | member 2: raw public key, tier `member` | |
| 180 | 32 | proposer id (raw) | Who signed |
| 212 | 64 | proposer's Ed25519 signature | Over `"symbolon/group/roster-op/v1" ‖ group id ‖ version ‖ prev hash ‖ op bytes` |

Later roster operations reuse the same outer shell (version, previous hash,
operation bytes, proposer, signature) with a different op body. An `Add` is a
raw 32-byte key plus a tier name; a `Remove` is the raw 32-byte target id.

### 6.4 The small messages

| Message | Total | Fields after the tag |
|---|---:|---|
| **Have** `0x17` | 41 | author id (32), u64 seq |
| **RelayRequest** `0x12` | 41 | author id (32), u64 `after_seq` |
| **FetchRequest** `0x15` | 41 | author id (32), u64 seq |
| **RosterSyncRequest** `0x13` | 9 | u64 `have_version` |
| **Existence** `0x14` | 177 | author id, u64 seq, 32-byte prev_hash, u64 roster version, **32-byte content hash**, 64-byte signature |
| **Receipt** `0x16` | 170 | author id, u64 seq, 32-byte content hash, 1-byte kind (0 delivered, 1 read), receiver id (32), 64-byte signature |

### 6.5 Files

A file is shared in two parts. The **offer** is an ordinary Application
message (6.2) with **content kind 3**: after the kind byte comes the offer
exactly as laid out in [Files](FILES.md#the-offer) (optional name, size,
chunk size, 32-byte root, up to 512 prefix bytes). It is signed and sits in
the author's hash chain, so it is ordered, relayable and deletable like a
post. Deleting it also stops the author serving it.

The **bytes** move as tag `0x18` messages, pairwise: tag, then one file frame
(kind byte, 32-byte file id = the offer's root, then the fields):

| Frame | Kind | Fields |
|---|---:|---|
| ManifestRequest | 0 | none |
| Manifest | 1 | 32 bytes per chunk, back to back |
| ChunkRequest | 2 | u16 count (at most 64), then u32 indices |
| Chunk | 3 | u32 index, the chunk bytes |
| Unavailable | 4 | none |

These carry no signature of their own: the signed offer's root and the
authenticated session are what make them trustworthy.

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
| Handshake: the two ephemeral public keys | **Yes** (random-looking) |
| Handshake: identity public keys, versions, epochs, signatures | No (Msg3 and Msg4 are encrypted) |
| Frame length prefix | **Yes** (so message sizes leak) |
| Channel byte (Data or Control) and sequence number | **Yes** (authenticated, not hidden) |
| Ratchet header (key, pn, n) | No (inside the transport encryption) |
| Group message type, author, content, signatures | No |
| Whether a message is a post or a ping | Only roughly, from size and channel |

## 9. The size bill, and what we could trim

For one post "hello group" (11 bytes of text) the cost is 247 bytes on the wire
with padding off, about 4.5% useful. Where it goes:

| Part | Bytes | Share of the 247 |
|---|---:|---:|
| Your text | 11 | 4% |
| Author id (raw) | 32 | 13% |
| Author signature | 64 | 26% |
| prev_hash | 32 | 13% |
| Ratchet header + tag | 56 | 23% |
| Transport (channel, seq, tag) + frame prefix | 29 | 12% |
| Seq, roster version, content length, kind, tag, padding marker | 23 | 9% |

**Done in 0.3.0:** ids are raw 32-byte values (they were 64 hex characters plus
a 2-byte length, 66 bytes), which took the same post from 280 to 246 bytes (247 once the 1-byte padding
marker was added later in the same release).
The type in the code is `PeerId` / `GroupId`, so an id can no longer be mixed
up with a string. A small member index (about 62 bytes saved per id) was
rejected: the receiver would need the roster just to read a message, so an
unknown member would become unreadable instead of rejectable. Compression is
not used; it does nothing for random ids or signatures and is unsafe in general
([Plan](PLAN.md)). Signatures (64) and hashes (32) cannot be shrunk without
weakening the design.

## Reproducing this page

```
cargo run --example wire_dump
```

prints every table above from live bytes (fresh keys each time).

## Related

[Sessions](SESSIONS.md) · [Handshake and versioning](HANDSHAKE_AND_VERSIONING.md) ·
[Groups](GROUPS.md) · [Messages](MESSAGES.md) · [Storage](STORAGE_AND_PLUGINS.md) ·
[Threat model](THREAT_MODEL.md) · [Plan](PLAN.md)
