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
| Quantum computer, later | **No** for recorded traffic (hybrid X25519 + ML-KEM-768 key exchange, since 0.3.0) | **Yes**, in principle: Ed25519 signatures are not post-quantum | See the status table below and [Future crypto](FUTURE_CRYPTO.md) |

## Metadata: what still leaks

Content is the easy part. **Metadata** is who talks to whom, when, how much.

- A network observer sees who connects to whom (IP addresses), when, and
  roughly how large messages are. Message sizes can be hidden with **optional
  padding** (off by default, 256 or 1024-byte blocks or a custom size; see
  [Wire format](WIRE_FORMAT.md#51-optional-padding-inside-the-encrypted-plaintext)),
  at the cost of bandwidth. Padding does not hide timing or message counts.
- **Identities are hidden from passive observers (0.3.0).** The handshake
  sends two bare key bundles (X25519 plus ML-KEM) and then encrypts the identities, versions and
  epochs ([Wire format](WIRE_FORMAT.md#3-layer-2-the-handshake-only-two-bare-key-bundles-are-visible)).
  An *active* attacker who intercepts the exchange still learns the dialler's
  identity (the dialler speaks first), but cannot authenticate and never learns
  the listener's. Hiding the dialler too would need the listener's key known in
  advance.
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
3. **Signatures and identities are not post-quantum.** The key exchange is hybrid
   (see the table below); Ed25519 identity keys and every signature are not.
   Healing after a stolen session is also only classical. All planned for 1.0.0.
4. **No key rotation or recovery.**
5. **State rewrite on every message** (performance, not secrecy).
6. **Not audited.** This is a research and learning implementation. It has not
   had third-party cryptographic review. Do not protect anything that matters
   with it yet.

## Post-quantum status

What a future quantum computer could and could not do to each part, as of 0.3.0:

| Part | Post-quantum? | Notes |
|---|---|---|
| Handshake key exchange | **Yes** | Hybrid X25519 + ML-KEM-768. An attacker must break both |
| Recorded sessions ("harvest now, decrypt later") | **Yes** | The ML-KEM secret is in the root key every later key derives from |
| Handshake identities (Msg3 and Msg4) | **Yes** | Encrypted under keys that include the ML-KEM secret, so a recording does not reveal who connected |
| Message encryption (ChaCha20-Poly1305, 256-bit keys) | **Yes** | A quantum computer roughly halves the effective strength, still about 128 bits |
| SHA-256, HKDF, hash chains | **Yes** | Hash-based security holds up |
| Argon2id identity file | **Yes** | The Ed25519 key stored inside is the weak part |
| Ratchet DH steps (X25519) | **Partly** | Safe against recording, because the root key is already hybrid. Self-healing after a stolen session is classical only. Planned fix: periodic re-handshake or a post-quantum ratchet |
| Identity keys and every signature (Ed25519) | **No** | Handshake authentication, roster operations, group messages and receipts. A quantum attacker who recovers a private key from its public key could impersonate that person from then on. Planned fix: hybrid Ed25519 + ML-DSA, with a design that avoids a 3 KB signature on every message |
| Future tree groups | **Not yet** | A tree needs a post-quantum KEM at its nodes, or a secret mixed in from the pairwise hybrid sessions; this is a stated requirement of any tree design ([Plan](PLAN.md)) |

**Caveat on the ML-KEM implementation.** It comes from the RustCrypto `ml-kem`
crate, whose own README says it has **never been independently audited**. The
hybrid construction is chosen so that a flaw in it alone does not expose a
session (the X25519 half still protects), but it is one more reason the project
as a whole must not be trusted with anything important yet.

## File transfer

Design and the full list of checks are in [File transfer](FILES.md). The
threats specific to it:

| Threat | Defence | Left over |
|---|---|---|
| A peer sends corrupt or forged chunks | Every chunk is checked against the signed offer's root before it is written | Wasted bandwidth |
| A malicious holder serves wrong data in place of the author | Same: any holder's chunks are verified, so any holder is safe to use | None for integrity |
| An offer claims a huge size to fill the disk | Size is checked against the receiver's limit (default 1 GiB, hard maximum 4 GiB) before anything is stored, and a file is never requested without the app's accept | An app that auto-accepts must also check free space |
| A lying prefix ("this is a PDF") | The first chunk is checked against it; a lie aborts the transfer | The extension and the type are still claims |
| A name that escapes the folder or hides its extension | `sanitize_name` | Windows reserved names are the app's job |
| A symlink planted at the download path, or a file that appears during the download | The part file refuses existing entries and links; the final step never replaces a file | None known |
| The file changes on the sender's disk after the offer | The sender re-hashes each chunk before sending | The receiver is told the transfer failed |
| Metadata | Name and size are visible to every group member; sizes are visible on the wire unless [padding](WIRE_FORMAT.md#51-optional-padding-inside-the-encrypted-plaintext) is on (padding hides a chunk's exact length only for the last, shorter chunk; all others are the same size anyway) | Anyone in the group learns that a file of that size and name was shared |
| Malware inside the file | **Not defended.** The library moves bytes; it does not scan them | The app and the user |

## Number theory, Riemann and quantum algorithms

**Status of the news (as of 22 November 2026).** Reports say two claimed
proofs of the Riemann Hypothesis (and its generalized form) appeared on the
same day: one by an Anthropic number theorist working with Claude, posted with
Lean code, and one by a Stanford postdoc with no AI involved. As far as the
coverage I could read says, neither has been peer reviewed or independently
confirmed, and whether the formal statement in the Lean code matches the
standard one is still open. **Treat both as claims, not results.** (Sources:
[DataCamp](https://www.datacamp.com/blog/ai-solved-riemann-hypothesis) and the
other outlets it lists; I could not open the others.)

**Even if it is true, it does not change our cryptography.** The Riemann
Hypothesis is about how primes are spread along the number line. It would
sharpen estimates and settle many results that are currently stated "assuming
RH". It does **not** give a way to factor a number or to solve a discrete
logarithm, which are the problems cryptography relies on. It also does not
help us find primes in any way that matters, because we do not generate
primes: every primitive here uses fixed, public, standardized parameters.

| What we use | What its security rests on | Does RH change it? | Does Shor's algorithm? |
|---|---|---|---|
| X25519, Ed25519 (the curve over the prime 2^255 - 19) | The elliptic-curve discrete logarithm | No | **Yes**, on a large enough quantum computer |
| ML-KEM-768 | Lattice problems (module learning with errors) | No | No (not known to be) |
| ChaCha20-Poly1305, SHA-256, HKDF, Argon2id | No structure to exploit; best attack is brute force or collision search | No | Only Grover's generic speedup: key and preimage strength is roughly halved (still about 128 bits) |

**What does affect us is Shor's algorithm, and the estimates keep falling.**
Google Quantum AI has reported that breaking 256-bit elliptic-curve
cryptography would need fewer than about 1,200 logical qubits and under
500,000 physical ones, running for minutes, about a 20-fold cut from earlier
estimates, and set 2029 as its own target for moving to post-quantum
cryptography. Such hardware does not exist today, but the gap is narrowing.
(Source: [SecurityWeek](https://www.securityweek.com/google-slashes-quantum-resource-requirements-for-breaking-cryptocurrency-encryption/amp/),
reporting that whitepaper; I have not read the whitepaper itself.)

What that means for Symbolon, using the [status table](#post-quantum-status):

* **Recorded traffic is protected** by the hybrid ML-KEM + X25519 key
  exchange. Shor breaking X25519 alone does not expose a session.
* **Identities and signatures are the exposed part.** A quantum attacker who
  derives an Ed25519 private key from its public key could impersonate that
  person and forge roster changes and messages from then on. This is the
  work planned for 1.0.0 (hybrid ML-DSA). **The falling estimates are a reason
  not to let that slip**, and to settle the signature-size design early
  (see [Future crypto](FUTURE_CRYPTO.md)).
* **No new key is needed for storage.** The Argon2id-protected identity file
  and the AEAD are unaffected apart from Grover's halving.

**AI-assisted mathematics in general.** If tools like this can find proofs,
they may also find new attacks on primitives, faster than before. We cannot
predict that, so the defences are the ordinary ones: **hybrids** (two
independent assumptions), **conservative, standardized primitives**, a
**versioned handshake** so algorithms can be replaced (major and minor must
match, so a change is a deliberate bump), and **outside review**, which is
still the biggest item missing from this project.

## Out of scope

- A compromised device. If malware runs as you, it reads the same memory the
  app does.
- Denial of service by a determined network attacker (they can always drop
  packets). We cap sizes and counts so one peer cannot exhaust memory.
- Deciding whether your friend is who they say they are. That is the
  out-of-band step ([Identity and trust](IDENTITY_AND_TRUST.md)).

## Related

[Wire format](WIRE_FORMAT.md) · [Library vs app](LIBRARY_VS_APP.md) · [Future crypto](FUTURE_CRYPTO.md)
