# Future cryptography: post-quantum, MLS, sender keys

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

Three big ideas keep coming up. This page explains each from scratch, what we
decided, and what is still open.

## 1. Post-quantum (PQ)

**The problem.** A large quantum computer could break X25519 (key exchange) and
Ed25519 (signatures). Nobody has one today. But an attacker can **record
traffic now and decrypt it later** (*harvest-now-decrypt-later*). So the
*key exchange* is urgent; *signatures* are less so, because forging a
signature needs the computer at the time of the connection.

| Option | Good | Bad |
|---|---|---|
| Do nothing | Nothing to build | Recorded traffic becomes readable |
| PQ-only key exchange (ML-KEM alone) | Simple story | ML-KEM is newer; if a flaw is found you have nothing |
| **Hybrid: X25519 + ML-KEM-768 together** (**BUILT in 0.3.0**) | Safe if *either* holds; same approach as Signal and browsers | 2272 bytes extra per handshake (1184-byte key + 1088-byte ciphertext), once per connection; more code; a new wire format (minor bump) |
| Hybrid signatures too (Ed25519 + ML-DSA) | Protects identity from quantum forgery | Large keys and signatures (kilobytes); later |

**Plan.** Hybrid key exchange first (done), signatures later (1.0.0). Recent
reports of falling quantum resource estimates are a reason not to let the
signature work slip; see
[Number theory, Riemann and quantum algorithms](THREAT_MODEL.md#number-theory-riemann-and-quantum-algorithms)
for what does and does not affect us (the Riemann Hypothesis does not). Bundled with it: the
handshake oracle fix ([Handshake](HANDSHAKE_AND_VERSIONING.md)), since that
handshake gets redesigned anyway. Constraint: the implementation must stay a
small dependency, in keeping with the "library not framework" rule.

**Does it affect MLS?** Yes, in specific places: MLS key packages and the
tree's public keys would need PQ KEM equivalents, and its signature scheme
needs a PQ option. Standards work for PQ MLS is still moving. This is a
reason to decide MLS *after* PQ is settled, not before.

## 2. MLS (tree-based groups)

**What it is.** Messaging Layer Security is an IETF standard for group chat.
Members sit at leaves of a binary tree; each node has a key. When someone
joins, leaves or refreshes their key, only the keys on their path to the root
change: O(log N) work instead of O(N). It gives forward secrecy and
post-compromise healing for the *whole group*.

**What we have instead.** A [full mesh](GROUPS.md): N-1 separate ratcheted
sessions per member. Per-pair security is excellent, but cost grows with
group size.

**Why it is not built yet: commit ordering.** MLS changes are *commits*, and
every member must apply them in the *same order*. A server normally provides
that order. We have none. Options:

| Option | How | Good | Bad |
|---|---|---|---|
| **Owner-ordered** (**recommended**) | One designated member (or small set of owners) sequences commits | Simple, deterministic | Owner offline means no membership changes; owner is a trusted ordering point |
| Epoch with retry | Anyone may commit; conflicting commits at the same epoch are resolved by a rule (e.g. smallest hash wins) and losers re-apply | No single owner | Complex; members may briefly diverge; needs careful testing |
| Consensus | Members vote | No single point | Heavy; stalls without quorum |

This decision is **still open**; we lean owner-ordered. Other costs: a
well-reviewed MLS crate is a large dependency, writing our own is a large risk,
and the tree needs saved state like sessions do.

## 3. Sender keys (rejected)

**What it is.** Used by Signal groups and WhatsApp. Each sender makes one key
and gives it to every member once; afterwards a message is encrypted *once*
for everyone.

**Why we declined.**

- Cheaper to send, but weaker healing: if a sender key leaks, everything that
  sender writes stays readable until that sender rotates, and each removal
  forces every sender to rotate.
- We already get strong guarantees from pairwise ratchets; sender keys would
  *reduce* security to save computation, and the tree-based option gets the
  computational savings without that loss.

## Order of work

1. Hybrid PQ handshake and oracle fix.
2. Decide commit ordering.
3. Tree-based groups (MLS or an MLS-shaped design).
4. PQ signatures.

Each step changes a wire format and therefore bumps the minor version.

## Related

[Groups](GROUPS.md) · [Handshake](HANDSHAKE_AND_VERSIONING.md) ·
[Threat model](THREAT_MODEL.md) · [Plan](PLAN.md)
