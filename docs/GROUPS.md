# Groups: roster, tiers, type, governance

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

## In plain words

A group is a set of people who all talk to each other. With no server, someone
has to answer "who is in the group right now?" without anyone being able to
lie about it. The answer is the **roster**: a list of signed changes, each one
pointing at the hash of the one before it, like a tiny blockchain without the
coins. Anyone can check it; nobody can quietly rewrite it.

## How it works here

**Full mesh.** Every member keeps a direct [session](SESSIONS.md) with every
other member. A group of N people has N(N-1)/2 links. Simple and private (no
middleman sees anything), but it grows quadratically, so it suits small and
medium groups.

**Roster operations** (`group.rs`): `Genesis`, `Add`, `AddBot`, `Remove`,
`ChangeTier`, `DefineTier`. Each is signed by a current member with the right
permission and must build on the exact previous roster state. A forged
operation, or one that forks history, is rejected.

**Tiers and permissions.** A tier is a named bundle of four switches:
`can_add`, `can_remove`, `can_read`, `can_write`. Tiers are named per group
(for example "owner", "member", "lurker"), defined by `DefineTier`, and
assigned by `Add`/`ChangeTier`.

**`can_read` is real.** A member without read permission is excluded when we
*push* messages, and they are also refused when they *ask* (pull) for content.
This second check was a hole found in testing and fixed.

**Group type is fixed forever.** It is chosen at genesis and no operation
changes it. Today there is exactly one kind, `FullMesh`. A group that shrinks
to two people is still a group, with no special-casing of member count.

**Relay policy** is also chosen at genesis; see [Messages](MESSAGES.md).

**Removal.** A removed member's later messages are rejected by everyone who
has seen the removal. Their sessions are not yet torn down (see the plan).

## Options for how groups are encrypted

| Option | Idea | Good | Bad |
|---|---|---|---|
| **Full mesh of pairwise sessions** (**chosen for now**) | Send one copy per member, each through its own ratcheted session | Strongest per-pair properties (forward secrecy, healing); no shared key to leak; simple to reason about | O(N) sends per message and O(N²) links; not for huge groups |
| Sender keys (Signal groups, WhatsApp) | Each sender has one group key, shared once | One encryption per message | Weaker healing after compromise; rekey cost on removal; rejected here |
| Tree-based (**MLS** / TreeKEM) | Members form a key tree; updates cost O(log N) | Scales to large groups; standardised; strong healing | Needs a total order on membership changes, which a serverless design lacks; large dependency or large implementation |
| Server fan-out | A server forwards | Efficient | A server; metadata concentrated there |

We expect to move to the tree-based option later. Why we did not do it yet,
and what "commit ordering" means, is in [Future crypto](FUTURE_CRYPTO.md).

## Group tiers versus group types

These are different. *Tiers* are people-level permissions and change over a
group's life. *Type* is the structural kind of group and never changes.

## What the app handles

Names for groups and tiers in the UI, invitation flow, who gets which default
tier, and how to explain "you were removed". See
[Library vs app](LIBRARY_VS_APP.md).

## Related

[Messages](MESSAGES.md) · [Bots](BOTS.md) · [Ordering](ORDERING.md) ·
[Future crypto](FUTURE_CRYPTO.md) · [Sessions](SESSIONS.md)
