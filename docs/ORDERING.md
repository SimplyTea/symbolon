# Ordering: what "the order of messages" means without a server

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

## In plain words

In a chat app with a server, the server stamps messages and everyone sees the
same order. Here nobody is in charge, so there is no single "true" order.
Two people can type at the same moment and each sees their own message first.

## What we have today

- Each author's messages are strictly ordered by their own sequence number
  (`#seq`, [author chain](MESSAGES.md)). That order is verified and
  tamper-evident.
- There is **no group-wide sequence number** and **no trusted timestamp**.
  `/history` in the CLI therefore lists messages grouped by author, authors
  sorted by fingerprint, each author's messages in their own order.
- An app that wants one merged timeline can use its **local arrival order**.
  That differs from node to node, which is acceptable for display but can make
  "what was this a reply to?" confusing after reconnecting.

## Options for a group-wide order

| Option | How | Good | Bad |
|---|---|---|---|
| **Per-author order only** (**today**) | Nothing extra | Simple, verifiable, no new wire format | No shared timeline; replies are hard to anchor |
| Local arrival order | App sorts by when it received | Zero protocol cost | Different on every device; changes after reconnect |
| Sender wall-clock timestamps | Sender writes the time | Familiar | Clocks lie; a malicious member can backdate; unverifiable |
| **Lamport clock** | Each message carries `max(seen)+1` | Consistent causal order; tiny | Shows "happened-after" not real time; ties need a rule; a liar can inflate it; harder to explain and verify |
| **Cross-linked hash chains (a DAG)** | Each message names the latest message it has seen from *each* member | Cryptographically proves "I had seen X when I wrote this"; solves reply anchoring; tamper-evident | Headers grow with group size; more complex verification; messages must wait for their dependencies |
| Consensus / total order | Members agree on one order | One timeline | Needs a leader or voting; heavy and fragile when members are offline |

## What we decided

**Shelved, not rejected.** We discussed the Lamport clock and a cross-linked
design and decided the added complexity did not feel right yet. Today's
per-author chains are enough for correctness. A merged order is a **display**
problem the app can solve for now with local arrival order.

A likely future shape if a shared order is wanted: a **reply-to** field that
names (author, seq) of the message being answered. That anchors a reply
without any global clock, because the reference is to a verified chain entry.
Reply-to "sounds alright" but is not built.

## Related ideas, parked

- **Typing indicator.** An ephemeral "X is typing" signal. This is chiefly an
  app concern (when to show it, how long it lasts); the library would at most
  provide a lightweight non-stored channel. Idea only; to be discussed with
  prospective users since some people dislike being observed typing.

## Library vs app

Library: per-author order and integrity. App: the merged timeline, reply
display, typing, and any "sorted by" setting. See
[Library vs app](LIBRARY_VS_APP.md).

## Related

[Messages](MESSAGES.md) · [Groups](GROUPS.md) · [Plan](PLAN.md)
