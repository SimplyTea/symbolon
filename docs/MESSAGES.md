# Messages in a group: chains, relaying, receipts, forwarding

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

## 1. Author chains: detecting a lying sender

In a [full mesh](GROUPS.md) every message is sent separately to each member.
Encryption alone cannot stop a malicious author telling Alice "message 7 is
*yes*" and Bob "message 7 is *no*" (**equivocation**), because each copy is
validly encrypted.

So each author keeps a **hash chain**. Every message carries a signed header:
sender, sequence number, hash of the previous message, the roster version it
was written under, and a hash of the content. Members compare chain tips; two
different "message 7"s cannot both fit one chain, and the signatures prove who
lied. Messages that arrive ahead of a missing one are held (up to 1000) until
the gap fills.

Content kinds: `Post`, `Edit` (refers to an earlier seq), `Delete` (same). An
edit or delete is itself a new chain entry, so history stays verifiable.

| Option | Good | Bad |
|---|---|---|
| Nothing (trust the sender) | Free | Silent equivocation possible |
| **Per-author signed hash chain** (**chosen**) | Detects equivocation and reordering by the author; cheap | `#seq` is per author, not group-wide (see [Ordering](ORDERING.md)) |
| One group-wide chain / consensus | One order for all | Needs agreement among members; heavy without a server |

## 2. Relaying: getting a message you missed

A member can miss a message because they were offline, or because they have no
direct link to the author. They can ask others (`RelayRequest`) or the author
(`FetchRequest`). Each member keeps a **relay cache** (default 256 messages per
sender) to answer.

Who is allowed to serve content is the group's **relay policy**, fixed at
genesis:

| Policy | Meaning | Good | Bad |
|---|---|---|---|
| **Open** | Any holder may serve a message | Works when the author is offline | A member can pass content on that the author might not have wanted spread |
| **AuthorOnly** | Only the author serves content; others serve an **existence notice** ("seq N exists") | Author controls distribution | Content is unavailable while the author is offline |

Serving order is author first, then fall back to other holders. On the
receiving side an app setting, `RelayedContent::Deliver` or `ExistenceOnly`,
chooses whether content that came via someone other than its author is shown.
`GroupHub::relayed_by` tells the app who relayed it, so it can show a warning.
Both ends check `can_read` before serving.

## 3. Forwarding: how everyone learns a message exists

Problem: a post reaches only the members directly connected to its author. A
member with no link to the author would otherwise never hear of it until they
asked. Options we weighed:

| Option | Good | Bad |
|---|---|---|
| Periodic catch-up timer | Trivial | Polls forever; noisy; hides real bugs (removed as default; `--catchup` remains an opt-in safety net in the CLI) |
| Flood-forward full messages | Fast | O(N²) copies; leaks content to people who should only get existence notices |
| Link-state hints ("who is connected to whom") | Efficient routing | Tells every member the group's connection graph, which is metadata |
| **Announce-and-request (`Have`)** (**chosen**) | After accepting a message, tell other readers "I have (author, seq)"; whoever lacks it asks once | Tiny messages; honours relay policy; no extra copies in a full mesh; a hop-by-hop spread | One extra round trip; needs a request limit (one per author per 300 ms, with one follow-up so the last announcement is never lost) |

Privacy by construction: a `Have` travels only over sessions attached to **this
group**, only to members who currently hold `can_read`, and says nothing about
links, other groups or one-to-one chats. Duplicates are dropped before they can
loop. How other systems do it, as far as we know: Signal and Matrix use
servers; Briar syncs per shared group with contacts only; Secure Scuttlebutt
gossips whole feeds, which exposes who follows whom; libp2p gossip exposes
topic subscriptions.

**Duplicates.** The same message can legitimately arrive twice (straight from
its author and again via a `Have`-prompted fetch). An identical second copy is
ignored quietly (trace event `GroupMessageDuplicate`). A *different* message
under a sequence number we already hold is the author signing two versions,
and is rejected loudly. See [Threat model](THREAT_MODEL.md).

## 4. Receipts

A **receipt** is a signed statement "I received (author, seq)". *Delivery*
receipts are on by default; *read* receipts are opt-in per member. They are
signed so they cannot be forged, and sent only to a currently connected
author. If the author is offline the receipt is not queued yet (see
[Plan](PLAN.md)).

| Option | Good | Bad |
|---|---|---|
| No receipts | Most private | Sender never knows |
| **Delivery on, read opt-in** (**chosen**) | Useful default, privacy respected | Delivery still tells the author when you were online |
| Read receipts on by default | Convenient for senders | Pressure and a presence leak |

## Library vs app

Library: chain checks, relay and forward rules, receipts. App: whether to show
relayed content, how to display "delivered/read", how to render an edit or a
deleted message, and whether to show per-author or merged history. See
[Library vs app](LIBRARY_VS_APP.md).

## Related

[Wire format](WIRE_FORMAT.md) · [Groups](GROUPS.md) · [Ordering](ORDERING.md) ·
[Bots](BOTS.md) · [Threat model](THREAT_MODEL.md)
