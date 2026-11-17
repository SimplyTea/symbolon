# Bots

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

## In plain words

A bot is a group member that a program runs rather than a person. Because a
program can misbehave, the group treats it with limits and honest labelling.

## How it works here

- A bot has its **own Ed25519 key**, its own sessions and its own
  [author chain](MESSAGES.md), like anyone else. Nothing about the wire is
  special.
- It is added with `AddBot`. Its kind (`Person` or `Bot`) is fixed at that
  moment; no operation converts one into the other, so a bot can never pose as
  a person.
- A bot may only hold tiers that grant neither `can_add` nor `can_remove`
  ("bot-safe" tiers), so it can never recruit, remove or re-tier anyone.
- A bot has a **sponsor**, the member who added it. If the sponsor leaves or is
  removed, the bot is removed in the same roster step on every node.

## Options for adding bots

| Option | Good | Bad |
|---|---|---|
| Bot is just a normal member | No new code | Can be given admin powers; indistinguishable from people; abandoned bots linger |
| **Delegated key with sponsor cascade and bot-safe tiers** (**chosen**) | Honest labels; bounded power; cleans up after itself | One more roster concept; the sponsor is a single point of removal |
| Bots run inside the library (plug-in code) | Convenient | Runs untrusted code in the security boundary; rejected |
| Shared group "bot key" | Easy | Everyone can impersonate the bot; no per-bot revoke |

## Scripting

The command-line tool can run a bot that reads and writes simple tab-separated
lines over stdin/stdout, so any language can drive it. `scripts/echo_bot.py`
is a worked example (answers `!ping` and `!echo`). Deliberately there is **no
"execute this command" feature**: message text is untrusted input, and a
chat-triggered shell would be remote code execution. A script must decide for
itself what a message means.

## Library vs app

Library: bot membership rules and the sponsor cascade. App (or script): what
the bot does, rate limits, how a UI badges bots, and whether to show a
sponsor's name. See [Library vs app](LIBRARY_VS_APP.md).

## Related

[Groups](GROUPS.md) · [Messages](MESSAGES.md) · [Threat model](THREAT_MODEL.md)
