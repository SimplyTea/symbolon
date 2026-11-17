# Discovery: finding peers on a network

*Part of the Symbolon docs. See the [Glossary](GLOSSARY.md) for terms.*

## In plain words

Before you can connect, you must know an address. On a home network, nodes can
shout "I'm here" and others can listen. That is discovery. It is helpful and
also a privacy cost, so it is **off unless you turn it on**.

## How it works here

`discovery.rs` sends a small UDP broadcast (magic `SYMD`, default port 47474)
containing a display name (up to 32 characters) and the **major** version.
Minor and patch versions are **separate opt-ins**, so by default you reveal as
little as possible about your software.

Important: a discovery packet is an **unauthenticated hint**. Anyone can forge
one. It only says "something claiming this name is at this address". Trust
always comes from the [handshake](HANDSHAKE_AND_VERSIONING.md) afterwards,
never from the hint.

| Option | Good | Bad |
|---|---|---|
| No discovery; type addresses | Reveals nothing | Poor usability |
| **Opt-in LAN broadcast** (**chosen**) | Easy on a local network | Anyone on the LAN sees your name and that you run the software; spoofable |
| mDNS / DNS-SD | Standard | Adds a dependency; similar exposure |
| DHT or rendezvous server | Works across the internet | Needs infrastructure or reveals lookups to it; large attack surface |
| Authenticated discovery (sign with identity) | Cannot be spoofed | Reveals your public key to the whole LAN, which links your name to your identity |

## Not covered

Crossing NATs and the internet (hole punching, relays, DHTs) is an **app**
decision, since each choice has its own privacy costs. The `Connection` trait
([Storage and plug-ins](STORAGE_AND_PLUGINS.md)) is where an app plugs in
another way of reaching peers. See [Library vs app](LIBRARY_VS_APP.md).

## Related

[Threat model](THREAT_MODEL.md) · [Plan](PLAN.md)
