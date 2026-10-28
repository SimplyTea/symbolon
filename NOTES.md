# Symbolon - roadmap notes (not the README)

Name: Greek *symbolon* (σύμβολον), a token split in two halves; each party kept one half and
matching the halves later proved who you were - i.e. pinned mutual verification.

**Legacy labels:** the on-wire domain-separation strings still read `p2p-secure-chat/...`
(handshake transcript, ratchet KDF labels). Renaming them changes the protocol, so builds
would stop interoperating. Do it at the first deliberate protocol bump (e.g. adding ML-KEM).
The default identity folder moved to `~/.symbolon`; an older `~/.p2pchat` is still honoured.

Working notes on what is deliberately NOT built yet. Newest decisions first.

## Post-quantum (decided: later, as an OPTION, not now)
Names, since they are easy to forget (all NIST-standardised, FIPS 203/204/205):
- **ML-KEM** (was "Kyber", FIPS 203): key exchange. Plan: HYBRID with X25519, i.e. mix the
  ML-KEM shared secret into the same HKDF as today's X25519 secret, so we are never weaker
  than classical. Protects against "record now, decrypt later".
- **ML-DSA** (was "Dilithium", FIPS 204): signatures. Replaces/augments Ed25519 identities,
  so authentication (not just confidentiality) survives a quantum attacker. Bigger keys/sigs.
- **SLH-DSA** (was "SPHINCS+", FIPS 205): hash-based signatures, conservative, large/slow.
- HQC: a second, code-based KEM NIST picked as a backup to ML-KEM (check current status).
Open questions: which pure-Rust crate (size, audit history, maintenance) given the
"no heavy crates" rule; ship behind a cargo feature flag; wire/protocol version bump.

## Next up
1. Heartbeat (encrypted ping on the control channel) + dead-peer detection + reconnect loop.
2. CLI group mode (needed for the cross-network group test).
3. Signed headers (header + content hash) -> existence notices, author-first fetch with
   relay fallback, delivered receipts / signed cursors, opt-in read receipts.
4. Persist ratchet + session state; derive the group-log key independently of the identity key.

## Known gaps
Argon2id instead of PBKDF2; key-committing AEAD for identity file; bounded outbox/message
store; permission snapshot at send time; bots via delegation certificates; multi-device
(device certificates, same idea as bots); compression (opt-in only, CRIME/BREACH-style
length leaks); NAT traversal / discovery (use Tailscale/WireGuard or port-forward meanwhile).
