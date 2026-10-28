//! The mutual-authentication handshake.
//!
//! Goal: after this handshake completes, *both* peers know, with
//! cryptographic certainty:
//!
//! 1. They are talking to the specific peer whose public key they pinned
//!    (mutual authentication - not just "the server proved who it is" like
//!    plain TLS, but both sides prove it, since there is no
//!    client/server distinction in P2P).
//! 2. Nobody in the middle can read the traffic (confidentiality, via a
//!    fresh Diffie-Hellman secret).
//! 3. Nobody in the middle can tamper with *which* keys or *which protocol
//!    version* were used to set up the session, because the signature
//!    covers a transcript that includes both parties' ephemeral public keys
//!    *and* both parties' declared protocol versions (transcript binding).
//!    Without binding the version in, a man-in-the-middle could quietly
//!    rewrite the version fields to force a downgrade to a weaker (future)
//!    protocol version without either side noticing - this is exactly the
//!    kind of thing TLS version-downgrade attacks have historically
//!    exploited elsewhere, so we close it off from the start rather than
//!    bolting version negotiation on later.
//! 4. Even if a session key is somehow compromised later, past traffic
//!    stays safe, because the encryption key is derived from a *freshly
//!    generated, never-reused* ephemeral keypair (forward secrecy) - the
//!    long-term identity keys are only ever used to *sign*, never to
//!    encrypt.
//!
//! # Protocol versioning
//!
//! Both sides declare the protocol version they speak in `Msg1`/`Msg2`.
//! Right now there is only [`PROTOCOL_VERSION_CURRENT`], so negotiation
//! always settles on that - but the mechanism is real and forward-looking:
//! a future version bump can widen [`negotiate_version`] to pick the
//! highest version both sides support, and old and new binaries can still
//! interoperate (each falls back to the highest version they have in
//! common) instead of every client breaking the moment the wire format
//! changes.
//!
//! # Message flow
//!
//! ```text
//! Initiator                                   Responder
//! ----------                                   ---------
//! generate ephemeral keypair (e_i)
//! Msg1 = { version_i, idpub_i, epub_i } -------->
//!                                              generate ephemeral keypair (e_r)
//!                                              negotiate version_i vs version_r
//!                                              transcript = H(version_i || idpub_i || epub_i || version_r || idpub_r || epub_r)
//!                                              sig_r = Sign_r(transcript)
//!               <---- Msg2 = { version_r, idpub_r, epub_r, sig_r }
//! negotiate version_i vs version_r (must match responder's own negotiation)
//! verify idpub_r is pinned
//! verify sig_r over recomputed transcript
//! sig_i = Sign_i(transcript)
//! Msg3 = { sig_i } -------------------------->
//!                                              verify idpub_i is pinned
//!                                              verify sig_i over transcript
//! both sides: shared = X25519(e_i priv, e_r pub) == X25519(e_r priv, e_i pub)
//! both sides: (key_i2r, key_r2i) = HKDF(salt = transcript, ikm = shared)
//! ```
//!
//! Both peers reject the handshake outright if the other side's long-term
//! identity key isn't already in their [`crate::peer::PeerRegistry`] - see
//! that module for the trust model this relies on.
//!
//! # Observability
//!
//! Callers can pass an `on_progress` callback to watch the handshake
//! unfold step by step - e.g. a UI can show "connecting" -> "negotiated
//! protocol v1" -> "verifying peer..." -> "verified: <fingerprint>" instead
//! of a single opaque blocking call. See [`HandshakeProgress`].

use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};

use crate::crypto::AeadKey;
use crate::error::{ChatError, Result};
use crate::framing::{read_frame, write_frame};
use crate::identity::{fingerprint, Identity, PeerId, PeerRegistry};
use crate::ratchet::RatchetSeed;

/// The protocol version this build of the library speaks. Bump this (and
/// extend [`negotiate_version`]) whenever the wire format changes in a way
/// old peers can't parse.
pub const PROTOCOL_VERSION_CURRENT: u16 = 1;
/// The oldest protocol version this build is still willing to interoperate
/// with. Peers offering something older than this are rejected with
/// [`ChatError::UnsupportedVersion`] rather than silently misbehaving.
pub const PROTOCOL_VERSION_MIN: u16 = 1;

/// Step-by-step handshake progress, suitable for driving a UI's "connecting
/// / verifying peer" indicator without needing to know anything about the
/// underlying crypto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeProgress {
    /// The handshake has begun; our own version/keys are about to go out.
    Started,
    /// Both sides' declared protocol versions were compatible, and this is
    /// the version that will actually be used for the rest of the session.
    VersionNegotiated(u16),
    /// We've received the peer's claimed long-term identity - not yet
    /// verified, just "here is who they say they are".
    PeerIdentityClaimed(PeerId),
    /// The peer's claimed identity is in our pinned trust registry (see
    /// [`PeerRegistry`]) - but we haven't yet checked they actually hold
    /// the matching private key.
    PeerIdentityTrusted(PeerId),
    /// The peer's signature over the handshake transcript checked out:
    /// they've proven they hold the private key for their pinned identity.
    PeerSignatureVerified(PeerId),
    /// The handshake is fully complete: both sides authenticated, session
    /// keys derived.
    Completed { peer_id: PeerId, negotiated_version: u16 },
}

/// Optional sink for [`HandshakeProgress`] events. A no-op closure is fine
/// if a caller doesn't care.
pub type ProgressCallback<'a> = &'a mut dyn FnMut(HandshakeProgress);

fn emit(cb: &mut Option<ProgressCallback<'_>>, event: HandshakeProgress) {
    if let Some(f) = cb.as_mut() {
        f(event);
    }
}

/// Pick the protocol version to actually use, given what each side offered.
/// With only one version in existence today this trivially requires an
/// exact match - but this is the seam a future version 2 would extend
/// (e.g. "pick the highest value both sides list as supported") without
/// having to touch anything else in the handshake.
pub fn negotiate_version(ours: u16, theirs: u16) -> Result<u16> {
    if theirs < PROTOCOL_VERSION_MIN || ours < PROTOCOL_VERSION_MIN {
        return Err(ChatError::UnsupportedVersion);
    }
    if ours == theirs {
        Ok(ours)
    } else {
        // No older/newer negotiation table exists yet - once one is added,
        // this becomes `Ok(min(ours, theirs))` guarded by a compatibility
        // check instead of a hard equality requirement.
        Err(ChatError::UnsupportedVersion)
    }
}

/// Everything a completed handshake hands back to the caller.
pub struct HandshakeResult {
    /// Fingerprint of the peer we just authenticated.
    pub peer_id: PeerId,
    /// Key to use for *encrypting* messages we send.
    pub send_key: AeadKey,
    /// Key to use for *decrypting* messages we receive.
    pub recv_key: AeadKey,
    /// Hash of the full handshake transcript. Unique per-session; useful as
    /// a "session id" for logging or for out-of-band verification (peers
    /// could read this aloud to each other as an extra check, similar to a
    /// Signal safety number).
    pub transcript_hash: [u8; 32],
    /// The protocol version both sides ended up agreeing to use.
    pub negotiated_version: u16,
    /// Seed material for the Double Ratchet (see [`crate::ratchet`]).
    pub ratchet: RatchetSeed,
}

/// Build the transcript both sides sign: both declared protocol versions,
/// both long-term identity public keys, and both ephemeral public keys, in
/// a fixed (initiator-then-responder) order. Binding the versions in means
/// a MITM can't rewrite either side's declared version without breaking the
/// signature; binding all four keys in stops mixing-and-matching pieces
/// from different handshakes.
fn transcript(
    version_i: u16,
    idpub_i: &VerifyingKey,
    epub_i: &XPublicKey,
    version_r: u16,
    idpub_r: &VerifyingKey,
    epub_r: &XPublicKey,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"p2p-secure-chat/handshake-v1"); // domain separation
    hasher.update(version_i.to_be_bytes());
    hasher.update(idpub_i.as_bytes());
    hasher.update(epub_i.as_bytes());
    hasher.update(version_r.to_be_bytes());
    hasher.update(idpub_r.as_bytes());
    hasher.update(epub_r.as_bytes());
    hasher.finalize().into()
}

/// Derive the two per-direction traffic keys from the raw DH shared secret,
/// salted with the handshake transcript so keys are unique per session even
/// if (hypothetically) the same DH secret ever recurred.
fn derive_keys(shared_secret: &[u8; 32], transcript_hash: &[u8; 32]) -> (AeadKey, AeadKey) {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret);

    let mut key_i2r = [0u8; 32];
    hk.expand(b"initiator-to-responder", &mut key_i2r)
        .expect("32 bytes is a valid HKDF output length");

    let mut key_r2i = [0u8; 32];
    hk.expand(b"responder-to-initiator", &mut key_r2i)
        .expect("32 bytes is a valid HKDF output length");

    (AeadKey(key_i2r), AeadKey(key_r2i))
}

/// Run the handshake as the connection initiator (the side that opened the
/// TCP connection). Blocks on `stream` until the handshake either completes
/// or fails. Pass `on_progress` to observe each step (e.g. for a UI); pass
/// `None` if you don't need that.
pub fn run_initiator<S: Read + Write>(
    stream: &mut S,
    identity: &Identity,
    registry: &PeerRegistry,
    mut on_progress: Option<ProgressCallback<'_>>,
) -> Result<HandshakeResult> {
    emit(&mut on_progress, HandshakeProgress::Started);

    let idpub_i = identity.public_key();
    let esecret_i = EphemeralSecret::random_from_rng(OsRng);
    let epub_i = XPublicKey::from(&esecret_i);
    let version_i = PROTOCOL_VERSION_CURRENT;

    // --- Msg1: send our version, identity, and ephemeral public key ---
    let mut msg1 = Vec::with_capacity(66);
    msg1.extend_from_slice(&version_i.to_be_bytes());
    msg1.extend_from_slice(idpub_i.as_bytes());
    msg1.extend_from_slice(epub_i.as_bytes());
    write_frame(stream, &msg1)?;

    // --- Msg2: receive responder's version, identity, ephemeral key, signature ---
    let msg2 = read_frame(stream)?;
    if msg2.len() != 2 + 32 + 32 + 64 {
        return Err(ChatError::MalformedMessage("handshake msg2 has wrong length"));
    }
    let version_r = u16::from_be_bytes(msg2[0..2].try_into().unwrap());
    let idpub_r = parse_verifying_key(&msg2[2..34])?;
    let epub_r = parse_x_public(&msg2[34..66])?;
    let sig_r = Signature::from_slice(&msg2[66..130])
        .map_err(|_| ChatError::MalformedMessage("bad signature encoding"))?;

    let negotiated_version = negotiate_version(version_i, version_r)?;
    emit(&mut on_progress, HandshakeProgress::VersionNegotiated(negotiated_version));

    let claimed_peer_id = fingerprint(&idpub_r);
    emit(&mut on_progress, HandshakeProgress::PeerIdentityClaimed(claimed_peer_id.clone()));

    // Refuse to proceed if we don't already trust this identity key.
    let peer_id = registry.verify_trusted(&idpub_r)?;
    emit(&mut on_progress, HandshakeProgress::PeerIdentityTrusted(peer_id.clone()));

    // Verify the responder actually holds the private key for idpub_r by
    // checking their signature over the full transcript (which includes
    // both declared versions, so this also proves neither version field
    // was tampered with in transit).
    let t = transcript(version_i, &idpub_i, &epub_i, version_r, &idpub_r, &epub_r);
    PeerRegistry::verify_signature(&idpub_r, &t, &sig_r)?;
    emit(&mut on_progress, HandshakeProgress::PeerSignatureVerified(peer_id.clone()));

    // --- Msg3: prove *we* hold our own private key, over the same transcript ---
    let sig_i = identity.sign(&t);
    write_frame(stream, sig_i.to_bytes().as_slice())?;

    // --- Derive session keys ---
    let shared_secret = esecret_i.diffie_hellman(&epub_r);
    // Refuse a degenerate (low-order peer key) exchange: the "secret" would
    // be a known constant no matter what we contributed.
    if !shared_secret.was_contributory() {
        return Err(ChatError::InvalidPublicKey);
    }
    let (key_i2r, key_r2i) = derive_keys(shared_secret.as_bytes(), &t);
    let ratchet = RatchetSeed::for_initiator(shared_secret.as_bytes(), &t, epub_r.to_bytes());

    emit(&mut on_progress, HandshakeProgress::Completed { peer_id: peer_id.clone(), negotiated_version });

    Ok(HandshakeResult {
        peer_id,
        send_key: key_i2r, // we are the initiator: we send with i->r key
        recv_key: key_r2i, // and receive with r->i key
        transcript_hash: t,
        negotiated_version,
        ratchet,
    })
}

/// Run the handshake as the connection responder (the side that accepted an
/// incoming TCP connection).
pub fn run_responder<S: Read + Write>(
    stream: &mut S,
    identity: &Identity,
    registry: &PeerRegistry,
    mut on_progress: Option<ProgressCallback<'_>>,
) -> Result<HandshakeResult> {
    emit(&mut on_progress, HandshakeProgress::Started);

    // --- Msg1: receive initiator's version, identity, ephemeral key ---
    let msg1 = read_frame(stream)?;
    if msg1.len() != 2 + 32 + 32 {
        return Err(ChatError::MalformedMessage("handshake msg1 has wrong length"));
    }
    let version_i = u16::from_be_bytes(msg1[0..2].try_into().unwrap());
    let idpub_i = parse_verifying_key(&msg1[2..34])?;
    let epub_i = parse_x_public(&msg1[34..66])?;

    let version_r = PROTOCOL_VERSION_CURRENT;
    let negotiated_version = negotiate_version(version_r, version_i)?;
    emit(&mut on_progress, HandshakeProgress::VersionNegotiated(negotiated_version));

    let claimed_peer_id = fingerprint(&idpub_i);
    emit(&mut on_progress, HandshakeProgress::PeerIdentityClaimed(claimed_peer_id.clone()));

    // Refuse unknown peers before we do any expensive crypto or reveal
    // anything about ourselves beyond our own public key.
    let peer_id = registry.verify_trusted(&idpub_i)?;
    emit(&mut on_progress, HandshakeProgress::PeerIdentityTrusted(peer_id.clone()));

    let idpub_r = identity.public_key();
    let esecret_r = StaticSecret::random_from_rng(OsRng);
    let epub_r = XPublicKey::from(&esecret_r);

    let t = transcript(version_i, &idpub_i, &epub_i, version_r, &idpub_r, &epub_r);
    let sig_r = identity.sign(&t);

    // --- Msg2: send our version, identity, ephemeral key, and signature ---
    let mut msg2 = Vec::with_capacity(130);
    msg2.extend_from_slice(&version_r.to_be_bytes());
    msg2.extend_from_slice(idpub_r.as_bytes());
    msg2.extend_from_slice(epub_r.as_bytes());
    msg2.extend_from_slice(&sig_r.to_bytes());
    write_frame(stream, &msg2)?;

    // --- Msg3: receive initiator's proof of identity ---
    let msg3 = read_frame(stream)?;
    if msg3.len() != 64 {
        return Err(ChatError::MalformedMessage("handshake msg3 has wrong length"));
    }
    let sig_i = Signature::from_slice(&msg3)
        .map_err(|_| ChatError::MalformedMessage("bad signature encoding"))?;
    PeerRegistry::verify_signature(&idpub_i, &t, &sig_i)?;
    emit(&mut on_progress, HandshakeProgress::PeerSignatureVerified(peer_id.clone()));

    // --- Derive session keys ---
    let shared_secret = esecret_r.diffie_hellman(&epub_i);
    if !shared_secret.was_contributory() {
        return Err(ChatError::InvalidPublicKey);
    }
    let (key_i2r, key_r2i) = derive_keys(shared_secret.as_bytes(), &t);
    // Our handshake ephemeral doubles as the first ratchet key (like a
    // signed prekey in X3DH), which is what lets us speak first.
    let ratchet = RatchetSeed::for_responder(shared_secret.as_bytes(), &t, esecret_r.to_bytes());

    emit(&mut on_progress, HandshakeProgress::Completed { peer_id: peer_id.clone(), negotiated_version });

    Ok(HandshakeResult {
        peer_id,
        send_key: key_r2i, // we are the responder: we send with r->i key
        recv_key: key_i2r, // and receive with i->r key
        transcript_hash: t,
        negotiated_version,
        ratchet,
    })
}

fn parse_verifying_key(bytes: &[u8]) -> Result<VerifyingKey> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| ChatError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| ChatError::InvalidPublicKey)
}

fn parse_x_public(bytes: &[u8]) -> Result<XPublicKey> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| ChatError::InvalidPublicKey)?;
    Ok(XPublicKey::from(arr))
}

/// Convenience re-export so callers can pin peers using the same
/// fingerprint function the handshake itself uses internally.
pub fn peer_fingerprint(key: &VerifyingKey) -> PeerId {
    fingerprint(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_version_agrees_on_the_only_version_that_exists() {
        assert_eq!(negotiate_version(1, 1).unwrap(), 1);
    }

    #[test]
    fn negotiate_version_rejects_anything_below_the_minimum() {
        assert!(matches!(negotiate_version(1, 0), Err(ChatError::UnsupportedVersion)));
        assert!(matches!(negotiate_version(0, 1), Err(ChatError::UnsupportedVersion)));
    }

    #[test]
    fn negotiate_version_rejects_a_mismatch_above_the_minimum() {
        // Once a real version 2 exists this becomes a "picks the highest
        // mutually supported version" test instead of an equality check -
        // see the module docs on `negotiate_version`.
        assert!(matches!(negotiate_version(1, 2), Err(ChatError::UnsupportedVersion)));
    }
}
