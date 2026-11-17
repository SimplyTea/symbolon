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
//! The protocol version IS the crate's `major.minor.patch` ([`Version`]);
//! see [`negotiate_version`] for the compatibility rule. (Older text below
//! about "only one version" predates this and is superseded.)
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
//! Msg1 = { version_i, idpub_i, epub_i, epoch_i } -------->
//!                                              generate ephemeral keypair (e_r)
//!                                              negotiate version_i vs version_r
//!                                              transcript = H(version_i || idpub_i || epub_i || epoch_i || version_r || idpub_r || epub_r || epoch_r)
//!                                              sig_r = Sign_r(transcript)
//!               <---- Msg2 = { version_r, idpub_r, epub_r, epoch_r, sig_r }
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

/// A `major.minor.patch` version. The crate version IS the protocol version:
/// there is no separate protocol number to forget to bump.
///
/// Compatibility rule (see [`negotiate_version`]): two builds interoperate
/// when their MAJOR and MINOR match; the PATCH may differ. So any change to a
/// wire or signed format must bump major or minor (while the crate is 0.x,
/// bump minor); a patch bump promises "no wire change".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl Version {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Version {
        Version {
            major,
            minor,
            patch,
        }
    }

    /// Wire form: three big-endian u16s (6 bytes).
    pub fn to_bytes(self) -> [u8; 6] {
        let mut out = [0u8; 6];
        out[0..2].copy_from_slice(&self.major.to_be_bytes());
        out[2..4].copy_from_slice(&self.minor.to_be_bytes());
        out[4..6].copy_from_slice(&self.patch.to_be_bytes());
        out
    }

    /// Inverse of [`Version::to_bytes`]; `bytes` must be exactly 6 long.
    fn from_bytes(bytes: &[u8]) -> Version {
        Version {
            major: u16::from_be_bytes(bytes[0..2].try_into().unwrap()),
            minor: u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
            patch: u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Parse a decimal number at compile time (used to read Cargo's version).
const fn parse_u16(s: &str) -> u16 {
    let b = s.as_bytes();
    assert!(!b.is_empty(), "empty version component");
    let mut i = 0;
    let mut n: u32 = 0;
    while i < b.len() {
        assert!(b[i].is_ascii_digit(), "non-numeric version component");
        n = n * 10 + (b[i] - b'0') as u32;
        assert!(n <= u16::MAX as u32, "version component too large");
        i += 1;
    }
    n as u16
}

/// The version this build speaks: taken from `Cargo.toml` at compile time,
/// so the crate version and the protocol version cannot drift apart.
pub const PROTOCOL_VERSION_CURRENT: Version = Version::new(
    parse_u16(env!("CARGO_PKG_VERSION_MAJOR")),
    parse_u16(env!("CARGO_PKG_VERSION_MINOR")),
    parse_u16(env!("CARGO_PKG_VERSION_PATCH")),
);

/// Step-by-step handshake progress, suitable for driving a UI's "connecting
/// / verifying peer" indicator without needing to know anything about the
/// underlying crypto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeProgress {
    /// The handshake has begun; our own version/keys are about to go out.
    Started,
    /// Both sides' declared protocol versions were compatible, and this is
    /// the version that will actually be used for the rest of the session.
    VersionNegotiated(Version),
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
    Completed {
        peer_id: PeerId,
        negotiated_version: Version,
    },
}

/// Optional sink for [`HandshakeProgress`] events. A no-op closure is fine
/// if a caller doesn't care.
pub type ProgressCallback<'a> = &'a mut dyn FnMut(HandshakeProgress);

fn emit(cb: &mut Option<ProgressCallback<'_>>, event: HandshakeProgress) {
    if let Some(f) = cb.as_mut() {
        f(event);
    }
}

/// Decide whether two builds can talk, and which version the session uses.
///
/// * MAJOR and MINOR must be equal, otherwise [`ChatError::VersionMismatch`]
///   (it names both versions so the mismatch is obvious).
/// * PATCH may differ; the session is labelled with the LOWER of the two.
///
/// Both versions are bound into the signed handshake transcript, so a
/// man-in-the-middle cannot rewrite them.
pub fn negotiate_version(ours: Version, theirs: Version) -> Result<Version> {
    if ours.major != theirs.major || ours.minor != theirs.minor {
        return Err(ChatError::VersionMismatch { ours, theirs });
    }
    Ok(ours.min(theirs))
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
    pub negotiated_version: Version,
    /// Seed material for the Double Ratchet (see [`crate::ratchet`]).
    pub ratchet: RatchetSeed,
    /// The peer's SESSION EPOCH: a random 16-byte value that identifies the
    /// peer's session STATE (ratchet, outbox, inbox). It stays the same
    /// across that session's reconnects and changes whenever the peer
    /// creates a brand-new session (e.g. after an app restart). Comparing it
    /// with the epoch recorded earlier tells us whether the peer can still
    /// resume our old session or has lost its state. Bound into the signed
    /// transcript, so it cannot be altered in transit.
    pub peer_epoch: [u8; 16],
    /// The epoch WE presented in this handshake.
    pub own_epoch: [u8; 16],
}

/// Build the transcript both sides sign: both declared protocol versions,
/// both long-term identity public keys, and both ephemeral public keys, in
/// a fixed (initiator-then-responder) order. Binding the versions in means
/// a MITM can't rewrite either side's declared version without breaking the
/// signature; binding all four keys in stops mixing-and-matching pieces
/// from different handshakes.
#[allow(clippy::too_many_arguments)]
fn transcript(
    version_i: Version,
    idpub_i: &VerifyingKey,
    epub_i: &XPublicKey,
    epoch_i: &[u8; 16],
    version_r: Version,
    idpub_r: &VerifyingKey,
    epub_r: &XPublicKey,
    epoch_r: &[u8; 16],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"symbolon/handshake/v2"); // domain separation
    hasher.update(version_i.to_bytes());
    hasher.update(idpub_i.as_bytes());
    hasher.update(epub_i.as_bytes());
    hasher.update(epoch_i);
    hasher.update(version_r.to_bytes());
    hasher.update(idpub_r.as_bytes());
    hasher.update(epub_r.as_bytes());
    hasher.update(epoch_r);
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
    own_epoch: &[u8; 16],
    on_progress: Option<ProgressCallback<'_>>,
) -> Result<HandshakeResult> {
    run_initiator_as(
        PROTOCOL_VERSION_CURRENT,
        stream,
        identity,
        registry,
        own_epoch,
        on_progress,
    )
}

/// Like [`run_initiator`] but speaking an explicit version (for tests of
/// version negotiation; applications call [`run_initiator`]).
#[doc(hidden)]
pub fn run_initiator_as<S: Read + Write>(
    our_version: Version,
    stream: &mut S,
    identity: &Identity,
    registry: &PeerRegistry,
    own_epoch: &[u8; 16],
    mut on_progress: Option<ProgressCallback<'_>>,
) -> Result<HandshakeResult> {
    emit(&mut on_progress, HandshakeProgress::Started);

    let idpub_i = identity.public_key();
    let esecret_i = EphemeralSecret::random_from_rng(OsRng);
    let epub_i = XPublicKey::from(&esecret_i);
    let version_i = our_version;

    // --- Msg1: send our version, identity, and ephemeral public key ---
    let mut msg1 = Vec::with_capacity(86);
    msg1.extend_from_slice(&version_i.to_bytes());
    msg1.extend_from_slice(idpub_i.as_bytes());
    msg1.extend_from_slice(epub_i.as_bytes());
    msg1.extend_from_slice(own_epoch);
    write_frame(stream, &msg1)?;

    // --- Msg2: receive responder's version, identity, ephemeral key, signature ---
    let msg2 = read_frame(stream)?;
    if msg2.len() != 6 + 32 + 32 + 16 + 64 {
        return Err(ChatError::MalformedMessage(
            "handshake msg2 has wrong length",
        ));
    }
    let version_r = Version::from_bytes(&msg2[0..6]);
    let idpub_r = parse_verifying_key(&msg2[6..38])?;
    let epub_r = parse_x_public(&msg2[38..70])?;
    let epoch_r: [u8; 16] = msg2[70..86].try_into().unwrap();
    let sig_r = Signature::from_slice(&msg2[86..150])
        .map_err(|_| ChatError::MalformedMessage("bad signature encoding"))?;

    let negotiated_version = negotiate_version(version_i, version_r)?;
    emit(
        &mut on_progress,
        HandshakeProgress::VersionNegotiated(negotiated_version),
    );

    let claimed_peer_id = fingerprint(&idpub_r);
    emit(
        &mut on_progress,
        HandshakeProgress::PeerIdentityClaimed(claimed_peer_id.clone()),
    );

    // Refuse to proceed if we don't already trust this identity key.
    let peer_id = registry.verify_trusted(&idpub_r)?;
    emit(
        &mut on_progress,
        HandshakeProgress::PeerIdentityTrusted(peer_id.clone()),
    );

    // Verify the responder actually holds the private key for idpub_r by
    // checking their signature over the full transcript (which includes
    // both declared versions, so this also proves neither version field
    // was tampered with in transit).
    let t = transcript(
        version_i, &idpub_i, &epub_i, own_epoch, version_r, &idpub_r, &epub_r, &epoch_r,
    );
    PeerRegistry::verify_signature(&idpub_r, &t, &sig_r)?;
    emit(
        &mut on_progress,
        HandshakeProgress::PeerSignatureVerified(peer_id.clone()),
    );

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

    emit(
        &mut on_progress,
        HandshakeProgress::Completed {
            peer_id: peer_id.clone(),
            negotiated_version,
        },
    );

    Ok(HandshakeResult {
        peer_id,
        send_key: key_i2r, // we are the initiator: we send with i->r key
        recv_key: key_r2i, // and receive with r->i key
        transcript_hash: t,
        negotiated_version,
        ratchet,
        peer_epoch: epoch_r,
        own_epoch: *own_epoch,
    })
}

/// Run the handshake as the connection responder (the side that accepted an
/// incoming TCP connection).
pub fn run_responder<S: Read + Write>(
    stream: &mut S,
    identity: &Identity,
    registry: &PeerRegistry,
    own_epoch_for: &dyn Fn(&PeerId) -> [u8; 16],
    on_progress: Option<ProgressCallback<'_>>,
) -> Result<HandshakeResult> {
    run_responder_as(
        PROTOCOL_VERSION_CURRENT,
        stream,
        identity,
        registry,
        own_epoch_for,
        on_progress,
    )
}

/// Like [`run_responder`] but speaking an explicit version (for tests of
/// version negotiation; applications call [`run_responder`]).
#[doc(hidden)]
pub fn run_responder_as<S: Read + Write>(
    our_version: Version,
    stream: &mut S,
    identity: &Identity,
    registry: &PeerRegistry,
    own_epoch_for: &dyn Fn(&PeerId) -> [u8; 16],
    mut on_progress: Option<ProgressCallback<'_>>,
) -> Result<HandshakeResult> {
    emit(&mut on_progress, HandshakeProgress::Started);

    // --- Msg1: receive initiator's version, identity, ephemeral key ---
    let msg1 = read_frame(stream)?;
    if msg1.len() != 6 + 32 + 32 + 16 {
        return Err(ChatError::MalformedMessage(
            "handshake msg1 has wrong length",
        ));
    }
    let version_i = Version::from_bytes(&msg1[0..6]);
    let idpub_i = parse_verifying_key(&msg1[6..38])?;
    let epub_i = parse_x_public(&msg1[38..70])?;
    let epoch_i: [u8; 16] = msg1[70..86].try_into().unwrap();

    let version_r = our_version;
    let negotiated_version = negotiate_version(version_r, version_i)?;
    emit(
        &mut on_progress,
        HandshakeProgress::VersionNegotiated(negotiated_version),
    );

    let claimed_peer_id = fingerprint(&idpub_i);
    emit(
        &mut on_progress,
        HandshakeProgress::PeerIdentityClaimed(claimed_peer_id.clone()),
    );

    // Refuse unknown peers before we do any expensive crypto or reveal
    // anything about ourselves beyond our own public key.
    let peer_id = registry.verify_trusted(&idpub_i)?;
    emit(
        &mut on_progress,
        HandshakeProgress::PeerIdentityTrusted(peer_id.clone()),
    );

    // Only now (the initiator is trusted) do we choose our epoch: a resumed
    // session must present the epoch it was saved with, which depends on
    // WHO is calling.
    let own_epoch_value = own_epoch_for(&peer_id);
    let own_epoch = &own_epoch_value;

    let idpub_r = identity.public_key();
    let esecret_r = StaticSecret::random_from_rng(OsRng);
    let epub_r = XPublicKey::from(&esecret_r);

    let t = transcript(
        version_i, &idpub_i, &epub_i, &epoch_i, version_r, &idpub_r, &epub_r, own_epoch,
    );
    let sig_r = identity.sign(&t);

    // --- Msg2: send our version, identity, ephemeral key, and signature ---
    let mut msg2 = Vec::with_capacity(150);
    msg2.extend_from_slice(&version_r.to_bytes());
    msg2.extend_from_slice(idpub_r.as_bytes());
    msg2.extend_from_slice(epub_r.as_bytes());
    msg2.extend_from_slice(own_epoch);
    msg2.extend_from_slice(&sig_r.to_bytes());
    write_frame(stream, &msg2)?;

    // --- Msg3: receive initiator's proof of identity ---
    let msg3 = read_frame(stream)?;
    if msg3.len() != 64 {
        return Err(ChatError::MalformedMessage(
            "handshake msg3 has wrong length",
        ));
    }
    let sig_i = Signature::from_slice(&msg3)
        .map_err(|_| ChatError::MalformedMessage("bad signature encoding"))?;
    PeerRegistry::verify_signature(&idpub_i, &t, &sig_i)?;
    emit(
        &mut on_progress,
        HandshakeProgress::PeerSignatureVerified(peer_id.clone()),
    );

    // --- Derive session keys ---
    let shared_secret = esecret_r.diffie_hellman(&epub_i);
    if !shared_secret.was_contributory() {
        return Err(ChatError::InvalidPublicKey);
    }
    let (key_i2r, key_r2i) = derive_keys(shared_secret.as_bytes(), &t);
    // Our handshake ephemeral doubles as the first ratchet key (like a
    // signed prekey in X3DH), which is what lets us speak first.
    let ratchet = RatchetSeed::for_responder(shared_secret.as_bytes(), &t, esecret_r.to_bytes());

    emit(
        &mut on_progress,
        HandshakeProgress::Completed {
            peer_id: peer_id.clone(),
            negotiated_version,
        },
    );

    Ok(HandshakeResult {
        peer_id,
        send_key: key_r2i, // we are the responder: we send with r->i key
        recv_key: key_i2r, // and receive with i->r key
        transcript_hash: t,
        negotiated_version,
        ratchet,
        peer_epoch: epoch_i,
        own_epoch: *own_epoch,
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

    fn v(a: u16, b: u16, c: u16) -> Version {
        Version::new(a, b, c)
    }

    #[test]
    fn current_version_is_the_crate_version() {
        assert_eq!(
            PROTOCOL_VERSION_CURRENT.to_string(),
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn version_round_trips_on_the_wire() {
        let x = v(1, 2, 65535);
        assert_eq!(Version::from_bytes(&x.to_bytes()), x);
    }

    #[test]
    fn same_version_agrees() {
        assert_eq!(
            negotiate_version(v(0, 1, 0), v(0, 1, 0)).unwrap(),
            v(0, 1, 0)
        );
    }

    #[test]
    fn patch_difference_connects_at_the_lower_patch() {
        assert_eq!(
            negotiate_version(v(0, 1, 3), v(0, 1, 2)).unwrap(),
            v(0, 1, 2)
        );
        assert_eq!(
            negotiate_version(v(0, 1, 2), v(0, 1, 3)).unwrap(),
            v(0, 1, 2)
        );
    }

    #[test]
    fn minor_or_major_difference_is_refused_and_names_both() {
        for (a, b) in [
            (v(0, 1, 0), v(0, 2, 0)),
            (v(1, 0, 0), v(2, 0, 0)),
            (v(1, 4, 0), v(1, 3, 9)),
        ] {
            match negotiate_version(a, b) {
                Err(ChatError::VersionMismatch { ours, theirs }) => {
                    assert_eq!((ours, theirs), (a, b));
                }
                other => panic!("expected VersionMismatch, got {other:?}"),
            }
        }
    }

    /// Run a full handshake between two builds claiming the given versions.
    fn handshake_between(
        vi: Version,
        vr: Version,
    ) -> (Result<HandshakeResult>, Result<HandshakeResult>) {
        use crate::transport::memory_pair;
        use crate::transport::Connection;
        let (mut a, mut b) = memory_pair(std::time::Duration::ZERO);
        // A responder that refuses stays silent, so bound the initiator's wait.
        a.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        b.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let (alice, bob) = (Identity::generate(), Identity::generate());
        let mut reg_a = PeerRegistry::new();
        reg_a.trust(bob.public_key());
        let mut reg_b = PeerRegistry::new();
        reg_b.trust(alice.public_key());
        let t = std::thread::spawn(move || {
            run_responder_as(vr, &mut b, &bob, &reg_b, &|_| [2u8; 16], None)
        });
        let ri = run_initiator_as(vi, &mut a, &alice, &reg_a, &[1u8; 16], None);
        // Close our end so a responder that bailed early is not waited on.
        drop(a);
        (ri, t.join().unwrap())
    }

    #[test]
    fn handshake_connects_across_a_patch_difference() {
        let (ri, rr) = handshake_between(v(0, 1, 3), v(0, 1, 2));
        let (ri, rr) = (ri.unwrap(), rr.unwrap());
        assert_eq!(ri.negotiated_version, v(0, 1, 2));
        assert_eq!(rr.negotiated_version, v(0, 1, 2));
        assert_eq!(ri.transcript_hash, rr.transcript_hash);
    }

    #[test]
    fn handshake_refuses_a_minor_difference_on_both_sides() {
        let (ri, rr) = handshake_between(v(0, 1, 0), v(0, 2, 0));
        assert!(rr.is_err(), "the responder must refuse");
        // The responder stays silent (no reply to an unproven caller), so the
        // initiator sees a failed read, not a version message.
        assert!(ri.is_err());
        assert!(matches!(
            rr,
            Err(ChatError::VersionMismatch { ours, theirs }) if ours == v(0, 2, 0) && theirs == v(0, 1, 0)
        ));
    }
}
