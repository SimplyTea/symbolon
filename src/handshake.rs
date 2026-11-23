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
//! # Message flow (five frames, hybrid post-quantum)
//!
//! The key exchange is a HYBRID: classical X25519 plus the post-quantum
//! ML-KEM-768 (FIPS 203). Both shared secrets are fed into one key
//! derivation, so an attacker must break BOTH to read a session. A recorded
//! conversation therefore stays unreadable even if a quantum computer
//! later breaks X25519 ("harvest now, decrypt later").
//!
//! ```text
//! Initiator                                    Responder
//! ----------                                   ---------
//! X25519 ephemeral e_i, ML-KEM keypair (dk, ek)
//! Msg1 = epub_i || ek  (32 + 1184 bytes) ----->
//!                                              X25519 ephemeral e_r
//!                                              (ct, ss_pq) = Encapsulate(ek)
//!                                              ss_x = X25519(e_r, epub_i)
//!               <----- Msg2 = epub_r || ct  (32 + 1088 bytes)
//! ss_pq = Decapsulate(dk, ct)
//! ss_x  = X25519(e_i, epub_r)
//! both: eph      = H(Msg1 || Msg2)
//! both: combined = HKDF(salt = eph, ikm = ss_pq || ss_x)
//! both: handshake keys = HKDF(combined)   (protect Msg3 and Msg4)
//!
//! Msg3 (encrypted) = { version, idpub_i, epoch_i, sig_i over eph + own fields } ->
//!                                              verify sig_i, then check idpub_i is pinned
//!                                              (an unpinned caller gets NO reply)
//!               <----- Msg4 (encrypted) = { version, idpub_r, epoch_r, sig_r over the full transcript }
//! verify idpub_r is pinned, verify sig_r
//! Msg5 (encrypted, empty) = "I checked you" ->
//! both: session keys and ratchet seed = HKDF(combined, salt = transcript)
//! ```
//!
//! Messages 1 and 2 carry no identity at all, and messages 3 and 4 are
//! encrypted under keys that already include the post-quantum secret, so
//! even a recorded handshake does not reveal who connected to whom.
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
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem},
    Ciphertext, EncapsulationKey768, Key, KeyExport, MlKem768,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{decrypt, encrypt, AeadKey, Channel};
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

/// Size of an ML-KEM-768 encapsulation (public) key, from FIPS 203.
const KEM_EK_LEN: usize = 1184;
/// Size of an ML-KEM-768 ciphertext, from FIPS 203.
const KEM_CT_LEN: usize = 1088;
/// Message 1: the initiator's X25519 ephemeral key then its ML-KEM encapsulation key.
const MSG1_LEN: usize = 32 + KEM_EK_LEN;
/// Message 2: the responder's X25519 ephemeral key then the ML-KEM ciphertext.
const MSG2_LEN: usize = 32 + KEM_CT_LEN;
/// Length of the first message in the 0.2 format (version, identity key,
/// ephemeral key, epoch). Only used to give an old caller a clear error.
const LEGACY_MSG1_LEN: usize = 6 + 32 + 32 + 16;
/// Plaintext of messages 3 and 4: version (6) + identity public key (32) +
/// session epoch (16) + signature (64).
const AUTH_PLAINTEXT_LEN: usize = 6 + 32 + 16 + 64;

/// Hash of messages 1 and 2 exactly as they travelled (both X25519 keys, the
/// ML-KEM encapsulation key and the ML-KEM ciphertext). It salts the secret
/// combiner and is the associated data of messages 3 and 4, so those
/// ciphertexts only verify in THIS exchange. Both signatures cover it too,
/// which binds the post-quantum key and ciphertext into the authentication.
fn eph_hash(msg1: &[u8], msg2: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"symbolon/handshake/v4/eph"); // domain separation
    h.update(msg1);
    h.update(msg2);
    h.finalize().into()
}

/// The hybrid combiner: one 32-byte secret from the classical and the
/// post-quantum shared secrets. Both go in as input keying material, so the
/// output is unpredictable unless an attacker knows BOTH. The transcript
/// hash `eph` is the salt, tying the secret to this exact exchange.
fn combine_secrets(
    ss_x25519: &[u8; 32],
    ss_mlkem: &[u8; 32],
    eph: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    use hkdf::Hkdf;
    // Wiped from memory when dropped, like the output.
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_mlkem);
    ikm[32..].copy_from_slice(ss_x25519);
    let hk = Hkdf::<Sha256>::new(Some(eph), ikm.as_slice());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(b"symbolon/hybrid/v1 x25519+ml-kem-768", out.as_mut_slice())
        .expect("32 bytes is a valid HKDF output length");
    out
}

/// Keys that protect handshake messages 3 and 4 (one per direction). They are
/// derived straight from the anonymous ephemeral exchange, BEFORE anyone has
/// said who they are, which is what lets the identities travel encrypted.
/// They are separate from the session keys derived at the end.
fn handshake_keys(shared_secret: &[u8; 32], eph: &[u8; 32]) -> (AeadKey, AeadKey) {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(Some(eph), shared_secret);
    let mut i2r = [0u8; 32];
    hk.expand(b"handshake-initiator-to-responder", &mut i2r)
        .expect("32 bytes is a valid HKDF output length");
    let mut r2i = [0u8; 32];
    hk.expand(b"handshake-responder-to-initiator", &mut r2i)
        .expect("32 bytes is a valid HKDF output length");
    (AeadKey(i2r), AeadKey(r2i))
}

/// What the INITIATOR signs in message 3: its own declared fields and the
/// hash of messages 1 and 2. The responder's identity is not known yet at this point.
fn initiator_digest(
    eph: &[u8; 32],
    version_i: Version,
    idpub_i: &VerifyingKey,
    epoch_i: &[u8; 16],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"symbolon/handshake/v4/initiator");
    h.update(eph);
    h.update(version_i.to_bytes());
    h.update(idpub_i.as_bytes());
    h.update(epoch_i);
    h.finalize().into()
}

/// Everything the two sides of one finished handshake have said, hashed. The
/// RESPONDER signs this in message 4 (so its signature also covers the
/// initiator's identity and signature), and it salts the session keys, so a
/// session is tied to this exact conversation. Returned to the caller as
/// `transcript_hash`.
#[allow(clippy::too_many_arguments)]
fn full_transcript(
    eph: &[u8; 32],
    version_i: Version,
    idpub_i: &VerifyingKey,
    epoch_i: &[u8; 16],
    sig_i: &[u8; 64],
    version_r: Version,
    idpub_r: &VerifyingKey,
    epoch_r: &[u8; 16],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"symbolon/handshake/v4/transcript");
    h.update(eph);
    h.update(version_i.to_bytes());
    h.update(idpub_i.as_bytes());
    h.update(epoch_i);
    h.update(sig_i);
    h.update(version_r.to_bytes());
    h.update(idpub_r.as_bytes());
    h.update(epoch_r);
    h.finalize().into()
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

/// Pack the plaintext of message 3 or 4.
fn pack_auth(version: Version, idpub: &VerifyingKey, epoch: &[u8; 16], sig: &[u8; 64]) -> Vec<u8> {
    let mut p = Vec::with_capacity(AUTH_PLAINTEXT_LEN);
    p.extend_from_slice(&version.to_bytes());
    p.extend_from_slice(idpub.as_bytes());
    p.extend_from_slice(epoch);
    p.extend_from_slice(sig);
    p
}

/// The four fields of a decrypted message 3 or 4.
struct AuthFields {
    version: Version,
    idpub: VerifyingKey,
    epoch: [u8; 16],
    sig: [u8; 64],
}

fn unpack_auth(p: &[u8]) -> Result<AuthFields> {
    if p.len() != AUTH_PLAINTEXT_LEN {
        return Err(ChatError::MalformedMessage(
            "handshake auth message has wrong length",
        ));
    }
    Ok(AuthFields {
        version: Version::from_bytes(&p[0..6]),
        idpub: parse_verifying_key(&p[6..38])?,
        epoch: p[38..54].try_into().unwrap(),
        sig: p[54..118].try_into().unwrap(),
    })
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
    let version_i = our_version;
    let esecret_i = EphemeralSecret::random_from_rng(OsRng);
    let epub_i = XPublicKey::from(&esecret_i);
    // A fresh post-quantum keypair for this one handshake. The decapsulation
    // (private) key never leaves this function and is wiped when dropped.
    let (dk, ek) = MlKem768::generate_keypair();

    // --- Msg1: our ephemeral public key and the ML-KEM encapsulation key.
    // No identity, version or epoch: nothing here says who we are. ---
    let mut msg1 = Vec::with_capacity(MSG1_LEN);
    msg1.extend_from_slice(epub_i.as_bytes());
    msg1.extend_from_slice(&ek.to_bytes());
    debug_assert_eq!(msg1.len(), MSG1_LEN);
    write_frame(stream, &msg1)?;

    // --- Msg2: the responder's ephemeral key and the ML-KEM ciphertext ---
    let msg2 = read_frame(stream)?;
    if msg2.len() != MSG2_LEN {
        return Err(ChatError::MalformedMessage(
            "handshake msg2 has wrong length",
        ));
    }
    let epub_r = parse_x_public(&msg2[..32])?;
    let ct: Ciphertext<MlKem768> = msg2[32..]
        .try_into()
        .map_err(|_| ChatError::MalformedMessage("bad ML-KEM ciphertext length"))?;

    // Both sides can now compute the same two secrets. Nobody has said who
    // they are yet, so the result is anonymous, but it is enough to encrypt
    // the identities that follow.
    let shared_x = esecret_i.diffie_hellman(&epub_r);
    // Refuse a degenerate (low-order peer key) exchange: the "secret" would
    // be a known constant no matter what we contributed.
    if !shared_x.was_contributory() {
        return Err(ChatError::InvalidPublicKey);
    }
    // ML-KEM never reports a bad ciphertext: it returns an unrelated secret
    // instead ("implicit rejection"), so a tampered Msg2 surfaces as a
    // failed decryption of Msg4 below, not here.
    let shared_pq = dk.decapsulate(&ct);
    let eph = eph_hash(&msg1, &msg2);
    let combined = combine_secrets(shared_x.as_bytes(), shared_pq.as_ref(), &eph);
    let (hs_i2r, hs_r2i) = handshake_keys(&combined, &eph);

    // --- Msg3 (encrypted): who we are, plus proof we hold that key ---
    let digest_i = initiator_digest(&eph, version_i, &idpub_i, own_epoch);
    let sig_i = identity.sign(&digest_i).to_bytes();
    let p3 = pack_auth(version_i, &idpub_i, own_epoch, &sig_i);
    write_frame(stream, &encrypt(&hs_i2r, Channel::Data, 0, &eph, &p3)?)?;

    // --- Msg4 (encrypted): the responder answers only if it trusts us ---
    let c4 = read_frame(stream)?;
    let p4 = decrypt(&hs_r2i, Channel::Data, 0, &eph, &c4)?;
    let r = unpack_auth(&p4)?;

    let negotiated_version = negotiate_version(version_i, r.version)?;
    emit(
        &mut on_progress,
        HandshakeProgress::VersionNegotiated(negotiated_version),
    );
    let claimed_peer_id = fingerprint(&r.idpub);
    emit(
        &mut on_progress,
        HandshakeProgress::PeerIdentityClaimed(claimed_peer_id),
    );

    // Refuse to proceed if we don't already trust this identity key.
    let peer_id = registry.verify_trusted(&r.idpub)?;
    emit(
        &mut on_progress,
        HandshakeProgress::PeerIdentityTrusted(peer_id),
    );

    // The responder proves it holds the private key over the FULL transcript
    // (both identities, both signatures-so-far, both versions).
    let t = full_transcript(
        &eph, version_i, &idpub_i, own_epoch, &sig_i, r.version, &r.idpub, &r.epoch,
    );
    let sig_r = Signature::from_slice(&r.sig)
        .map_err(|_| ChatError::MalformedMessage("bad signature encoding"))?;
    PeerRegistry::verify_signature(&r.idpub, &t, &sig_r)?;
    emit(
        &mut on_progress,
        HandshakeProgress::PeerSignatureVerified(peer_id),
    );

    // --- Msg5 (encrypted, empty): "I checked you and I agree". Sent only
    // after every check above passed. The responder waits for it before it
    // attaches a session, so dialling the wrong machine never leaves a
    // half-open session behind on that machine. The transcript is the
    // associated data, so it also proves we saw the same conversation. ---
    write_frame(stream, &encrypt(&hs_i2r, Channel::Data, 1, &t, b"")?)?;

    // --- Derive session keys ---
    let (key_i2r, key_r2i) = derive_keys(&combined, &t);
    let ratchet = RatchetSeed::for_initiator(&combined, &t, epub_r.to_bytes());

    emit(
        &mut on_progress,
        HandshakeProgress::Completed {
            peer_id,
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
        peer_epoch: r.epoch,
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

    // --- Msg1: the initiator's ephemeral key and ML-KEM encapsulation key ---
    let msg1 = read_frame(stream)?;
    if msg1.len() == LEGACY_MSG1_LEN {
        // A 0.2-format first message. It starts with the caller's version, so
        // we can say clearly why we refuse (we stay silent on the wire).
        return Err(ChatError::VersionMismatch {
            ours: our_version,
            theirs: Version::from_bytes(&msg1[0..6]),
        });
    }
    if msg1.len() != MSG1_LEN {
        // Includes the 32-byte first message of the pre-hybrid 0.3.0 draft.
        return Err(ChatError::MalformedMessage(
            "handshake msg1 has wrong length",
        ));
    }
    let epub_i = parse_x_public(&msg1[..32])?;
    // `new` also checks the key is well formed (FIPS 203 "modulus check"),
    // so a garbage key is refused before we do anything with it.
    let ek_bytes: Key<EncapsulationKey768> = msg1[32..]
        .try_into()
        .map_err(|_| ChatError::InvalidPublicKey)?;
    let ek = EncapsulationKey768::new(&ek_bytes).map_err(|_| ChatError::InvalidPublicKey)?;

    // --- Msg2: our ephemeral public key and the ML-KEM ciphertext. Anyone
    // who sends a well-formed Msg1 gets this; it says nothing about who we
    // are. ---
    let esecret_r = StaticSecret::random_from_rng(OsRng);
    let epub_r = XPublicKey::from(&esecret_r);
    let (ct, shared_pq) = ek.encapsulate();
    let mut msg2 = Vec::with_capacity(MSG2_LEN);
    msg2.extend_from_slice(epub_r.as_bytes());
    msg2.extend_from_slice(ct.as_ref());
    debug_assert_eq!(msg2.len(), MSG2_LEN);
    write_frame(stream, &msg2)?;

    let shared_x = esecret_r.diffie_hellman(&epub_i);
    if !shared_x.was_contributory() {
        return Err(ChatError::InvalidPublicKey);
    }
    let eph = eph_hash(&msg1, &msg2);
    let combined = combine_secrets(shared_x.as_bytes(), shared_pq.as_ref(), &eph);
    let (hs_i2r, hs_r2i) = handshake_keys(&combined, &eph);

    // --- Msg3 (encrypted): the initiator says who it is ---
    let c3 = read_frame(stream)?;
    let p3 = decrypt(&hs_i2r, Channel::Data, 0, &eph, &c3)?;
    let i = unpack_auth(&p3)?;

    let version_r = our_version;
    let negotiated_version = negotiate_version(version_r, i.version)?;
    emit(
        &mut on_progress,
        HandshakeProgress::VersionNegotiated(negotiated_version),
    );
    let claimed_peer_id = fingerprint(&i.idpub);
    emit(
        &mut on_progress,
        HandshakeProgress::PeerIdentityClaimed(claimed_peer_id),
    );

    // Check the caller really holds the key it names BEFORE looking at trust:
    // only keys that proved possession are ever recorded for approval, so a
    // stranger cannot fill the approval queue with made-up keys.
    let digest_i = initiator_digest(&eph, i.version, &i.idpub, &i.epoch);
    let sig_i = Signature::from_slice(&i.sig)
        .map_err(|_| ChatError::MalformedMessage("bad signature encoding"))?;
    PeerRegistry::verify_signature(&i.idpub, &digest_i, &sig_i)?;

    // An untrusted caller gets NO reply at all: we close without ever having
    // revealed our identity, version or epoch (no probing oracle).
    let peer_id = registry.verify_trusted(&i.idpub)?;
    emit(
        &mut on_progress,
        HandshakeProgress::PeerIdentityTrusted(peer_id),
    );
    emit(
        &mut on_progress,
        HandshakeProgress::PeerSignatureVerified(peer_id),
    );

    // Only now (the initiator is trusted) do we choose our epoch: a resumed
    // session must present the epoch it was saved with, which depends on
    // WHO is calling.
    let own_epoch_value = own_epoch_for(&peer_id);
    let own_epoch = &own_epoch_value;
    let idpub_r = identity.public_key();

    let t = full_transcript(
        &eph, i.version, &i.idpub, &i.epoch, &i.sig, version_r, &idpub_r, own_epoch,
    );
    let sig_r = identity.sign(&t).to_bytes();

    // --- Msg4 (encrypted): who we are, plus proof we hold that key ---
    let p4 = pack_auth(version_r, &idpub_r, own_epoch, &sig_r);
    write_frame(stream, &encrypt(&hs_r2i, Channel::Data, 0, &eph, &p4)?)?;

    // --- Msg5 (encrypted, empty): the initiator confirms it accepted us.
    // Until it arrives no session exists on our side. ---
    let c5 = read_frame(stream)?;
    decrypt(&hs_i2r, Channel::Data, 1, &t, &c5)?;

    // --- Derive session keys ---
    let (key_i2r, key_r2i) = derive_keys(&combined, &t);
    // Our handshake ephemeral doubles as the first ratchet key (like a
    // signed prekey in X3DH), which is what lets us speak first.
    let ratchet = RatchetSeed::for_responder(&combined, &t, esecret_r.to_bytes());

    emit(
        &mut on_progress,
        HandshakeProgress::Completed {
            peer_id,
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
        peer_epoch: i.epoch,
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

    /// Wraps a stream and records every byte that crosses it, both ways: what
    /// a passive eavesdropper on the wire would see.
    struct Tap<S> {
        inner: S,
        seen: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }
    impl<S: Read> Read for Tap<S> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.seen.lock().unwrap().extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }
    impl<S: Write> Write for Tap<S> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = self.inner.write(buf)?;
            self.seen.lock().unwrap().extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn an_eavesdropper_sees_no_identity_version_or_epoch() {
        use crate::transport::memory_pair;
        let (a, mut b) = memory_pair(std::time::Duration::ZERO);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut a = Tap {
            inner: a,
            seen: seen.clone(),
        };
        let (alice, bob) = (Identity::generate(), Identity::generate());
        let mut reg_a = PeerRegistry::new();
        reg_a.trust(bob.public_key());
        let mut reg_b = PeerRegistry::new();
        reg_b.trust(alice.public_key());
        let bob2 = Identity::from_bytes(&bob.secret_bytes());
        let t =
            std::thread::spawn(move || run_responder(&mut b, &bob2, &reg_b, &|_| [0xBE; 16], None));
        run_initiator(&mut a, &alice, &reg_a, &[0xAE; 16], None).unwrap();
        t.join().unwrap().unwrap();

        let wire = seen.lock().unwrap().clone();
        assert!(
            wire.len() > 200,
            "the capture should hold the whole handshake"
        );
        assert!(
            !contains(&wire, alice.public_key().as_bytes()),
            "initiator key leaked"
        );
        assert!(
            !contains(&wire, bob.public_key().as_bytes()),
            "responder key leaked"
        );
        assert!(
            !contains(&wire, &PROTOCOL_VERSION_CURRENT.to_bytes()),
            "version leaked"
        );
        assert!(
            !contains(&wire, &[0xAE; 16]) && !contains(&wire, &[0xBE; 16]),
            "epoch leaked"
        );
    }

    #[test]
    fn an_unpinned_caller_learns_nothing_about_the_listener() {
        use crate::transport::{memory_pair, Connection};
        let (mut a, mut b) = memory_pair(std::time::Duration::ZERO);
        a.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        let (stranger, bob) = (Identity::generate(), Identity::generate());
        let mut reg_a = PeerRegistry::new();
        reg_a.trust(bob.public_key()); // the stranger would happily trust Bob
        let reg_b = PeerRegistry::new(); // but Bob trusts nobody
        let t =
            std::thread::spawn(move || run_responder(&mut b, &bob, &reg_b, &|_| [2u8; 16], None));
        let ri = run_initiator(&mut a, &stranger, &reg_a, &[1u8; 16], None);
        drop(a);
        assert!(matches!(t.join().unwrap(), Err(ChatError::UnknownPeer)));
        // The only thing the stranger got back is msg2 (an ephemeral key);
        // message 4, which carries Bob's identity, never came.
        assert!(ri.is_err());
    }

    #[test]
    fn only_a_caller_that_proved_its_key_is_recorded_for_approval() {
        use crate::transport::{memory_pair, Connection};
        let (mut a, mut b) = memory_pair(std::time::Duration::ZERO);
        a.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        let (stranger, bob) = (Identity::generate(), Identity::generate());
        let reg_b = PeerRegistry::new();
        let reg_a = PeerRegistry::new();
        let stranger_key = stranger.public_key();
        let store_b = reg_b.store().clone();
        let t =
            std::thread::spawn(move || run_responder(&mut b, &bob, &reg_b, &|_| [2u8; 16], None));
        let _ = run_initiator(&mut a, &stranger, &reg_a, &[1u8; 16], None);
        drop(a);
        let _ = t.join().unwrap();
        assert!(
            store_b
                .pending()
                .iter()
                .any(|k| k.as_bytes() == stranger_key.as_bytes()),
            "a key that signed the handshake is queued for approval"
        );
    }

    #[test]
    fn an_old_format_first_message_is_refused_with_both_versions_named() {
        use crate::transport::memory_pair;
        let (mut a, mut b) = memory_pair(std::time::Duration::ZERO);
        let bob = Identity::generate();
        let reg = PeerRegistry::new();
        let old = Version::new(0, 2, 0);
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&old.to_bytes());
        legacy.extend_from_slice(&[7u8; 80]);
        write_frame(&mut a, &legacy).unwrap();
        match run_responder(&mut b, &bob, &reg, &|_| [2u8; 16], None) {
            Err(ChatError::VersionMismatch { ours, theirs }) => {
                assert_eq!(ours, PROTOCOL_VERSION_CURRENT);
                assert_eq!(theirs, old);
            }
            Err(e) => panic!("expected VersionMismatch, got {e:?}"),
            Ok(_) => panic!("an old-format caller must be refused"),
        }
    }

    #[test]
    fn handshake_messages_have_the_hybrid_sizes() {
        use crate::transport::memory_pair;
        let (a, mut b) = memory_pair(std::time::Duration::ZERO);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut a = Tap {
            inner: a,
            seen: seen.clone(),
        };
        let (alice, bob) = (Identity::generate(), Identity::generate());
        let mut reg_a = PeerRegistry::new();
        reg_a.trust(bob.public_key());
        let mut reg_b = PeerRegistry::new();
        reg_b.trust(alice.public_key());
        let t =
            std::thread::spawn(move || run_responder(&mut b, &bob, &reg_b, &|_| [2u8; 16], None));
        run_initiator(&mut a, &alice, &reg_a, &[1u8; 16], None).unwrap();
        t.join().unwrap().unwrap();

        // Walk the captured frames: each is a 4-byte length then that many bytes.
        let wire = seen.lock().unwrap().clone();
        let mut sizes = Vec::new();
        let mut at = 0;
        while at < wire.len() {
            let n = u32::from_be_bytes(wire[at..at + 4].try_into().unwrap()) as usize;
            sizes.push(n);
            at += 4 + n;
        }
        // Msg1 = 32 + 1184, Msg2 = 32 + 1088, then Msg3, Msg4 (118 + 16 tag), Msg5 (empty + 16 tag).
        assert_eq!(sizes, vec![1216, 1120, 134, 134, 16]);
    }

    #[test]
    fn the_combiner_needs_both_secrets() {
        let (x, pq, eph) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let base = combine_secrets(&x, &pq, &eph);
        // Changing either secret, or the transcript, changes the result.
        assert_ne!(*base, *combine_secrets(&[9u8; 32], &pq, &eph));
        assert_ne!(*base, *combine_secrets(&x, &[9u8; 32], &eph));
        assert_ne!(*base, *combine_secrets(&x, &pq, &[9u8; 32]));
        // And it is deterministic, so both sides agree.
        assert_eq!(*base, *combine_secrets(&x, &pq, &eph));
    }

    /// Flips one bit of the byte at a chosen offset in what a stream READS
    /// (an active attacker tampering with the reply).
    struct Flip<S> {
        inner: S,
        at: usize,
        read_so_far: usize,
    }
    impl<S: Read> Read for Flip<S> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            if self.read_so_far <= self.at && self.at < self.read_so_far + n {
                buf[self.at - self.read_so_far] ^= 0x01;
            }
            self.read_so_far += n;
            Ok(n)
        }
    }
    impl<S: Write> Write for Flip<S> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    /// Run a handshake where the initiator's incoming bytes are tampered with
    /// at `flip_at` (offset 0..4 is the length prefix, 4..36 the X25519 key,
    /// 36.. the ML-KEM ciphertext).
    fn tampered_handshake(flip_at: usize) -> (Result<HandshakeResult>, Result<HandshakeResult>) {
        use crate::transport::{memory_pair, Connection};
        let (mut a, mut b) = memory_pair(std::time::Duration::ZERO);
        a.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        b.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut a = Flip {
            inner: a,
            at: flip_at,
            read_so_far: 0,
        };
        let (alice, bob) = (Identity::generate(), Identity::generate());
        let mut reg_a = PeerRegistry::new();
        reg_a.trust(bob.public_key());
        let mut reg_b = PeerRegistry::new();
        reg_b.trust(alice.public_key());
        let t =
            std::thread::spawn(move || run_responder(&mut b, &bob, &reg_b, &|_| [2u8; 16], None));
        let ri = run_initiator(&mut a, &alice, &reg_a, &[1u8; 16], None);
        drop(a);
        (ri, t.join().unwrap())
    }

    #[test]
    fn a_tampered_ml_kem_ciphertext_breaks_the_handshake() {
        // One flipped bit in the ciphertext: ML-KEM "implicitly rejects" it
        // by producing a different secret, so the two sides' keys differ and
        // the responder cannot decrypt Msg3. Nobody ends up with a session.
        let (ri, rr) = tampered_handshake(36 + 500);
        assert!(rr.is_err(), "the responder must not complete");
        assert!(ri.is_err(), "the initiator must not complete");
    }

    #[test]
    fn a_tampered_x25519_half_also_breaks_the_handshake() {
        // The classical half alone is also covered: both secrets must agree.
        let (ri, rr) = tampered_handshake(4 + 5);
        assert!(rr.is_err() && ri.is_err());
    }

    #[test]
    fn an_untampered_run_of_the_same_helper_succeeds() {
        // Guards the two tests above: the helper itself must not be what
        // breaks the handshake. An offset past the end flips nothing.
        let (ri, rr) = tampered_handshake(usize::MAX);
        assert!(ri.is_ok() && rr.is_ok());
    }

    #[test]
    fn a_malformed_ml_kem_key_is_refused_before_any_reply() {
        use crate::transport::memory_pair;
        let (mut a, mut b) = memory_pair(std::time::Duration::ZERO);
        let bob = Identity::generate();
        let reg = PeerRegistry::new();
        // A plausible-looking first message whose ML-KEM key is garbage
        // (0xFF coefficients are out of range, so the key fails validation).
        let mut msg1 = vec![0x09u8; 32];
        msg1.extend_from_slice(&[0xFFu8; KEM_EK_LEN]);
        write_frame(&mut a, &msg1).unwrap();
        assert!(matches!(
            run_responder(&mut b, &bob, &reg, &|_| [2u8; 16], None),
            Err(ChatError::InvalidPublicKey)
        ));
    }

    #[test]
    fn the_pre_hybrid_32_byte_first_message_is_refused() {
        use crate::transport::memory_pair;
        let (mut a, mut b) = memory_pair(std::time::Duration::ZERO);
        let bob = Identity::generate();
        let reg = PeerRegistry::new();
        write_frame(&mut a, &[7u8; 32]).unwrap();
        assert!(matches!(
            run_responder(&mut b, &bob, &reg, &|_| [2u8; 16], None),
            Err(ChatError::MalformedMessage(_))
        ));
    }

    #[test]
    fn dialling_the_wrong_machine_leaves_no_session_on_that_machine() {
        use crate::transport::{memory_pair, Connection};
        let (mut a, mut b) = memory_pair(std::time::Duration::ZERO);
        b.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        let (alice, wrong) = (Identity::generate(), Identity::generate());
        let reg_a = PeerRegistry::new(); // Alice does NOT trust this machine
        let mut reg_w = PeerRegistry::new();
        reg_w.trust(alice.public_key()); // but the machine trusts Alice
        let t =
            std::thread::spawn(move || run_responder(&mut b, &wrong, &reg_w, &|_| [2u8; 16], None));
        let ri = run_initiator(&mut a, &alice, &reg_a, &[1u8; 16], None);
        drop(a);
        assert!(matches!(ri, Err(ChatError::UnknownPeer)));
        // Alice never sent the final confirmation, so the machine must not
        // consider the handshake complete.
        assert!(
            t.join().unwrap().is_err(),
            "the wrong machine attached a session"
        );
    }
}
