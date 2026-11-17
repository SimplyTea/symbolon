//! The Double Ratchet: per-message forward secrecy and post-compromise
//! healing, layered *inside* the per-connection transport encryption.
//!
//! # What problem this solves
//!
//! The handshake gives one set of traffic keys per TCP connection. If those
//! keys (or the device memory holding them) leak mid-connection, *everything*
//! sent on that connection is exposed, past and future. The ratchet shrinks
//! the blast radius of a key leak to a single message:
//!
//! - **Forward secrecy per message**: every message is encrypted under its own
//!   key, derived from a hash chain and deleted right after use. Stealing the
//!   current state reveals nothing about messages already processed.
//! - **Post-compromise security**: every time the conversation changes
//!   direction, a fresh X25519 exchange is mixed into the root key. An
//!   attacker who stole the state once is locked out again after one
//!   round trip, unless they keep actively stealing it.
//!
//! # Structure (follows Signal's published Double Ratchet spec)
//!
//! - **Root key** `rk`: updated by every DH step. `KDF_RK(rk, dh)` yields a
//!   new root key plus a fresh chain key.
//! - **Chain keys** (`cks` sending, `ckr` receiving): `KDF_CK(ck)` yields a
//!   one-time message key plus the next chain key. The old chain key is
//!   overwritten, which is the "ratchet": you cannot run a hash backwards.
//! - **Header** (40 bytes, sent in the clear but authenticated): sender's
//!   current ratchet public key, length of the previous sending chain (`pn`),
//!   and this message's index in the current chain (`n`).
//! - **Skipped message keys**: if messages arrive out of order or are lost,
//!   keys for the gap are derived and cached so late arrivals still decrypt.
//!   Both the per-jump gap ([`MAX_SKIP`]) and the total cache
//!   ([`MAX_STORED_SKIPPED`]) are hard-capped so an attacker cannot make us
//!   burn CPU or memory by claiming a huge message number.
//!
//! # Deviation from the textbook: the responder can speak first
//!
//! In the textbook protocol only the party that received an initial prekey
//! can start; the other side must wait for the first message. A chat session
//! has no natural "first sender", so both sides are seeded from the handshake
//! with a shared *initial responder-to-initiator chain*. The responder starts
//! with its handshake ephemeral as its ratchet key and may send immediately
//! on that chain; the initiator immediately performs a DH step against the
//! same key. Messages on that very first chain have forward secrecy but no
//! post-compromise healing until the first full round trip, exactly like the
//! first flight in Signal's X3DH.
//!
//! # Atomic decryption
//!
//! `decrypt` works on a *copy* of the state and commits only if the AEAD tag
//! verifies. A forged or corrupted message therefore can never advance,
//! desynchronise or poison the real state. (This is the single most common
//! implementation bug in homemade ratchets.)
//!
//! # Where it sits in the stack
//!
//! The session stores the *ratchet-encrypted* blob in its outbox, so a
//! retransmission resends the identical ciphertext (a ratchet key must never
//! be used twice). The transport layer then wraps that blob again with the
//! per-connection AEAD. The inbox deduplicates and orders blobs before they
//! reach the ratchet, so in normal operation the ratchet sees each message
//! exactly once and in order; the out-of-order machinery is defence in depth
//! and is tested standalone.

use std::collections::{HashMap, VecDeque};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{ChatError, Result};

/// Maximum number of message keys we will derive-and-cache for a single gap
/// (one chain jump). A claim of "message 4 billion" is rejected instead of
/// making us hash four billion times.
pub const MAX_SKIP: u32 = 1000;

/// Maximum number of cached skipped message keys in total. Oldest are evicted
/// first. Bounds memory regardless of attacker behaviour.
pub const MAX_STORED_SKIPPED: usize = 2000;

/// Header: 32-byte DH public key + 4-byte `pn` + 4-byte `n`.
pub const HEADER_LEN: usize = 40;

/// Poly1305 tag length appended by the AEAD.
const TAG_LEN: usize = 16;

const LABEL_ROOT: &[u8] = b"symbolon/ratchet/v1/root";
const LABEL_INIT_CHAIN: &[u8] = b"symbolon/ratchet/v1/initial-chain-r2i";
const LABEL_KDF_RK: &[u8] = b"symbolon/ratchet/v1/kdf-rk";
const LABEL_MK: &[u8] = b"symbolon/ratchet/v1/message-key";
const LABEL_CK: &[u8] = b"symbolon/ratchet/v1/chain-key";
const LABEL_AEAD: &[u8] = b"symbolon/ratchet/v1/aead";
const AD_PREFIX: &[u8] = b"symbolon/ratchet/v1/ad";

/// A 32-byte secret that wipes itself when dropped.
#[derive(Clone)]
pub(crate) struct Secret32([u8; 32]);

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Everything the handshake hands to the ratchet. Opaque to callers.
pub struct RatchetSeed {
    root_key: Secret32,
    initial_chain: Secret32,
    ad: Vec<u8>,
    role: SeedRole,
}

enum SeedRole {
    /// Initiator knows the responder's handshake ephemeral public key.
    Initiator { responder_ratchet_public: [u8; 32] },
    /// Responder keeps its handshake ephemeral secret as its first ratchet key.
    Responder { ratchet_secret: Secret32 },
}

fn derive_roots(shared: &[u8; 32], transcript: &[u8; 32]) -> (Secret32, Secret32, Vec<u8>) {
    let hk = Hkdf::<Sha256>::new(Some(transcript), shared);
    let mut rk = [0u8; 32];
    let mut ck = [0u8; 32];
    hk.expand(LABEL_ROOT, &mut rk).expect("32 bytes is valid");
    hk.expand(LABEL_INIT_CHAIN, &mut ck)
        .expect("32 bytes is valid");
    let mut ad = Vec::with_capacity(AD_PREFIX.len() + 32);
    ad.extend_from_slice(AD_PREFIX);
    // The transcript hash already binds both identities, both ephemerals and
    // both protocol versions, so it doubles as the session-binding AD.
    ad.extend_from_slice(transcript);
    (Secret32(rk), Secret32(ck), ad)
}

impl RatchetSeed {
    pub(crate) fn for_initiator(
        shared: &[u8; 32],
        transcript: &[u8; 32],
        responder_ratchet_public: [u8; 32],
    ) -> Self {
        let (root_key, initial_chain, ad) = derive_roots(shared, transcript);
        RatchetSeed {
            root_key,
            initial_chain,
            ad,
            role: SeedRole::Initiator {
                responder_ratchet_public,
            },
        }
    }

    pub(crate) fn for_responder(
        shared: &[u8; 32],
        transcript: &[u8; 32],
        ratchet_secret: [u8; 32],
    ) -> Self {
        let (root_key, initial_chain, ad) = derive_roots(shared, transcript);
        RatchetSeed {
            root_key,
            initial_chain,
            ad,
            role: SeedRole::Responder {
                ratchet_secret: Secret32(ratchet_secret),
            },
        }
    }
}

/// `KDF_RK`: mix a DH output into the root key, producing a new root key and
/// a new chain key.
fn kdf_rk(rk: &Secret32, dh_out: &[u8; 32]) -> (Secret32, Secret32) {
    let hk = Hkdf::<Sha256>::new(Some(&rk.0), dh_out);
    let mut out = [0u8; 64];
    hk.expand(LABEL_KDF_RK, &mut out)
        .expect("64 bytes is valid");
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    new_rk.copy_from_slice(&out[..32]);
    ck.copy_from_slice(&out[32..]);
    out.zeroize();
    (Secret32(new_rk), Secret32(ck))
}

/// `KDF_CK`: advance a chain key, producing a one-time message key and the
/// next chain key. Distinct labels keep the two outputs independent.
fn kdf_ck(ck: &Secret32) -> (Secret32, Secret32) {
    let hk = Hkdf::<Sha256>::new(None, &ck.0);
    let mut mk = [0u8; 32];
    let mut next = [0u8; 32];
    hk.expand(LABEL_MK, &mut mk).expect("32 bytes is valid");
    hk.expand(LABEL_CK, &mut next).expect("32 bytes is valid");
    (Secret32(mk), Secret32(next))
}

/// Expand a message key into an AEAD key and nonce. Each message key is used
/// exactly once, so a derived nonce is safe.
fn aead_material(mk: &Secret32) -> ([u8; 32], [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(None, &mk.0);
    let mut out = [0u8; 44];
    hk.expand(LABEL_AEAD, &mut out).expect("44 bytes is valid");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&out[..32]);
    nonce.copy_from_slice(&out[32..]);
    out.zeroize();
    (key, nonce)
}

/// X25519 that refuses degenerate results. A low-order public key makes the
/// shared secret all-zero regardless of our secret, which would let an
/// attacker pick the "secret" that gets mixed into the root key.
fn checked_dh(secret: &StaticSecret, public: &[u8; 32]) -> Result<[u8; 32]> {
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(ChatError::Ratchet("degenerate DH public key"));
    }
    Ok(*shared.as_bytes())
}

struct Header {
    dh: [u8; 32],
    pn: u32,
    n: u32,
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..32].copy_from_slice(&self.dh);
        out[32..36].copy_from_slice(&self.pn.to_be_bytes());
        out[36..40].copy_from_slice(&self.n.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Header> {
        if bytes.len() < HEADER_LEN + TAG_LEN {
            return Err(ChatError::Ratchet("message shorter than header plus tag"));
        }
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&bytes[..32]);
        Ok(Header {
            dh,
            pn: u32::from_be_bytes(bytes[32..36].try_into().unwrap()),
            n: u32::from_be_bytes(bytes[36..40].try_into().unwrap()),
        })
    }
}

fn seal(mk: &Secret32, ad: &[u8], header: &[u8; HEADER_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let (key, nonce) = aead_material(mk);
    let mut aad = Vec::with_capacity(ad.len() + HEADER_LEN);
    aad.extend_from_slice(ad);
    aad.extend_from_slice(header);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| ChatError::Ratchet("encryption failed"))
}

fn open(mk: &Secret32, ad: &[u8], header: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let (key, nonce) = aead_material(mk);
    let mut aad = Vec::with_capacity(ad.len() + header.len());
    aad.extend_from_slice(ad);
    aad.extend_from_slice(header);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| ChatError::Ratchet("authentication failed"))
}

/// A read-only, non-secret snapshot of a ratchet's position, for debug
/// displays and tests. Contains NO key material except our own *public*
/// ratchet key (which is sent on the wire in every message header anyway).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetInfo {
    /// Our current public ratchet key. Changes on every DH step.
    pub own_public: [u8; 32],
    /// Messages sent so far in the current sending chain.
    pub sent_in_chain: u32,
    /// Messages received so far in the current receiving chain.
    pub received_in_chain: u32,
    /// Length of our previous sending chain (told to the peer in headers).
    pub previous_chain_len: u32,
    /// How many skipped-message keys are cached right now.
    pub cached_skipped_keys: usize,
}

/// One side of a Double Ratchet conversation.
#[derive(Clone)]
pub struct Ratchet {
    ad: Vec<u8>,
    dh_s: StaticSecret,
    dh_s_pub: [u8; 32],
    dh_r: Option<[u8; 32]>,
    rk: Secret32,
    cks: Secret32,
    ckr: Option<Secret32>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: HashMap<([u8; 32], u32), Secret32>,
    skipped_order: VecDeque<([u8; 32], u32)>,
}

impl Ratchet {
    /// Build a ratchet from handshake material.
    pub fn from_seed(seed: RatchetSeed) -> Result<Ratchet> {
        match seed.role {
            SeedRole::Initiator {
                responder_ratchet_public,
            } => {
                let dh_s = StaticSecret::random_from_rng(OsRng);
                let dh_s_pub = PublicKey::from(&dh_s).to_bytes();
                // Immediate DH step against the responder's first ratchet key.
                let dh_out = checked_dh(&dh_s, &responder_ratchet_public)?;
                let (rk, cks) = kdf_rk(&seed.root_key, &dh_out);
                Ok(Ratchet {
                    ad: seed.ad,
                    dh_s,
                    dh_s_pub,
                    dh_r: Some(responder_ratchet_public),
                    rk,
                    cks,
                    // The responder's very first chain is known to us already.
                    ckr: Some(seed.initial_chain),
                    ns: 0,
                    nr: 0,
                    pn: 0,
                    skipped: HashMap::new(),
                    skipped_order: VecDeque::new(),
                })
            }
            SeedRole::Responder { ratchet_secret } => {
                let dh_s = StaticSecret::from(ratchet_secret.0);
                let dh_s_pub = PublicKey::from(&dh_s).to_bytes();
                Ok(Ratchet {
                    ad: seed.ad,
                    dh_s,
                    dh_s_pub,
                    dh_r: None,
                    rk: seed.root_key,
                    cks: seed.initial_chain,
                    ckr: None,
                    ns: 0,
                    nr: 0,
                    pn: 0,
                    skipped: HashMap::new(),
                    skipped_order: VecDeque::new(),
                })
            }
        }
    }

    /// Serialize the COMPLETE state, secrets included, for the session
    /// state file ([`crate::sessionstate`]). The caller must encrypt the
    /// result before it touches disk; this function does not.
    ///
    /// Restoring an OLD copy of this state after newer messages were sent
    /// would reuse message keys, which breaks the encryption. The session
    /// layer therefore saves BEFORE any ciphertext leaves the process.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        fn put32(out: &mut Vec<u8>, b: &[u8; 32]) {
            out.extend_from_slice(b);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&(self.ad.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ad);
        put32(&mut out, &self.dh_s.to_bytes());
        match &self.dh_r {
            Some(k) => {
                out.push(1);
                put32(&mut out, k);
            }
            None => out.push(0),
        }
        put32(&mut out, &self.rk.0);
        put32(&mut out, &self.cks.0);
        match &self.ckr {
            Some(k) => {
                out.push(1);
                put32(&mut out, &k.0);
            }
            None => out.push(0),
        }
        for n in [self.ns, self.nr, self.pn] {
            out.extend_from_slice(&n.to_be_bytes());
        }
        out.extend_from_slice(&(self.skipped_order.len() as u32).to_be_bytes());
        for key in &self.skipped_order {
            // Invariant: every key in `skipped_order` is in `skipped`.
            if let Some(mk) = self.skipped.get(key) {
                put32(&mut out, &key.0);
                out.extend_from_slice(&key.1.to_be_bytes());
                put32(&mut out, &mk.0);
            }
        }
        out
    }

    /// Inverse of [`Ratchet::to_bytes`]. Strict: any inconsistency is an
    /// error, and the skipped-key cache is re-capped.
    pub(crate) fn from_bytes(b: &[u8]) -> Result<Ratchet> {
        const BAD: ChatError = ChatError::MalformedMessage("bad saved ratchet state");
        struct R<'a>(&'a [u8]);
        impl<'a> R<'a> {
            fn take(&mut self, n: usize) -> Result<&'a [u8]> {
                if self.0.len() < n {
                    return Err(BAD);
                }
                let (h, t) = self.0.split_at(n);
                self.0 = t;
                Ok(h)
            }
            fn a32(&mut self) -> Result<[u8; 32]> {
                Ok(self.take(32)?.try_into().unwrap())
            }
            fn u32(&mut self) -> Result<u32> {
                Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
            }
            fn flag(&mut self) -> Result<bool> {
                match self.take(1)?[0] {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(BAD),
                }
            }
        }
        let mut r = R(b);
        let ad_len = r.u32()? as usize;
        if ad_len > 1024 {
            return Err(BAD);
        }
        let ad = r.take(ad_len)?.to_vec();
        let dh_s = StaticSecret::from(r.a32()?);
        let dh_s_pub = PublicKey::from(&dh_s).to_bytes();
        let dh_r = if r.flag()? { Some(r.a32()?) } else { None };
        let rk = Secret32(r.a32()?);
        let cks = Secret32(r.a32()?);
        let ckr = if r.flag()? {
            Some(Secret32(r.a32()?))
        } else {
            None
        };
        let (ns, nr, pn) = (r.u32()?, r.u32()?, r.u32()?);
        let count = r.u32()? as usize;
        if count > MAX_STORED_SKIPPED {
            return Err(BAD);
        }
        let mut skipped = HashMap::new();
        let mut skipped_order = VecDeque::new();
        for _ in 0..count {
            let pk = r.a32()?;
            let n = r.u32()?;
            let mk = Secret32(r.a32()?);
            skipped_order.push_back((pk, n));
            skipped.insert((pk, n), mk);
        }
        if !r.0.is_empty() {
            return Err(BAD);
        }
        Ok(Ratchet {
            ad,
            dh_s,
            dh_s_pub,
            dh_r,
            rk,
            cks,
            ckr,
            ns,
            nr,
            pn,
            skipped,
            skipped_order,
        })
    }

    /// Create a matched initiator/responder pair from a shared secret. This
    /// does what the handshake does, without a network. Intended for tests,
    /// benchmarks and fuzzing - real sessions get their seeds from
    /// [`crate::handshake`].
    pub fn pair_from_shared_secret(
        shared: &[u8; 32],
        transcript: &[u8; 32],
    ) -> Result<(Ratchet, Ratchet)> {
        let responder_secret = StaticSecret::random_from_rng(OsRng);
        let responder_pub = PublicKey::from(&responder_secret).to_bytes();
        let init = Ratchet::from_seed(RatchetSeed::for_initiator(
            shared,
            transcript,
            responder_pub,
        ))?;
        let resp = Ratchet::from_seed(RatchetSeed::for_responder(
            shared,
            transcript,
            responder_secret.to_bytes(),
        ))?;
        Ok((init, resp))
    }

    /// Our current ratchet public key (changes every time we receive a new
    /// key from the peer). Useful for UIs and tests.
    pub fn own_ratchet_public(&self) -> [u8; 32] {
        self.dh_s_pub
    }

    /// Snapshot of the ratchet's counters (no secrets). See [`RatchetInfo`].
    pub fn info(&self) -> RatchetInfo {
        RatchetInfo {
            own_public: self.dh_s_pub,
            sent_in_chain: self.ns,
            received_in_chain: self.nr,
            previous_chain_len: self.pn,
            cached_skipped_keys: self.skipped.len(),
        }
    }

    /// Number of cached skipped message keys.
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    /// Encrypt one message. Output is `header(40) || ciphertext || tag(16)`.
    /// Every call consumes a fresh one-time message key.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let n = self.ns;
        let next_n = n
            .checked_add(1)
            .ok_or(ChatError::Ratchet("sending chain exhausted"))?;
        let (mk, next_ck) = kdf_ck(&self.cks);
        let header = Header {
            dh: self.dh_s_pub,
            pn: self.pn,
            n,
        }
        .encode();
        let sealed = seal(&mk, &self.ad, &header, plaintext)?;
        // Commit only after the AEAD succeeded.
        self.cks = next_ck;
        self.ns = next_n;
        let mut out = Vec::with_capacity(HEADER_LEN + sealed.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Decrypt one message. On any error the state is left exactly as it was.
    pub fn decrypt(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        let mut work = self.clone();
        let plaintext = work.decrypt_inner(wire)?;
        *self = work;
        Ok(plaintext)
    }

    fn decrypt_inner(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        let header = Header::decode(wire)?;
        let header_bytes = &wire[..HEADER_LEN];
        let ciphertext = &wire[HEADER_LEN..];

        // 1. A key we cached earlier for a late message?
        if let Some(mk) = self.skipped.remove(&(header.dh, header.n)) {
            self.skipped_order.retain(|k| *k != (header.dh, header.n));
            return open(&mk, &self.ad, header_bytes, ciphertext);
        }

        // 2. New ratchet key from the peer: finish the old chain, then step.
        if self.dh_r != Some(header.dh) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(&header)?;
        } else if header.n < self.nr {
            // Same chain, index already consumed, key not cached: replay.
            return Err(ChatError::Ratchet("replayed or already-consumed message"));
        }

        // 3. Catch up within the current chain, then take this message's key.
        self.skip_message_keys(header.n)?;
        let ckr = self
            .ckr
            .as_ref()
            .ok_or(ChatError::Ratchet("no receiving chain"))?;
        let (mk, next) = kdf_ck(ckr);
        self.ckr = Some(next);
        self.nr = self
            .nr
            .checked_add(1)
            .ok_or(ChatError::Ratchet("receiving chain exhausted"))?;
        open(&mk, &self.ad, header_bytes, ciphertext)
    }

    /// Derive and cache keys for messages `nr..until` of the current
    /// receiving chain.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        let Some(dh_r) = self.dh_r else { return Ok(()) };
        if self.ckr.is_none() || until <= self.nr {
            return Ok(());
        }
        if until - self.nr > MAX_SKIP {
            return Err(ChatError::Ratchet("too many skipped messages"));
        }
        while self.nr < until {
            let (mk, next) = kdf_ck(self.ckr.as_ref().expect("checked above"));
            self.ckr = Some(next);
            let key = (dh_r, self.nr);
            self.skipped.insert(key, mk);
            self.skipped_order.push_back(key);
            self.nr += 1;
            while self.skipped.len() > MAX_STORED_SKIPPED {
                if let Some(old) = self.skipped_order.pop_front() {
                    self.skipped.remove(&old);
                } else {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Perform a DH ratchet step on receipt of a new peer ratchet key: derive
    /// the new receiving chain, then immediately generate our own fresh key
    /// and derive the new sending chain.
    fn dh_ratchet(&mut self, header: &Header) -> Result<()> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dh_r = Some(header.dh);

        let dh_out = checked_dh(&self.dh_s, &header.dh)?;
        let (rk, ckr) = kdf_rk(&self.rk, &dh_out);
        self.rk = rk;
        self.ckr = Some(ckr);

        self.dh_s = StaticSecret::random_from_rng(OsRng);
        self.dh_s_pub = PublicKey::from(&self.dh_s).to_bytes();
        let dh_out2 = checked_dh(&self.dh_s, &header.dh)?;
        let (rk, cks) = kdf_rk(&self.rk, &dh_out2);
        self.rk = rk;
        self.cks = cks;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Ratchet, Ratchet) {
        Ratchet::pair_from_shared_secret(&[9u8; 32], &[3u8; 32]).unwrap()
    }

    /// Tiny deterministic PRNG so the model test is reproducible.
    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    #[test]
    fn alternating_conversation_round_trips() {
        let (mut a, mut b) = pair();
        for i in 0..20u32 {
            let m = format!("a->b {i}");
            assert_eq!(
                b.decrypt(&a.encrypt(m.as_bytes()).unwrap()).unwrap(),
                m.as_bytes()
            );
            let m = format!("b->a {i}");
            assert_eq!(
                a.decrypt(&b.encrypt(m.as_bytes()).unwrap()).unwrap(),
                m.as_bytes()
            );
        }
    }

    #[test]
    fn responder_can_speak_first_and_initiator_can_reply() {
        let (mut a, mut b) = pair();
        for i in 0..3u8 {
            assert_eq!(a.decrypt(&b.encrypt(&[i]).unwrap()).unwrap(), vec![i]);
        }
        assert_eq!(b.decrypt(&a.encrypt(b"reply").unwrap()).unwrap(), b"reply");
        assert_eq!(a.decrypt(&b.encrypt(b"again").unwrap()).unwrap(), b"again");
    }

    #[test]
    fn long_one_directional_run_stays_in_sync() {
        let (mut a, mut b) = pair();
        for i in 0..500u32 {
            let m = i.to_be_bytes();
            assert_eq!(b.decrypt(&a.encrypt(&m).unwrap()).unwrap(), m);
        }
    }

    #[test]
    fn same_plaintext_never_produces_the_same_ciphertext() {
        let (mut a, _b) = pair();
        let c1 = a.encrypt(b"same").unwrap();
        let c2 = a.encrypt(b"same").unwrap();
        assert_ne!(c1, c2);
        assert_ne!(&c1[HEADER_LEN..], &c2[HEADER_LEN..]);
    }

    #[test]
    fn out_of_order_within_one_chain() {
        let (mut a, mut b) = pair();
        let msgs: Vec<_> = (0..6u8).map(|i| a.encrypt(&[i]).unwrap()).collect();
        for i in [3usize, 0, 5, 1, 4, 2] {
            assert_eq!(b.decrypt(&msgs[i]).unwrap(), vec![i as u8]);
        }
        assert_eq!(b.skipped_count(), 0, "every cached key was consumed");
    }

    #[test]
    fn late_message_from_an_old_chain_still_decrypts_after_a_dh_step() {
        let (mut a, mut b) = pair();
        let m0 = a.encrypt(b"zero").unwrap();
        let m1 = a.encrypt(b"one").unwrap();
        let m2 = a.encrypt(b"two").unwrap();
        assert_eq!(b.decrypt(&m0).unwrap(), b"zero");
        // m1 is delayed. B replies, A answers with a new ratchet key.
        let r = b.encrypt(b"reply").unwrap();
        assert_eq!(a.decrypt(&r).unwrap(), b"reply");
        let m3 = a.encrypt(b"three").unwrap();
        assert_ne!(m3[..32], m2[..32], "A must have rotated its ratchet key");
        assert_eq!(b.decrypt(&m3).unwrap(), b"three");
        // The delayed ones arrive after the ratchet turned over.
        assert_eq!(b.decrypt(&m2).unwrap(), b"two");
        assert_eq!(b.decrypt(&m1).unwrap(), b"one");
    }

    #[test]
    fn gap_larger_than_max_skip_is_refused_and_state_survives() {
        let (mut a, mut b) = pair();
        let first = a.encrypt(b"first").unwrap();
        for _ in 0..(MAX_SKIP + 5) {
            let _ = a.encrypt(b"x").unwrap();
        }
        let far = a.encrypt(b"far").unwrap();
        assert!(b.decrypt(&far).is_err());
        // The failed attempt must not have advanced anything.
        assert_eq!(b.skipped_count(), 0);
        assert_eq!(b.decrypt(&first).unwrap(), b"first");
    }

    #[test]
    fn gap_of_exactly_max_skip_is_accepted() {
        let (mut a, mut b) = pair();
        let mut all = Vec::new();
        for _ in 0..MAX_SKIP {
            all.push(a.encrypt(b"x").unwrap());
        }
        let last = a.encrypt(b"last").unwrap();
        assert_eq!(b.decrypt(&last).unwrap(), b"last");
        assert_eq!(b.skipped_count() as u32, MAX_SKIP);
        assert_eq!(b.decrypt(&all[0]).unwrap(), b"x");
        assert_eq!(b.decrypt(&all[(MAX_SKIP - 1) as usize]).unwrap(), b"x");
    }

    #[test]
    fn total_skipped_cache_is_bounded() {
        let (mut a, mut b) = pair();
        // Several maximal jumps in a row, each leaving MAX_SKIP keys behind.
        for _ in 0..5 {
            for _ in 0..MAX_SKIP {
                let _ = a.encrypt(b"x").unwrap();
            }
            let m = a.encrypt(b"marker").unwrap();
            assert_eq!(b.decrypt(&m).unwrap(), b"marker");
        }
        assert!(b.skipped_count() <= MAX_STORED_SKIPPED);
    }

    #[test]
    fn replayed_message_is_rejected() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"once").unwrap();
        assert_eq!(b.decrypt(&m).unwrap(), b"once");
        assert!(b.decrypt(&m).is_err());
        // And again after the chain has moved on.
        let m2 = a.encrypt(b"two").unwrap();
        b.decrypt(&m2).unwrap();
        assert!(b.decrypt(&m).is_err());
    }

    #[test]
    fn replay_after_a_dh_step_is_rejected_too() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"old").unwrap();
        b.decrypt(&m).unwrap();
        let r = b.encrypt(b"r").unwrap();
        a.decrypt(&r).unwrap();
        let m2 = a.encrypt(b"new chain").unwrap();
        b.decrypt(&m2).unwrap();
        assert!(b.decrypt(&m).is_err());
    }

    #[test]
    fn flipping_any_single_bit_anywhere_is_rejected_and_state_is_untouched() {
        let (mut a, mut b) = pair();
        let good = a.encrypt(b"integrity matters").unwrap();
        for byte in 0..good.len() {
            for bit in [0u8, 3, 7] {
                let mut bad = good.clone();
                bad[byte] ^= 1 << bit;
                assert!(
                    b.decrypt(&bad).is_err(),
                    "byte {byte} bit {bit} was accepted"
                );
            }
        }
        assert_eq!(b.skipped_count(), 0);
        assert_eq!(b.decrypt(&good).unwrap(), b"integrity matters");
    }

    #[test]
    fn every_truncation_and_the_empty_input_are_rejected() {
        let (mut a, mut b) = pair();
        let good = a.encrypt(b"x").unwrap();
        for len in 0..good.len() {
            assert!(b.decrypt(&good[..len]).is_err(), "length {len} accepted");
        }
        let mut extended = good.clone();
        extended.push(0);
        assert!(b.decrypt(&extended).is_err());
        assert_eq!(b.decrypt(&good).unwrap(), b"x");
    }

    #[test]
    fn empty_plaintext_is_fine() {
        let (mut a, mut b) = pair();
        assert_eq!(b.decrypt(&a.encrypt(b"").unwrap()).unwrap(), b"");
    }

    #[test]
    fn large_plaintext_round_trips() {
        let (mut a, mut b) = pair();
        let big = vec![0xA5u8; 1 << 20];
        assert_eq!(b.decrypt(&a.encrypt(&big).unwrap()).unwrap(), big);
    }

    #[test]
    fn messages_bound_to_a_different_session_are_rejected() {
        let (mut a1, _b1) = Ratchet::pair_from_shared_secret(&[1u8; 32], &[2u8; 32]).unwrap();
        let (_a2, mut b2) = Ratchet::pair_from_shared_secret(&[1u8; 32], &[99u8; 32]).unwrap();
        let m = a1.encrypt(b"cross-session").unwrap();
        assert!(b2.decrypt(&m).is_err());
    }

    #[test]
    fn low_order_and_zero_dh_keys_in_a_header_are_rejected() {
        let (mut a, mut b) = pair();
        let good = a.encrypt(b"hi").unwrap();
        // Order-1 / order-2 / order-8 points on Curve25519 and all-zero.
        let evil: [[u8; 32]; 3] = [
            [0u8; 32],
            {
                let mut p = [0u8; 32];
                p[0] = 1; // u = 1
                p
            },
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
        ];
        for p in evil {
            let mut bad = good.clone();
            bad[..32].copy_from_slice(&p);
            assert!(b.decrypt(&bad).is_err());
        }
        assert_eq!(b.decrypt(&good).unwrap(), b"hi");
    }

    #[test]
    fn forward_secrecy_a_later_state_theft_cannot_open_earlier_traffic() {
        let (mut a, mut b) = pair();
        let early = a.encrypt(b"secret from the past").unwrap();
        assert_eq!(b.decrypt(&early).unwrap(), b"secret from the past");
        let r = b.encrypt(b"r").unwrap();
        a.decrypt(&r).unwrap();
        // Attacker steals B's complete state *after* these were processed
        // and has recorded `early` off the wire.
        let mut stolen = b.clone();
        assert!(stolen.decrypt(&early).is_err());
    }

    #[test]
    fn forward_secrecy_keys_of_delivered_messages_are_not_retained() {
        let (mut a, mut b) = pair();
        let msgs: Vec<_> = (0..10u8).map(|i| a.encrypt(&[i]).unwrap()).collect();
        for m in &msgs {
            b.decrypt(m).unwrap();
        }
        assert_eq!(b.skipped_count(), 0);
        for m in &msgs {
            assert!(b.clone().decrypt(m).is_err());
        }
    }

    #[test]
    fn post_compromise_security_heals_after_one_round_trip() {
        let (mut a, mut b) = pair();
        // Warm up so both sides are on ordinary DH chains.
        for _ in 0..2 {
            b.decrypt(&a.encrypt(b"w").unwrap()).unwrap();
            a.decrypt(&b.encrypt(b"w").unwrap()).unwrap();
        }
        // Attacker steals B's full state right now.
        let mut stolen = b.clone();

        // While the attacker is still "in", they can follow along.
        let during = a.encrypt(b"during compromise").unwrap();
        assert_eq!(stolen.decrypt(&during).unwrap(), b"during compromise");
        b.decrypt(&during).unwrap();

        // The conversation turns over: B replies with a fresh key, A answers.
        let reply = b.encrypt(b"fresh dh from b").unwrap();
        a.decrypt(&reply).unwrap();
        let healed = a.encrypt(b"after healing").unwrap();
        assert_eq!(b.decrypt(&healed).unwrap(), b"after healing");

        // The stolen copy cannot read anything past the healing point, even
        // if it is handed every ciphertext in order.
        assert!(stolen.decrypt(&healed).is_err());
        let healed2 = a.encrypt(b"and more").unwrap();
        assert!(stolen.decrypt(&healed2).is_err());
    }

    #[test]
    fn each_dh_step_rotates_the_senders_public_key() {
        let (mut a, mut b) = pair();
        let k1 = a.own_ratchet_public();
        b.decrypt(&a.encrypt(b"1").unwrap()).unwrap();
        a.decrypt(&b.encrypt(b"2").unwrap()).unwrap();
        let k2 = a.own_ratchet_public();
        assert_ne!(k1, k2);
    }

    #[test]
    fn randomized_reordering_and_loss_never_breaks_decryption_or_leaks_across_messages() {
        for seed in 1..=25u64 {
            let mut rng = XorShift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let (mut a, mut b) = pair();
            // (wire, expected plaintext) in flight in each direction.
            let mut a_to_b: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            let mut b_to_a: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            let mut delivered_ok = 0usize;

            for step in 0..400u32 {
                match rng.below(5) {
                    0 | 1 => {
                        let p = format!("a{seed}-{step}").into_bytes();
                        a_to_b.push((a.encrypt(&p).unwrap(), p));
                    }
                    2 => {
                        let p = format!("b{seed}-{step}").into_bytes();
                        b_to_a.push((b.encrypt(&p).unwrap(), p));
                    }
                    3 if !a_to_b.is_empty() => {
                        let i = rng.below(a_to_b.len());
                        let (w, p) = a_to_b.remove(i);
                        if rng.below(10) == 0 {
                            continue; // lost in transit
                        }
                        assert_eq!(b.decrypt(&w).unwrap(), p, "seed {seed} step {step}");
                        delivered_ok += 1;
                    }
                    4 if !b_to_a.is_empty() => {
                        let i = rng.below(b_to_a.len());
                        let (w, p) = b_to_a.remove(i);
                        if rng.below(10) == 0 {
                            continue;
                        }
                        assert_eq!(a.decrypt(&w).unwrap(), p, "seed {seed} step {step}");
                        delivered_ok += 1;
                    }
                    _ => {}
                }
            }
            assert!(delivered_ok > 20, "seed {seed} exercised too little");
        }
    }

    #[test]
    fn saved_state_round_trips_and_keeps_conversing() {
        let (mut a, mut b) = Ratchet::pair_from_shared_secret(&[5u8; 32], &[6u8; 32]).unwrap();
        let w1 = b.encrypt(b"one").unwrap();
        assert_eq!(a.decrypt(&w1).unwrap(), b"one");
        let w2 = a.encrypt(b"two").unwrap();
        // Leave a gap so the skipped-key cache is non-empty.
        let w3 = a.encrypt(b"three").unwrap();
        assert_eq!(b.decrypt(&w3).unwrap(), b"three");
        assert!(b.skipped_count() > 0);

        let mut b2 = Ratchet::from_bytes(&b.to_bytes()).unwrap();
        let mut a2 = Ratchet::from_bytes(&a.to_bytes()).unwrap();
        assert_eq!(b2.info(), b.info());
        // The late message still decrypts from the RESTORED skipped cache.
        assert_eq!(b2.decrypt(&w2).unwrap(), b"two");
        // And the restored pair keeps talking both ways.
        let w4 = b2.encrypt(b"four").unwrap();
        assert_eq!(a2.decrypt(&w4).unwrap(), b"four");
        let w5 = a2.encrypt(b"five").unwrap();
        assert_eq!(b2.decrypt(&w5).unwrap(), b"five");
    }

    #[test]
    fn saved_state_rejects_truncation_and_trailing_bytes() {
        let (a, _b) = Ratchet::pair_from_shared_secret(&[5u8; 32], &[6u8; 32]).unwrap();
        let bytes = a.to_bytes();
        for cut in 0..bytes.len() {
            assert!(Ratchet::from_bytes(&bytes[..cut]).is_err(), "cut {cut}");
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Ratchet::from_bytes(&extra).is_err());
    }
}
