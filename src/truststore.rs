//! Pluggable trust: WHO we are willing to talk to.
//!
//! The handshake asks one question of this module: "is this public key one
//! the user has approved?" ([`TrustStore::is_trusted`]). Everything else here
//! exists so an application can answer that question its own way and manage
//! the list over time.
//!
//! # Pieces
//! * [`TrustStore`]: the trait. Implement it to keep trusted keys in a
//!   database, the OS keychain, a company directory, etc.
//! * [`MemoryTrustStore`]: in-memory implementation (tests, short-lived tools).
//! * [`FileTrustStore`]: durable implementation. The file is **encrypted and
//!   authenticated** with a key derived from our own identity, so someone who
//!   can write to the data directory but does not hold our identity key
//!   cannot quietly add themselves to the trusted list (a tampered file
//!   fails to open instead of being believed).
//! * The **approval queue** (below).
//!
//! # Approval queue (no TOFU)
//! When an UNKNOWN key attempts a handshake we reject it, exactly as before,
//! but also remember the key in a small queue. The application can show that
//! list ("this key tried to connect") and the user can approve one after
//! verifying it out-of-band. The next connection attempt then succeeds.
//!
//! Why reject-and-record instead of pausing the handshake for a yes/no?
//! A held-open handshake lets any stranger tie up a thread and a socket
//! until a human answers; rejecting immediately keeps the cost to us at one
//! signature check. The queue is bounded ([`MAX_PENDING`]) and de-duplicated
//! so a scanner flooding us with fresh keys can only push old entries out;
//! it can never grow memory without limit and never gets trusted by itself.
//!
//! Note an entry only means "someone CLAIMED this identity": the check runs
//! on the claimed public key BEFORE its signature is verified (the handshake
//! aborts on rejection). Show entries as claims and verify the fingerprint
//! out-of-band before approving. Approving a key nobody holds the private
//! half of is harmless: nobody can then authenticate as it.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;

use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::AeadKey;
use crate::error::{ChatError, Result};
use crate::identity::{fingerprint, Identity, PeerId};
use crate::storage::{open, seal};

/// Most unknown-key attempts remembered at once. Oldest are dropped first.
pub const MAX_PENDING: usize = 64;

/// Cap on trusted keys a file may hold when loading (defends against a
/// corrupt or hostile file making us allocate unboundedly).
const MAX_TRUSTED: usize = 100_000;

/// Where trusted keys live. All methods take `&self`: implementations use
/// interior mutability because one store is shared by many sessions/threads.
pub trait TrustStore: Send + Sync {
    /// Is this exact key approved? Called by the handshake. Must be cheap.
    fn is_trusted(&self, key: &VerifyingKey) -> bool;
    /// Approve a key. Idempotent. Also clears it from the pending queue.
    fn add(&self, key: VerifyingKey) -> Result<()>;
    /// Revoke a key. Returns whether it was present. Existing sessions are
    /// NOT torn down by this call (the session layer decides that).
    fn remove(&self, id: &PeerId) -> Result<bool>;
    /// All approved keys (order unspecified).
    fn list(&self) -> Vec<VerifyingKey>;
    /// Called by the handshake when an unapproved key tried to connect.
    /// Default: ignore (a store without an approval queue).
    fn record_unknown(&self, _key: &VerifyingKey) {}
    /// Unapproved keys that tried to connect, oldest first.
    fn pending(&self) -> Vec<VerifyingKey> {
        Vec::new()
    }
    /// Approve a queued key by fingerprint. `Ok(false)` if it is not queued
    /// (expired out, or never seen), so a typo can't approve something else.
    fn approve(&self, _id: &PeerId) -> Result<bool> {
        Ok(false)
    }
    /// Forget a queued key without approving it.
    fn dismiss(&self, _id: &PeerId) {}
}

#[derive(Default)]
struct Inner {
    trusted: HashMap<PeerId, VerifyingKey>,
    pending: VecDeque<(PeerId, VerifyingKey)>,
}

/// In-memory [`TrustStore`] with the approval queue.
#[derive(Default)]
pub struct MemoryTrustStore {
    inner: Mutex<Inner>,
}

impl MemoryTrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    // Poisoning can only happen if another thread panicked while holding the
    // lock; the data is plain maps, so continuing is safe.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl TrustStore for MemoryTrustStore {
    fn is_trusted(&self, key: &VerifyingKey) -> bool {
        self.lock().trusted.contains_key(&fingerprint(key))
    }
    fn add(&self, key: VerifyingKey) -> Result<()> {
        let id = fingerprint(&key);
        let mut g = self.lock();
        g.pending.retain(|(p, _)| *p != id);
        g.trusted.insert(id, key);
        Ok(())
    }
    fn remove(&self, id: &PeerId) -> Result<bool> {
        Ok(self.lock().trusted.remove(id).is_some())
    }
    fn list(&self) -> Vec<VerifyingKey> {
        self.lock().trusted.values().copied().collect()
    }
    fn record_unknown(&self, key: &VerifyingKey) {
        let id = fingerprint(key);
        let mut g = self.lock();
        if g.trusted.contains_key(&id) || g.pending.iter().any(|(p, _)| *p == id) {
            return; // de-duplicate: a repeat attempt neither grows nor reorders the queue
        }
        if g.pending.len() >= MAX_PENDING {
            g.pending.pop_front();
        }
        g.pending.push_back((id, *key));
    }
    fn pending(&self) -> Vec<VerifyingKey> {
        self.lock().pending.iter().map(|(_, k)| *k).collect()
    }
    fn approve(&self, id: &PeerId) -> Result<bool> {
        let mut g = self.lock();
        let Some(pos) = g.pending.iter().position(|(p, _)| p == id) else {
            return Ok(false);
        };
        let (pid, key) = g.pending.remove(pos).expect("position just found");
        g.trusted.insert(pid, key);
        Ok(true)
    }
    fn dismiss(&self, id: &PeerId) {
        self.lock().pending.retain(|(p, _)| p != id);
    }
}

/// Derive the key protecting the trust file from our identity. Separate HKDF
/// label from every other use of the identity secret.
fn derive_trust_key(identity: &Identity) -> AeadKey {
    let hk = Hkdf::<Sha256>::new(None, &identity.secret_bytes());
    let mut out = [0u8; 32];
    hk.expand(b"symbolon/truststore/key/v1", &mut out)
        .expect("32 bytes is a valid HKDF output length");
    AeadKey(out)
}

/// Durable [`TrustStore`]: one file holding `seal(key, concat(32-byte keys))`.
/// Every change rewrites the file atomically (temp file + rename), so a crash
/// leaves either the old or the new list, never a torn one.
pub struct FileTrustStore {
    path: PathBuf,
    key: AeadKey,
    mem: MemoryTrustStore,
}

impl FileTrustStore {
    /// Open (or create empty, in memory until the first change) the trust
    /// file at `path`, protected by a key derived from `identity`.
    ///
    /// Fails if the file exists but does not authenticate (wrong identity,
    /// corruption or tampering): we refuse to guess rather than start with
    /// an empty or attacker-chosen list.
    pub fn open(path: impl Into<PathBuf>, identity: &Identity) -> Result<Self> {
        let path = path.into();
        let key = derive_trust_key(identity);
        let mem = MemoryTrustStore::new();
        match std::fs::read(&path) {
            Ok(bytes) => {
                let plain = open(&key, &bytes)?;
                if plain.len() % 32 != 0 || plain.len() / 32 > MAX_TRUSTED {
                    return Err(ChatError::MalformedMessage(
                        "trust file has an invalid length",
                    ));
                }
                for chunk in plain.chunks_exact(32) {
                    let arr: [u8; 32] = chunk.try_into().expect("chunk is 32 bytes");
                    let k =
                        VerifyingKey::from_bytes(&arr).map_err(|_| ChatError::InvalidPublicKey)?;
                    mem.add(k)?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(ChatError::Io(e)),
        }
        Ok(FileTrustStore { path, key, mem })
    }

    fn flush(&self) -> Result<()> {
        let mut plain = Vec::new();
        for k in self.mem.list() {
            plain.extend_from_slice(k.as_bytes());
        }
        let sealed = seal(&self.key, &plain)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &sealed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

impl TrustStore for FileTrustStore {
    fn is_trusted(&self, key: &VerifyingKey) -> bool {
        self.mem.is_trusted(key)
    }
    fn add(&self, key: VerifyingKey) -> Result<()> {
        self.mem.add(key)?;
        self.flush()
    }
    fn remove(&self, id: &PeerId) -> Result<bool> {
        let had = self.mem.remove(id)?;
        if had {
            self.flush()?;
        }
        Ok(had)
    }
    fn list(&self) -> Vec<VerifyingKey> {
        self.mem.list()
    }
    fn record_unknown(&self, key: &VerifyingKey) {
        self.mem.record_unknown(key)
    }
    fn pending(&self) -> Vec<VerifyingKey> {
        self.mem.pending()
    }
    fn approve(&self, id: &PeerId) -> Result<bool> {
        let ok = self.mem.approve(id)?;
        if ok {
            self.flush()?;
        }
        Ok(ok)
    }
    fn dismiss(&self, id: &PeerId) {
        self.mem.dismiss(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> VerifyingKey {
        Identity::generate().public_key()
    }

    #[test]
    fn memory_add_remove() {
        let s = MemoryTrustStore::new();
        let k = key();
        assert!(!s.is_trusted(&k));
        s.add(k).unwrap();
        assert!(s.is_trusted(&k));
        assert!(s.remove(&fingerprint(&k)).unwrap());
        assert!(!s.is_trusted(&k));
        assert!(!s.remove(&fingerprint(&k)).unwrap());
    }

    #[test]
    fn unknown_is_queued_deduped_and_approvable() {
        let s = MemoryTrustStore::new();
        let k = key();
        s.record_unknown(&k);
        s.record_unknown(&k);
        assert_eq!(s.pending().len(), 1);
        assert!(!s.is_trusted(&k), "queueing must never trust");
        assert!(s.approve(&fingerprint(&k)).unwrap());
        assert!(s.is_trusted(&k));
        assert!(s.pending().is_empty());
        assert!(
            !s.approve(&fingerprint(&k)).unwrap(),
            "second approve is a no-op"
        );
    }

    #[test]
    fn cannot_approve_what_was_never_seen() {
        let s = MemoryTrustStore::new();
        assert!(!s.approve(&fingerprint(&key())).unwrap());
    }

    #[test]
    fn queue_is_bounded_oldest_dropped() {
        let s = MemoryTrustStore::new();
        let first = key();
        s.record_unknown(&first);
        for _ in 0..MAX_PENDING {
            s.record_unknown(&key());
        }
        assert_eq!(s.pending().len(), MAX_PENDING);
        assert!(!s.pending().contains(&first));
    }

    #[test]
    fn dismiss_forgets() {
        let s = MemoryTrustStore::new();
        let k = key();
        s.record_unknown(&k);
        s.dismiss(&fingerprint(&k));
        assert!(s.pending().is_empty());
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("symbolon-ts-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("trust.bin")
    }

    #[test]
    fn file_roundtrip() {
        let id = Identity::generate();
        let p = tmp("rt");
        let k = key();
        {
            let s = FileTrustStore::open(&p, &id).unwrap();
            s.add(k).unwrap();
        }
        let s = FileTrustStore::open(&p, &id).unwrap();
        assert!(s.is_trusted(&k));
        assert_eq!(s.list().len(), 1);
    }

    #[test]
    fn file_approve_and_remove_persist() {
        let id = Identity::generate();
        let p = tmp("ar");
        let k = key();
        let s = FileTrustStore::open(&p, &id).unwrap();
        s.record_unknown(&k);
        s.approve(&fingerprint(&k)).unwrap();
        assert!(FileTrustStore::open(&p, &id).unwrap().is_trusted(&k));
        s.remove(&fingerprint(&k)).unwrap();
        assert!(!FileTrustStore::open(&p, &id).unwrap().is_trusted(&k));
    }

    #[test]
    fn file_tamper_and_wrong_identity_rejected() {
        let id = Identity::generate();
        let p = tmp("tp");
        FileTrustStore::open(&p, &id).unwrap().add(key()).unwrap();
        // Wrong identity cannot read it.
        assert!(FileTrustStore::open(&p, &Identity::generate()).is_err());
        // A flipped bit is detected, not believed.
        let mut b = std::fs::read(&p).unwrap();
        let n = b.len();
        b[n - 1] ^= 1;
        std::fs::write(&p, b).unwrap();
        assert!(FileTrustStore::open(&p, &id).is_err());
    }

    #[test]
    fn attacker_cannot_forge_file_without_identity_key() {
        let id = Identity::generate();
        let p = tmp("fg");
        // Attacker writes a plausible file sealed under a key they chose.
        let evil = key();
        let forged = seal(&AeadKey([9u8; 32]), evil.as_bytes()).unwrap();
        std::fs::write(&p, forged).unwrap();
        assert!(FileTrustStore::open(&p, &id).is_err());
    }
}
