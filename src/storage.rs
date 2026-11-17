//! Pluggable storage: WHERE the library's durable state lives.
//!
//! Symbolon is a protocol library, not an application, so it does not decide
//! whether your data goes in a file, SQLite, a cloud bucket, or the OS
//! keychain. It talks to three small traits instead, and ships simple file
//! and in-memory implementations so it works out of the box:
//!
//! | trait          | holds                                   | file impl            | memory impl           |
//! |----------------|-----------------------------------------|----------------------|-----------------------|
//! | [`EventStore`] | append-only log (group roster + content)| [`FileEventStore`]   | [`MemoryEventStore`]  |
//! | [`KeyStore`]   | the long-term identity (private key)    | [`FileKeyStore`]     | [`MemoryKeyStore`]    |
//! | [`StateStore`] | small named blobs (session/ratchet state)| [`FileStateStore`]  | [`MemoryStateStore`]  |
//!
//! # Who encrypts what
//! * **Event log and state blobs: the library encrypts BEFORE handing bytes
//!   to the store** (see [`SealedEventStore`], [`seal`], [`open`]). A store
//!   implementation therefore only ever sees ciphertext, so a careless or
//!   untrusted backend (a shared database, a sync service) cannot read chat
//!   content. It can still delete or truncate data - that is availability,
//!   not confidentiality, and integrity is caught on replay.
//! * **Identity: the [`KeyStore`] itself is responsible for protection**,
//!   because the right answer depends on the platform (passphrase-encrypted
//!   file, OS keychain, hardware token). [`FileKeyStore`] uses
//!   [`crate::persistence::EncryptedIdentity`].
//!
//! # Retention
//! Nothing here deletes, expires or caps anything. Limits and deletion
//! periods are the application's decision (see NOTES.md).
//!
//! # Error handling
//! Storage can fail (disk full, permissions, network drive gone). Methods
//! return [`Result`]; the group hub records a failed append and exposes it
//! via `GroupHub::persistence_healthy`, rather than silently losing history.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chacha20poly1305::{aead::Aead, aead::KeyInit, ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::AeadKey;
use crate::error::{ChatError, Result};
use crate::framing::{read_frame, write_frame};
use crate::identity::Identity;
use crate::persistence::EncryptedIdentity;

// ---------------------------------------------------------------------------
// Sealing helpers (library-side encryption of what stores receive)
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` under `key` with a fresh random 96-bit nonce.
/// Output layout: `nonce (12) || ciphertext+tag`. This is the same record
/// layout the original encrypted event log used, so existing log files stay
/// readable.
pub fn seal(key: &AeadKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| ChatError::DecryptionFailed)?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`seal`]. Any failure (wrong key, corruption, tampering) is
/// reported as [`ChatError::DecryptionFailed`], as for every AEAD in the crate.
pub fn open(key: &AeadKey, sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < 12 {
        return Err(ChatError::MalformedMessage("sealed record too short"));
    }
    let (nonce_bytes, ct) = sealed.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| ChatError::DecryptionFailed)
}

// ---------------------------------------------------------------------------
// EventStore
// ---------------------------------------------------------------------------

/// An append-only sequence of opaque records. Implement this to keep the
/// group log somewhere other than a local file.
///
/// Contract: `append` is atomic per record (a record is either fully there
/// or not at all), order is preserved, and `read_all` returns every record
/// ever appended, oldest first. Records are opaque ciphertext to the store.
pub trait EventStore: Send + Sync {
    /// Add one record at the end.
    fn append(&self, record: &[u8]) -> Result<()>;
    /// Force everything appended so far to durable storage (fsync or the
    /// backend's equivalent). Separate from `append` because syncing every
    /// record is a real throughput cost callers should opt into.
    fn sync(&self) -> Result<()>;
    /// Return all records, oldest first.
    fn read_all(&self) -> Result<Vec<Vec<u8>>>;
}

/// File-backed [`EventStore`]: length-prefixed records appended to one file
/// (the same framing the network layer uses).
pub struct FileEventStore {
    path: PathBuf,
    file: Mutex<File>,
}

impl FileEventStore {
    /// Open (creating if needed) the log file at `path`. On Unix a new file
    /// is created owner-only (0600).
    pub fn open(path: &Path) -> Result<FileEventStore> {
        let mut opts = OpenOptions::new();
        opts.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path)?;
        Ok(FileEventStore {
            path: path.to_path_buf(),
            file: Mutex::new(file),
        })
    }
}

impl EventStore for FileEventStore {
    fn append(&self, record: &[u8]) -> Result<()> {
        // `write_frame` issues a single write_all, so a crash can leave at
        // worst one torn record at the very end (see `read_all`).
        write_frame(&mut *self.file.lock().unwrap(), record)
    }

    fn sync(&self) -> Result<()> {
        self.file.lock().unwrap().sync_all()?;
        Ok(())
    }

    fn read_all(&self) -> Result<Vec<Vec<u8>>> {
        // A separate read handle, so the append position is undisturbed.
        let mut f = OpenOptions::new().read(true).open(&self.path)?;
        f.seek(SeekFrom::Start(0))?;
        let mut out = Vec::new();
        loop {
            match read_frame(&mut f) {
                Ok(r) => out.push(r),
                // Clean EOF between records.
                Err(ChatError::ConnectionClosed) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
}

/// In-memory [`EventStore`] for tests and simulation. Lost when dropped.
#[derive(Default)]
pub struct MemoryEventStore {
    records: Mutex<Vec<Vec<u8>>>,
}

impl MemoryEventStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl EventStore for MemoryEventStore {
    fn append(&self, record: &[u8]) -> Result<()> {
        self.records.lock().unwrap().push(record.to_vec());
        Ok(())
    }
    fn sync(&self) -> Result<()> {
        Ok(())
    }
    fn read_all(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.records.lock().unwrap().clone())
    }
}

/// Wraps any [`EventStore`] so every record is encrypted (with [`seal`])
/// on the way in and decrypted on the way out. This is how the group hub
/// guarantees the backend only sees ciphertext.
pub struct SealedEventStore<S: EventStore> {
    inner: S,
    key: AeadKey,
}

impl<S: EventStore> SealedEventStore<S> {
    pub fn new(inner: S, key: AeadKey) -> Self {
        SealedEventStore { inner, key }
    }
}

impl<S: EventStore> EventStore for SealedEventStore<S> {
    fn append(&self, record: &[u8]) -> Result<()> {
        self.inner.append(&seal(&self.key, record)?)
    }
    fn sync(&self) -> Result<()> {
        self.inner.sync()
    }
    fn read_all(&self) -> Result<Vec<Vec<u8>>> {
        self.inner
            .read_all()?
            .iter()
            .map(|r| open(&self.key, r))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// KeyStore
// ---------------------------------------------------------------------------

/// Custody of the long-term identity. The store is responsible for
/// protecting the private key at rest (passphrase, OS keychain, HSM...).
pub trait KeyStore: Send + Sync {
    /// Is an identity stored? Must not require unlocking.
    fn exists(&self) -> bool;
    /// Load (unlock) the identity.
    fn load(&self) -> Result<Identity>;
    /// Store `identity`, replacing any existing one.
    fn save(&self, identity: &Identity) -> Result<()>;
}

/// Passphrase-encrypted file ([`EncryptedIdentity`]). The passphrase is held
/// in a zeroizing buffer for the life of the store.
pub struct FileKeyStore {
    path: PathBuf,
    passphrase: Zeroizing<String>,
}

impl FileKeyStore {
    pub fn new(path: impl Into<PathBuf>, passphrase: &str) -> Self {
        FileKeyStore {
            path: path.into(),
            passphrase: Zeroizing::new(passphrase.to_string()),
        }
    }
}

impl KeyStore for FileKeyStore {
    fn exists(&self) -> bool {
        self.path.exists()
    }
    fn load(&self) -> Result<Identity> {
        EncryptedIdentity::load(&self.path, &self.passphrase)
    }
    fn save(&self, identity: &Identity) -> Result<()> {
        EncryptedIdentity::save(identity, &self.path, &self.passphrase)
    }
}

/// Holds the identity's secret bytes in process memory (zeroized on drop).
/// For tests and simulation only: nothing survives a restart.
#[derive(Default)]
pub struct MemoryKeyStore {
    secret: Mutex<Option<Zeroizing<[u8; 32]>>>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn exists(&self) -> bool {
        self.secret.lock().unwrap().is_some()
    }
    fn load(&self) -> Result<Identity> {
        match &*self.secret.lock().unwrap() {
            Some(s) => Ok(Identity::from_bytes(s)),
            None => Err(ChatError::MalformedMessage("no identity stored")),
        }
    }
    fn save(&self, identity: &Identity) -> Result<()> {
        *self.secret.lock().unwrap() = Some(Zeroizing::new(identity.secret_bytes()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// StateStore
// ---------------------------------------------------------------------------

/// Small named blobs: per-peer session / ratchet state, trust lists, cursors.
/// Keys are short ASCII names (`[A-Za-z0-9._-]`, max 128 chars); anything
/// else is rejected so a file-backed store can never be steered outside its
/// directory. Values are opaque (callers [`seal`] them first).
pub trait StateStore: Send + Sync {
    fn put(&self, key: &str, value: &[u8]) -> Result<()>;
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn delete(&self, key: &str) -> Result<()>;
    /// All keys currently stored (order unspecified).
    fn keys(&self) -> Result<Vec<String>>;
}

fn check_key(key: &str) -> Result<()> {
    let ok = !key.is_empty()
        && key.len() <= 128
        && key != "."
        && key != ".."
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(ChatError::MalformedMessage("invalid state key"))
    }
}

/// One file per key inside a directory. Writes are crash-safe: data goes to
/// a temporary file that is fsynced and then atomically renamed over the
/// target, so a reader sees the old value or the new one, never half.
pub struct FileStateStore {
    dir: PathBuf,
}

impl FileStateStore {
    /// Use (creating if needed) `dir`. On Unix the directory is 0700.
    pub fn open(dir: impl Into<PathBuf>) -> Result<FileStateStore> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(FileStateStore { dir })
    }
}

impl StateStore for FileStateStore {
    fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        check_key(key)?;
        // A UNIQUE temp name per write: two writers saving the same key at
        // once (e.g. two sessions with the same peer) must not share one
        // temp file, or one rename would pull it out from under the other
        // ("No such file or directory"). The last rename wins; each write is
        // still all-or-nothing.
        static NEXT_TMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT_TMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = self
            .dir
            .join(format!(".{key}.{}.{n}.tmp", std::process::id()));
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(value)?;
        f.sync_all()?;
        if let Err(e) = std::fs::rename(&tmp, self.dir.join(key)) {
            let _ = std::fs::remove_file(&tmp); // don't leave litter behind
            return Err(e.into());
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        check_key(key)?;
        match File::open(self.dir.join(key)) {
            Ok(mut f) => {
                let mut v = Vec::new();
                f.read_to_end(&mut v)?;
                Ok(Some(v))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        check_key(key)?;
        match std::fs::remove_file(self.dir.join(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn keys(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if !name.starts_with('.') {
                out.push(name); // skips in-flight ".tmp" files
            }
        }
        Ok(out)
    }
}

/// In-memory [`StateStore`] for tests and simulation.
#[derive(Default)]
pub struct MemoryStateStore {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateStore for MemoryStateStore {
    fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        check_key(key)?;
        self.map
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_vec());
        Ok(())
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        check_key(key)?;
        Ok(self.map.lock().unwrap().get(key).cloned())
    }
    fn delete(&self, key: &str) -> Result<()> {
        check_key(key)?;
        self.map.lock().unwrap().remove(key);
        Ok(())
    }
    fn keys(&self) -> Result<Vec<String>> {
        Ok(self.map.lock().unwrap().keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("symbolon-storage-{name}-{}", std::process::id()));
        p
    }

    #[test]
    fn concurrent_puts_to_one_key_never_fail() {
        let dir = tmp("concurrent");
        let store = std::sync::Arc::new(FileStateStore::open(&dir).unwrap());
        let handles: Vec<_> = (0..8u8)
            .map(|t| {
                let store = std::sync::Arc::clone(&store);
                std::thread::spawn(move || {
                    for i in 0..50u8 {
                        store.put("shared", &[t, i]).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        // Whatever won, it is one writer's complete value.
        let v = store.get("shared").unwrap().unwrap();
        assert_eq!(v.len(), 2);
        // No temp litter left behind.
        assert!(std::fs::read_dir(&dir).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn key() -> AeadKey {
        AeadKey([7u8; 32])
    }

    #[test]
    fn seal_open_round_trip_and_tamper_detection() {
        let s = seal(&key(), b"hello").unwrap();
        assert_eq!(open(&key(), &s).unwrap(), b"hello");
        let mut bad = s.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(matches!(
            open(&key(), &bad),
            Err(ChatError::DecryptionFailed)
        ));
        assert!(matches!(
            open(&AeadKey([8u8; 32]), &s),
            Err(ChatError::DecryptionFailed)
        ));
        assert!(open(&key(), &[0u8; 5]).is_err());
    }

    #[test]
    fn seal_uses_fresh_nonces() {
        assert_ne!(seal(&key(), b"x").unwrap(), seal(&key(), b"x").unwrap());
    }

    fn exercise_event_store(s: &dyn EventStore) {
        assert!(s.read_all().unwrap().is_empty());
        s.append(b"one").unwrap();
        s.append(b"").unwrap(); // empty records are legal
        s.append(&vec![9u8; 100_000]).unwrap();
        s.sync().unwrap();
        let all = s.read_all().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0], b"one");
        assert!(all[1].is_empty());
        assert_eq!(all[2].len(), 100_000);
    }

    #[test]
    fn memory_event_store_contract() {
        exercise_event_store(&MemoryEventStore::new());
    }

    #[test]
    fn file_event_store_contract_and_reopen() {
        let p = tmp("events");
        let _ = std::fs::remove_file(&p);
        exercise_event_store(&FileEventStore::open(&p).unwrap());
        // Reopening sees the old records and appends after them.
        let again = FileEventStore::open(&p).unwrap();
        again.append(b"four").unwrap();
        assert_eq!(again.read_all().unwrap().len(), 4);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn sealed_store_hides_plaintext_from_backend() {
        let backend = std::sync::Arc::new(MemoryEventStore::new());
        struct Shared(std::sync::Arc<MemoryEventStore>);
        impl EventStore for Shared {
            fn append(&self, r: &[u8]) -> Result<()> {
                self.0.append(r)
            }
            fn sync(&self) -> Result<()> {
                self.0.sync()
            }
            fn read_all(&self) -> Result<Vec<Vec<u8>>> {
                self.0.read_all()
            }
        }
        let sealed = SealedEventStore::new(Shared(backend.clone()), key());
        sealed.append(b"top secret chat line").unwrap();
        let raw = backend.read_all().unwrap();
        assert!(
            !raw[0].windows(10).any(|w| w == b"top secret"),
            "backend must only see ciphertext"
        );
        assert_eq!(sealed.read_all().unwrap()[0], b"top secret chat line");
        // Wrong key fails loudly.
        let wrong = SealedEventStore::new(Shared(backend), AeadKey([1u8; 32]));
        assert!(wrong.read_all().is_err());
    }

    #[test]
    fn key_stores_round_trip() {
        let id = Identity::generate();
        let m = MemoryKeyStore::new();
        assert!(!m.exists() && m.load().is_err());
        m.save(&id).unwrap();
        assert_eq!(m.load().unwrap().fingerprint(), id.fingerprint());

        let p = tmp("key");
        let _ = std::fs::remove_file(&p);
        let f = FileKeyStore::new(&p, "pw");
        assert!(!f.exists());
        crate::persistence::EncryptedIdentity::save_with_params(
            &id,
            &p,
            "pw",
            crate::persistence::KdfParams::insecure_fast_for_tests(),
        )
        .unwrap();
        assert!(f.exists());
        assert_eq!(f.load().unwrap().fingerprint(), id.fingerprint());
        assert!(FileKeyStore::new(&p, "nope").load().is_err());
        let _ = std::fs::remove_file(&p);
    }

    fn exercise_state_store(s: &dyn StateStore) {
        assert_eq!(s.get("a").unwrap(), None);
        s.put("a", b"1").unwrap();
        s.put("a", b"22").unwrap(); // overwrite
        s.put("peer-1.ratchet", b"xyz").unwrap();
        assert_eq!(s.get("a").unwrap().unwrap(), b"22");
        let mut keys = s.keys().unwrap();
        keys.sort();
        assert_eq!(keys, vec!["a", "peer-1.ratchet"]);
        s.delete("a").unwrap();
        s.delete("a").unwrap(); // deleting twice is fine
        assert_eq!(s.get("a").unwrap(), None);
    }

    #[test]
    fn state_stores_contract() {
        exercise_state_store(&MemoryStateStore::new());
        let d = tmp("state");
        let _ = std::fs::remove_dir_all(&d);
        exercise_state_store(&FileStateStore::open(&d).unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn state_keys_cannot_escape_the_directory() {
        let d = tmp("traversal");
        let _ = std::fs::remove_dir_all(&d);
        let s = FileStateStore::open(&d).unwrap();
        for bad in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            "a\\b",
            "x\0y",
            "sp ace",
            &"k".repeat(129),
        ] {
            assert!(s.put(bad, b"v").is_err(), "key {bad:?} must be rejected");
            assert!(s.get(bad).is_err());
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn file_stores_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("perms");
        let _ = std::fs::remove_dir_all(&d);
        let s = FileStateStore::open(&d).unwrap();
        s.put("k", b"v").unwrap();
        assert_eq!(
            std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(d.join("k")).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
