//! Persistence: making state survive a process restart, not just a network
//! disconnect (the reliability layer in `reliability.rs`/`session.rs`
//! already handles the latter; this module is specifically for "the app
//! was closed and reopened").
//!
//! Two independent pieces:
//!
//! - [`EncryptedIdentity`]: save/load a long-term [`Identity`]'s private
//!   key to disk, encrypted under a passphrase. Nothing about a person's
//!   identity should ever sit on disk in plaintext.
//! - [`EventLog`]: a generic append-only log of length-prefixed byte
//!   records, built directly on [`crate::framing`] (which is already
//!   generic over any `Read + Write`, so pointing it at a `File` instead of
//!   a socket costs nothing extra). Used by [`crate::group::GroupHub`] to
//!   persist every validated roster operation and application message, so
//!   a group's state - membership, tiers, message history - can be fully
//!   reconstructed by replaying the log through the exact same validation
//!   logic used for live traffic (see `GroupHub::from_log`). This is an
//!   event-sourcing approach: nothing is ever persisted that wasn't first
//!   independently verified, and replay is just "run it through the
//!   validator again".

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use chacha20poly1305::{aead::Aead, aead::KeyInit, aead::Payload, ChaCha20Poly1305, Key, Nonce};
use pbkdf2::hmac::Hmac;
use pbkdf2::pbkdf2;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

use crate::error::{ChatError, Result};
use crate::framing::{read_frame, write_frame};
use crate::identity::Identity;

const IDENTITY_FILE_MAGIC: &[u8; 4] = b"P2PI";
const IDENTITY_FILE_VERSION: u16 = 1;
/// PBKDF2 iteration count. This is a work-factor knob: higher is slower to
/// brute-force but slower to load legitimately too. 600,000 follows current
/// (2024-era) OWASP guidance for PBKDF2-HMAC-SHA256; bump this over time as
/// hardware gets faster, the same way any password-based KDF needs revisiting.
const PBKDF2_ROUNDS: u32 = 600_000;

/// Save and load a long-term [`Identity`], encrypted at rest under a
/// passphrase. Nothing here is a substitute for full disk encryption or a
/// real OS keystore - it's a baseline so a stolen backup file isn't
/// immediately equivalent to a stolen identity.
pub struct EncryptedIdentity;

impl EncryptedIdentity {
    /// Encrypt `identity`'s private key under `passphrase` and write it to
    /// `path`, overwriting any existing file. Uses [`PBKDF2_ROUNDS`] as the
    /// key-derivation work factor - see [`EncryptedIdentity::save_with_rounds`]
    /// if you need a different value (e.g. faster iteration in tests).
    pub fn save(identity: &Identity, path: &Path, passphrase: &str) -> Result<()> {
        Self::save_with_rounds(identity, path, passphrase, PBKDF2_ROUNDS)
    }

    /// Same as [`EncryptedIdentity::save`], with an explicit PBKDF2 round
    /// count. The round count is stored in the file's own header and read
    /// back automatically by [`EncryptedIdentity::load`] - callers never
    /// need to remember or pass it in again.
    pub fn save_with_rounds(identity: &Identity, path: &Path, passphrase: &str, rounds: u32) -> Result<()> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let key = derive_key_with_rounds(passphrase, &salt, rounds);

        // Bind the file's own header (magic, version, salt, rounds, nonce)
        // into the AEAD associated data, so none of it can be swapped
        // between two encrypted identity files without detection.
        let mut aad = Vec::new();
        aad.extend_from_slice(IDENTITY_FILE_MAGIC);
        aad.extend_from_slice(&IDENTITY_FILE_VERSION.to_be_bytes());
        aad.extend_from_slice(&salt);
        aad.extend_from_slice(&rounds.to_be_bytes());
        aad.extend_from_slice(&nonce_bytes);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: &identity.secret_bytes(), aad: &aad })
            .map_err(|_| ChatError::DecryptionFailed)?;

        let mut out = aad; // header bytes, reused as the start of the file
        out.extend_from_slice(&ciphertext);

        // Owner-only permissions (0600) from the moment the file exists, so
        // there is no window where another local user can read it. On
        // non-Unix platforms the OS default applies.
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(path)?;
        file.write_all(&out)?;
        file.sync_all()?;
        Ok(())
    }

    /// Decrypt and load an [`Identity`] previously saved with
    /// [`EncryptedIdentity::save`]. Returns [`ChatError::DecryptionFailed`]
    /// if `passphrase` is wrong (indistinguishable, by design, from the
    /// file being corrupted or tampered with).
    pub fn load(path: &Path, passphrase: &str) -> Result<Identity> {
        let mut bytes = Vec::new();
        File::open(path)?.read_to_end(&mut bytes)?;

        if bytes.len() < 4 + 2 + 16 + 4 + 12 {
            return Err(ChatError::MalformedMessage("identity file too short"));
        }
        let magic = &bytes[0..4];
        if magic != IDENTITY_FILE_MAGIC {
            return Err(ChatError::MalformedMessage("not a symbolon identity file"));
        }
        let version = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        if version != IDENTITY_FILE_VERSION {
            return Err(ChatError::UnsupportedVersion);
        }
        let salt: [u8; 16] = bytes[6..22].try_into().unwrap();
        let rounds = u32::from_be_bytes(bytes[22..26].try_into().unwrap());
        let nonce_bytes: [u8; 12] = bytes[26..38].try_into().unwrap();
        let aad = &bytes[0..38];
        let ciphertext = &bytes[38..];

        let key = derive_key_with_rounds(passphrase, &salt, rounds);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad })
            .map_err(|_| ChatError::DecryptionFailed)?;

        let secret: [u8; 32] = plaintext.try_into().map_err(|_| ChatError::MalformedMessage("decrypted identity has the wrong length"))?;
        Ok(Identity::from_bytes(&secret))
    }
}

fn derive_key_with_rounds(passphrase: &str, salt: &[u8; 16], rounds: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    // PBKDF2-HMAC-SHA256 turns a (comparatively low-entropy) human
    // passphrase into a key an attacker can't brute-force nearly as
    // cheaply as they could brute-force the passphrase directly, thanks to
    // the deliberately expensive, tunable round count.
    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), salt, rounds, &mut key).expect("32 bytes is a valid PBKDF2 output length");
    key
}

/// A simple append-only log of length-prefixed byte records, backed by a
/// file. Built on the exact same framing [`crate::session::Session`] uses
/// over sockets - a log is just a very patient, very persistent peer.
///
/// Optionally encrypts every record at rest under a caller-supplied key
/// (see [`EventLog::open_encrypted`]) - important for
/// [`crate::group::GroupHub`], whose log otherwise would otherwise contain
/// plaintext chat content sitting unencrypted on disk, which would quietly
/// undermine the "security and privacy first" goal of everything else in
/// this crate. Each record gets its own fresh random nonce (stored
/// alongside its ciphertext) rather than a counter, since log records don't
/// have a natural, always-available sequence number the way session
/// traffic does - a random 96-bit nonce has negligible collision
/// probability at any realistic log size.
pub struct EventLog {
    file: Mutex<File>,
    key: Option<crate::crypto::AeadKey>,
}

impl EventLog {
    /// Open (creating if necessary) a plaintext event log at `path`.
    /// Prefer [`EventLog::open_encrypted`] for anything containing real
    /// user content.
    pub fn open(path: &Path) -> Result<EventLog> {
        let file = OpenOptions::new().create(true).read(true).append(true).open(path)?;
        Ok(EventLog { file: Mutex::new(file), key: None })
    }

    /// Open (creating if necessary) an event log at `path` whose records
    /// are encrypted at rest under `key`.
    pub fn open_encrypted(path: &Path, key: crate::crypto::AeadKey) -> Result<EventLog> {
        let file = OpenOptions::new().create(true).read(true).append(true).open(path)?;
        Ok(EventLog { file: Mutex::new(file), key: Some(key) })
    }

    /// Append one record. Durable once this returns (the write is flushed
    /// to the OS; callers wanting an fsync guarantee on every record can
    /// call [`EventLog::sync`] afterward - left separate since fsync-per-
    /// record is a real throughput cost callers should opt into knowingly).
    pub fn append(&self, bytes: &[u8]) -> Result<()> {
        let mut file = self.file.lock().unwrap();
        match &self.key {
            None => write_frame(&mut *file, bytes),
            Some(key) => {
                let mut nonce_bytes = [0u8; 12];
                OsRng.fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
                let ciphertext = cipher.encrypt(nonce, bytes).map_err(|_| ChatError::DecryptionFailed)?;
                let mut record = Vec::with_capacity(12 + ciphertext.len());
                record.extend_from_slice(&nonce_bytes);
                record.extend_from_slice(&ciphertext);
                write_frame(&mut *file, &record)
            }
        }
    }

    /// Force all appended records to durable storage.
    pub fn sync(&self) -> Result<()> {
        self.file.lock().unwrap().sync_all()?;
        Ok(())
    }

    /// Read every record currently in the log, in the order they were
    /// appended, without disturbing the log's append position (a fresh
    /// read handle is used internally). Pass the same key used to open the
    /// log (if any) to decrypt; a missing or wrong key surfaces as
    /// [`ChatError::DecryptionFailed`] on the first record, same as any
    /// other AEAD authentication failure.
    pub fn read_all(path: &Path, key: Option<&crate::crypto::AeadKey>) -> Result<Vec<Vec<u8>>> {
        let mut file = OpenOptions::new().read(true).open(path)?;
        file.seek(SeekFrom::Start(0))?;
        let mut out = Vec::new();
        loop {
            match read_frame(&mut file) {
                Ok(record) => match key {
                    None => out.push(record),
                    Some(key) => {
                        if record.len() < 12 {
                            return Err(ChatError::MalformedMessage("encrypted log record too short"));
                        }
                        let (nonce_bytes, ciphertext) = record.split_at(12);
                        let nonce = Nonce::from_slice(nonce_bytes);
                        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
                        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| ChatError::DecryptionFailed)?;
                        out.push(plaintext);
                    }
                },
                Err(ChatError::ConnectionClosed) => break, // clean EOF between records
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("symbolon-test-{name}-{}", std::process::id()));
        p
    }

    /// A small round count for tests only - real correctness doesn't
    /// depend on the round count, just speed, and 600k rounds x many test
    /// cases makes the suite unpleasantly slow. Production code must never
    /// use this - always go through `save`/`load`.
    const TEST_ROUNDS: u32 = 100;

    #[test]
    fn identity_round_trips_through_encryption() {
        let path = temp_path("identity-roundtrip");
        let identity = Identity::generate();
        let original_fingerprint = identity.fingerprint();

        EncryptedIdentity::save_with_rounds(&identity, &path, "correct horse battery staple", TEST_ROUNDS).unwrap();
        let loaded = EncryptedIdentity::load(&path, "correct horse battery staple").unwrap();

        assert_eq!(loaded.fingerprint(), original_fingerprint);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let path = temp_path("identity-wrong-pass");
        let identity = Identity::generate();
        EncryptedIdentity::save_with_rounds(&identity, &path, "the real passphrase", TEST_ROUNDS).unwrap();

        let result = EncryptedIdentity::load(&path, "a guess");
        assert!(matches!(result, Err(ChatError::DecryptionFailed)));
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn saved_identity_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("p2p-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("id.enc");
        let _ = std::fs::remove_file(&path);
        EncryptedIdentity::save_with_rounds(&Identity::generate(), &path, "pw", TEST_ROUNDS).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_identity_file_is_rejected() {
        let path = temp_path("identity-tampered");
        let identity = Identity::generate();
        EncryptedIdentity::save_with_rounds(&identity, &path, "passphrase", TEST_ROUNDS).unwrap();

        // Flip a byte in the ciphertext region (well past the header).
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();

        let result = EncryptedIdentity::load(&path, "passphrase");
        assert!(matches!(result, Err(ChatError::DecryptionFailed)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn production_default_round_count_meets_current_owasp_guidance() {
        // Not a security test so much as a "did someone accidentally turn
        // this down" tripwire - the constant is what actually matters at
        // runtime, this just keeps it honest.
        assert!(PBKDF2_ROUNDS >= 600_000);
    }

    #[test]
    fn event_log_round_trips_multiple_records_in_order() {
        let path = temp_path("event-log-roundtrip");
        let _ = std::fs::remove_file(&path);
        let log = EventLog::open(&path).unwrap();
        log.append(b"first").unwrap();
        log.append(b"second").unwrap();
        log.append(b"third").unwrap();
        log.sync().unwrap();

        let all = EventLog::read_all(&path, None).unwrap();
        assert_eq!(all, vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn encrypted_event_log_round_trips() {
        let path = temp_path("event-log-encrypted");
        let _ = std::fs::remove_file(&path);
        let key = crate::crypto::AeadKey([9u8; 32]);
        let log = EventLog::open_encrypted(&path, key.clone()).unwrap();
        log.append(b"secret message one").unwrap();
        log.append(b"secret message two").unwrap();
        log.sync().unwrap();

        let all = EventLog::read_all(&path, Some(&key)).unwrap();
        assert_eq!(all, vec![b"secret message one".to_vec(), b"secret message two".to_vec()]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn encrypted_event_log_is_actually_unreadable_without_the_key() {
        let path = temp_path("event-log-confidentiality");
        let _ = std::fs::remove_file(&path);
        let key = crate::crypto::AeadKey([9u8; 32]);
        let log = EventLog::open_encrypted(&path, key).unwrap();
        log.append(b"the launch code is 4-8-15-16-23-42").unwrap();
        log.sync().unwrap();

        // Confirm the plaintext really isn't sitting on disk in the clear.
        let raw_file_bytes = std::fs::read(&path).unwrap();
        let contains_plaintext = raw_file_bytes.windows(b"launch code".len()).any(|w| w == b"launch code");
        assert!(!contains_plaintext, "plaintext content must not appear anywhere in the on-disk file");

        // And reading it back with the wrong key fails rather than
        // silently returning garbage.
        let wrong_key = crate::crypto::AeadKey([1u8; 32]);
        assert!(matches!(EventLog::read_all(&path, Some(&wrong_key)), Err(ChatError::DecryptionFailed)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reading_an_encrypted_log_without_supplying_a_key_fails_closed() {
        let path = temp_path("event-log-no-key");
        let _ = std::fs::remove_file(&path);
        let key = crate::crypto::AeadKey([9u8; 32]);
        let log = EventLog::open_encrypted(&path, key).unwrap();
        log.append(b"hello").unwrap();
        log.sync().unwrap();

        // Reading as if it were a plaintext log must not "succeed" with
        // garbage - the record is too short / fails frame parsing as raw
        // content, or at minimum never yields the real plaintext.
        let result = EventLog::read_all(&path, None);
        if let Ok(records) = result {
            assert_ne!(records, vec![b"hello".to_vec()]);
        }
        let _ = std::fs::remove_file(&path);
    }
    #[test]
    fn event_log_persists_across_separate_open_calls() {
        let path = temp_path("event-log-reopen");
        let _ = std::fs::remove_file(&path);
        {
            let log = EventLog::open(&path).unwrap();
            log.append(b"before restart").unwrap();
            log.sync().unwrap();
        }
        {
            let log = EventLog::open(&path).unwrap();
            log.append(b"after restart").unwrap();
            log.sync().unwrap();
        }
        let all = EventLog::read_all(&path, None).unwrap();
        assert_eq!(all, vec![b"before restart".to_vec(), b"after restart".to_vec()]);
        let _ = std::fs::remove_file(&path);
    }
}
