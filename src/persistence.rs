//! Identity at rest: saving and loading a long-term [`Identity`] under a
//! passphrase.
//!
//! (Event logs and other durable state live in [`crate::storage`], behind
//! pluggable traits. This module is only the passphrase-protected identity
//! FILE, which [`crate::storage::FileKeyStore`] wraps.)
//!
//! # File format (version 2)
//!
//! ```text
//! offset  size  field
//!      0     4  magic "SYMI"
//!      4     2  format version (2), big-endian
//!      6    16  random salt
//!     22     4  Argon2id memory cost in KiB
//!     26     4  Argon2id time cost (passes)
//!     30     4  Argon2id parallelism (lanes)
//!     34    12  random AEAD nonce
//!     46    32  key commitment
//!     78  ...   ChaCha20-Poly1305 ciphertext of the 32-byte secret, + 16-byte tag
//! ```
//!
//! Everything before the ciphertext is the header; it is bound into the
//! AEAD as associated data, so no field can be altered or swapped between
//! files without detection.
//!
//! # Key derivation
//! `master = Argon2id(passphrase, salt, m, t, p)` (32 bytes). Two
//! independent keys are then derived from it with HKDF-SHA256 under
//! different labels: the AEAD key, and a 32-byte *commitment*.
//!
//! * **Argon2id** is memory-hard, so a stolen file is expensive to attack
//!   with GPUs/ASICs (PBKDF2 is not). It runs once per unlock, not per
//!   peer, group or message.
//! * **Key commitment.** ChaCha20-Poly1305 is not "key committing": in
//!   principle a ciphertext can be crafted that decrypts successfully under
//!   two different keys. The stored commitment is a one-way function of the
//!   same master secret, checked in constant time BEFORE decrypting, so a
//!   file is bound to exactly one passphrase-derived key. It costs 32 bytes
//!   in this file only (nothing is added to messages).
//!
//! A wrong passphrase, a corrupted file and a tampered file are all reported
//! identically as [`ChatError::DecryptionFailed`], by design.
//!
//! # Compatibility
//! None. Symbolon is unreleased; the older PBKDF2 format (magic "P2PI") is
//! not read.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{aead::Aead, aead::KeyInit, aead::Payload, ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{ChatError, Result};
use crate::identity::Identity;

const MAGIC: &[u8; 4] = b"SYMI";
const FORMAT_VERSION: u16 = 2;
const HEADER_LEN: usize = 4 + 2 + 16 + 4 + 4 + 4 + 12 + 32; // = 78
const SECRET_LEN: usize = 32;
const TAG_LEN: usize = 16;

/// HKDF labels (domain separation: the two derived values are independent).
const LABEL_ENC_KEY: &[u8] = b"symbolon/identity-file/v2/aead-key";
const LABEL_COMMITMENT: &[u8] = b"symbolon/identity-file/v2/key-commitment";

/// Upper bounds accepted when LOADING, so a crafted file cannot make us
/// allocate gigabytes or spin for minutes before we even know it is invalid.
const MAX_MEMORY_KIB: u32 = 1024 * 1024; // 1 GiB
const MAX_TIME_COST: u32 = 64;
const MAX_LANES: u32 = 16;

/// Argon2id cost settings. They are stored in the file header, so loading
/// needs no configuration and costs can be raised later without breaking
/// existing files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB (65536 = 64 MiB).
    pub memory_kib: u32,
    /// Number of passes over memory.
    pub time_cost: u32,
    /// Parallel lanes (1 keeps the cost predictable on small devices).
    pub lanes: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 1 lane: this follows the OWASP "second
    /// recommendation" tier and is meant to land around half a second to a
    /// second on a Raspberry Pi class device. Tune with `cargo run
    /// --release --example bench` on the real hardware.
    fn default() -> Self {
        KdfParams {
            memory_kib: 64 * 1024,
            time_cost: 3,
            lanes: 1,
        }
    }
}

impl KdfParams {
    /// Deliberately weak settings so tests run fast. NEVER use in real code.
    pub fn insecure_fast_for_tests() -> Self {
        KdfParams {
            memory_kib: 64,
            time_cost: 1,
            lanes: 1,
        }
    }
}

/// Save and load a long-term [`Identity`], encrypted at rest under a
/// passphrase. This is a baseline, not a substitute for full-disk
/// encryption or an OS keystore (see [`crate::storage::KeyStore`] for
/// plugging those in).
pub struct EncryptedIdentity;

impl EncryptedIdentity {
    /// Encrypt `identity`'s private key under `passphrase` and write it to
    /// `path` (owner-only permissions on Unix), overwriting any existing file.
    pub fn save(identity: &Identity, path: &Path, passphrase: &str) -> Result<()> {
        Self::save_with_params(identity, path, passphrase, KdfParams::default())
    }

    /// [`EncryptedIdentity::save`] with explicit Argon2id costs.
    pub fn save_with_params(
        identity: &Identity,
        path: &Path,
        passphrase: &str,
        params: KdfParams,
    ) -> Result<()> {
        check_params(&params)?;
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let master = derive_master(passphrase, &salt, &params)?;
        let (enc_key, commitment) = split_master(&master);

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        header.extend_from_slice(&salt);
        header.extend_from_slice(&params.memory_kib.to_be_bytes());
        header.extend_from_slice(&params.time_cost.to_be_bytes());
        header.extend_from_slice(&params.lanes.to_be_bytes());
        header.extend_from_slice(&nonce_bytes);
        header.extend_from_slice(&commitment);
        debug_assert_eq!(header.len(), HEADER_LEN);

        let secret = Zeroizing::new(identity.secret_bytes());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*enc_key));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &secret[..],
                    aad: &header,
                },
            )
            .map_err(|_| ChatError::DecryptionFailed)?;

        let mut out = header;
        out.extend_from_slice(&ciphertext);

        // Owner-only (0600) from the moment the file exists, so there is no
        // window in which another local user can read it.
        let mut opts = OpenOptions::new();
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

    /// Decrypt and load an identity saved with [`EncryptedIdentity::save`].
    /// Returns [`ChatError::DecryptionFailed`] for a wrong passphrase,
    /// corruption or tampering (indistinguishable by design).
    pub fn load(path: &Path, passphrase: &str) -> Result<Identity> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?.read_to_end(&mut bytes)?;

        if bytes.len() != HEADER_LEN + SECRET_LEN + TAG_LEN {
            return Err(ChatError::MalformedMessage(
                "identity file has the wrong size",
            ));
        }
        if &bytes[0..4] != MAGIC {
            return Err(ChatError::MalformedMessage("not a symbolon identity file"));
        }
        let version = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        if version != FORMAT_VERSION {
            return Err(ChatError::UnsupportedVersion);
        }
        let salt: [u8; 16] = bytes[6..22].try_into().unwrap();
        let params = KdfParams {
            memory_kib: u32::from_be_bytes(bytes[22..26].try_into().unwrap()),
            time_cost: u32::from_be_bytes(bytes[26..30].try_into().unwrap()),
            lanes: u32::from_be_bytes(bytes[30..34].try_into().unwrap()),
        };
        let nonce_bytes: [u8; 12] = bytes[34..46].try_into().unwrap();
        let stored_commitment: [u8; 32] = bytes[46..78].try_into().unwrap();
        let (header, ciphertext) = bytes.split_at(HEADER_LEN);

        // Refuse absurd costs BEFORE doing any expensive work.
        check_params(&params)?;

        let master = derive_master(passphrase, &salt, &params)?;
        let (enc_key, commitment) = split_master(&master);

        // Key commitment first, in constant time: if it does not match, the
        // passphrase (or file) is wrong and we never attempt decryption.
        if !ct_eq(&commitment, &stored_commitment) {
            return Err(ChatError::DecryptionFailed);
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*enc_key));
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: ciphertext,
                        aad: header,
                    },
                )
                .map_err(|_| ChatError::DecryptionFailed)?,
        );
        let secret: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| ChatError::MalformedMessage("decrypted identity has the wrong length"))?;
        Ok(Identity::from_bytes(&secret))
    }
}

/// Reject parameter sets that are absurdly large (DoS) or that Argon2 itself
/// would refuse.
fn check_params(p: &KdfParams) -> Result<()> {
    let ok = p.lanes >= 1
        && p.lanes <= MAX_LANES
        && p.time_cost >= 1
        && p.time_cost <= MAX_TIME_COST
        && p.memory_kib >= 8 * p.lanes
        && p.memory_kib <= MAX_MEMORY_KIB;
    if ok {
        Ok(())
    } else {
        Err(ChatError::MalformedMessage(
            "identity file has unacceptable KDF parameters",
        ))
    }
}

/// Passphrase -> 32-byte master secret via Argon2id.
fn derive_master(passphrase: &str, salt: &[u8; 16], p: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(p.memory_kib, p.time_cost, p.lanes, Some(32))
        .map_err(|_| ChatError::MalformedMessage("invalid KDF parameters"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut *out)
        .map_err(|_| ChatError::MalformedMessage("key derivation failed"))?;
    Ok(out)
}

/// Master secret -> (AEAD key, key commitment), independent via HKDF labels.
fn split_master(master: &[u8; 32]) -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut commit = [0u8; 32];
    hk.expand(LABEL_ENC_KEY, &mut *enc)
        .expect("32 bytes is a valid HKDF output length");
    hk.expand(LABEL_COMMITMENT, &mut commit)
        .expect("32 bytes is a valid HKDF output length");
    (enc, commit)
}

/// Constant-time equality for equal-length byte arrays.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("symbolon-test-{name}-{}", std::process::id()));
        p
    }

    fn fast() -> KdfParams {
        KdfParams::insecure_fast_for_tests()
    }

    #[test]
    fn identity_round_trips_through_encryption() {
        let path = temp_path("identity-roundtrip");
        let identity = Identity::generate();
        EncryptedIdentity::save_with_params(
            &identity,
            &path,
            "correct horse battery staple",
            fast(),
        )
        .unwrap();
        let loaded = EncryptedIdentity::load(&path, "correct horse battery staple").unwrap();
        assert_eq!(loaded.fingerprint(), identity.fingerprint());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn default_save_and_load_work_with_production_costs() {
        let path = temp_path("identity-default-cost");
        let identity = Identity::generate();
        EncryptedIdentity::save(&identity, &path, "pw").unwrap();
        assert_eq!(
            EncryptedIdentity::load(&path, "pw").unwrap().fingerprint(),
            identity.fingerprint()
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let path = temp_path("identity-wrong-pass");
        EncryptedIdentity::save_with_params(
            &Identity::generate(),
            &path,
            "the real passphrase",
            fast(),
        )
        .unwrap();
        assert!(matches!(
            EncryptedIdentity::load(&path, "a guess"),
            Err(ChatError::DecryptionFailed)
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn saved_identity_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("symbolon-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("id.enc");
        let _ = std::fs::remove_file(&path);
        EncryptedIdentity::save_with_params(&Identity::generate(), &path, "pw", fast()).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flipping_any_single_byte_of_the_file_is_detected() {
        let path = temp_path("identity-bitflip");
        EncryptedIdentity::save_with_params(&Identity::generate(), &path, "pw", fast()).unwrap();
        let original = std::fs::read(&path).unwrap();
        for i in 0..original.len() {
            let mut bad = original.clone();
            bad[i] ^= 0x01;
            std::fs::write(&path, &bad).unwrap();
            assert!(
                EncryptedIdentity::load(&path, "pw").is_err(),
                "flip at byte {i} was not detected"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_key_commitment_rejects_a_wrong_key_before_decryption() {
        // Replace the stored commitment with the right one for a DIFFERENT
        // passphrase: even a header that is otherwise self-consistent must
        // not unlock under the wrong passphrase.
        let path = temp_path("identity-commit");
        EncryptedIdentity::save_with_params(&Identity::generate(), &path, "right", fast()).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let salt: [u8; 16] = bytes[6..22].try_into().unwrap();
        let master = derive_master("wrong", &salt, &fast()).unwrap();
        let (_, wrong_commit) = split_master(&master);
        bytes[46..78].copy_from_slice(&wrong_commit);
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            EncryptedIdentity::load(&path, "right"),
            Err(ChatError::DecryptionFailed)
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn old_pbkdf2_files_and_garbage_are_refused_not_misread() {
        let path = temp_path("identity-old-format");
        let mut old = b"P2PI".to_vec();
        old.extend_from_slice(&[0u8; 80]);
        std::fs::write(&path, &old).unwrap();
        assert!(EncryptedIdentity::load(&path, "pw").is_err());
        std::fs::write(&path, b"").unwrap();
        assert!(EncryptedIdentity::load(&path, "pw").is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn absurd_kdf_parameters_in_a_file_are_refused_without_doing_the_work() {
        let path = temp_path("identity-dos");
        EncryptedIdentity::save_with_params(&Identity::generate(), &path, "pw", fast()).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[22..26].copy_from_slice(&u32::MAX.to_be_bytes()); // 4 TiB of memory
        std::fs::write(&path, &bytes).unwrap();
        let start = std::time::Instant::now();
        assert!(EncryptedIdentity::load(&path, "pw").is_err());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "must fail fast, not attempt the KDF"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn production_defaults_are_not_accidentally_weakened() {
        let d = KdfParams::default();
        assert!(d.memory_kib >= 64 * 1024 && d.time_cost >= 3);
    }

    #[test]
    fn saving_with_unacceptable_params_fails() {
        let path = temp_path("identity-bad-params");
        let bad = KdfParams {
            memory_kib: 0,
            time_cost: 0,
            lanes: 0,
        };
        assert!(
            EncryptedIdentity::save_with_params(&Identity::generate(), &path, "pw", bad).is_err()
        );
    }
}
