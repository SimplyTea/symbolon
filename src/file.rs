//! File transfer, stage 1: the transport-independent core.
//!
//! This module knows how to describe a file ([`FileOffer`]), prove its
//! pieces are genuine ([`Manifest`]), read it out in chunks ([`FileServer`])
//! and reassemble it safely ([`FileReceiver`]). It does NOT send anything:
//! the messages in [`FileFrame`] are carried by sessions and groups (a later
//! stage), so the same logic serves both 1:1 chats and groups.
//!
//! # The flow
//!
//! ```text
//! sender                                         receiver
//! ------                                         --------
//! prepare(): hash the file chunk by chunk
//!   -> FileOffer (name, size, root, prefix)
//!   -> Manifest  (one hash per chunk)
//! offer is shown to the receiver  ------------->  the APP shows "report.pdf, 3 MB,
//!                                                  claims to be a PDF" and decides
//!                                                  (nothing downloads before that)
//!                                 <-------------  ManifestRequest        (accepted)
//! Manifest                        ------------->  check it matches the offer's root
//!                                 <-------------  ChunkRequest (a window of indices)
//! Chunk, Chunk, ...               ------------->  check each chunk's hash, then write it
//!                                 <-------------  more requests as chunks arrive
//!                                                  when every chunk is verified the
//!                                                  sink is finished (renamed into place)
//! ```
//!
//! # Why it is safe
//!
//! * **The offer is signed** (it travels inside a signed group message or an
//!   authenticated session), and it contains the **root**: a hash over the
//!   file size, the chunk size and the hash of every chunk. Change any byte
//!   of the file and the root changes.
//! * The receiver fetches the full list of chunk hashes first
//!   ([`Manifest`]) and checks it against the root. After that **every chunk
//!   is checked against its own hash before it is written**, so a bad or
//!   malicious chunk (from the sender or from any other peer serving the
//!   file) is rejected immediately and can simply be asked for again. We
//!   never wait until the end of a 1 GB download to find out it was wrong.
//! * The **prefix** (first 512 bytes, for showing a file type before the
//!   download) is a CLAIM by the sender. When the first chunk arrives the
//!   receiver checks that it really begins with that prefix, and aborts if
//!   the sender lied about it.
//! * The declared size is checked against the receiver's limit **before
//!   anything is allocated or written**, and no chunk is accepted beyond the
//!   declared size.
//! * Nothing is held in memory except one chunk at a time and the manifest
//!   (32 bytes per 256 KiB chunk, so 128 KiB for a 1 GiB file): files are
//!   streamed through [`ChunkSource`] and [`FileSink`].
//!
//! # What this module does not do
//!
//! It has no file-type database (the app decides what a prefix means, and the
//! prefix is only a claim), and it does not decide whether to accept a file
//! (the app does). It does offer [`sanitize_name`], because a file name is
//! attacker-controlled text.

// `x % 32 != 0` reads most clearly as "not a whole number of hashes";
// `is_multiple_of` would need a newer compiler than the rest of the crate.
#![allow(clippy::manual_is_multiple_of)]

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::error::{ChatError, Result};

/// A file's identity: the root hash in its offer. Two offers with the same id
/// are byte-for-byte the same file.
pub type FileId = [u8; 32];

/// Chunk size used unless the sender picks another: 256 KiB. Well under the
/// 4 MiB frame cap, big enough that per-chunk overhead (85 bytes of framing)
/// is negligible.
pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;
/// Smallest chunk size accepted in an offer.
pub const MIN_CHUNK_SIZE: u32 = 16 * 1024;
/// Largest chunk size accepted in an offer (leaves room for framing under the
/// 4 MiB frame cap).
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
/// Most chunks one file may have. The manifest is 32 bytes per chunk, so this
/// keeps it (2 MiB) inside a single frame.
pub const MAX_CHUNKS: u64 = 65_536;
/// Default limit on the size of a file we will accept: 1 GiB.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 1 << 30;
/// The most any limit can be raised to: 4 GiB. (The offer carries a 64-bit
/// size, so raising this later does not change the wire format.)
pub const HARD_MAX_FILE_SIZE: u64 = 4 << 30;
/// How many bytes from the start of the file travel in the offer.
pub const PREFIX_LEN: usize = 512;
/// Longest file name (in UTF-8 bytes) allowed in an offer.
pub const MAX_NAME_BYTES: usize = 255;
/// Most chunk indices one request may ask for.
pub const MAX_REQUEST_INDICES: usize = 64;

/// Number of chunks in a file of `size` bytes cut into `chunk_size` pieces.
pub fn chunk_count(size: u64, chunk_size: u32) -> u64 {
    size.div_ceil(chunk_size as u64)
}

/// Hash of one chunk (domain separated so it can never equal another kind of
/// hash in this crate).
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"symbolon/file/leaf/v1");
    h.update(data);
    h.finalize().into()
}

/// The root: a hash over the size, the chunk size and every chunk hash, in
/// order. Binding the size and chunk size means they cannot be changed
/// without changing the id.
fn compute_root(size: u64, chunk_size: u32, leaves: &[[u8; 32]]) -> FileId {
    let mut h = Sha256::new();
    h.update(b"symbolon/file/root/v1");
    h.update(size.to_be_bytes());
    h.update(chunk_size.to_be_bytes());
    for l in leaves {
        h.update(l);
    }
    h.finalize().into()
}

fn bad(reason: &'static str) -> ChatError {
    ChatError::FileTransfer(reason)
}

// ============================================================================
// The offer
// ============================================================================

/// What a sender announces: enough for the receiver to decide, and to verify
/// what it later downloads.
///
/// Wire layout (all integers big-endian):
///
/// ```text
/// u16  name length (0 = no name)      then that many UTF-8 bytes
/// u64  size in bytes
/// u32  chunk size
/// 32   root (the file id)
/// u16  prefix length                  then that many bytes (at most 512)
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileOffer {
    /// The sender's file name, if it gave one. Attacker-controlled text:
    /// run it through [`sanitize_name`] before using it as a path.
    pub name: Option<String>,
    /// Size of the file in bytes.
    pub size: u64,
    /// Size of each chunk (the last one may be shorter).
    pub chunk_size: u32,
    /// The root hash, which is also the file's id.
    pub root: FileId,
    /// The first bytes of the file (up to 512), for showing a file type
    /// before download. A claim until the first chunk arrives and is checked.
    pub prefix: Vec<u8>,
}

impl FileOffer {
    /// The file's id (the root hash).
    pub fn id(&self) -> FileId {
        self.root
    }

    /// How many chunks the file has.
    pub fn chunk_count(&self) -> u32 {
        chunk_count(self.size, self.chunk_size) as u32
    }

    /// Length of chunk `index` (the last chunk holds the remainder).
    pub fn chunk_len(&self, index: u32) -> usize {
        let start = index as u64 * self.chunk_size as u64;
        (self.size - start).min(self.chunk_size as u64) as usize
    }

    /// Check an offer is sane and within `max_size` BEFORE acting on it.
    /// `max_size` is the receiver's limit (see [`DEFAULT_MAX_FILE_SIZE`]).
    pub fn validate(&self, max_size: u64) -> Result<()> {
        if max_size > HARD_MAX_FILE_SIZE {
            return Err(ChatError::InvalidConfig(
                "file size limit is above the 4 GiB maximum",
            ));
        }
        if self.size > max_size {
            return Err(bad("file is larger than the allowed size"));
        }
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&self.chunk_size) {
            return Err(bad("chunk size out of range"));
        }
        if chunk_count(self.size, self.chunk_size) > MAX_CHUNKS {
            return Err(bad("too many chunks"));
        }
        if self.prefix.len() > PREFIX_LEN || self.prefix.len() as u64 > self.size {
            return Err(bad("prefix longer than allowed"));
        }
        if let Some(n) = &self.name {
            if n.is_empty() || n.len() > MAX_NAME_BYTES {
                return Err(bad("file name length out of range"));
            }
        }
        Ok(())
    }

    /// Serialize (see the layout above).
    pub fn encode(&self) -> Vec<u8> {
        let name = self.name.as_deref().unwrap_or("").as_bytes();
        let mut out = Vec::with_capacity(2 + name.len() + 8 + 4 + 32 + 2 + self.prefix.len());
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&(self.prefix.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.prefix);
        out
    }

    /// Parse and check shape (exact length, UTF-8 name). Limits that depend on
    /// the receiver's settings are checked separately by
    /// [`FileOffer::validate`].
    pub fn decode(bytes: &[u8]) -> Result<FileOffer> {
        let mut r = Cursor::new(bytes);
        let name_len = r.u16()? as usize;
        if name_len > MAX_NAME_BYTES {
            return Err(bad("file name too long"));
        }
        let name = if name_len == 0 {
            None
        } else {
            Some(
                String::from_utf8(r.take(name_len)?.to_vec())
                    .map_err(|_| bad("file name is not UTF-8"))?,
            )
        };
        let size = r.u64()?;
        let chunk_size = r.u32()?;
        let root: FileId = r.take(32)?.try_into().expect("32 bytes");
        let prefix_len = r.u16()? as usize;
        if prefix_len > PREFIX_LEN {
            return Err(bad("prefix longer than allowed"));
        }
        let prefix = r.take(prefix_len)?.to_vec();
        r.finish()?;
        Ok(FileOffer {
            name,
            size,
            chunk_size,
            root,
            prefix,
        })
    }
}

/// A tiny bounds-checked reader for the decoders in this module.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or_else(|| bad("truncated"))?;
        let s = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| bad("truncated"))?;
        self.at = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2")))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4")))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8")))
    }
    fn rest(&mut self) -> &'a [u8] {
        let s = &self.bytes[self.at..];
        self.at = self.bytes.len();
        s
    }
    fn finish(&self) -> Result<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(bad("trailing bytes"))
        }
    }
}

// ============================================================================
// The manifest
// ============================================================================

/// One hash per chunk. The receiver downloads this once, checks it against
/// the offer's root, and then verifies every chunk against it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    leaves: Vec<[u8; 32]>,
}

impl Manifest {
    /// The chunk hashes, in order.
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Serialize: the hashes back to back (32 bytes each).
    pub fn encode(&self) -> Vec<u8> {
        self.leaves.concat()
    }

    /// Parse the serialized form (a whole number of 32-byte hashes).
    pub fn decode(bytes: &[u8]) -> Result<Manifest> {
        if bytes.len() % 32 != 0 || bytes.len() / 32 > MAX_CHUNKS as usize {
            return Err(bad("manifest has a bad length"));
        }
        Ok(Manifest {
            leaves: bytes
                .chunks_exact(32)
                .map(|c| c.try_into().expect("32"))
                .collect(),
        })
    }
}

// ============================================================================
// Reading the file (sender side)
// ============================================================================

/// Random-access reading of the file being sent. Implement it for whatever
/// holds the data; [`FileSource`] (a file on disk) and [`MemorySource`] are
/// provided.
pub trait ChunkSource: Send + Sync {
    /// Total size in bytes.
    fn size(&self) -> u64;
    /// Read up to `buf.len()` bytes starting at `offset`; returns how many
    /// were read (0 only at the end).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;
}

fn read_exact_at(source: &dyn ChunkSource, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        let n = source.read_at(offset + done as u64, &mut buf[done..])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "file is shorter than its recorded size",
            ));
        }
        done += n;
    }
    Ok(())
}

/// A file on disk, read with seek + read (works on every platform).
pub struct FileSource {
    file: Mutex<fs::File>,
    size: u64,
}

impl FileSource {
    /// Open `path` for reading and record its current size.
    pub fn open(path: &Path) -> io::Result<FileSource> {
        let file = fs::File::open(path)?;
        let size = file.metadata()?.len();
        Ok(FileSource {
            file: Mutex::new(file),
            size,
        })
    }
}

impl ChunkSource for FileSource {
    fn size(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let mut f = self.file.lock().unwrap();
        f.seek(SeekFrom::Start(offset))?;
        f.read(buf)
    }
}

/// A file held in memory (for tests and small data).
pub struct MemorySource(pub Vec<u8>);

impl ChunkSource for MemorySource {
    fn size(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let start = (offset as usize).min(self.0.len());
        let n = buf.len().min(self.0.len() - start);
        buf[..n].copy_from_slice(&self.0[start..start + n]);
        Ok(n)
    }
}

/// Read the whole file once, chunk by chunk, and build the offer and manifest
/// for it. This is the slow step for a big file: it hashes everything once.
/// Measured on a development machine with the file already in memory it ran at
/// about 1.1 GiB/s, so on real hardware expect the disk, not the hashing, to
/// set the pace. Not measured on a small board.
///
/// `name` is optional (a Linux file piped in may have none). `chunk_size`
/// must be between [`MIN_CHUNK_SIZE`] and [`MAX_CHUNK_SIZE`]; use
/// [`DEFAULT_CHUNK_SIZE`] unless you have a reason.
pub fn prepare(
    source: &dyn ChunkSource,
    name: Option<&str>,
    chunk_size: u32,
) -> Result<(FileOffer, Manifest)> {
    let size = source.size();
    let mut offer = FileOffer {
        name: name.filter(|n| !n.is_empty()).map(str::to_owned),
        size,
        chunk_size,
        root: [0; 32],
        prefix: Vec::new(),
    };
    // Reuse the receiver's own checks (size limit is the hard maximum here;
    // the receiving side applies its own, lower, limit).
    offer.validate(HARD_MAX_FILE_SIZE)?;

    let n = offer.chunk_count();
    let mut leaves = Vec::with_capacity(n as usize);
    let mut buf = vec![0u8; chunk_size as usize];
    for i in 0..n {
        let len = offer.chunk_len(i);
        read_exact_at(source, i as u64 * chunk_size as u64, &mut buf[..len])?;
        if i == 0 {
            offer.prefix = buf[..len.min(PREFIX_LEN)].to_vec();
        }
        leaves.push(leaf_hash(&buf[..len]));
    }
    offer.root = compute_root(size, chunk_size, &leaves);
    Ok((offer, Manifest { leaves }))
}

/// Serves chunks of a file we are sharing, checking each against the manifest
/// so a file that changed on disk after the offer is noticed instead of sent.
pub struct FileServer {
    source: Arc<dyn ChunkSource>,
    offer: FileOffer,
    manifest: Manifest,
}

impl FileServer {
    /// Check the source, offer and manifest agree, then serve from them.
    pub fn new(source: Arc<dyn ChunkSource>, offer: FileOffer, manifest: Manifest) -> Result<Self> {
        offer.validate(HARD_MAX_FILE_SIZE)?;
        if source.size() != offer.size {
            return Err(bad("file size changed since the offer was made"));
        }
        if manifest.leaves.len() != offer.chunk_count() as usize
            || compute_root(offer.size, offer.chunk_size, &manifest.leaves) != offer.root
        {
            return Err(bad("manifest does not match the offer"));
        }
        Ok(FileServer {
            source,
            offer,
            manifest,
        })
    }

    /// The offer being served.
    pub fn offer(&self) -> &FileOffer {
        &self.offer
    }

    /// The serialized manifest, to send when it is requested.
    pub fn manifest_bytes(&self) -> Vec<u8> {
        self.manifest.encode()
    }

    /// Read chunk `index`, verifying it against the manifest first.
    pub fn chunk(&self, index: u32) -> Result<Vec<u8>> {
        if index >= self.offer.chunk_count() {
            return Err(bad("chunk index out of range"));
        }
        let mut buf = vec![0u8; self.offer.chunk_len(index)];
        read_exact_at(
            self.source.as_ref(),
            index as u64 * self.offer.chunk_size as u64,
            &mut buf,
        )?;
        if leaf_hash(&buf) != self.manifest.leaves[index as usize] {
            return Err(bad("file changed on disk since the offer was made"));
        }
        Ok(buf)
    }
}

// ============================================================================
// Writing the file (receiver side)
// ============================================================================

/// Where a received file goes. Implement it to put the bytes anywhere
/// (a database, an encrypted store); [`PartFileSink`] writes a file on disk.
pub trait FileSink: Send {
    /// Write `data` at byte `offset`. Chunks arrive in any order.
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()>;
    /// Called once, after every chunk is verified and written.
    fn finish(&mut self) -> io::Result<()>;
}

/// Writes to `<path>.part` and moves it to `<path>` only when the whole file
/// has verified, so a half-finished or abandoned download never looks like a
/// real file.
///
/// Safety properties (each one tested):
/// * it **never overwrites** an existing `<path>`, checked when it starts and
///   again at the final step, where the move itself fails rather than replace
///   a file that appeared in the meantime;
/// * the `.part` file is created with "must not already exist", which also
///   refuses a **symbolic link** planted at that name (an attacker cannot make
///   us write through a link to some other file);
/// * a stale `.part` from an earlier attempt is not silently reused: it must be
///   resumed explicitly with [`PartFileSink::resume`], which checks it is a
///   plain file of the right size.
pub struct PartFileSink {
    file: Option<fs::File>,
    part: PathBuf,
    path: PathBuf,
}

fn part_path(path: &Path) -> PathBuf {
    let mut part = path.as_os_str().to_owned();
    part.push(".part");
    PathBuf::from(part)
}

/// Anything at `path` at all, including a link to nowhere.
fn something_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

impl PartFileSink {
    /// Prepare to write `path`: creates a new `<path>.part` sized to `size`.
    /// Fails if `<path>` or `<path>.part` already exists.
    pub fn create(path: &Path, size: u64) -> io::Result<PartFileSink> {
        if something_exists(path) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to overwrite an existing file",
            ));
        }
        let part = part_path(path);
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true) // fails if anything, even a symlink, is there
            .open(&part)?;
        // On most file systems this makes a sparse file, so a large declared
        // size does not use disk until it is written.
        file.set_len(size)?;
        Ok(PartFileSink {
            file: Some(file),
            part,
            path: path.to_path_buf(),
        })
    }

    /// Continue an earlier download: reopen an existing `<path>.part`. It must
    /// be a plain file (not a link) of exactly `size` bytes. Use together with
    /// [`FileReceiver::restore_verified`].
    pub fn resume(path: &Path, size: u64) -> io::Result<PartFileSink> {
        if something_exists(path) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to overwrite an existing file",
            ));
        }
        let part = part_path(path);
        let meta = fs::symlink_metadata(&part)?;
        if !meta.file_type().is_file() || meta.len() != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the partial file is not a plain file of the expected size",
            ));
        }
        let file = fs::OpenOptions::new().write(true).open(&part)?;
        Ok(PartFileSink {
            file: Some(file),
            part,
            path: path.to_path_buf(),
        })
    }
}

impl FileSink for PartFileSink {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        let f = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("download already finished"))?;
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(data)
    }
    fn finish(&mut self) -> io::Result<()> {
        if let Some(f) = self.file.take() {
            f.sync_all()?;
        }
        // A hard link fails if the destination exists, so unlike a rename it
        // can never replace a file that appeared while we were downloading.
        match fs::hard_link(&self.part, &self.path) {
            Ok(()) => fs::remove_file(&self.part),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a file appeared at the destination while downloading",
            )),
            // Some file systems cannot hard-link; fall back to a check then rename.
            Err(_) => {
                if something_exists(&self.path) {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "a file appeared at the destination while downloading",
                    ));
                }
                fs::rename(&self.part, &self.path)
            }
        }
    }
}

/// How far a download has got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Chunks verified and written.
    pub done: u32,
    /// Chunks in the file.
    pub total: u32,
    /// `true` once every chunk is in and the sink has been finished.
    pub complete: bool,
}

/// Reassembles a file from verified chunks. Chunks may come in any order and
/// from any peer that holds the file; each is checked before it is written.
pub struct FileReceiver {
    offer: FileOffer,
    sink: Box<dyn FileSink>,
    manifest: Option<Vec<[u8; 32]>>,
    done: Vec<bool>,
    done_count: u32,
    in_flight: HashSet<u32>,
    finished: bool,
}

impl FileReceiver {
    /// Start receiving `offer` into `sink`. Fails if the offer is malformed or
    /// bigger than `max_size` (use [`DEFAULT_MAX_FILE_SIZE`]); nothing has
    /// been requested or written at that point.
    pub fn new(offer: FileOffer, sink: Box<dyn FileSink>, max_size: u64) -> Result<FileReceiver> {
        offer.validate(max_size)?;
        let n = offer.chunk_count() as usize;
        Ok(FileReceiver {
            offer,
            sink,
            manifest: None,
            done: vec![false; n],
            done_count: 0,
            in_flight: HashSet::new(),
            finished: false,
        })
    }

    /// The offer being received.
    pub fn offer(&self) -> &FileOffer {
        &self.offer
    }

    /// `true` until [`FileReceiver::set_manifest`] has succeeded.
    pub fn needs_manifest(&self) -> bool {
        self.manifest.is_none()
    }

    /// Accept the manifest if (and only if) it matches the offer's root.
    /// Completes the download at once for an empty file.
    pub fn set_manifest(&mut self, manifest: Manifest) -> Result<Progress> {
        if self.manifest.is_some() {
            return Ok(self.progress());
        }
        if manifest.leaves.len() != self.offer.chunk_count() as usize {
            return Err(bad("manifest has the wrong number of chunks"));
        }
        if compute_root(self.offer.size, self.offer.chunk_size, &manifest.leaves) != self.offer.root
        {
            return Err(bad("manifest does not match the offer"));
        }
        self.manifest = Some(manifest.leaves);
        self.maybe_finish()?;
        Ok(self.progress())
    }

    /// Pick the next chunks to ask for, keeping at most `window` requests
    /// outstanding in total (so a big file does not flood the link or the
    /// outbox). Returns nothing until the manifest is in. Chunks returned are
    /// remembered as "in flight"; see [`FileReceiver::release_in_flight`].
    pub fn next_requests(&mut self, window: usize) -> Vec<u32> {
        if self.manifest.is_none() || self.finished {
            return Vec::new();
        }
        let room = window.saturating_sub(self.in_flight.len());
        let mut out = Vec::new();
        for (i, d) in self.done.iter().enumerate() {
            if out.len() >= room.min(MAX_REQUEST_INDICES) {
                break;
            }
            let i = i as u32;
            if !*d && !self.in_flight.contains(&i) {
                out.push(i);
            }
        }
        for i in &out {
            self.in_flight.insert(*i);
        }
        out
    }

    /// Forget which chunks were requested (the link dropped, or the peer we
    /// asked went away) so they are asked for again, possibly from someone
    /// else. Chunks already verified are kept.
    pub fn release_in_flight(&mut self) {
        self.in_flight.clear();
    }

    /// Give one chunk back for re-requesting (for example a peer said it does
    /// not have it).
    pub fn release_chunk(&mut self, index: u32) {
        self.in_flight.remove(&index);
    }

    /// Check a received chunk against the manifest and, if it is genuine,
    /// write it. A bad chunk returns an error and is NOT written; the chunk
    /// goes back to "not requested" so it can be asked for again. A chunk we
    /// already have is ignored.
    pub fn receive_chunk(&mut self, index: u32, data: &[u8]) -> Result<Progress> {
        let manifest = self
            .manifest
            .as_ref()
            .ok_or_else(|| bad("chunk arrived before the manifest"))?;
        if index >= self.offer.chunk_count() {
            return Err(bad("chunk index out of range"));
        }
        if self.done[index as usize] {
            return Ok(self.progress()); // duplicate (e.g. asked twice): fine
        }
        self.in_flight.remove(&index);
        if data.len() != self.offer.chunk_len(index) {
            return Err(bad("chunk has the wrong length"));
        }
        if leaf_hash(data) != manifest[index as usize] {
            return Err(bad("chunk failed its hash check"));
        }
        if index == 0 && !data.starts_with(&self.offer.prefix) {
            // The hash matched, so this really is the file; the SENDER's
            // claim about its first bytes was false.
            return Err(bad(
                "the file does not start with the prefix the sender claimed",
            ));
        }
        self.sink
            .write_at(index as u64 * self.offer.chunk_size as u64, data)?;
        self.done[index as usize] = true;
        self.done_count += 1;
        self.maybe_finish()?;
        Ok(self.progress())
    }

    fn maybe_finish(&mut self) -> Result<()> {
        if !self.finished && self.manifest.is_some() && self.done_count == self.offer.chunk_count()
        {
            self.sink.finish()?;
            self.finished = true;
        }
        Ok(())
    }

    /// Current progress.
    pub fn progress(&self) -> Progress {
        Progress {
            done: self.done_count,
            total: self.offer.chunk_count(),
            complete: self.finished,
        }
    }

    /// `true` when the whole file is verified and the sink is finished.
    pub fn is_complete(&self) -> bool {
        self.finished
    }

    /// Which chunks are verified and written, to save so a download can
    /// resume after a restart (one flag per chunk). Only trust a saved copy if
    /// the sink's data was flushed to disk before it was saved.
    pub fn verified_chunks(&self) -> Vec<bool> {
        self.done.clone()
    }

    /// Restore progress saved by [`FileReceiver::verified_chunks`]. The
    /// manifest must already be set. The restored chunks are not re-checked;
    /// that is only sound if the sink really holds them.
    pub fn restore_verified(&mut self, verified: &[bool]) -> Result<Progress> {
        if self.manifest.is_none() {
            return Err(bad("manifest is needed before restoring progress"));
        }
        if verified.len() != self.done.len() {
            return Err(bad("saved progress does not match this file"));
        }
        self.done.copy_from_slice(verified);
        self.done_count = verified.iter().filter(|v| **v).count() as u32;
        self.in_flight.clear();
        self.maybe_finish()?;
        Ok(self.progress())
    }
}

// ============================================================================
// Messages
// ============================================================================

/// The messages two peers exchange to move a file. They carry no signature of
/// their own: the signed offer (via its root) and the session's authentication
/// are what make them trustworthy. Layout: one kind byte, the 32-byte file id,
/// then the fields below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileFrame {
    /// "Send me the manifest for this file."
    ManifestRequest { file: FileId },
    /// The manifest (32 bytes per chunk, back to back).
    Manifest { file: FileId, manifest: Vec<u8> },
    /// "Send me these chunks" (at most [`MAX_REQUEST_INDICES`]).
    ChunkRequest { file: FileId, indices: Vec<u32> },
    /// One chunk of data.
    Chunk {
        file: FileId,
        index: u32,
        data: Vec<u8>,
    },
    /// "I do not have this file (any more)", so the asker can try someone else.
    Unavailable { file: FileId },
}

impl FileFrame {
    /// The file this message is about.
    pub fn file(&self) -> FileId {
        match self {
            FileFrame::ManifestRequest { file }
            | FileFrame::Manifest { file, .. }
            | FileFrame::ChunkRequest { file, .. }
            | FileFrame::Chunk { file, .. }
            | FileFrame::Unavailable { file } => *file,
        }
    }

    /// Serialize.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            FileFrame::ManifestRequest { file } => {
                out.push(0);
                out.extend_from_slice(file);
            }
            FileFrame::Manifest { file, manifest } => {
                out.push(1);
                out.extend_from_slice(file);
                out.extend_from_slice(manifest);
            }
            FileFrame::ChunkRequest { file, indices } => {
                out.push(2);
                out.extend_from_slice(file);
                out.extend_from_slice(&(indices.len() as u16).to_be_bytes());
                for i in indices {
                    out.extend_from_slice(&i.to_be_bytes());
                }
            }
            FileFrame::Chunk { file, index, data } => {
                out.push(3);
                out.extend_from_slice(file);
                out.extend_from_slice(&index.to_be_bytes());
                out.extend_from_slice(data);
            }
            FileFrame::Unavailable { file } => {
                out.push(4);
                out.extend_from_slice(file);
            }
        }
        out
    }

    /// Parse, rejecting anything not exactly shaped like one of the above.
    pub fn decode(bytes: &[u8]) -> Result<FileFrame> {
        let mut r = Cursor::new(bytes);
        let kind = r.take(1)?[0];
        let file: FileId = r.take(32)?.try_into().expect("32");
        let frame = match kind {
            0 => FileFrame::ManifestRequest { file },
            1 => {
                let manifest = r.rest().to_vec();
                if manifest.len() % 32 != 0 || manifest.len() / 32 > MAX_CHUNKS as usize {
                    return Err(bad("manifest has a bad length"));
                }
                FileFrame::Manifest { file, manifest }
            }
            2 => {
                let n = r.u16()? as usize;
                if n > MAX_REQUEST_INDICES {
                    return Err(bad("too many chunks requested at once"));
                }
                let mut indices = Vec::with_capacity(n);
                for _ in 0..n {
                    indices.push(r.u32()?);
                }
                FileFrame::ChunkRequest { file, indices }
            }
            3 => {
                let index = r.u32()?;
                let data = r.rest().to_vec();
                if data.len() > MAX_CHUNK_SIZE as usize {
                    return Err(bad("chunk is larger than allowed"));
                }
                FileFrame::Chunk { file, index, data }
            }
            4 => FileFrame::Unavailable { file },
            _ => return Err(bad("unknown file message kind")),
        };
        r.finish()?;
        Ok(frame)
    }
}

// ============================================================================
// Names
// ============================================================================

/// Turn a sender-supplied name into something safe to show and to use as a
/// file name, or `None` if nothing usable is left.
///
/// A name is attacker-controlled text. This keeps only the last path
/// component (so `../../etc/passwd` and `C:\x\y.txt` become `passwd` and
/// `y.txt`), and removes control characters and the invisible text-direction
/// overrides used to disguise extensions (`invoice\u{202E}fdp.exe`). Names that
/// are only dots or spaces, and names longer than 255 bytes, are shortened or
/// refused. It does NOT handle Windows reserved names (`CON`, `NUL`); an app
/// that writes on Windows should also check those.
pub fn sanitize_name(name: &str) -> Option<String> {
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = last
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(
                    *c,
                    '\u{200B}'..='\u{200F}'   // zero-width and direction marks
                    | '\u{202A}'..='\u{202E}' // embedding and override controls
                    | '\u{2060}'..='\u{2069}' // word joiner, isolates
                    | '\u{FEFF}'              // byte order mark
                )
        })
        .collect();
    let cleaned = cleaned.trim_matches(|c: char| c == ' ' || c == '.');
    if cleaned.is_empty() {
        return None;
    }
    // Shorten on a character boundary, not in the middle of a character.
    let mut end = cleaned.len().min(MAX_NAME_BYTES);
    while !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    Some(cleaned[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink that keeps everything in memory so tests can compare bytes.
    struct MemSink {
        data: Arc<Mutex<Vec<u8>>>,
        finished: Arc<Mutex<u32>>,
    }
    impl FileSink for MemSink {
        fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
            let mut d = self.data.lock().unwrap();
            let end = offset as usize + data.len();
            if d.len() < end {
                d.resize(end, 0);
            }
            d[offset as usize..end].copy_from_slice(data);
            Ok(())
        }
        fn finish(&mut self) -> io::Result<()> {
            *self.finished.lock().unwrap() += 1;
            Ok(())
        }
    }

    type MemParts = (Box<dyn FileSink>, Arc<Mutex<Vec<u8>>>, Arc<Mutex<u32>>);

    fn mem_sink() -> MemParts {
        let data = Arc::new(Mutex::new(Vec::new()));
        let finished = Arc::new(Mutex::new(0));
        (
            Box::new(MemSink {
                data: data.clone(),
                finished: finished.clone(),
            }),
            data,
            finished,
        )
    }

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 31 + i / 7) % 251) as u8).collect()
    }

    /// Offer + server + manifest for `bytes`, using the smallest chunk size so
    /// small files still have several chunks.
    fn serve(bytes: Vec<u8>) -> (FileServer, FileOffer, Manifest) {
        let src = MemorySource(bytes);
        let (offer, manifest) = prepare(&src, Some("a.bin"), MIN_CHUNK_SIZE).unwrap();
        let server = FileServer::new(Arc::new(src), offer.clone(), manifest.clone()).unwrap();
        (server, offer, manifest)
    }

    /// Run a whole transfer in memory and return what the sink received.
    fn transfer(bytes: Vec<u8>) -> Vec<u8> {
        let (server, offer, manifest) = serve(bytes);
        let (sink, data, finished) = mem_sink();
        let mut rx = FileReceiver::new(offer, sink, DEFAULT_MAX_FILE_SIZE).unwrap();
        assert!(rx.needs_manifest());
        rx.set_manifest(manifest).unwrap();
        while !rx.is_complete() {
            let want = rx.next_requests(4);
            assert!(!want.is_empty(), "stalled before completing");
            for i in want {
                rx.receive_chunk(i, &server.chunk(i).unwrap()).unwrap();
            }
        }
        assert_eq!(*finished.lock().unwrap(), 1, "finish() exactly once");
        let out = data.lock().unwrap().clone();
        out
    }

    #[test]
    fn files_of_every_awkward_size_arrive_byte_for_byte() {
        let c = MIN_CHUNK_SIZE as usize;
        for len in [0, 1, 511, 512, 513, c - 1, c, c + 1, 3 * c, 3 * c + 17] {
            let bytes = sample(len);
            assert_eq!(transfer(bytes.clone()), bytes, "length {len}");
        }
    }

    #[test]
    fn offer_describes_the_file() {
        let bytes = sample(100_000);
        let (offer, manifest) = prepare(
            &MemorySource(bytes.clone()),
            Some("x.tar.gz"),
            MIN_CHUNK_SIZE,
        )
        .unwrap();
        assert_eq!(offer.size, 100_000);
        assert_eq!(offer.name.as_deref(), Some("x.tar.gz"));
        assert_eq!(offer.prefix, bytes[..PREFIX_LEN]);
        assert_eq!(offer.chunk_count(), 7); // 100000 / 16384 rounded up
        assert_eq!(manifest.leaves().len(), 7);
        assert_eq!(offer.chunk_len(6), 100_000 - 6 * 16_384);
    }

    #[test]
    fn a_tiny_file_has_a_short_prefix_and_no_name_is_allowed() {
        let (offer, _) = prepare(&MemorySource(b"hi".to_vec()), None, MIN_CHUNK_SIZE).unwrap();
        assert_eq!(offer.name, None);
        assert_eq!(offer.prefix, b"hi");
    }

    #[test]
    fn offers_survive_encoding_and_reject_garbage() {
        let (offer, _) =
            prepare(&MemorySource(sample(40_000)), Some("é.txt"), MIN_CHUNK_SIZE).unwrap();
        let wire = offer.encode();
        assert_eq!(FileOffer::decode(&wire).unwrap(), offer);
        // Truncated at every point, and with trailing bytes, must fail.
        for cut in 0..wire.len() {
            assert!(FileOffer::decode(&wire[..cut]).is_err(), "cut at {cut}");
        }
        let mut extra = wire.clone();
        extra.push(0);
        assert!(FileOffer::decode(&extra).is_err());
        // A name that is not UTF-8.
        let mut bad_name = wire.clone();
        bad_name[2] = 0xFF;
        assert!(FileOffer::decode(&bad_name).is_err());
    }

    #[test]
    fn the_size_limit_is_enforced_before_anything_is_written() {
        let (mut offer, _) = prepare(&MemorySource(sample(40_000)), None, MIN_CHUNK_SIZE).unwrap();
        let (sink, data, _) = mem_sink();
        assert!(FileReceiver::new(offer.clone(), sink, 39_999).is_err());
        assert!(data.lock().unwrap().is_empty());
        // A lying size in an offer is caught by the limit, too.
        offer.size = u64::MAX;
        assert!(offer.validate(DEFAULT_MAX_FILE_SIZE).is_err());
        // The limit itself cannot be raised past the hard maximum.
        offer.size = 10;
        assert!(matches!(
            offer.validate(HARD_MAX_FILE_SIZE + 1),
            Err(ChatError::InvalidConfig(_))
        ));
    }

    #[test]
    fn nonsense_chunk_sizes_and_counts_are_refused() {
        let (offer, _) = prepare(&MemorySource(sample(40_000)), None, MIN_CHUNK_SIZE).unwrap();
        for cs in [0, 1, MIN_CHUNK_SIZE - 1, MAX_CHUNK_SIZE + 1] {
            let o = FileOffer {
                chunk_size: cs,
                ..offer.clone()
            };
            assert!(
                o.validate(DEFAULT_MAX_FILE_SIZE).is_err(),
                "chunk size {cs}"
            );
        }
        // 4 GiB in minimum-size chunks would be over the chunk-count limit.
        let o = FileOffer {
            size: HARD_MAX_FILE_SIZE,
            chunk_size: MIN_CHUNK_SIZE,
            ..offer.clone()
        };
        assert!(o.validate(HARD_MAX_FILE_SIZE).is_err());
        // The same size at the default chunk size is fine.
        let o = FileOffer {
            size: HARD_MAX_FILE_SIZE,
            chunk_size: DEFAULT_CHUNK_SIZE,
            ..offer
        };
        assert!(o.validate(HARD_MAX_FILE_SIZE).is_ok());
    }

    #[test]
    fn a_manifest_that_does_not_match_the_offer_is_refused() {
        let (_, offer, manifest) = serve(sample(100_000));
        let (sink, _, _) = mem_sink();
        let mut rx = FileReceiver::new(offer, sink, DEFAULT_MAX_FILE_SIZE).unwrap();
        // One hash changed.
        let mut tampered = manifest.clone();
        tampered.leaves[3][0] ^= 1;
        assert!(rx.set_manifest(tampered).is_err());
        // A hash missing.
        let mut short = manifest.clone();
        short.leaves.pop();
        assert!(rx.set_manifest(short).is_err());
        assert!(rx.needs_manifest(), "a refused manifest leaves no trace");
        // The real one still works afterwards.
        rx.set_manifest(manifest).unwrap();
        assert!(!rx.needs_manifest());
    }

    #[test]
    fn a_corrupt_chunk_is_rejected_unwritten_and_can_be_asked_for_again() {
        let (server, offer, manifest) = serve(sample(100_000));
        let (sink, data, _) = mem_sink();
        let mut rx = FileReceiver::new(offer, sink, DEFAULT_MAX_FILE_SIZE).unwrap();
        rx.set_manifest(manifest).unwrap();
        let asked = rx.next_requests(2);
        assert_eq!(asked, vec![0, 1]);
        let mut bad_chunk = server.chunk(1).unwrap();
        bad_chunk[100] ^= 0x40;
        assert!(rx.receive_chunk(1, &bad_chunk).is_err());
        assert!(data.lock().unwrap().is_empty(), "nothing written");
        assert_eq!(rx.progress().done, 0);
        // Chunk 1 is asked for again (chunk 0 is still outstanding).
        assert_eq!(rx.next_requests(2), vec![1]);
        rx.receive_chunk(1, &server.chunk(1).unwrap()).unwrap();
        assert_eq!(rx.progress().done, 1);
    }

    #[test]
    fn wrong_length_and_out_of_range_chunks_are_rejected() {
        let (server, offer, manifest) = serve(sample(100_000));
        let (sink, _, _) = mem_sink();
        let mut rx = FileReceiver::new(offer, sink, DEFAULT_MAX_FILE_SIZE).unwrap();
        // Before the manifest, chunks are refused.
        assert!(rx.receive_chunk(0, &server.chunk(0).unwrap()).is_err());
        rx.set_manifest(manifest).unwrap();
        let c0 = server.chunk(0).unwrap();
        assert!(rx.receive_chunk(0, &c0[..c0.len() - 1]).is_err(), "short");
        let mut long = c0.clone();
        long.push(0);
        assert!(rx.receive_chunk(0, &long).is_err(), "long");
        assert!(rx.receive_chunk(7, &c0).is_err(), "index past the end");
        assert!(rx.receive_chunk(u32::MAX, &c0).is_err());
    }

    #[test]
    fn a_false_prefix_claim_is_caught_when_the_first_chunk_arrives() {
        let bytes = sample(50_000);
        let src = MemorySource(bytes);
        let (mut offer, manifest) = prepare(&src, None, MIN_CHUNK_SIZE).unwrap();
        offer.prefix = b"%PDF-1.7 (not really)".to_vec(); // the sender lies
        let server = FileServer::new(Arc::new(src), offer.clone(), manifest.clone()).unwrap();
        let (sink, data, _) = mem_sink();
        let mut rx = FileReceiver::new(offer, sink, DEFAULT_MAX_FILE_SIZE).unwrap();
        rx.set_manifest(manifest).unwrap();
        let err = rx.receive_chunk(0, &server.chunk(0).unwrap()).unwrap_err();
        assert!(err.to_string().contains("prefix"), "{err}");
        assert!(data.lock().unwrap().is_empty());
    }

    #[test]
    fn changing_the_size_or_chunk_size_changes_the_id() {
        let (offer, manifest) =
            prepare(&MemorySource(sample(100_000)), None, MIN_CHUNK_SIZE).unwrap();
        let leaves = manifest.leaves();
        let base = compute_root(offer.size, offer.chunk_size, leaves);
        assert_eq!(base, offer.root);
        assert_ne!(base, compute_root(offer.size + 1, offer.chunk_size, leaves));
        assert_ne!(base, compute_root(offer.size, offer.chunk_size * 2, leaves));
    }

    #[test]
    fn a_file_that_changed_after_the_offer_is_not_served() {
        let bytes = sample(100_000);
        let src = MemorySource(bytes.clone());
        let (offer, manifest) = prepare(&src, None, MIN_CHUNK_SIZE).unwrap();
        // Same size, one byte different in chunk 2.
        let mut changed = bytes;
        changed[2 * MIN_CHUNK_SIZE as usize + 5] ^= 1;
        let server = FileServer::new(
            Arc::new(MemorySource(changed)),
            offer.clone(),
            manifest.clone(),
        )
        .unwrap();
        assert!(server.chunk(1).is_ok());
        assert!(server.chunk(2).is_err());
        // A different size is caught up front.
        assert!(FileServer::new(Arc::new(MemorySource(sample(99_999))), offer, manifest).is_err());
    }

    #[test]
    fn chunks_may_arrive_in_any_order_and_twice() {
        let bytes = sample(100_000);
        let (server, offer, manifest) = serve(bytes.clone());
        let (sink, data, finished) = mem_sink();
        let mut rx = FileReceiver::new(offer, sink, DEFAULT_MAX_FILE_SIZE).unwrap();
        rx.set_manifest(manifest).unwrap();
        for i in [6u32, 2, 4, 0, 5, 1, 1, 6, 3] {
            rx.receive_chunk(i, &server.chunk(i).unwrap()).unwrap();
        }
        assert!(rx.is_complete());
        assert_eq!(*finished.lock().unwrap(), 1);
        assert_eq!(*data.lock().unwrap(), bytes);
        // Anything after completion is harmless.
        rx.receive_chunk(3, &server.chunk(3).unwrap()).unwrap();
        assert_eq!(*finished.lock().unwrap(), 1);
    }

    #[test]
    fn the_request_window_limits_what_is_outstanding() {
        let (server, offer, manifest) = serve(sample(100_000)); // 7 chunks
        let (sink, _, _) = mem_sink();
        let mut rx = FileReceiver::new(offer, sink, DEFAULT_MAX_FILE_SIZE).unwrap();
        assert!(
            rx.next_requests(4).is_empty(),
            "nothing before the manifest"
        );
        rx.set_manifest(manifest).unwrap();
        assert_eq!(rx.next_requests(3), vec![0, 1, 2]);
        assert!(rx.next_requests(3).is_empty(), "window is full");
        rx.receive_chunk(0, &server.chunk(0).unwrap()).unwrap();
        assert_eq!(rx.next_requests(3), vec![3], "one slot opened");
        // The link drops: everything outstanding is asked for again.
        rx.release_in_flight();
        assert_eq!(rx.next_requests(3), vec![1, 2, 3]);
        rx.release_chunk(2);
        assert_eq!(rx.next_requests(3), vec![2]);
    }

    #[test]
    fn progress_can_be_saved_and_restored() {
        let bytes = sample(100_000);
        let (server, offer, manifest) = serve(bytes.clone());
        let (sink, data, _) = mem_sink();
        let mut rx = FileReceiver::new(offer.clone(), sink, DEFAULT_MAX_FILE_SIZE).unwrap();
        rx.set_manifest(manifest.clone()).unwrap();
        for i in [0u32, 1, 4] {
            rx.receive_chunk(i, &server.chunk(i).unwrap()).unwrap();
        }
        let saved = rx.verified_chunks();
        // "Restart": a new receiver on the same sink data.
        let finished = Arc::new(Mutex::new(0));
        let sink2 = Box::new(MemSink {
            data: data.clone(),
            finished: finished.clone(),
        });
        let mut rx2 = FileReceiver::new(offer, sink2, DEFAULT_MAX_FILE_SIZE).unwrap();
        assert!(rx2.restore_verified(&saved).is_err(), "manifest first");
        rx2.set_manifest(manifest).unwrap();
        assert!(rx2.restore_verified(&saved[..3]).is_err(), "wrong length");
        assert_eq!(rx2.restore_verified(&saved).unwrap().done, 3);
        assert_eq!(rx2.next_requests(10), vec![2, 3, 5, 6]);
        for i in [2u32, 3, 5, 6] {
            rx2.receive_chunk(i, &server.chunk(i).unwrap()).unwrap();
        }
        assert!(rx2.is_complete());
        assert_eq!(*data.lock().unwrap(), bytes);
    }

    #[test]
    fn frames_round_trip_and_reject_malformed_input() {
        let f = [7u8; 32];
        let frames = vec![
            FileFrame::ManifestRequest { file: f },
            FileFrame::Manifest {
                file: f,
                manifest: vec![9u8; 96],
            },
            FileFrame::ChunkRequest {
                file: f,
                indices: vec![0, 5, 4_000_000_000],
            },
            FileFrame::Chunk {
                file: f,
                index: 12,
                data: vec![1, 2, 3],
            },
            FileFrame::Unavailable { file: f },
        ];
        for fr in &frames {
            let wire = fr.encode();
            assert_eq!(&FileFrame::decode(&wire).unwrap(), fr);
            assert_eq!(fr.file(), f);
        }
        assert!(FileFrame::decode(&[]).is_err());
        assert!(FileFrame::decode(&[0; 10]).is_err(), "short id");
        let mut unknown = vec![99u8];
        unknown.extend_from_slice(&f);
        assert!(FileFrame::decode(&unknown).is_err());
        // Trailing bytes after a request.
        let mut extra = FileFrame::ManifestRequest { file: f }.encode();
        extra.push(0);
        assert!(FileFrame::decode(&extra).is_err());
        // A manifest that is not a whole number of hashes.
        let mut odd = FileFrame::Manifest {
            file: f,
            manifest: vec![],
        }
        .encode();
        odd.extend_from_slice(&[0; 33]);
        assert!(FileFrame::decode(&odd).is_err());
        // Too many indices in one request, and a request that promises more
        // indices than it carries.
        let many = FileFrame::ChunkRequest {
            file: f,
            indices: vec![0; MAX_REQUEST_INDICES + 1],
        };
        assert!(FileFrame::decode(&many.encode()).is_err());
        let mut liar = FileFrame::ChunkRequest {
            file: f,
            indices: vec![1],
        }
        .encode();
        liar[33] = 0;
        liar[34] = 5; // claims 5 indices, carries 1
        assert!(FileFrame::decode(&liar).is_err());
        // An oversized chunk.
        let huge = FileFrame::Chunk {
            file: f,
            index: 0,
            data: vec![0; MAX_CHUNK_SIZE as usize + 1],
        };
        assert!(FileFrame::decode(&huge.encode()).is_err());
    }

    #[test]
    fn names_are_made_safe() {
        assert_eq!(sanitize_name("report.pdf").as_deref(), Some("report.pdf"));
        assert_eq!(sanitize_name("../../etc/passwd").as_deref(), Some("passwd"));
        assert_eq!(
            sanitize_name("C:\\Users\\x\\y.txt").as_deref(),
            Some("y.txt")
        );
        assert_eq!(sanitize_name("dir/").as_deref(), None);
        assert_eq!(sanitize_name("..").as_deref(), None);
        assert_eq!(sanitize_name("   ").as_deref(), None);
        assert_eq!(sanitize_name("").as_deref(), None);
        assert_eq!(
            sanitize_name("a\nb\tc\u{0}d.txt").as_deref(),
            Some("abcd.txt")
        );
        // Right-to-left override used to disguise an extension.
        assert_eq!(
            sanitize_name("invoice\u{202E}fdp.exe").as_deref(),
            Some("invoicefdp.exe")
        );
        assert_eq!(sanitize_name(".hidden").as_deref(), Some("hidden"));
        assert_eq!(
            sanitize_name("ünïcödé ✓.txt").as_deref(),
            Some("ünïcödé ✓.txt")
        );
        // Long names are cut on a character boundary.
        let long = "é".repeat(200); // 400 bytes
        let cut = sanitize_name(&long).unwrap();
        assert!(cut.len() <= MAX_NAME_BYTES && cut.chars().all(|c| c == 'é'));
    }

    #[test]
    fn the_part_file_sink_renames_only_when_complete() {
        let dir = std::env::temp_dir().join(format!("symbolon-file-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("out.bin");
        let _ = fs::remove_file(&dest);
        let bytes = sample(100_000);
        let (server, offer, manifest) = serve(bytes.clone());
        let sink = PartFileSink::create(&dest, offer.size).unwrap();
        let mut rx = FileReceiver::new(offer, Box::new(sink), DEFAULT_MAX_FILE_SIZE).unwrap();
        rx.set_manifest(manifest).unwrap();
        let part = dir.join("out.bin.part");
        for i in 0..rx.offer().chunk_count() - 1 {
            rx.receive_chunk(i, &server.chunk(i).unwrap()).unwrap();
            assert!(part.exists() && !dest.exists(), "not final until complete");
        }
        let last = rx.offer().chunk_count() - 1;
        rx.receive_chunk(last, &server.chunk(last).unwrap())
            .unwrap();
        assert!(dest.exists() && !part.exists());
        assert_eq!(fs::read(&dest).unwrap(), bytes);
        // An existing destination is never overwritten.
        assert!(PartFileSink::create(&dest, 1).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("symbolon-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_destination_that_appears_mid_download_is_never_replaced() {
        let dir = scratch_dir("appears");
        let dest = dir.join("out.bin");
        let (server, offer, manifest) = serve(sample(40_000));
        let sink = PartFileSink::create(&dest, offer.size).unwrap();
        let mut rx = FileReceiver::new(offer, Box::new(sink), DEFAULT_MAX_FILE_SIZE).unwrap();
        rx.set_manifest(manifest).unwrap();
        fs::write(&dest, b"somebody else's file").unwrap(); // appears mid-download
        let last = rx.offer().chunk_count() - 1;
        for i in 0..last {
            rx.receive_chunk(i, &server.chunk(i).unwrap()).unwrap();
        }
        assert!(rx
            .receive_chunk(last, &server.chunk(last).unwrap())
            .is_err());
        assert_eq!(fs::read(&dest).unwrap(), b"somebody else's file");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_stale_part_file_is_not_silently_reused_but_can_be_resumed() {
        let dir = scratch_dir("stale");
        let dest = dir.join("out.bin");
        let (server, offer, manifest) = serve(sample(40_000));
        // First attempt: write one chunk, then "crash" (drop without finishing).
        {
            let sink = PartFileSink::create(&dest, offer.size).unwrap();
            let mut rx =
                FileReceiver::new(offer.clone(), Box::new(sink), DEFAULT_MAX_FILE_SIZE).unwrap();
            rx.set_manifest(manifest.clone()).unwrap();
            rx.receive_chunk(0, &server.chunk(0).unwrap()).unwrap();
        }
        // A fresh create refuses the leftover; resume accepts it only at the right size.
        assert!(PartFileSink::create(&dest, offer.size).is_err());
        assert!(PartFileSink::resume(&dest, offer.size + 1).is_err());
        let sink = PartFileSink::resume(&dest, offer.size).unwrap();
        let mut rx =
            FileReceiver::new(offer.clone(), Box::new(sink), DEFAULT_MAX_FILE_SIZE).unwrap();
        rx.set_manifest(manifest).unwrap();
        let mut saved = vec![false; offer.chunk_count() as usize];
        saved[0] = true;
        rx.restore_verified(&saved).unwrap();
        for i in 1..offer.chunk_count() {
            rx.receive_chunk(i, &server.chunk(i).unwrap()).unwrap();
        }
        assert_eq!(fs::read(&dest).unwrap(), sample(40_000));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_planted_at_the_part_name_is_not_followed() {
        let dir = scratch_dir("symlink");
        let victim = dir.join("victim.txt");
        fs::write(&victim, b"precious").unwrap();
        let dest = dir.join("out.bin");
        std::os::unix::fs::symlink(&victim, dir.join("out.bin.part")).unwrap();
        // create refuses (does not truncate through the link) ...
        assert!(PartFileSink::create(&dest, 10).is_err());
        // ... and resume refuses a link even though it points at a file.
        assert!(PartFileSink::resume(&dest, 8).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        // A dangling symlink at the destination counts as "exists" too.
        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(dir.join("nowhere"), &dangling).unwrap();
        assert!(PartFileSink::create(&dangling, 10).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_real_file_on_disk_can_be_the_source() {
        let dir = std::env::temp_dir().join(format!("symbolon-file-src-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("in.bin");
        let bytes = sample(70_000);
        fs::write(&path, &bytes).unwrap();
        let src = FileSource::open(&path).unwrap();
        assert_eq!(src.size(), 70_000);
        let (offer, manifest) = prepare(&src, Some("in.bin"), MIN_CHUNK_SIZE).unwrap();
        let (offer2, _) = prepare(&MemorySource(bytes), Some("in.bin"), MIN_CHUNK_SIZE).unwrap();
        assert_eq!(offer, offer2, "disk and memory give the same offer");
        FileServer::new(Arc::new(src), offer, manifest).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
