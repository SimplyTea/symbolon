//! File sharing inside a group: offers, downloads and serving.
//!
//! This is a child module of `group` so it can use the hub's private state.
//! The file mechanics themselves (hashing, chunking, verification) live in
//! [`crate::file`]; this module only connects them to the group:
//!
//! * an **offer** is a signed message in the author's chain (content kind 3),
//!   so it is ordered, authenticated, relayable and deletable like a post;
//! * the **bytes** move afterwards, pairwise, as `GroupMessage::File` frames,
//!   and only if the receiver asks. The receiver drives: it requests the
//!   manifest, then a small window of chunks, and every chunk is checked
//!   against the manifest (whose root the signed offer commits to) before it
//!   is written;
//! * **author first**: a download starts with the author, and moves to the
//!   next connected member only if the author answers "unavailable", sends
//!   something that fails a check, or the app calls
//!   [`GroupHub::try_another_source`]. There are no timers in the library, so
//!   a source that simply goes silent is the app's call to move on from;
//! * only current readers are served, and only for files this member holds
//!   (its own, or ones it has verified and registered with
//!   [`GroupHub::serve_file`]).
//!
//! Locking: the `files` lock is never held while taking another hub lock
//! except in the order files -> (nothing). Candidate sources are computed
//! BEFORE it is taken, and frames are sent AFTER it is released.

use std::collections::HashMap;
use std::sync::Arc;

use super::{GroupEvent, GroupHub, GroupMessage};
use crate::error::{ChatError, Result};
use crate::file::{
    prepare, ChunkSource, FileFrame, FileId, FileOffer, FileReceiver, FileServer, FileSink,
    Manifest,
};
use crate::identity::{Identity, PeerId};

/// Chunks kept outstanding per download. With the default 256 KiB chunk that
/// is 2 MiB in flight: enough to keep a link busy, small enough not to flood.
const WINDOW: usize = 8;

/// The most chunks we answer from ONE request (a request may name up to 64).
/// Extra indices are ignored; an honest receiver asks again.
const MAX_CHUNKS_PER_REQUEST: usize = 16;

/// A running download.
struct Download {
    author: PeerId,
    seq: u64,
    receiver: FileReceiver,
    /// Who we are asking right now.
    current: PeerId,
    /// Everyone already tried (including `current`).
    tried: Vec<PeerId>,
    /// Last whole percentage reported, so progress events stay sparse.
    last_pct: u32,
}

/// All file state of one hub.
#[derive(Default)]
pub(super) struct FileState {
    /// Offers we have seen and not deleted: `(author, seq)`.
    offers: HashMap<(PeerId, u64), FileOffer>,
    /// Files we can hand out.
    serving: HashMap<FileId, Arc<FileServer>>,
    /// Downloads in progress, by file id.
    downloads: HashMap<FileId, Download>,
}

/// What to do after the lock is released.
#[derive(Default)]
struct Outcome {
    send: Vec<(PeerId, FileFrame)>,
    events: Vec<GroupEvent>,
}

impl GroupHub {
    // ------------------------------------------------------------------
    // Hooks called from group.rs
    // ------------------------------------------------------------------

    pub(super) fn is_file_offer(&self, author: &PeerId, seq: u64) -> bool {
        self.files
            .lock()
            .unwrap()
            .offers
            .contains_key(&(*author, seq))
    }

    pub(super) fn remember_file_offer(&self, author: PeerId, seq: u64, offer: FileOffer) {
        self.files
            .lock()
            .unwrap()
            .offers
            .insert((author, seq), offer);
    }

    /// A file message was deleted: forget the offer, stop serving it and
    /// cancel its download.
    pub(super) fn forget_file_offer(&self, author: &PeerId, seq: u64) {
        let mut f = self.files.lock().unwrap();
        if let Some(offer) = f.offers.remove(&(*author, seq)) {
            f.serving.remove(&offer.id());
            f.downloads.remove(&offer.id());
        }
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Offer a file to the group. Hashes the whole file once (see
    /// [`crate::file::prepare`]), starts serving it, and posts the signed
    /// offer. Requires `can_write`. Returns the message's sequence number.
    ///
    /// `name` is optional. `chunk_size` is usually
    /// [`crate::file::DEFAULT_CHUNK_SIZE`].
    pub fn offer_file(
        &self,
        identity: &Identity,
        source: Arc<dyn ChunkSource>,
        name: Option<&str>,
        chunk_size: u32,
    ) -> Result<u64> {
        self.require_permission(|p| p.can_write)?;
        let (offer, manifest) = prepare(source.as_ref(), name, chunk_size)?;
        let id = offer.id();
        let server = FileServer::new(source, offer.clone(), manifest)?;
        // Serve BEFORE announcing, so a fast request is not answered "no".
        self.files
            .lock()
            .unwrap()
            .serving
            .insert(id, Arc::new(server));
        match self.sign_and_send(identity, super::GroupContent::File { offer }) {
            Ok(seq) => Ok(seq),
            Err(e) => {
                self.files.lock().unwrap().serving.remove(&id);
                Err(e)
            }
        }
    }

    /// Say yes to an offer: start downloading `author`'s file `seq` into
    /// `sink` (for example a [`crate::file::PartFileSink`]). Asks the author
    /// first. Progress and the outcome arrive as events.
    ///
    /// Fails (and starts nothing) if the offer is unknown or was deleted, is
    /// over [`super::GroupHubConfig::max_file_size`], is already downloading,
    /// is our own, or too many downloads are running.
    pub fn accept_file(&self, author: &PeerId, seq: u64, sink: Box<dyn FileSink>) -> Result<()> {
        self.require_permission(|p| p.can_read)?;
        let readers = self.connected_readers();
        let author_only = self.author_only();
        let mut out = Outcome::default();
        {
            let mut f = self.files.lock().unwrap();
            let offer = f
                .offers
                .get(&(*author, seq))
                .cloned()
                .ok_or(ChatError::FileTransfer("no such file offer"))?;
            if *author == self.own_id {
                return Err(ChatError::FileTransfer("this is our own file"));
            }
            if f.downloads.contains_key(&offer.id()) {
                return Err(ChatError::FileTransfer("this file is already downloading"));
            }
            if f.downloads.len() >= self.config.max_concurrent_downloads {
                return Err(ChatError::FileTransfer("too many downloads are running"));
            }
            // Author first, then anyone else connected.
            let first = if readers.contains(author) {
                *author
            } else if author_only {
                return Err(ChatError::ConnectionClosed); // only the author may serve
            } else {
                *readers.first().ok_or(ChatError::ConnectionClosed)?
            };
            let receiver = FileReceiver::new(offer.clone(), sink, self.config.max_file_size)?;
            f.downloads.insert(
                offer.id(),
                Download {
                    author: *author,
                    seq,
                    receiver,
                    current: first,
                    tried: vec![first],
                    last_pct: 0,
                },
            );
            out.send
                .push((first, FileFrame::ManifestRequest { file: offer.id() }));
        }
        self.flush(out);
        Ok(())
    }

    /// Say no. Cancels a running download of this file and forgets the
    /// offer. Purely local: nobody is told. (An app that never calls this
    /// and just ignores the offer behaves the same, apart from the memory
    /// the offer takes.)
    pub fn decline_file(&self, author: &PeerId, seq: u64) {
        self.forget_file_offer(author, seq);
    }

    /// Give up on the member currently asked and ask the next connected one.
    /// Use it when a source has gone quiet. Errors if the file is not
    /// downloading; ends the download with [`GroupEvent::FileFailed`] if
    /// nobody is left to ask.
    pub fn try_another_source(&self, author: &PeerId, seq: u64) -> Result<()> {
        let readers = self.connected_readers();
        let author_only = self.author_only();
        let mut out = Outcome::default();
        {
            let mut f = self.files.lock().unwrap();
            let id = f
                .offers
                .get(&(*author, seq))
                .map(|o| o.id())
                .filter(|id| f.downloads.contains_key(id))
                .ok_or(ChatError::FileTransfer("that file is not downloading"))?;
            Self::fail_over(&mut f, id, &readers, author_only, &mut out);
        }
        self.flush(out);
        Ok(())
    }

    /// Start serving a file we already hold (for example one we finished
    /// downloading), so other members can fetch it from us when the author
    /// is away. The whole file is hashed again and must match the offer's
    /// root, so a wrong or damaged file is refused here.
    pub fn serve_file(
        &self,
        author: &PeerId,
        seq: u64,
        source: Arc<dyn ChunkSource>,
    ) -> Result<()> {
        if self.author_only() && *author != self.own_id {
            return Err(ChatError::FileTransfer(
                "this group lets only the author serve its files",
            ));
        }
        let offer = self
            .files
            .lock()
            .unwrap()
            .offers
            .get(&(*author, seq))
            .cloned()
            .ok_or(ChatError::FileTransfer("no such file offer"))?;
        let (check, manifest) = prepare(source.as_ref(), offer.name.as_deref(), offer.chunk_size)?;
        if check.root != offer.root {
            return Err(ChatError::FileTransfer("that file is not the one offered"));
        }
        let server = FileServer::new(source, offer.clone(), manifest)?;
        self.files
            .lock()
            .unwrap()
            .serving
            .insert(offer.id(), Arc::new(server));
        Ok(())
    }

    /// The offer for `author`'s message `seq`, if we have it and it was not
    /// deleted.
    pub fn file_offer(&self, author: &PeerId, seq: u64) -> Option<FileOffer> {
        self.files
            .lock()
            .unwrap()
            .offers
            .get(&(*author, seq))
            .cloned()
    }

    // ------------------------------------------------------------------
    // Incoming frames
    // ------------------------------------------------------------------

    pub(super) fn handle_file_frame(&self, from: PeerId, frame: FileFrame) {
        // Everything here needs the other side to be a current reader.
        if !self.roster.lock().unwrap().permissions_of(&from).can_read {
            return;
        }
        match frame {
            FileFrame::ManifestRequest { file } => {
                let server = self.files.lock().unwrap().serving.get(&file).cloned();
                let reply = match server {
                    Some(s) => FileFrame::Manifest {
                        file,
                        manifest: s.manifest_bytes(),
                    },
                    None => FileFrame::Unavailable { file },
                };
                self.send_file_frame(&from, reply);
            }
            FileFrame::ChunkRequest { file, indices } => {
                let server = self.files.lock().unwrap().serving.get(&file).cloned();
                let Some(server) = server else {
                    self.send_file_frame(&from, FileFrame::Unavailable { file });
                    return;
                };
                for index in indices.into_iter().take(MAX_CHUNKS_PER_REQUEST) {
                    match server.chunk(index) {
                        Ok(data) => {
                            self.send_file_frame(&from, FileFrame::Chunk { file, index, data })
                        }
                        Err(_) => {
                            // Out of range, or the file changed on disk.
                            self.send_file_frame(&from, FileFrame::Unavailable { file });
                            break;
                        }
                    }
                }
            }
            reply => self.handle_file_reply(from, reply),
        }
    }

    /// A manifest, chunk or "unavailable" answer to one of OUR requests.
    fn handle_file_reply(&self, from: PeerId, frame: FileFrame) {
        let readers = self.connected_readers();
        let author_only = self.author_only();
        let id = frame.file();
        let mut out = Outcome::default();
        {
            let mut f = self.files.lock().unwrap();
            let Some(dl) = f.downloads.get_mut(&id) else {
                return; // not downloading this: ignore
            };
            if dl.current != from {
                return; // only the member we asked may answer
            }
            let step = match frame {
                FileFrame::Manifest { manifest, .. } => {
                    Manifest::decode(&manifest).and_then(|m| dl.receiver.set_manifest(m))
                }
                FileFrame::Chunk { index, data, .. } => dl.receiver.receive_chunk(index, &data),
                FileFrame::Unavailable { .. } => {
                    Self::fail_over(&mut f, id, &readers, author_only, &mut out);
                    drop(f);
                    self.flush(out);
                    return;
                }
                _ => return,
            };
            match step {
                Ok(progress) => {
                    let pct = (progress.done as u64 * 100 / progress.total.max(1) as u64) as u32;
                    if progress.complete {
                        out.events.push(GroupEvent::FileComplete {
                            author: dl.author,
                            seq: dl.seq,
                        });
                        f.downloads.remove(&id);
                    } else {
                        if pct != dl.last_pct {
                            dl.last_pct = pct;
                            out.events.push(GroupEvent::FileProgress {
                                author: dl.author,
                                seq: dl.seq,
                                done: progress.done,
                                total: progress.total,
                            });
                        }
                        let wanted = dl.receiver.next_requests(WINDOW);
                        if !wanted.is_empty() {
                            out.send.push((
                                dl.current,
                                FileFrame::ChunkRequest {
                                    file: id,
                                    indices: wanted,
                                },
                            ));
                        }
                    }
                }
                // The member sent data that fails a check: try someone else.
                Err(ChatError::FileTransfer(_)) | Err(ChatError::MalformedMessage(_)) => {
                    Self::fail_over(&mut f, id, &readers, author_only, &mut out);
                }
                // Anything else (the disk) is ours: stop, keep what we have.
                Err(_) => {
                    if let Some(dl) = f.downloads.remove(&id) {
                        out.events.push(GroupEvent::FileFailed {
                            author: dl.author,
                            seq: dl.seq,
                            reason: "could not write the file",
                        });
                    }
                }
            }
        }
        self.flush(out);
    }

    /// Move download `id` to the next untried connected member, or end it.
    fn fail_over(
        f: &mut FileState,
        id: FileId,
        readers: &[PeerId],
        author_only: bool,
        out: &mut Outcome,
    ) {
        let Some(dl) = f.downloads.get_mut(&id) else {
            return;
        };
        dl.receiver.release_in_flight();
        let author = dl.author;
        match readers
            .iter()
            .find(|p| !dl.tried.contains(p) && (!author_only || **p == author))
            .copied()
        {
            Some(next) => {
                dl.tried.push(next);
                dl.current = next;
                let first = if dl.receiver.needs_manifest() {
                    FileFrame::ManifestRequest { file: id }
                } else {
                    FileFrame::ChunkRequest {
                        file: id,
                        indices: dl.receiver.next_requests(WINDOW),
                    }
                };
                out.send.push((next, first));
            }
            None => {
                out.events.push(GroupEvent::FileFailed {
                    author: dl.author,
                    seq: dl.seq,
                    reason: "no member could provide the file",
                });
                f.downloads.remove(&id);
            }
        }
    }

    // ------------------------------------------------------------------
    // Small helpers
    // ------------------------------------------------------------------

    /// Connected members who currently have `can_read`, in a stable order.
    fn connected_readers(&self) -> Vec<PeerId> {
        let roster = self.roster.lock().unwrap();
        let sessions = self.sessions.lock().unwrap();
        let mut v: Vec<PeerId> = sessions
            .keys()
            .filter(|p| roster.permissions_of(p).can_read)
            .copied()
            .collect();
        v.sort_by_key(|p| *p.as_bytes());
        v
    }

    /// In an AuthorOnly group only an author serves its own content, and that
    /// holds for its files too.
    fn author_only(&self) -> bool {
        self.roster.lock().unwrap().relay_policy() == super::RelayPolicy::AuthorOnly
    }

    fn send_file_frame(&self, to: &PeerId, frame: FileFrame) {
        let wire = GroupMessage::File(frame).encode();
        if let Some(session) = self.sessions.lock().unwrap().get(to) {
            let _ = session.send(&wire);
        }
    }

    fn flush(&self, out: Outcome) {
        for (to, frame) in out.send {
            self.send_file_frame(&to, frame);
        }
        for e in out.events {
            let _ = self.event_tx.send(e);
        }
    }
}
