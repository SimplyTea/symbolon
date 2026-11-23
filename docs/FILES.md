# File transfer

Status: **the core is built and tested (0.4.0, stage 1); it is not yet wired
into sessions, groups or the command line.** This page describes the design
and says what exists. Code: `src/file.rs`.

## What you get

- The receiver **sees an offer first**: name (optional), size, and the first
  512 bytes of the file so an app can show a file type. **Nothing downloads
  until the app accepts.** Whether to ask, auto-accept or auto-deny is the
  app's policy ([Library vs app](LIBRARY_VS_APP.md)); the library default is
  to ask, and declining is silent (no message goes back).
- Files up to **1 GiB by default**; an app can raise its own limit up to a
  hard maximum of **4 GiB**. The size field is 64-bit, so raising the maximum
  later does not change the format.
- Files are **streamed**: one chunk and a list of hashes are in memory, never
  the whole file. The same logic is meant for **groups and 1:1 chats**.

## How a transfer works

```text
sender                                         receiver
------                                         --------
prepare(): hash the file chunk by chunk
  -> FileOffer, Manifest
offer is shown ------------------------------> app decides (nothing downloaded yet)
                                <------------  ManifestRequest        (accepted)
Manifest ------------------------------------>  checked against the offer's root
                                <------------  ChunkRequest (a window of indices)
Chunk, Chunk, ... --------------------------->  each checked against its own hash,
                                <------------  then written; more requests follow
                                                when all verified: finished (renamed)
```

The receiver keeps only a **window** of requests outstanding (a few chunks),
rather than the sender pushing the whole file. Pushing 1 GB into a session's
outbox would use all memory, and one big transfer would hold up chat messages
on the same link.

## The offer

| Field | Size | Why |
|---|---:|---|
| name length, name | 2 + up to 255 | Optional (0 = none). Attacker-controlled text, see [names](#names) |
| size | 8 (u64) | Shown to the user; checked against the limit before anything is stored |
| chunk size | 4 (u32) | 16 KiB to 1 MiB; the sender normally uses 256 KiB |
| root | 32 | The file's id: a hash over the size, the chunk size and every chunk hash |
| prefix length, prefix | 2 + up to 512 | The first bytes of the file, to show a type before downloading |

The offer is meant to travel inside something already authenticated: a signed
group message or a 1:1 session. The **root** is what ties everything after it
to that signed offer.

## The manifest, and why it is a flat list

The manifest is one 32-byte hash per chunk, back to back (128 KiB for a 1 GiB
file at 256 KiB chunks). The receiver downloads it once, recomputes the root
from it and compares with the offer. After that each chunk is checked against
its own hash **before it is written**.

| Option | Trade-off |
|---|---|
| **Flat hash list (chosen)** | Simple to get right. The whole list (at most 2 MiB, one frame) is fetched once before the first chunk. Chunk messages carry no proofs |
| Merkle tree with a proof per chunk | No upfront list, but about 12 extra hashes (384 bytes) on every chunk and noticeably more code. The benefit (verifying a chunk without the full list) is not needed because the receiver always has the list first |
| One hash of the whole file | Cannot tell which chunk is bad, so no early rejection, no resume, no serving from several peers |

Because every chunk is verified on its own, a chunk can come from **any peer
that holds the file**, not only the author. That is what lets the author-first
rule with fallback to other holders work for files the same way it does for
messages.

## Every check, in full

Each row is something the code refuses to do, and where. **Built** rows are in
`src/file.rs` and have tests; **Planned** rows belong to the wiring stage.

### Built

**The offer, before anything is requested, allocated or written**
(`FileOffer::decode`, `FileOffer::validate`)

| # | Check | Refused with |
|--:|---|---|
| 1 | The message is exactly the right length: not truncated, no trailing bytes | truncated / trailing bytes |
| 2 | The name is at most 255 bytes and valid UTF-8; a name, if present, is not empty | file name too long / not UTF-8 / length out of range |
| 3 | The prefix is at most 512 bytes, and no longer than the file | prefix longer than allowed |
| 4 | The size is within the **receiver's own limit** (default 1 GiB) | file is larger than the allowed size |
| 5 | The receiver's limit itself is not above the 4 GiB hard maximum | invalid setting |
| 6 | The chunk size is 16 KiB to 1 MiB | chunk size out of range |
| 7 | The file has at most 65536 chunks (keeps the manifest inside one frame) | too many chunks |

**The manifest** (`Manifest::decode`, `FileReceiver::set_manifest`)

| # | Check | Refused with |
|--:|---|---|
| 8 | The length is a whole number of 32-byte hashes, at most 65536 of them | manifest has a bad length |
| 9 | It has exactly as many hashes as the file has chunks | wrong number of chunks |
| 10 | Hashing it (with the size and chunk size) gives **exactly the offer's root** | manifest does not match the offer |
| 11 | A refused manifest leaves no trace; the real one is still accepted afterwards | (tested) |

**Every chunk, before it is written** (`FileReceiver::receive_chunk`)

| # | Check | Refused with |
|--:|---|---|
| 12 | The manifest is already in (no chunks before it) | chunk arrived before the manifest |
| 13 | The index is inside the file | chunk index out of range |
| 14 | A chunk already received is ignored, not written twice | (duplicate ignored) |
| 15 | The length is exactly what that chunk must be (the last one is the remainder), so nothing beyond the declared size is ever accepted | chunk has the wrong length |
| 16 | The chunk's hash matches its entry in the manifest | chunk failed its hash check |
| 17 | Chunk 0 starts with the **prefix the sender claimed** | the file does not start with the prefix the sender claimed |
| 18 | A refused chunk is not written and goes back to "not requested", so it can be asked for again, possibly from another peer | (tested) |
| 19 | When the last chunk is in, the sink is finished **exactly once** | (tested) |

**Pacing** (`FileReceiver::next_requests`)

| # | Check | Effect |
|--:|---|---|
| 20 | At most `window` chunks are outstanding at once, and at most 64 per request | a big file cannot flood the link or the outbox |
| 21 | Nothing is requested until the manifest is verified | |

**The sender** (`prepare`, `FileServer`)

| # | Check | Refused with |
|--:|---|---|
| 22 | The offer is validated (against the 4 GiB maximum) before the file is read | as rows 3 to 7 |
| 23 | The file is not shorter than its recorded size | file is shorter than its recorded size |
| 24 | The source's size still equals the offer's size when serving starts | file size changed since the offer was made |
| 25 | The manifest matches the offer (count and root) | manifest does not match the offer |
| 26 | The index asked for is inside the file | chunk index out of range |
| 27 | **Each chunk is hashed again just before it is sent**, so a file that changed on disk after the offer is noticed instead of served | file changed on disk since the offer was made |

**Messages** (`FileFrame::decode`)

| # | Check | Refused with |
|--:|---|---|
| 28 | The kind byte is known and the 32-byte file id is present | unknown file message kind / truncated |
| 29 | A manifest message is a whole number of hashes, at most 2 MiB | manifest has a bad length |
| 30 | A request asks for at most 64 chunks and carries exactly as many indices as it says | too many chunks requested at once |
| 31 | A chunk message carries at most 1 MiB of data | chunk is larger than allowed |
| 32 | No trailing bytes after any message | trailing bytes |

**Writing to disk** (`PartFileSink`)

| # | Check | Refused with |
|--:|---|---|
| 33 | The destination does not exist (a dangling symlink counts as existing) | refusing to overwrite an existing file |
| 34 | `<name>.part` is created with "must not already exist", which also **refuses a symlink planted at that name**, so we can never be made to write through a link to another file | already exists |
| 35 | A leftover `.part` is not silently reused; `resume` accepts it only if it is a **plain file (not a link) of exactly the expected size** | not a plain file of the expected size |
| 36 | Data is flushed to disk before the final step | |
| 37 | The final step is a hard link, which **fails if the destination appeared meanwhile**, so a file that showed up during the download is never replaced | a file appeared at the destination while downloading |
| 38 | On a file system without hard links it falls back to a check and then a rename | |
| 39 | The file only gets its real name after every chunk has verified; until then it is `<name>.part` | |

**Resuming** (`FileReceiver::restore_verified`)

| # | Check | Refused with |
|--:|---|---|
| 40 | The manifest must already be set, and the saved progress must have one flag per chunk of this file | manifest is needed / saved progress does not match |

**Names** (`sanitize_name`, used by the app before it builds a path)

| # | Check | Effect |
|--:|---|---|
| 41 | Only the last path component is kept (handles `/` and `\`) | `../../etc/passwd` becomes `passwd` |
| 42 | Control characters, zero-width characters and the text-direction overrides are removed | `invoice` + U+202E + `fdp.exe` shows as it really is |
| 43 | Leading and trailing dots and spaces are trimmed; a name that is nothing but those is refused | `..` gives no name |
| 44 | Long names are cut to 255 bytes on a character boundary | |

### Group wiring (built, `src/group/files.rs`, 9 tests)

| # | Check | Notes |
|---:|---|---|
| 45 | The offer is only believed inside a **signed group message**: author key, signature, roster-version permission and hash chain are all checked first, like a post | The author needs `can_write` as of the version it signed |
| 46 | An offer is validated when it is **decoded** (sizes, chunk size, chunk count, prefix) at the 4 GiB ceiling; the receiver's own lower limit is applied again at accept | A bad offer is dropped as undecodable |
| 47 | A manifest or chunk request is only answered if the asker **currently has `can_read`** in the roster | Tested by a member with no read tier sending raw requests |
| 48 | We only serve files we **offered** or **registered** with `serve_file`, which re-hashes the file and requires the offer's root | A wrong or damaged file is refused |
| 49 | In an **AuthorOnly** group only the author serves (and only the author is asked) | Tested |
| 50 | A file is **never requested without an explicit `accept_file`**; offers just produce an event | Tested |
| 51 | Downloads are **capped** at `max_concurrent_downloads` (default 4) | |
| 52 | A **window** of 8 chunks is outstanding per download; we answer at most 16 chunks per request | An honest receiver asks again |
| 53 | A reply is only taken from **the member we asked**; others are ignored | |
| 54 | A source that sends a **bad manifest, a chunk failing its hash, or a false prefix** is dropped and the next member is asked; with nobody left the download fails | |
| 55 | A source answering **Unavailable** is skipped the same way | |
| 56 | **Deleting** the offer removes it, stops serving it and cancels any download of it | Tested |
| 57 | You cannot accept **your own** file or a file that is **already downloading** | |
| 58 | An offer **over our size limit** is shown but cannot be accepted | |
| 59 | An offer **cannot be edited** into something else | |
| 60 | Offers are acknowledged with a **delivery receipt**, like posts | |

### Still planned

| Check | Where |
|---|---|
| The same for **1:1 sessions** (needs the small message envelope) | session wiring |
| Rate limiting **per peer** (requests per second), beyond the per-request and per-download caps above | both |
| **Stall detection**: a source that goes silent is only left by `try_another_source`, because the library has no timers | both |
| Offers from a member since **removed** are not accepted, if the removal reached us first (served files already stop: no read, no answer) | group |

### Known gaps (said plainly)

| Gap | Why it matters, and what to do |
|---|---|
| A valid chunk we did not ask for is still accepted from the member we asked | Harmless (it is verified) but it lets that one member spend our disk writes. Chunks from anyone else are dropped |
| **Serving reads the disk on the group's processing thread** | A busy server delays its other group traffic by up to 16 chunk reads per request. Fine for now; a worker thread is a later change |
| A download is **not resumed after a restart** | The part file and its verified-chunk list are not saved yet |
| **No free-disk-space check** | The part file is created at its full declared size. On most file systems that is a sparse file, but on some it reserves the space at once. An app should check free space before it accepts |
| A leftover `.part` file is not cleaned up if a download is abandoned | The app decides (it may want to resume) |
| `sanitize_name` does not handle **Windows reserved names** (`CON`, `NUL`) or NTFS alternate streams (`name:stream`) | An app that writes on Windows must check those too |
| The **name and size are visible to every member** of the group, and the offer stays in the author's chain | Do not put secrets in a file name |
| The **prefix and name say nothing reliable about the content** beyond the first 512 bytes (and `.docx` and `.zip` look the same) | Treat the file type as a claim; the library does no malware or content scanning |
| An offer is only as trustworthy as the channel it came through | In groups: a signed message (checks 45-46). In 1:1: still planned |
| The hash is SHA-256. Its security (collision and preimage resistance) is what makes the checks mean anything | See the [post-quantum status](THREAT_MODEL.md#post-quantum-status): Grover only halves its preimage strength, and collisions stay infeasible |

## Names

A file name is attacker-controlled text. `sanitize_name` keeps only the last
path component (`../../etc/passwd` becomes `passwd`), drops control
characters and the invisible direction overrides used to disguise extensions
(`invoice` + U+202E + `fdp.exe`), trims dots and spaces, and shortens long names on a
character boundary. It does not handle Windows reserved names (`CON`, `NUL`);
an app writing on Windows should check those as well. The destination sink
refuses to overwrite an existing file and writes to `<name>.part`, renaming
only when the whole file has verified.

## The prefix is a claim

The first 512 bytes let an app say "claims to be a PDF" before downloading.
Some types cannot be told apart from the start: `.docx`, `.pptx` and `.xlsx`
are all ZIP files, and `.txt` has no signature at all. The library ships **no
file-type database** (that belongs in the app or an add-on), and treats the
prefix as untrusted: it is verified against the real file when it arrives.

## Speed

Preparing an offer hashes the file once. Measured on a development machine
with the file already in memory: about 1.1 GiB/s to prepare, and about 0.6
GiB/s to serve, verify and write chunks. On real hardware the disk and network
set the pace. Not measured on a small board.

## Built and not built

| Piece | State |
|---|---|
| Offer, manifest, chunk server, receiver with window, resume bookkeeping, part-file sink (no overwrite, no symlink following), frames, name sanitizing | **Built**, 22 tests |
| Wiring into **group** messages (content kind 3, tag `0x18`, author first then other holders, events, caps) | **Built**, 9 tests |
| Wiring into **1:1 sessions** (needs a small message envelope so a session can carry text and file messages) | Next |
| App-facing events and accept/decline calls, auto-accept policy hook | Next |
| CLI: y/n prompt, `--auto-accept`, `--auto-deny`, send command | Next |
| Wire format section and end-to-end scripts | With the wiring |
