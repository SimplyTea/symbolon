//! Length-prefixed message framing.
//!
//! TCP is a byte stream, not a message stream, so every logical message on
//! the wire is wrapped as:
//!
//! ```text
//! [ 4 bytes: big-endian u32 length N ][ N bytes: payload ]
//! ```
//!
//! We cap `N` at [`MAX_FRAME_LEN`] so a malicious or buggy peer can't make us
//! allocate an unbounded amount of memory just by sending a huge length
//! prefix before any actual data.

use std::io::{Read, Write};

use crate::error::{ChatError, Result};

/// Refuse to allocate more than 4 MiB for a single frame. Generous enough
/// for chat-sized messages, small enough to bound memory use per frame.
pub const MAX_FRAME_LEN: u32 = 4 * 1024 * 1024;

/// Write one length-prefixed frame to `writer` and flush it.
///
/// The 4-byte length and the payload are assembled into ONE buffer and sent
/// with a single `write_all`. Two separate small writes interact badly with
/// Nagle's algorithm + delayed ACKs (the second write waits for the ACK of
/// the first, which the peer delays ~40 ms), adding tens of milliseconds to
/// every request/response exchange such as the handshake. One write avoids
/// that and also keeps a frame contiguous when several threads share a socket.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<()> {
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    writer.write_all(&buf)?;
    writer.flush()?;
    Ok(())
}

/// Block until one full length-prefixed frame has been read from `reader`,
/// then return its payload bytes.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    // read_exact returns UnexpectedEof if the peer closed the connection
    // cleanly with no more data - translate that into our own error so
    // callers can distinguish "peer hung up" from other I/O failures.
    if let Err(e) = reader.read_exact(&mut len_buf) {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Err(ChatError::ConnectionClosed);
        }
        return Err(ChatError::Io(e));
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(ChatError::FrameTooLarge);
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trips_a_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello world").unwrap();
        let mut cursor = Cursor::new(buf);
        let got = read_frame(&mut cursor).unwrap();
        assert_eq!(got, b"hello world");
    }

    #[test]
    fn rejects_oversized_frames() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes());
        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor).unwrap_err();
        matches!(err, ChatError::FrameTooLarge);
    }
}
