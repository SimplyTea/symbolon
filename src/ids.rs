//! Identifier types: [`PeerId`] and [`GroupId`].
//!
//! Both are exactly 32 bytes (a SHA-256 hash). Earlier versions carried them
//! as 64-character hex *strings*, which doubled their size on the wire and let
//! any piece of text pose as an id. They are now real types:
//!
//! * the wire and the saved files carry the **32 raw bytes**;
//! * hex exists only at the edges: [`Display`](std::fmt::Display) and
//!   [`Debug`](std::fmt::Debug) print it, and [`PeerId::from_hex`] /
//!   [`GroupId::from_hex`] parse it (what a person copies from the screen);
//! * you cannot pass a [`GroupId`] where a [`PeerId`] is expected, or a random
//!   string where either is expected - the compiler refuses.

/// Lower-case hex of `bytes`.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Parse exactly 64 hex characters (either case) into 32 bytes.
pub(crate) fn from_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wrap 32 raw bytes.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                $name(bytes)
            }
            /// The 32 raw bytes (what travels on the wire).
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
            /// Lower-case hex, 64 characters (for display and copy/paste).
            pub fn to_hex(&self) -> String {
                to_hex(&self.0)
            }
            /// The first 8 hex characters: a short label for logs and screens.
            pub fn short(&self) -> String {
                to_hex(&self.0[..4])
            }
            /// Parse 64 hex characters; `None` if the text is not exactly that.
            pub fn from_hex(s: &str) -> Option<Self> {
                from_hex32(s).map($name)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&to_hex(&self.0))
            }
        }

        // Debug prints the quoted hex, like the old `String` ids did, so logs
        // and trace output look the same.
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "\"{}\"", to_hex(&self.0))
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(b: [u8; 32]) -> Self {
                $name(b)
            }
        }
    };
}

id_type!(
    /// A stable identifier for a peer: the SHA-256 fingerprint of their
    /// long-term public key (32 raw bytes; shown as 64 hex characters). This
    /// is what you read aloud or compare on a QR code to check you pinned the
    /// right key.
    PeerId
);

id_type!(
    /// Identifier of a group: a SHA-256 hash that commits to the founding
    /// members, kind and policy (32 raw bytes; shown as 64 hex characters).
    GroupId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_is_strict() {
        let id = PeerId::from_bytes([0xAB; 32]);
        assert_eq!(id.to_hex().len(), 64);
        assert_eq!(PeerId::from_hex(&id.to_hex()), Some(id));
        assert_eq!(PeerId::from_hex(&format!(" {id}\n")), Some(id));
        assert_eq!(PeerId::from_hex("abcd"), None);
        assert_eq!(PeerId::from_hex(&"zz".repeat(32)), None);
        assert_eq!(format!("{id}"), "ab".repeat(32));
    }

    #[test]
    fn ids_are_32_bytes_not_64() {
        assert_eq!(std::mem::size_of::<PeerId>(), 32);
        assert_eq!(std::mem::size_of::<GroupId>(), 32);
    }
}
