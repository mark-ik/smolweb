//! An implementation of the [Scorpion protocol](https://github.com/zzo38/scorpion)
//! and its document file format.
//!
//! Scorpion is a small-web protocol by zzo38 with a wider surface than most of
//! its neighbours: four subprotocols rather than one verb, range requests,
//! uploads with conflict detection, and a two-way interactive mode. Its
//! document format is binary blocks, not a line grammar.
//!
//! ```
//! use scorpion_protocol::{Request, Header, Status};
//!
//! let request = Request::receive("scorpion://example.com/");
//! assert_eq!(request.to_wire(), b"R scorpion://example.com/\r\n");
//!
//! let header = Header::parse("20 1234 text/plain").unwrap();
//! assert_eq!(header.status, Status::OK);
//! assert!(header.status.has_body());
//! ```
//!
//! ## What costs what
//!
//! The wire grammar ([`request`], [`response`], [`status`]) and the document
//! format ([`document`]) have **no dependencies** and are always compiled. A
//! consumer that only parses -- a crawler, an archiver, a renderer -- takes
//! the crate with `default-features = false` and pulls in no async runtime and
//! no TLS stack.
//!
//! Everything that touches a socket is behind a feature: `client`, `tls` for
//! `scorpions://`, and `server`.
//!
//! ## One port, two protocols
//!
//! Scorpion runs TLS and plaintext on the **same** port, 1517. The
//! specification distinguishes them by the first byte the client sends: `0x16`
//! is a TLS record header, and anything else is a subprotocol byte. That makes
//! a server's accept path a one-byte peek rather than two listeners, and
//! [`is_tls_hello`] is that check.
//!
//! Note the asymmetry the specification insists on: a **server** treats
//! `scorpion:` and `scorpions:` as equivalent, but a **client** MUST treat
//! them as different. A client that collapsed them would silently accept a
//! plaintext answer to a request the user made encrypted.
//!
//! ## Relationship to the specification
//!
//! Written against the published specification, which is marked a draft. This
//! is an independent implementation: the reference implementation is C and
//! carries no licence file, so none of it was copied. The specification's
//! author explicitly invites independent implementations.
//!
//! Where the specification leaves something open, this crate carries the bytes
//! rather than inventing a meaning -- unknown status minor codes route by
//! their major class, unknown block types are preserved rather than dropped,
//! and interactive capability codes are passed through verbatim.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod document;
pub mod request;
pub mod response;
pub mod status;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "tls")]
pub mod tls;

pub use document::{Block, BlockType, Encoding};
pub use request::{Parameter, Range, Request, RequestError, Subprotocol};
pub use response::{Header, ResponseError, RetryAfter, Size};
pub use status::{Major, Status};

/// The default port, for both TLS and plaintext.
pub const DEFAULT_PORT: u16 = 1517;

/// The plaintext URL scheme.
pub const SCHEME: &str = "scorpion";

/// The TLS URL scheme.
pub const SCHEME_TLS: &str = "scorpions";

/// Whether a connection's first byte marks it as TLS rather than plaintext.
///
/// The specification puts both on one port and separates them here: `0x16` is
/// the TLS `handshake` record type, and no Scorpion subprotocol byte can
/// collide with it, since those are the ASCII letters `R`, `S`, `I`, and `M`.
pub fn is_tls_hello(first_byte: u8) -> bool {
    first_byte == 0x16
}

/// The largest request line this crate will read by default.
///
/// The specification sets no limit, so this is a defensive choice rather than
/// a protocol fact: without one, a server would buffer until it ran out of
/// memory for a client that never sent a newline.
pub const MAX_REQUEST_LINE: usize = 8192;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_subprotocol_byte_can_be_mistaken_for_a_tls_hello() {
        // The premise of sharing a port: the disambiguating byte must be
        // unambiguous. If any subprotocol byte were 0x16 the whole scheme
        // would be broken, so this is worth asserting rather than assuming.
        for subprotocol in [
            Subprotocol::Receive,
            Subprotocol::Send,
            Subprotocol::Interactive,
            Subprotocol::Meta,
        ] {
            assert!(
                !is_tls_hello(subprotocol.byte()),
                "{subprotocol} would be read as a TLS record"
            );
        }
        assert!(is_tls_hello(0x16));
    }
}
