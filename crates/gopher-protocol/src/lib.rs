//! # gopher-protocol
//!
//! An implementation of [Gopher](https://datatracker.ietf.org/doc/html/rfc1436)
//! (`gopher://`, port 70): an async client and a menu parser.
//!
//! Gopher is the elder smolweb protocol. A request is a selector and a CRLF; a
//! reply is a body with no status line and no MIME type. The item-type
//! character carried in the URL path is the only hint about what the bytes are,
//! which is why this crate reports a best-effort MIME rather than inventing a
//! status the protocol does not have.
//!
//! ## Two halves, separately usable
//!
//! [`menu`] parses RFC 1436 menus into typed items with RFC 4266 URLs. It has
//! no dependencies and is always compiled, so a consumer that only renders
//! gophermaps can take this crate with `default-features = false` and pull no
//! async runtime:
//!
//! ```toml
//! gopher-protocol = { version = "0.1", default-features = false }
//! ```
//!
//! [`client`] fetches over TCP and rides the default `client` feature.
//!
//! ## Parsing a menu
//!
//! ```
//! let menu = "1Software\t/software\tgopher.example\t70\r\niA note\t\t\t\r\n";
//! let items = gopher_protocol::parse_menu(menu);
//!
//! assert_eq!(items[0].url.as_deref(), Some("gopher://gopher.example/1/software"));
//! assert_eq!(items[1].kind, gopher_protocol::GopherKind::Info);
//! assert!(items[1].url.is_none(), "info lines carry no resource");
//! ```
//!
//! Fetching is [`client::fetch`], documented on that module so this example
//! stays honest under `default-features = false`.
//!
//! ## Scope
//!
//! This crate is a client and a parser. It does not serve gopher, and it holds
//! no document or render model: what a `Search` item or an `Image` item should
//! look like on screen is the consumer's decision.

#![forbid(unsafe_code)]

pub mod menu;

#[cfg(feature = "client")]
pub mod client;

pub use menu::{GopherItem, GopherKind, parse as parse_menu};

#[cfg(feature = "client")]
pub use client::{ClientError, DEFAULT_PORT, Response, fetch, mime_for_item_type};
