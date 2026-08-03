//! # finger-protocol
//!
//! Finger ([RFC 1288](https://datatracker.ietf.org/doc/html/rfc1288), port 79)
//! and its successor WebFinger
//! ([RFC 7033](https://www.rfc-editor.org/rfc/rfc7033.html)), which honours it
//! by name.
//!
//! Both answer the same question, thirty years apart: *who is this person?*
//! Finger answers with whatever text the host felt like printing. WebFinger
//! answers with a JSON Resource Descriptor, which is why it, and not finger,
//! is what resolves `@alice@example.social` on the fediverse.
//!
//! ## Two protocols, two features
//!
//! | | Module | Feature | Pulls |
//! |---|---|---|---|
//! | Finger, RFC 1288 | [`client`] | `client` | tokio, url |
//! | WebFinger, RFC 7033 | [`webfinger`] | `webfinger` | serde, serde_json, percent-encoding |
//!
//! Both are on by default. Take `default-features = false` with just one when
//! the other is dead weight.
//!
//! ## WebFinger without an HTTP client
//!
//! WebFinger rides on HTTPS and this crate deliberately contains no HTTP
//! stack: it builds the request URL and parses the response, and the GET
//! itself belongs to the caller, who already has an HTTP client and opinions
//! about timeouts, redirects, and TLS. See [`webfinger`].
//!
//! Fingering a host is [`client::fetch`], documented on that module so the
//! example stays honest when the `client` feature is off.

#![forbid(unsafe_code)]

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "webfinger")]
pub mod webfinger;

#[cfg(feature = "client")]
pub use client::{ClientError, DEFAULT_PORT, Query, Response, fetch, query};

#[cfg(feature = "webfinger")]
pub use webfinger::{Jrd, Link, MEDIA_TYPE, acct, request_url};
