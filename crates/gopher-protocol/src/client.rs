//! The gopher client (`gopher://`, port 70).
//!
//! A gopher URL is `gopher://host/<type><selector>`: the first path character is
//! the item type, the rest is the selector sent verbatim. The request is just
//! the selector and a CRLF; a type-7 search appends the query after a TAB.
//!
//! Gopher has no status line. Every reply is a body, and the item type is the
//! only hint about what the bytes are, so the client reports a best-effort
//! MIME alongside them rather than inventing a status the protocol lacks.
//!
//! ```no_run
//! # async fn run() -> Result<(), gopher_protocol::ClientError> {
//! let reply = gopher_protocol::fetch("gopher://gopher.floodgap.com/1/").await?;
//! if reply.mime == "application/gopher-menu" {
//!     for item in gopher_protocol::parse_menu(&String::from_utf8_lossy(&reply.body)) {
//!         println!("{:?} {}", item.kind, item.display);
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

/// Gopher's well-known port.
pub const DEFAULT_PORT: u16 = 70;

/// What can go wrong fetching a gopher resource. There is no protocol-error
/// variant because gopher has no status line: a server that dislikes a request
/// answers with an error *item* inside an ordinary menu body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    /// The URL could not be parsed, or it lacks a host.
    BadUrl(String),
    /// The TCP connection could not be established.
    Connect(String),
    /// A read or write failed mid-exchange.
    Io(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadUrl(m) => write!(f, "bad url: {m}"),
            Self::Connect(m) => write!(f, "connect: {m}"),
            Self::Io(m) => write!(f, "io: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// One gopher reply: the body, plus the MIME inferred from the item type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// A best-effort MIME type from the requested item type. Menus report
    /// `application/gopher-menu` so a consumer can route them to
    /// [`crate::menu::parse`].
    pub mime: String,
    /// The reply body, read to EOF.
    pub body: Vec<u8>,
}

/// Fetch a `gopher://` URL.
///
/// The URL is taken as a string so this signature does not carry a `url`
/// major version into the public API.
pub async fn fetch(url: &str) -> Result<Response, ClientError> {
    let url = Url::parse(url).map_err(|e| ClientError::BadUrl(e.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| ClientError::BadUrl("gopher URL has no host".into()))?;
    let port = url.port().unwrap_or(DEFAULT_PORT);
    let (item_type, selector) = split_path(&url);

    let mut request = selector;
    // A type-7 item is a search server: the query rides after a TAB.
    if let Some(query) = url.query() {
        request.push('\t');
        request.push_str(query);
    }
    request.push_str("\r\n");

    let body = exchange(host, port, request.as_bytes()).await?;
    Ok(Response {
        mime: mime_for_item_type(item_type).to_string(),
        body,
    })
}

/// Open a plaintext TCP connection, send `request`, and read the whole reply to
/// EOF (gopher servers close the stream when done).
async fn exchange(host: &str, port: u16, request: &[u8]) -> Result<Vec<u8>, ClientError> {
    let mut stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
    stream
        .write_all(request)
        .await
        .map_err(|e| ClientError::Io(e.to_string()))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| ClientError::Io(e.to_string()))?;
    Ok(buf)
}

/// Split a gopher path into its item-type character and selector. An empty path
/// is the root menu (type `1`, empty selector).
fn split_path(url: &Url) -> (char, String) {
    let path = url.path();
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    let mut chars = trimmed.chars();
    match chars.next() {
        Some(item_type) => (item_type, chars.as_str().to_string()),
        None => ('1', String::new()),
    }
}

/// A best-effort MIME type for a gopher item type. Menus get an
/// `application/gopher-menu` type so a consumer can route them to a gophermap
/// renderer; unknown types fall back to opaque bytes.
///
/// This is a client convention, not part of RFC 1436 — gopher carries no MIME.
pub fn mime_for_item_type(item_type: char) -> &'static str {
    match item_type {
        '0' => "text/plain",
        '1' | '7' => "application/gopher-menu",
        'h' => "text/html",
        'g' => "image/gif",
        'I' | ':' => "image/*",
        's' | '<' => "audio/*",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(u: &str) -> (char, String) {
        split_path(&Url::parse(u).unwrap())
    }

    #[test]
    fn root_path_is_a_menu() {
        assert_eq!(split("gopher://example.org/"), ('1', String::new()));
        assert_eq!(split("gopher://example.org"), ('1', String::new()));
    }

    #[test]
    fn type_and_selector_split_at_the_first_char() {
        assert_eq!(
            split("gopher://example.org/0/about.txt"),
            ('0', "/about.txt".into())
        );
        assert_eq!(split("gopher://example.org/1/dir"), ('1', "/dir".into()));
    }

    #[test]
    fn mime_inference() {
        assert_eq!(mime_for_item_type('0'), "text/plain");
        assert_eq!(mime_for_item_type('1'), "application/gopher-menu");
        assert_eq!(mime_for_item_type('9'), "application/octet-stream");
    }

    #[tokio::test]
    async fn a_url_without_a_host_is_refused_before_connecting() {
        let error = fetch("gopher:///0/x").await.unwrap_err();
        assert!(matches!(error, ClientError::BadUrl(_)), "got {error:?}");
    }
}
