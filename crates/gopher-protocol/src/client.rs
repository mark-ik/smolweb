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

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use url::Url;

use crate::plus::{AttributeBlock, MalformedHeader, PlusHeader, parse_attributes, parse_header};

// Re-exported so `client::PlusRequest` remains a valid path after the type
// moved to `plus`, where it belongs: a request form is protocol vocabulary,
// not client machinery, and the server needs it too.
pub use crate::plus::PlusRequest;

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
    /// A Gopher+ reply did not begin with a well-formed header. Only Gopher+
    /// transactions can produce this; plain RFC 1436 replies have no header.
    BadPlusHeader(String),
    /// A Gopher+ server answered `--1`. The string is the error text it sent.
    PlusError(String),
}

impl From<MalformedHeader> for ClientError {
    fn from(error: MalformedHeader) -> Self {
        Self::BadPlusHeader(error.0)
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadUrl(m) => write!(f, "bad url: {m}"),
            Self::Connect(m) => write!(f, "connect: {m}"),
            Self::Io(m) => write!(f, "io: {m}"),
            Self::BadPlusHeader(m) => write!(f, "malformed gopher+ header: {m}"),
            Self::PlusError(m) => write!(f, "gopher+ error: {m}"),
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

    let body = exchange(&url, host, port, request.as_bytes()).await?;
    Ok(Response {
        mime: mime_for_item_type(item_type).to_string(),
        body,
    })
}

/// Open a connection (plaintext for `gopher://`, TLS for `gophers://`), send
/// `request`, and read the whole reply to EOF (gopher servers close the
/// stream when done).
async fn exchange(
    url: &Url,
    host: &str,
    port: u16,
    request: &[u8],
) -> Result<Vec<u8>, ClientError> {
    if url.scheme() == "gophers" {
        #[cfg(feature = "tls")]
        {
            let mut stream = crate::tls::connect(host, port).await?;
            return send_and_read(&mut stream, request).await;
        }
        #[cfg(not(feature = "tls"))]
        {
            // Refusing beats silently sending a gophers:// request in the
            // clear, which is what ignoring the scheme would do.
            return Err(ClientError::BadUrl(
                "gophers:// needs the `tls` feature".into(),
            ));
        }
    }
    let mut stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
    send_and_read(&mut stream, request).await
}

/// Send a request over an already-connected stream and read the reply to EOF.
async fn send_and_read<S>(stream: &mut S, request: &[u8]) -> Result<Vec<u8>, ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
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

// ── Gopher+ ────────────────────────────────────────────────────────────────

/// A Gopher+ reply: the header the server declared, and the body with any
/// period terminator removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlusReply {
    pub header: PlusHeader,
    pub body: Vec<u8>,
}

/// Run a Gopher+ transaction against a `gopher://` URL.
///
/// A Gopher+ request is the RFC 1436 request with a second TAB and a token:
/// `selector <TAB> search <TAB> token`. The search field is present but empty
/// for a non-search item, which is why the spec's own examples show two tabs.
pub async fn fetch_plus(url: &str, request: PlusRequest) -> Result<PlusReply, ClientError> {
    let url = Url::parse(url).map_err(|e| ClientError::BadUrl(e.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| ClientError::BadUrl("gopher URL has no host".into()))?;
    let port = url.port().unwrap_or(DEFAULT_PORT);
    let (_, selector) = split_path(&url);
    let search = url.query().unwrap_or("");

    let line = format!("{selector}\t{search}\t{}\r\n", request.token());
    let (header, body) = plus_exchange(&url, host, port, line.as_bytes()).await?;

    if header == PlusHeader::Error {
        return Err(ClientError::PlusError(
            String::from_utf8_lossy(&body).trim().to_string(),
        ));
    }
    Ok(PlusReply { header, body })
}

/// Fetch and parse an item's Gopher+ attribute blocks (`!`).
pub async fn fetch_attributes(url: &str) -> Result<Vec<AttributeBlock>, ClientError> {
    let reply = fetch_plus(url, PlusRequest::Attributes).await?;
    Ok(parse_attributes(&String::from_utf8_lossy(&reply.body)))
}

/// Fetch and parse the attribute blocks of every item in a directory (`$`).
pub async fn fetch_directory_attributes(url: &str) -> Result<Vec<AttributeBlock>, ClientError> {
    let reply = fetch_plus(url, PlusRequest::DirectoryAttributes).await?;
    Ok(parse_attributes(&String::from_utf8_lossy(&reply.body)))
}

/// Send a Gopher+ request and read the reply according to its header, rather
/// than always reading to EOF: a counted body stops at its count.
async fn plus_exchange(
    url: &Url,
    host: &str,
    port: u16,
    request: &[u8],
) -> Result<(PlusHeader, Vec<u8>), ClientError> {
    if url.scheme() == "gophers" {
        #[cfg(feature = "tls")]
        {
            let stream = crate::tls::connect(host, port).await?;
            return plus_over(stream, request).await;
        }
        #[cfg(not(feature = "tls"))]
        {
            return Err(ClientError::BadUrl(
                "gophers:// needs the `tls` feature".into(),
            ));
        }
    }
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
    plus_over(stream, request).await
}

/// The Gopher+ transaction over an already-connected stream.
async fn plus_over<S>(mut stream: S, request: &[u8]) -> Result<(PlusHeader, Vec<u8>), ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(request)
        .await
        .map_err(|e| ClientError::Io(e.to_string()))?;

    let mut reader = BufReader::new(stream);
    let mut header_line = String::new();
    reader
        .read_line(&mut header_line)
        .await
        .map_err(|e| ClientError::Io(e.to_string()))?;
    if header_line.is_empty() {
        return Err(ClientError::BadPlusHeader(
            "the server closed without a header".into(),
        ));
    }
    let header = parse_header(&header_line)?;

    let mut body = Vec::new();
    match header {
        // `take` rather than a pre-sized allocation: the count comes from the
        // server and a hostile one should not be able to ask for a huge Vec.
        PlusHeader::Length(count) => {
            reader
                .take(count)
                .read_to_end(&mut body)
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?;
        },
        _ => {
            reader
                .read_to_end(&mut body)
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?;
        },
    }

    if matches!(header, PlusHeader::PeriodTerminated | PlusHeader::Error) {
        body = strip_period_terminator(body);
    }
    Ok((header, body))
}

/// Remove a trailing `.` line. The newline before it belongs to the last data
/// line, so only the terminator line itself goes.
fn strip_period_terminator(mut body: Vec<u8>) -> Vec<u8> {
    for terminator in [
        b"\r\n.\r\n".as_slice(),
        b"\n.\n".as_slice(),
        b"\r\n.".as_slice(),
        b"\n.".as_slice(),
    ] {
        if body.ends_with(terminator) {
            let keep = if terminator.starts_with(b"\r\n") { 2 } else { 1 };
            body.truncate(body.len() - terminator.len() + keep);
            return body;
        }
    }
    body
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

    #[test]
    fn plus_tokens_match_the_spec() {
        assert_eq!(PlusRequest::Item(None).token(), "+");
        assert_eq!(
            PlusRequest::Item(Some("text/plain".into())).token(),
            "+text/plain"
        );
        assert_eq!(PlusRequest::Attributes.token(), "!");
        assert_eq!(PlusRequest::DirectoryAttributes.token(), "$");
    }

    #[test]
    fn the_period_terminator_goes_but_the_last_newline_stays() {
        assert_eq!(
            strip_period_terminator(b"one\r\ntwo\r\n.\r\n".to_vec()),
            b"one\r\ntwo\r\n".to_vec()
        );
        assert_eq!(
            strip_period_terminator(b"one\ntwo\n.\n".to_vec()),
            b"one\ntwo\n".to_vec()
        );
    }

    #[test]
    fn a_body_that_merely_ends_in_a_period_is_left_alone() {
        assert_eq!(
            strip_period_terminator(b"see fig. 1.".to_vec()),
            b"see fig. 1.".to_vec()
        );
    }
}
