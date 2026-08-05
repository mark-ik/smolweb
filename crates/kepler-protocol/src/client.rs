//! The kepler client.
//!
//! `kepler://` is plaintext on port 2009; `keplers://` is the same exchange
//! inside TLS on port 10009. Unlike gemini, encryption is not mandatory, so
//! which one you get is the scheme's choice rather than the protocol's.
//!
//! The exchange is one line out and one header back, and the body's length is
//! declared rather than implied by the connection closing, which is the whole
//! reason kepler exists.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use crate::wire::{CacheInfo, Header, MAX_URI, parse_header, request_line};

/// Plaintext kepler.
pub const DEFAULT_PORT: u16 = 2009;
/// Kepler inside TLS.
pub const DEFAULT_TLS_PORT: u16 = 10009;

/// What can go wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    BadUrl(String),
    Connect(String),
    Io(String),
    /// The reply did not obey the grammar.
    Protocol(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadUrl(m) => write!(f, "bad url: {m}"),
            Self::Connect(m) => write!(f, "connect: {m}"),
            Self::Io(m) => write!(f, "io: {m}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// One kepler reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub header: Header,
    /// The body, for a `2x`. Empty for every other class, none of which
    /// carries one.
    pub body: Vec<u8>,
}

impl Response {
    /// The cache metadata, for a success.
    pub fn cache(&self) -> Option<CacheInfo> {
        match &self.header {
            Header::Success { cache, .. } => Some(*cache),
            _ => None,
        }
    }

    /// The MIME type, for a success.
    pub fn mime(&self) -> Option<&str> {
        match &self.header {
            Header::Success { mimetype, .. } => Some(mimetype),
            _ => None,
        }
    }
}

/// Fetch a `kepler://` or `keplers://` URL.
///
/// `last_cached` is the epoch second of the copy you already hold, or `0` if
/// you hold none. A server may answer `7x` to say it has not changed, which is
/// the exchange kepler adds over its relatives.
pub async fn fetch(url: &str, last_cached: i64, language: &str) -> Result<Response, ClientError> {
    let parsed = Url::parse(url).map_err(|e| ClientError::BadUrl(e.to_string()))?;
    if url.len() > MAX_URI {
        return Err(ClientError::BadUrl(format!(
            "URI exceeds {MAX_URI} bytes"
        )));
    }
    if parsed.fragment().is_some() {
        return Err(ClientError::BadUrl("kepler URIs carry no fragment".into()));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| ClientError::BadUrl("kepler URL has no host".into()))?;

    let secure = match parsed.scheme() {
        "kepler" => false,
        "keplers" => true,
        other => return Err(ClientError::BadUrl(format!("scheme {other} is not kepler"))),
    };
    let port = parsed.port().unwrap_or(if secure {
        DEFAULT_TLS_PORT
    } else {
        DEFAULT_PORT
    });

    let line = request_line(url, last_cached, language);

    if secure {
        #[cfg(feature = "tls")]
        {
            return crate::tls::exchange_tls(host, port, line.as_bytes()).await;
        }
        #[cfg(not(feature = "tls"))]
        {
            return Err(ClientError::Connect(
                "keplers:// needs the `tls` feature".into(),
            ));
        }
    }

    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
    exchange(stream, line.as_bytes()).await
}

/// Run the exchange over any connected stream.
///
/// Transport-independent, like gemini's: an already-encrypted carrier needs
/// no TLS of its own.
pub async fn exchange<S>(mut stream: S, request: &[u8]) -> Result<Response, ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(request)
        .await
        .map_err(|e| ClientError::Io(e.to_string()))?;

    // The header is one line. Read byte-wise so the body that follows is not
    // swallowed by a buffered reader we would then have to unwind.
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let count = stream
            .read(&mut byte)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        if count == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > MAX_URI {
            return Err(ClientError::Protocol("header line is unreasonable".into()));
        }
    }

    let text = String::from_utf8(line).map_err(|_| ClientError::Protocol("header is not UTF-8".into()))?;
    let header = parse_header(&text).map_err(|e| ClientError::Protocol(e.0))?;

    let body = match &header {
        // A declared length is read exactly; -1 means read to end of stream.
        Header::Success { cache, .. } if cache.has_length() => {
            let mut body = Vec::new();
            stream
                .take(cache.length as u64)
                .read_to_end(&mut body)
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?;
            body
        },
        Header::Success { .. } => {
            let mut body = Vec::new();
            stream
                .read_to_end(&mut body)
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?;
            body
        },
        // No other class carries a body.
        _ => Vec::new(),
    };

    Ok(Response { header, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Status;

    #[tokio::test]
    async fn a_declared_length_is_read_exactly() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let n = server.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).ends_with("\r\n"));
            // Five bytes declared, then trailing bytes that must NOT be read.
            server
                .write_all(b"20 5 -1 -1 text/plain\r\nhellotrailing-garbage")
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });

        let response = exchange(client, b"kepler://x/ 0 en\r\n").await.unwrap();
        assert_eq!(response.body, b"hello", "stopped at the declared length");
        assert_eq!(response.mime(), Some("text/plain"));
    }

    #[tokio::test]
    async fn an_unknown_length_reads_to_the_end_of_the_stream() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await.unwrap();
            server
                .write_all(b"20 -1 -1 -1 text/gemini\r\n# All of it\n")
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });

        let response = exchange(client, b"kepler://x/ 0 en\r\n").await.unwrap();
        assert_eq!(response.body, b"# All of it\n");
    }

    #[tokio::test]
    async fn a_cache_hit_carries_no_body() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await.unwrap();
            server.write_all(b"70 1777759482\r\n").await.unwrap();
            server.shutdown().await.unwrap();
        });

        let response = exchange(client, b"kepler://x/ 100 en\r\n").await.unwrap();
        assert_eq!(response.header.status(), Status::Unchanged);
        assert!(response.body.is_empty());
        assert_eq!(response.cache(), None, "a 7x carries no cache block");
    }

    #[tokio::test]
    async fn a_failure_carries_its_message_and_no_body() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await.unwrap();
            server.write_all(b"51 not found\r\nignored").await.unwrap();
            server.shutdown().await.unwrap();
        });

        let response = exchange(client, b"kepler://x/ 0 en\r\n").await.unwrap();
        assert_eq!(response.header.status(), Status::PermanentFailure);
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn a_fragment_is_refused_before_connecting() {
        let error = fetch("kepler://example.net/a#frag", 0, "en").await.unwrap_err();
        assert!(matches!(error, ClientError::BadUrl(_)), "got {error:?}");
    }

    #[tokio::test]
    async fn another_scheme_is_refused() {
        let error = fetch("gemini://example.net/", 0, "en").await.unwrap_err();
        assert!(matches!(error, ClientError::BadUrl(_)), "got {error:?}");
    }
}
