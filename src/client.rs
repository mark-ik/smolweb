//! The sending client (the `client` feature): one misfin transaction per call
//! (specification §1.1) — connect, TLS handshake with an optional client
//! certificate, send the request line, read the response line, close with
//! close-notify.
//!
//! Server certificates are self-signed in misfin, so the TLS layer accepts
//! any certificate and trust is decided by fingerprint: [`send`] always
//! returns the server's fingerprint, and [`SendOptions::expected_fingerprint`]
//! pins it (trust-on-first-use is then the caller storing the first-seen value
//! and passing it back on later sends).

use std::sync::Arc;
use std::time::Duration;

use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::helpers::sha256_hex;
use super::status::parse_response_line;
use super::{
    MAX_REQUEST_BYTES, MISFIN_PORT, MisfinAddress, MisfinIdentityMaterial, MisfinStatus,
    normalize_fingerprint,
};

/// Options for a [`send`]: the sender's identity (strongly recommended — most
/// servers reply 60 without one), an alternate port, a pinned server
/// fingerprint, and the per-step IO timeout.
#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    /// The client certificate presented in the handshake. `None` sends
    /// anonymously; spec-following servers will likely reply 60.
    pub identity: Option<MisfinIdentityMaterial>,
    /// Overrides the well-known port (1958). Best practice: mailservers stay
    /// on the known port; this exists for clients reaching odd deployments.
    pub port: Option<u16>,
    /// A pinned server-certificate fingerprint (SHA-256 hex, any octet
    /// formatting). On mismatch the send aborts before the message is sent.
    pub expected_fingerprint: Option<String>,
    /// Per-step timeout (connect, handshake, write, read). `None` = 30s.
    pub timeout: Option<Duration>,
    /// Connect to this socket address instead of resolving the recipient's
    /// host. The recipient host is still used for TLS SNI. For deployments
    /// where the mailserver isn't where DNS says (and for tests).
    pub connect_addr: Option<std::net::SocketAddr>,
}

/// The outcome of a successful transaction: the server's status + META and
/// the fingerprint of the certificate it presented (pin this for TOFU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReceipt {
    pub status: MisfinStatus,
    pub meta: String,
    pub server_fingerprint: String,
}

/// Why a [`send`] failed before a response was obtained.
#[derive(Debug)]
pub enum SendError {
    /// The request line would exceed the spec's 2048-byte ceiling. Per the
    /// best-practices document, prompt the user to split the message.
    MessageTooLong { request_bytes: usize, max: usize },
    /// The message contains a carriage return, which would terminate the
    /// request line early (bare newlines are fine).
    MessageContainsCarriageReturn,
    /// The recipient host could not be used as a TLS server name.
    InvalidHost(String),
    /// The pinned fingerprint did not match the server's certificate.
    FingerprintMismatch { expected: String, found: String },
    /// TLS configuration or handshake failure.
    Tls(String),
    /// Connect / read / write failure.
    Io(String),
    /// A step exceeded the timeout.
    Timeout(&'static str),
    /// The server's response line did not parse.
    BadResponse(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessageTooLong { request_bytes, max } => write!(
                formatter,
                "misfin request would be {request_bytes} bytes (max {max}); split the message"
            ),
            Self::MessageContainsCarriageReturn => {
                write!(formatter, "misfin messages must not contain carriage returns")
            }
            Self::InvalidHost(host) => write!(formatter, "invalid misfin host '{host}'"),
            Self::FingerprintMismatch { expected, found } => write!(
                formatter,
                "misfin server fingerprint mismatch: expected {expected}, found {found}"
            ),
            Self::Tls(message) => write!(formatter, "misfin TLS error: {message}"),
            Self::Io(message) => write!(formatter, "misfin IO error: {message}"),
            Self::Timeout(step) => write!(formatter, "misfin {step} timed out"),
            Self::BadResponse(message) => {
                write!(formatter, "misfin response did not parse: {message}")
            }
        }
    }
}

impl std::error::Error for SendError {}

/// Build the request line for `recipient` + `message`, enforcing the byte
/// ceiling and the no-carriage-return rule.
pub fn build_request(recipient: &MisfinAddress, message: &str) -> Result<String, SendError> {
    if message.contains('\r') {
        return Err(SendError::MessageContainsCarriageReturn);
    }
    let request = format!(
        "misfin://{} {message}\r\n",
        recipient.as_addr_spec()
    );
    if request.len() > MAX_REQUEST_BYTES {
        return Err(SendError::MessageTooLong {
            request_bytes: request.len(),
            max: MAX_REQUEST_BYTES,
        });
    }
    Ok(request)
}

/// Deliver `message` (gemtext; bare newlines allowed) to `recipient` in one
/// misfin transaction and return the server's reply.
///
/// This does not retry, follow redirects (30/31), or resend on temporary
/// failure — per best practices those decisions belong to the user, so they
/// surface in the [`SendReceipt`] for the caller to act on.
pub async fn send(
    recipient: &MisfinAddress,
    message: &str,
    options: &SendOptions,
) -> Result<SendReceipt, SendError> {
    let request = build_request(recipient, message)?;
    let timeout = options.timeout.unwrap_or(Duration::from_secs(30));

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| SendError::Tls(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnySelfSigned));
    let config = match &options.identity {
        Some(identity) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(identity.certificate_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    identity.private_key_pkcs8_der.clone(),
                )),
            )
            .map_err(|error| SendError::Tls(error.to_string()))?,
        None => builder.with_no_client_auth(),
    };
    let connector = TlsConnector::from(Arc::new(config));

    let port = options.port.unwrap_or(MISFIN_PORT);
    let connect = async {
        match options.connect_addr {
            Some(addr) => TcpStream::connect(addr).await,
            None => TcpStream::connect((recipient.host.as_str(), port)).await,
        }
    };
    let tcp = tokio::time::timeout(timeout, connect)
        .await
        .map_err(|_| SendError::Timeout("connect"))?
        .map_err(|error| SendError::Io(error.to_string()))?;

    let server_name = ServerName::try_from(recipient.host.clone())
        .map_err(|_| SendError::InvalidHost(recipient.host.clone()))?;
    let mut tls = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| SendError::Timeout("TLS handshake"))?
        .map_err(|error| SendError::Tls(error.to_string()))?;

    let server_fingerprint = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| sha256_hex(cert.as_ref()))
        .ok_or_else(|| SendError::Tls("server presented no certificate".to_string()))?;

    if let Some(expected) = &options.expected_fingerprint {
        if normalize_fingerprint(expected) != server_fingerprint {
            let _ = tls.shutdown().await;
            return Err(SendError::FingerprintMismatch {
                expected: normalize_fingerprint(expected),
                found: server_fingerprint,
            });
        }
    }

    tokio::time::timeout(timeout, tls.write_all(request.as_bytes()))
        .await
        .map_err(|_| SendError::Timeout("request write"))?
        .map_err(|error| SendError::Io(error.to_string()))?;

    let line = read_response_line(&mut tls, timeout).await?;
    let (status, meta) =
        parse_response_line(&line).map_err(SendError::BadResponse)?;

    // Spec §3: send close-notify so the peer can distinguish a complete
    // transaction from a truncated one.
    let _ = tls.shutdown().await;

    Ok(SendReceipt {
        status,
        meta,
        server_fingerprint,
    })
}

/// Read the response line: bytes up to the first CRLF, capped at the spec
/// ceiling, with a timeout across the whole read.
async fn read_response_line<S>(stream: &mut S, timeout: Duration) -> Result<String, SendError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let read_all = async {
        let mut buf = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        loop {
            let count = stream
                .read(&mut byte)
                .await
                .map_err(|error| SendError::Io(error.to_string()))?;
            if count == 0 {
                break;
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n") || buf.len() >= MAX_REQUEST_BYTES {
                break;
            }
        }
        Ok::<_, SendError>(String::from_utf8_lossy(&buf).into_owned())
    };
    tokio::time::timeout(timeout, read_all)
        .await
        .map_err(|_| SendError::Timeout("response read"))?
}

/// Misfin peers are self-signed, so certificate-chain validation is
/// meaningless; trust is by fingerprint (TOFU / pinning), decided above the
/// TLS layer. Never use this verifier for CA-anchored TLS.
#[derive(Debug)]
struct AcceptAnySelfSigned;

impl ServerCertVerifier for AcceptAnySelfSigned {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(spec: &str) -> MisfinAddress {
        MisfinAddress::parse(spec).unwrap()
    }

    #[test]
    fn requests_carry_scheme_recipient_and_crlf() {
        let request = build_request(&addr("mark@example.test"), "Hello there").unwrap();
        assert_eq!(request, "misfin://mark@example.test Hello there\r\n");
    }

    #[test]
    fn newlines_are_allowed_but_carriage_returns_are_not() {
        assert!(build_request(&addr("a@b.test"), "line one\nline two").is_ok());
        assert!(matches!(
            build_request(&addr("a@b.test"), "bad\r\nline"),
            Err(SendError::MessageContainsCarriageReturn)
        ));
    }

    #[test]
    fn oversize_requests_are_rejected_with_the_spec_ceiling() {
        let long_message = "x".repeat(MAX_REQUEST_BYTES);
        match build_request(&addr("a@b.test"), &long_message) {
            Err(SendError::MessageTooLong { max, .. }) => assert_eq!(max, MAX_REQUEST_BYTES),
            other => panic!("expected MessageTooLong, got {other:?}"),
        }
    }
}
