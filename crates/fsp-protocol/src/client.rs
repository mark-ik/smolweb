//! The FSP client: UDP, with FSP's own reliability on top.
//!
//! FSP carries its own sequencing and retransmission because UDP gives it
//! none. Two rules drive this client:
//!
//! - the client **echoes the server's last key** in every request, and
//! - the client **chooses the sequence** and the server echoes it back, which
//!   is how a lost or stale reply is detected.
//!
//! A reply whose sequence does not match is discarded and the read continues,
//! rather than being handed up as an answer to a question nobody asked.
//!
//! ```no_run
//! # async fn run() -> Result<(), fsp_protocol::ClientError> {
//! let mut session = fsp_protocol::Session::connect("fsp.example", None).await?;
//!
//! for entry in session.list("/pub").await? {
//!     println!("{:?} {} ({} bytes)", entry.kind, entry.name, entry.size);
//! }
//! let bytes = session.get_file("/pub/readme.txt").await?;
//! session.bye().await?;
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use tokio::net::UdpSocket;

use crate::wire::{
    Command, DecodeError, DirEntry, Direction, Header, MAX_PAYLOAD, Packet, decode, encode,
    parse_directory,
};

/// The specification's minimum wait before a resend.
pub const RESEND_AFTER: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    Connect(String),
    Io(String),
    /// The reply did not decode.
    Protocol(String),
    /// The server answered `CC_ERR`; the string is its message.
    Refused(String),
    /// No valid reply arrived within the retry budget.
    TimedOut,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(m) => write!(f, "connect: {m}"),
            Self::Io(m) => write!(f, "io: {m}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
            Self::Refused(m) => write!(f, "server refused: {m}"),
            Self::TimedOut => write!(f, "no reply within the retry budget"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<DecodeError> for ClientError {
    fn from(error: DecodeError) -> Self {
        Self::Protocol(error.to_string())
    }
}

/// An FSP session: a socket plus the key and sequence bookkeeping.
pub struct Session {
    socket: UdpSocket,
    /// The server's last key, echoed back on every request.
    key: u16,
    sequence: u16,
    /// How many times a request is sent before giving up.
    pub attempts: u32,
    pub timeout: Duration,
}

impl Session {
    /// Open a session to an FSP server.
    pub async fn connect(host: &str, port: Option<u16>) -> Result<Self, ClientError> {
        let port = port.unwrap_or(crate::wire::DEFAULT_PORT);
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        socket
            .connect((host, port))
            .await
            .map_err(|e| ClientError::Connect(format!("udp {host}:{port}: {e}")))?;
        Ok(Self {
            socket,
            key: 0,
            sequence: 1,
            attempts: 3,
            timeout: RESEND_AFTER,
        })
    }

    /// The server version string.
    pub async fn version(&mut self) -> Result<String, ClientError> {
        let reply = self.request(Command::Version, &[], 0).await?;
        Ok(trim_nul(&reply.data))
    }

    /// Fetch one block of a file at `offset`. An empty block is end of file.
    pub async fn get_file_block(&mut self, path: &str, offset: u32) -> Result<Vec<u8>, ClientError> {
        let reply = self
            .request(Command::GetFile, &nul_terminated(path), offset)
            .await?;
        Ok(reply.data)
    }

    /// Fetch a whole file, block by block.
    pub async fn get_file(&mut self, path: &str) -> Result<Vec<u8>, ClientError> {
        let mut body = Vec::new();
        loop {
            let block = self.get_file_block(path, body.len() as u32).await?;
            if block.is_empty() {
                return Ok(body);
            }
            let short = block.len() < MAX_PAYLOAD;
            body.extend_from_slice(&block);
            // A short block is the last one.
            if short {
                return Ok(body);
            }
        }
    }

    /// List a directory.
    ///
    /// Directory blocks are never split across packets, so each reply is
    /// walked whole and the offset advances by the block's size.
    pub async fn list(&mut self, path: &str) -> Result<Vec<DirEntry>, ClientError> {
        let mut entries = Vec::new();
        let mut offset = 0u32;
        loop {
            let reply = self
                .request(Command::GetDir, &nul_terminated(path), offset)
                .await?;
            if reply.data.is_empty() {
                return Ok(entries);
            }
            let block = parse_directory(&reply.data);
            let finished = block.is_empty();
            entries.extend(block);
            if finished {
                return Ok(entries);
            }
            offset += reply.data.len() as u32;
        }
    }

    /// End the session politely.
    pub async fn bye(mut self) -> Result<(), ClientError> {
        self.request(Command::Bye, &[], 0).await.map(|_| ())
    }

    /// Send a command and wait for the reply that echoes our sequence.
    pub async fn request(
        &mut self,
        command: Command,
        data: &[u8],
        file_position: u32,
    ) -> Result<Packet, ClientError> {
        self.sequence = self.sequence.wrapping_add(1);
        let sequence = self.sequence;

        let outgoing = Packet {
            header: Header {
                command: command.code(),
                key: self.key,
                sequence,
                data_length: data.len() as u16,
                file_position,
            },
            data: data.to_vec(),
            extra: Vec::new(),
        };
        let bytes = encode(&outgoing, Direction::ClientToServer);

        for _ in 0..self.attempts {
            self.socket
                .send(&bytes)
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?;

            if let Some(reply) = self.await_reply(sequence).await? {
                // The server's key is echoed on our next request.
                self.key = reply.header.key;
                if reply.header.command == Command::Err.code() {
                    return Err(ClientError::Refused(trim_nul(&reply.data)));
                }
                return Ok(reply);
            }
        }
        Err(ClientError::TimedOut)
    }

    /// Read until a reply with the expected sequence arrives, or the timeout
    /// expires. Mismatched replies are stale and are dropped.
    async fn await_reply(&mut self, sequence: u16) -> Result<Option<Packet>, ClientError> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut buffer = vec![0u8; crate::wire::HEADER_LEN + MAX_PAYLOAD * 2];

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let read = match tokio::time::timeout(remaining, self.socket.recv(&mut buffer)).await {
                Err(_) => return Ok(None),
                Ok(Err(e)) => return Err(ClientError::Io(e.to_string())),
                Ok(Ok(read)) => read,
            };

            match decode(&buffer[..read], Direction::ServerToClient) {
                Ok(packet) if packet.header.sequence == sequence => return Ok(Some(packet)),
                // A stale or corrupt datagram is not an answer; keep waiting.
                _ => continue,
            }
        }
    }
}

fn nul_terminated(path: &str) -> Vec<u8> {
    let mut out = path.as_bytes().to_vec();
    out.push(0);
    out
}

fn trim_nul(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.trim_end_matches('\0').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_nul_terminated() {
        assert_eq!(nul_terminated("/pub"), b"/pub\0");
        assert_eq!(nul_terminated(""), b"\0");
    }

    #[tokio::test]
    async fn a_stale_sequence_is_ignored_and_the_right_reply_accepted() {
        // A fake server that answers the wrong sequence first.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let (read, peer) = server.recv_from(&mut buf).await.unwrap();
            let asked = decode(&buf[..read], Direction::ClientToServer).unwrap();

            let stale = Packet {
                header: Header {
                    command: Command::GetFile.code(),
                    key: 0x1111,
                    sequence: asked.header.sequence.wrapping_sub(7),
                    data_length: 5,
                    file_position: 0,
                },
                data: b"stale".to_vec(),
                extra: Vec::new(),
            };
            server
                .send_to(&encode(&stale, Direction::ServerToClient), peer)
                .await
                .unwrap();

            let good = Packet {
                header: Header {
                    command: Command::GetFile.code(),
                    key: 0x2222,
                    sequence: asked.header.sequence,
                    data_length: 5,
                    file_position: 0,
                },
                data: b"right".to_vec(),
                extra: Vec::new(),
            };
            server
                .send_to(&encode(&good, Direction::ServerToClient), peer)
                .await
                .unwrap();
        });

        let mut session = Session::connect("127.0.0.1", Some(addr.port())).await.unwrap();
        session.timeout = Duration::from_secs(3);
        let block = session.get_file_block("/x", 0).await.unwrap();

        assert_eq!(block, b"right", "the stale sequence must not be accepted");
        assert_eq!(session.key, 0x2222, "the server's key is adopted for next time");
    }

    #[tokio::test]
    async fn a_server_error_surfaces_with_its_message() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let (read, peer) = server.recv_from(&mut buf).await.unwrap();
            let asked = decode(&buf[..read], Direction::ClientToServer).unwrap();
            let error = Packet {
                header: Header {
                    command: Command::Err.code(),
                    key: 9,
                    sequence: asked.header.sequence,
                    data_length: 13,
                    file_position: 0,
                },
                data: b"no such file\0".to_vec(),
                extra: Vec::new(),
            };
            server
                .send_to(&encode(&error, Direction::ServerToClient), peer)
                .await
                .unwrap();
        });

        let mut session = Session::connect("127.0.0.1", Some(addr.port())).await.unwrap();
        session.timeout = Duration::from_secs(3);
        let error = session.get_file_block("/nope", 0).await.unwrap_err();
        assert_eq!(error, ClientError::Refused("no such file".into()));
    }

    #[tokio::test]
    async fn silence_times_out_rather_than_hanging() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        // Never answer.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            loop {
                let _ = server.recv_from(&mut buf).await;
            }
        });

        let mut session = Session::connect("127.0.0.1", Some(addr.port())).await.unwrap();
        session.timeout = Duration::from_millis(60);
        session.attempts = 2;
        assert_eq!(
            session.get_file_block("/x", 0).await.unwrap_err(),
            ClientError::TimedOut
        );
    }
}
