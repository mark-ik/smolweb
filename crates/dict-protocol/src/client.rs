//! The DICT client: a session, not a fetch.
//!
//! The connection stays open across commands, so this is a [`Session`] you
//! hold rather than a function you call. That is the protocol's shape and
//! hiding it behind a one-shot `fetch` would mean reconnecting per word,
//! which is exactly what a command loop exists to avoid.
//!
//! ## Looking a word up
//!
//! ```no_run
//! # async fn run() -> Result<(), dict_protocol::ClientError> {
//! let mut session = dict_protocol::Session::connect("dict.org", None).await?;
//!
//! for definition in session.define("*", "smolweb").await? {
//!     println!("[{}] {}", definition.database, definition.text.join("\n"));
//! }
//! session.quit().await?;
//! # Ok(())
//! # }
//! ```
//!
//! `"*"` asks every database and `"!"` asks for the first that matches. A word
//! that is absent yields an **empty vector rather than an error**, because
//! `552 no match` is an answer.
//!

use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::io::AsyncRead;
use tokio::net::TcpStream;

use crate::wire::{
    self, DEFAULT_PORT, Database, Definition, MAX_LINE, Match, Status, parse_definition_header,
};

/// What can go wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    Connect(String),
    Io(String),
    /// The server said something the grammar does not allow.
    Protocol(String),
    /// The server refused, with its own code and message.
    Refused { code: u16, text: String },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(m) => write!(f, "connect: {m}"),
            Self::Io(m) => write!(f, "io: {m}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
            Self::Refused { code, text } => write!(f, "server refused: {code} {text}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// An open DICT session.
pub struct Session<S> {
    stream: BufReader<S>,
    banner: Status,
}

impl Session<TcpStream> {
    /// Connect to a DICT server and read its banner.
    pub async fn connect(host: &str, port: Option<u16>) -> Result<Self, ClientError> {
        let port = port.unwrap_or(DEFAULT_PORT);
        let stream = TcpStream::connect((host, port))
            .await
            .map_err(|e| ClientError::Connect(format!("tcp {host}:{port}: {e}")))?;
        Self::over(stream).await
    }
}

impl<S> Session<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Start a session over an already-connected stream, reading the banner.
    ///
    /// Transport-independent, so DICT rides an encrypted carrier as readily as
    /// TCP.
    pub async fn over(stream: S) -> Result<Self, ClientError> {
        let mut stream = BufReader::new(stream);
        let banner = read_status(&mut stream).await?;
        if banner.code != wire::BANNER {
            return Err(ClientError::Protocol(format!(
                "expected a 220 banner, got {} {}",
                banner.code, banner.text
            )));
        }
        Ok(Self { stream, banner })
    }

    /// The server's greeting, which carries its capabilities and message id.
    pub fn banner(&self) -> &Status {
        &self.banner
    }

    /// `SHOW DB`: the databases this server offers.
    ///
    /// An empty list is a legitimate answer (`554 no databases present`), not
    /// an error.
    pub async fn databases(&mut self) -> Result<Vec<Database>, ClientError> {
        let status = self.command("SHOW DB").await?;
        match status.code {
            wire::DATABASES_FOLLOW => {
                let lines = self.read_text_block().await?;
                let databases = wire::parse_databases(&lines);
                self.expect_ok().await?;
                Ok(databases)
            },
            554 => Ok(Vec::new()),
            _ => Err(refused(status)),
        }
    }

    /// `SHOW STRAT`: the matching strategies this server supports.
    pub async fn strategies(&mut self) -> Result<Vec<Database>, ClientError> {
        let status = self.command("SHOW STRAT").await?;
        match status.code {
            wire::STRATEGIES_FOLLOW => {
                let lines = self.read_text_block().await?;
                let strategies = wire::parse_databases(&lines);
                self.expect_ok().await?;
                Ok(strategies)
            },
            555 => Ok(Vec::new()),
            _ => Err(refused(status)),
        }
    }

    /// `DEFINE database word`. Use `"*"` for every database, `"!"` for the
    /// first that matches.
    ///
    /// No match is an empty vector rather than an error: `552` means the word
    /// is absent, which is an answer.
    pub async fn define(
        &mut self,
        database: &str,
        word: &str,
    ) -> Result<Vec<Definition>, ClientError> {
        let status = self
            .command(&format!("DEFINE {} {}", quote(database), quote(word)))
            .await?;
        match status.code {
            wire::DEFINITIONS_FOLLOW => {},
            wire::NO_MATCH => return Ok(Vec::new()),
            _ => return Err(refused(status)),
        }

        // Then one 151-plus-text-block per definition, ending with a 250.
        let mut definitions = Vec::new();
        loop {
            let status = read_status(&mut self.stream).await?;
            match status.code {
                wire::DEFINITION_FOLLOWS => {
                    let (word, database, database_description) =
                        parse_definition_header(&status).ok_or_else(|| {
                            ClientError::Protocol(format!("malformed 151: {}", status.text))
                        })?;
                    definitions.push(Definition {
                        word,
                        database,
                        database_description,
                        text: self.read_text_block().await?,
                    });
                },
                code if (200..300).contains(&code) => return Ok(definitions),
                _ => return Err(refused(status)),
            }
        }
    }

    /// `MATCH database strategy word`.
    pub async fn matches(
        &mut self,
        database: &str,
        strategy: &str,
        word: &str,
    ) -> Result<Vec<Match>, ClientError> {
        let status = self
            .command(&format!(
                "MATCH {} {} {}",
                quote(database),
                quote(strategy),
                quote(word)
            ))
            .await?;
        match status.code {
            wire::MATCHES_FOLLOW => {
                let lines = self.read_text_block().await?;
                let matches = wire::parse_matches(&lines);
                self.expect_ok().await?;
                Ok(matches)
            },
            wire::NO_MATCH => Ok(Vec::new()),
            _ => Err(refused(status)),
        }
    }

    /// `CLIENT text`: announce who is calling. Servers log it; none require it.
    pub async fn announce(&mut self, text: &str) -> Result<(), ClientError> {
        let status = self.command(&format!("CLIENT {text}")).await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(refused(status))
        }
    }

    /// `QUIT`, consuming the session.
    pub async fn quit(mut self) -> Result<(), ClientError> {
        let status = self.command("QUIT").await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(refused(status))
        }
    }

    /// Send a command line and read its status response.
    pub async fn command(&mut self, line: &str) -> Result<Status, ClientError> {
        if line.len() + 2 > MAX_LINE {
            return Err(ClientError::Protocol(format!(
                "command exceeds {MAX_LINE} bytes"
            )));
        }
        self.stream
            .get_mut()
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        read_status(&mut self.stream).await
    }

    /// Read a dot-terminated text block, unstuffing as it goes.
    async fn read_text_block(&mut self) -> Result<Vec<String>, ClientError> {
        let mut lines = Vec::new();
        loop {
            let line = read_line(&mut self.stream).await?;
            if wire::is_terminator(&line) {
                return Ok(lines);
            }
            lines.push(wire::unstuff(line.trim_end_matches(['\r', '\n'])).to_string());
        }
    }

    /// Consume the `250 ok` that closes a text-block command.
    async fn expect_ok(&mut self) -> Result<(), ClientError> {
        let status = read_status(&mut self.stream).await?;
        if status.is_success() {
            Ok(())
        } else {
            Err(refused(status))
        }
    }
}

fn refused(status: Status) -> ClientError {
    ClientError::Refused {
        code: status.code,
        text: status.text,
    }
}

/// Quote a parameter if it needs it. Words with spaces would otherwise split.
fn quote(param: &str) -> String {
    if param.is_empty() || param.contains(|c: char| c.is_whitespace() || c == '"') {
        format!("\"{}\"", param.replace('\\', r"\\").replace('"', "\\\""))
    } else {
        param.to_string()
    }
}

async fn read_line<S>(stream: &mut BufReader<S>) -> Result<String, ClientError>
where
    S: AsyncRead + Unpin,
{
    let mut line = String::new();
    let read = stream
        .read_line(&mut line)
        .await
        .map_err(|e| ClientError::Io(e.to_string()))?;
    if read == 0 {
        return Err(ClientError::Protocol("server closed mid-response".into()));
    }
    Ok(line)
}

async fn read_status<S>(stream: &mut BufReader<S>) -> Result<Status, ClientError>
where
    S: AsyncRead + Unpin,
{
    let line = read_line(stream).await?;
    wire::parse_status(&line)
        .ok_or_else(|| ClientError::Protocol(format!("not a status line: {line:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Drive a session against a scripted server over an in-memory duplex.
    async fn scripted(script: &'static [&'static str]) -> Session<tokio::io::DuplexStream> {
        let (client, mut server) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            for chunk in script {
                server.write_all(chunk.as_bytes()).await.unwrap();
                // Let the client consume and issue its next command.
                let mut buf = [0u8; 512];
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(50),
                    server.read(&mut buf),
                )
                .await;
            }
        });
        Session::over(client).await.unwrap()
    }

    #[test]
    fn parameters_are_quoted_only_when_they_need_it() {
        assert_eq!(quote("wn"), "wn");
        assert_eq!(quote("free software"), "\"free software\"");
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote(r#"say "hi""#), r#""say \"hi\""#.to_string() + "\"");
    }

    #[tokio::test]
    async fn a_non_banner_greeting_is_refused() {
        let (client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            server.write_all(b"500 go away\r\n").await.unwrap();
        });
        match Session::over(client).await {
            Err(error) => assert!(matches!(error, ClientError::Protocol(_)), "got {error:?}"),
            Ok(_) => panic!("a 500 greeting must not open a session"),
        }
    }

    #[tokio::test]
    async fn a_definition_is_read_with_its_text_block() {
        let (client, mut server) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            server.write_all(b"220 test <1@x>\r\n").await.unwrap();
            let mut buf = [0u8; 512];
            let n = server.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with("DEFINE"));
            server
                .write_all(
                    b"150 1 definitions retrieved\r\n\
                      151 \"dict\" wn \"WordNet\"\r\n\
                      a reference work\r\n\
                      ..a line that began with a period\r\n\
                      .\r\n\
                      250 ok\r\n",
                )
                .await
                .unwrap();
        });

        let mut session = Session::over(client).await.unwrap();
        let definitions = session.define("wn", "dict").await.unwrap();

        assert_eq!(definitions.len(), 1);
        assert_eq!(definitions[0].word, "dict");
        assert_eq!(definitions[0].database, "wn");
        assert_eq!(definitions[0].database_description, "WordNet");
        assert_eq!(
            definitions[0].text,
            vec![
                "a reference work".to_string(),
                ".a line that began with a period".to_string(),
            ],
            "the doubled period must be undone"
        );
    }

    #[tokio::test]
    async fn no_match_is_an_empty_answer_not_an_error() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            server.write_all(b"220 test <1@x>\r\n").await.unwrap();
            let mut buf = [0u8; 512];
            let _ = server.read(&mut buf).await.unwrap();
            server.write_all(b"552 no match\r\n").await.unwrap();
        });

        let mut session = Session::over(client).await.unwrap();
        assert!(session.define("wn", "zzzz").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_invalid_database_is_refused_with_its_code() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            server.write_all(b"220 test <1@x>\r\n").await.unwrap();
            let mut buf = [0u8; 512];
            let _ = server.read(&mut buf).await.unwrap();
            server.write_all(b"550 invalid database\r\n").await.unwrap();
        });

        let mut session = Session::over(client).await.unwrap();
        let error = session.define("nope", "dict").await.unwrap_err();
        assert!(
            matches!(error, ClientError::Refused { code: 550, .. }),
            "got {error:?}"
        );
    }

    #[tokio::test]
    async fn a_database_list_is_read_and_the_trailing_ok_consumed() {
        let (client, mut server) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            server.write_all(b"220 test <1@x>\r\n").await.unwrap();
            let mut buf = [0u8; 512];
            let _ = server.read(&mut buf).await.unwrap();
            server
                .write_all(
                    b"110 2 databases present\r\n\
                      wn \"WordNet (r) 3.0\"\r\n\
                      foldoc \"Free On-line Dictionary of Computing\"\r\n\
                      .\r\n\
                      250 ok\r\n",
                )
                .await
                .unwrap();
            // A following command must see a clean stream, which only holds if
            // the 250 was consumed.
            let n = server.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with("QUIT"));
            server.write_all(b"221 bye\r\n").await.unwrap();
        });

        let mut session = Session::over(client).await.unwrap();
        let databases = session.databases().await.unwrap();
        assert_eq!(databases.len(), 2);
        assert_eq!(databases[1].name, "foldoc");
        session.quit().await.unwrap();
    }

    #[tokio::test]
    async fn an_over_long_command_never_reaches_the_wire() {
        let mut session = scripted(&["220 test <1@x>\r\n"]).await;
        let error = session
            .command(&format!("DEFINE wn {}", "x".repeat(MAX_LINE)))
            .await
            .unwrap_err();
        assert!(matches!(error, ClientError::Protocol(_)), "got {error:?}");
    }
}
