/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! The misfin status-code vocabulary (specification §2), typed.

/// The category of a status code, by its tens digit. Simple clients only need
/// this much to know, broadly, what to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCategory {
    /// 1x — reserved; must not be sent by a misfin server.
    Reserved,
    /// 2x — the message was delivered.
    Success,
    /// 3x — resend to a different address (META).
    Redirect,
    /// 4x — the request failed but may succeed if retried later.
    TemporaryFailure,
    /// 5x — the request failed and should not be retried.
    PermanentFailure,
    /// 6x — there was a problem with the client's certificate.
    AuthenticationFailure,
    /// Anything outside the spec's categories.
    Unknown,
}

/// A misfin response status (specification §2). `Other` carries codes the spec
/// does not define, preserving the wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MisfinStatus {
    /// 20 — delivered; META is the recipient's certificate fingerprint.
    Delivered,
    /// 30 — resend this message to the address in META.
    SendHereInstead,
    /// 31 — the mailbox moved permanently to the address in META.
    SendHereForever,
    /// 40 — transient server issue; resend later.
    TemporaryError,
    /// 41 — the mailserver can't accept mail right now.
    ServerUnavailable,
    /// 42 — a mailserver script errored on this message.
    CgiError,
    /// 43 — a proxying problem that might resolve itself.
    ProxyingError,
    /// 44 — rate limited; wait before sending more.
    SlowDown,
    /// 45 — the mailbox isn't accepting mail right now.
    MailboxFull,
    /// 50 — something is permanently wrong with the mailserver.
    PermanentError,
    /// 51 — the mailbox doesn't exist.
    MailboxDoesNotExist,
    /// 52 — the mailbox existed once, but doesn't anymore.
    MailboxGone,
    /// 53 — this mailserver doesn't serve mail for that hostname.
    DomainNotServiced,
    /// 59 — the request is malformed.
    BadRequest,
    /// 60 — a certificate is required to send here.
    CertificateRequired,
    /// 61 — the certificate is valid but not allowed to send to that mailbox.
    UnauthorizedSender,
    /// 62 — the certificate has a problem (expired, or not a misfin identity).
    CertificateInvalid,
    /// 63 — "you're a liar": the identity is known but the fingerprint changed.
    FingerprintChanged,
    /// 64 — "prove it": reserved for an anti-spam challenge.
    ProveIt,
    /// A status code the spec does not define.
    Other(u8),
}

impl MisfinStatus {
    pub fn from_code(code: u8) -> Self {
        match code {
            20 => Self::Delivered,
            30 => Self::SendHereInstead,
            31 => Self::SendHereForever,
            40 => Self::TemporaryError,
            41 => Self::ServerUnavailable,
            42 => Self::CgiError,
            43 => Self::ProxyingError,
            44 => Self::SlowDown,
            45 => Self::MailboxFull,
            50 => Self::PermanentError,
            51 => Self::MailboxDoesNotExist,
            52 => Self::MailboxGone,
            53 => Self::DomainNotServiced,
            59 => Self::BadRequest,
            60 => Self::CertificateRequired,
            61 => Self::UnauthorizedSender,
            62 => Self::CertificateInvalid,
            63 => Self::FingerprintChanged,
            64 => Self::ProveIt,
            other => Self::Other(other),
        }
    }

    pub fn code(&self) -> u8 {
        match self {
            Self::Delivered => 20,
            Self::SendHereInstead => 30,
            Self::SendHereForever => 31,
            Self::TemporaryError => 40,
            Self::ServerUnavailable => 41,
            Self::CgiError => 42,
            Self::ProxyingError => 43,
            Self::SlowDown => 44,
            Self::MailboxFull => 45,
            Self::PermanentError => 50,
            Self::MailboxDoesNotExist => 51,
            Self::MailboxGone => 52,
            Self::DomainNotServiced => 53,
            Self::BadRequest => 59,
            Self::CertificateRequired => 60,
            Self::UnauthorizedSender => 61,
            Self::CertificateInvalid => 62,
            Self::FingerprintChanged => 63,
            Self::ProveIt => 64,
            Self::Other(code) => *code,
        }
    }

    pub fn category(&self) -> StatusCategory {
        match self.code() / 10 {
            1 => StatusCategory::Reserved,
            2 => StatusCategory::Success,
            3 => StatusCategory::Redirect,
            4 => StatusCategory::TemporaryFailure,
            5 => StatusCategory::PermanentFailure,
            6 => StatusCategory::AuthenticationFailure,
            _ => StatusCategory::Unknown,
        }
    }

    pub fn is_success(&self) -> bool {
        self.category() == StatusCategory::Success
    }
}

impl std::fmt::Display for MisfinStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Delivered => "message delivered",
            Self::SendHereInstead => "send here instead",
            Self::SendHereForever => "send here forever",
            Self::TemporaryError => "temporary error",
            Self::ServerUnavailable => "server is unavailable",
            Self::CgiError => "CGI error",
            Self::ProxyingError => "proxying error",
            Self::SlowDown => "slow down",
            Self::MailboxFull => "mailbox full",
            Self::PermanentError => "permanent error",
            Self::MailboxDoesNotExist => "mailbox doesn't exist",
            Self::MailboxGone => "mailbox gone",
            Self::DomainNotServiced => "domain not serviced",
            Self::BadRequest => "bad request",
            Self::CertificateRequired => "certificate required",
            Self::UnauthorizedSender => "unauthorized sender",
            Self::CertificateInvalid => "certificate invalid",
            Self::FingerprintChanged => "fingerprint changed",
            Self::ProveIt => "prove it",
            Self::Other(code) => return write!(formatter, "unknown status {code}"),
        };
        write!(formatter, "{} ({name})", self.code())
    }
}

/// Parse a response line (`<STATUS><SPACE><META>`, CRLF already stripped) into
/// its status and META string. The META may be empty.
pub fn parse_response_line(line: &str) -> Result<(MisfinStatus, String), String> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.len() < 2 || !line.is_char_boundary(2) {
        return Err(format!("Response line too short: {line:?}"));
    }
    let (digits, rest) = line.split_at(2);
    let code: u8 = digits
        .parse()
        .map_err(|_| format!("Response status is not numeric: {line:?}"))?;
    let meta = rest.strip_prefix(' ').unwrap_or(rest).to_string();
    Ok((MisfinStatus::from_code(code), meta))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for code in [20, 30, 31, 40, 41, 42, 43, 44, 45, 50, 51, 52, 53, 59, 60, 61, 62, 63, 64] {
            assert_eq!(MisfinStatus::from_code(code).code(), code);
        }
        assert_eq!(MisfinStatus::from_code(99), MisfinStatus::Other(99));
    }

    #[test]
    fn categories_follow_the_tens_digit() {
        assert_eq!(MisfinStatus::Delivered.category(), StatusCategory::Success);
        assert_eq!(
            MisfinStatus::SendHereForever.category(),
            StatusCategory::Redirect
        );
        assert_eq!(
            MisfinStatus::SlowDown.category(),
            StatusCategory::TemporaryFailure
        );
        assert_eq!(
            MisfinStatus::BadRequest.category(),
            StatusCategory::PermanentFailure
        );
        assert_eq!(
            MisfinStatus::FingerprintChanged.category(),
            StatusCategory::AuthenticationFailure
        );
        assert_eq!(
            MisfinStatus::Other(15).category(),
            StatusCategory::Reserved
        );
    }

    #[test]
    fn response_lines_parse() {
        let (status, meta) = parse_response_line("20 abcdef\r\n").unwrap();
        assert_eq!(status, MisfinStatus::Delivered);
        assert_eq!(meta, "abcdef");

        let (status, meta) = parse_response_line("51 Mailbox doesn't exist.").unwrap();
        assert_eq!(status, MisfinStatus::MailboxDoesNotExist);
        assert_eq!(meta, "Mailbox doesn't exist.");

        let (status, meta) = parse_response_line("40").unwrap();
        assert_eq!(status, MisfinStatus::TemporaryError);
        assert_eq!(meta, "");

        assert!(parse_response_line("x").is_err());
        assert!(parse_response_line("ab meta").is_err());
    }
}
