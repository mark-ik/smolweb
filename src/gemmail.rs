/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Gemmail (specification §4): text/gemini plus three metadata line types —
//! sender (`<`), recipients (`:`), and timestamp (`@`). Only the first
//! occurrence of each is parsed, per the spec.

use super::helpers::split_once_whitespace;
use super::{MisfinAddress, MisfinGemmail, MisfinSender};

/// Parse gemmail text into its metadata and body. Metadata lines beyond the
/// first of each type are left in the body verbatim (the spec: "Misfin
/// utilites must only parse the first occurance of these lines").
pub fn parse_gemmail(text: &str) -> MisfinGemmail {
    let mut sender = None;
    let mut recipients = None;
    let mut timestamp = None;
    let mut body_lines = Vec::new();

    for line in text.lines() {
        let line = line.trim_end_matches('\r');

        if sender.is_none() {
            if let Some(parsed_sender) = parse_sender_line(line) {
                sender = Some(parsed_sender);
                continue;
            }
        }
        if recipients.is_none() {
            if let Some(parsed_recipients) = parse_recipients_line(line) {
                recipients = Some(parsed_recipients);
                continue;
            }
        }
        if timestamp.is_none() {
            if let Some(parsed_timestamp) = parse_timestamp_line(line) {
                timestamp = Some(parsed_timestamp);
                continue;
            }
        }

        body_lines.push(line.to_string());
    }

    let subject = body_lines.iter().find_map(|line| {
        line.strip_prefix("### ")
            .or_else(|| line.strip_prefix("## "))
            .or_else(|| line.strip_prefix("# "))
            .map(|heading| heading.trim().to_string())
    });

    MisfinGemmail {
        sender,
        recipients: recipients.unwrap_or_default(),
        timestamp,
        subject,
        body: body_lines.join("\n"),
    }
}

impl MisfinGemmail {
    /// Render this message back to gemmail text: sender line, recipients line,
    /// and timestamp line (each only if present), followed by the body.
    ///
    /// Per the best-practices document, sender and timestamp lines are the
    /// *receiving* mailserver's to add — a client composing fresh mail should
    /// leave them `None` and let this render just recipients + body.
    pub fn to_gemtext(&self) -> String {
        let mut out = String::new();
        if let Some(sender) = &self.sender {
            out.push_str("< ");
            out.push_str(&sender.address.as_addr_spec());
            if let Some(blurb) = &sender.blurb {
                out.push(' ');
                out.push_str(blurb);
            }
            out.push('\n');
        }
        if !self.recipients.is_empty() {
            out.push(':');
            for recipient in &self.recipients {
                out.push(' ');
                out.push_str(&recipient.as_addr_spec());
            }
            out.push('\n');
        }
        if let Some(timestamp) = &self.timestamp {
            out.push_str("@ ");
            out.push_str(timestamp);
            out.push('\n');
        }
        out.push_str(&self.body);
        out
    }
}

/// The reply set for a received message, per specification §4.2: the sender
/// (if present) followed by the recipients line's addresses, deduplicated,
/// and never including `me` (the replier's own address).
pub fn reply_recipients(gemmail: &MisfinGemmail, me: &MisfinAddress) -> Vec<MisfinAddress> {
    let mut out: Vec<MisfinAddress> = Vec::new();
    let mut push = |candidate: &MisfinAddress| {
        if candidate != me && !out.contains(candidate) {
            out.push(candidate.clone());
        }
    };
    if let Some(sender) = &gemmail.sender {
        push(&sender.address);
    }
    for recipient in &gemmail.recipients {
        push(recipient);
    }
    out
}

fn parse_sender_line(line: &str) -> Option<MisfinSender> {
    let remainder = line.strip_prefix('<')?.trim();
    if remainder.is_empty() {
        return None;
    }
    let (address, blurb) = split_once_whitespace(remainder);
    let address = MisfinAddress::parse(address).ok()?;
    Some(MisfinSender {
        address,
        blurb: blurb.map(|value| value.to_string()),
    })
}

fn parse_recipients_line(line: &str) -> Option<Vec<MisfinAddress>> {
    let remainder = line.strip_prefix(':')?.trim();
    let mut recipients = Vec::new();
    for part in remainder.split_whitespace() {
        recipients.push(MisfinAddress::parse(part).ok()?);
    }
    Some(recipients)
}

fn parse_timestamp_line(line: &str) -> Option<String> {
    let remainder = line.strip_prefix('@')?.trim();
    if remainder.is_empty() {
        None
    } else {
        Some(remainder.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(spec: &str) -> MisfinAddress {
        MisfinAddress::parse(spec).unwrap()
    }

    #[test]
    fn gemmail_extracts_metadata_and_subject() {
        let gemmail = parse_gemmail(
            "< friend@example.com Friendly Person\n: one@example.com two@example.com\n@ 2023-05-09T19:39:15Z\n# A note on flowers\n\nThe green ones bite.\n",
        );

        assert_eq!(
            gemmail
                .sender
                .as_ref()
                .map(|sender| sender.address.as_addr_spec()),
            Some("friend@example.com".to_string())
        );
        assert_eq!(gemmail.recipients.len(), 2);
        assert_eq!(gemmail.timestamp.as_deref(), Some("2023-05-09T19:39:15Z"));
        assert_eq!(gemmail.subject.as_deref(), Some("A note on flowers"));
        assert_eq!(gemmail.body, "# A note on flowers\n\nThe green ones bite.");
    }

    #[test]
    fn only_the_first_metadata_line_of_each_type_is_parsed() {
        let gemmail = parse_gemmail("< a@one.test First\n< b@two.test Second\nbody");
        assert_eq!(
            gemmail.sender.unwrap().address.as_addr_spec(),
            "a@one.test"
        );
        assert_eq!(gemmail.body, "< b@two.test Second\nbody");
    }

    #[test]
    fn gemmail_round_trips_through_to_gemtext() {
        let original = parse_gemmail(
            "< sender@example.test The Sender\n: a@x.test b@y.test\n@ 2026-07-03T00:00:00Z\nHello\nthere",
        );
        let rendered = original.to_gemtext();
        let reparsed = parse_gemmail(&rendered);
        assert_eq!(original, reparsed);
    }

    #[test]
    fn fresh_mail_renders_without_server_stamped_lines() {
        let draft = MisfinGemmail {
            sender: None,
            recipients: vec![addr("a@x.test")],
            timestamp: None,
            subject: None,
            body: "Hi".to_string(),
        };
        assert_eq!(draft.to_gemtext(), ": a@x.test\nHi");
    }

    #[test]
    fn reply_recipients_dedupe_and_exclude_me() {
        let gemmail = parse_gemmail(
            "< one@example.test Person One\n: me@here.test two@example.test one@example.test\nA funny joke",
        );
        let replies = reply_recipients(&gemmail, &addr("me@here.test"));
        let specs: Vec<String> = replies.iter().map(MisfinAddress::as_addr_spec).collect();
        assert_eq!(specs, vec!["one@example.test", "two@example.test"]);
    }
}
