//! The Scorpion document file format: a sequence of binary blocks.
//!
//! Unlike gemtext or scrolltext, this is not a line grammar. There is no
//! global header and no delimiters -- a document is just blocks, one after
//! another, each shaped:
//!
//! ```text
//! 1 byte    block type and character encoding, packed
//! 2 bytes   attribute length, big-endian
//! n bytes   attribute
//! 3 bytes   body length, big-endian
//! n bytes   body
//! ```
//!
//! ## The packed first byte
//!
//! The specification describes that byte as "the block type and character
//! encoding" and then lists the two sets separately: types run `0x00` to
//! `0x0F`, encodings are `0x00`, `0x10`, `0x20`, `0x80`, and `0xA0`. They
//! occupy disjoint halves of the byte, so the byte is the two OR'd together:
//! the low nibble is the type and the high nibble is the encoding. Reading it
//! as one flat value would make every non-ASCII block an unknown type.
//!
//! ## Text is bytes here
//!
//! Attribute and body are handed back as `&[u8]`, not `&str`. The encodings
//! this format admits are TRON-8, "PC", and ISO 2022 -- none of which is
//! UTF-8, and two of which are stateful. Decoding them is a job for a charset
//! crate against a declared [`Encoding`], and a parser that assumed UTF-8
//! would corrupt the very documents the format exists to carry. The one
//! exception is a link's attribute, which the specification pins to ASCII.

use core::fmt;

/// What a block is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockType {
    /// `0x00` -- a normal paragraph. The attribute must be empty.
    Paragraph,
    /// `0x01`-`0x06` -- a heading, 1 outermost through 6 innermost. The
    /// attribute is the fragment that refers to this section, empty when the
    /// section cannot be linked to.
    Heading(u8),
    /// `0x08` -- a hyperlink. The attribute is the URL, the body the text.
    Link,
    /// `0x09` -- a hyperlink that asks for input first, as a `10` status would.
    InputLink,
    /// `0x0A` -- a hyperlink opening the `I` subprotocol.
    InteractiveLink,
    /// `0x0B` -- an alternate service for the preceding link block, or for the
    /// document when it is the first block.
    AlternateService,
    /// `0x0C` -- a blockquote. The attribute must be empty.
    Blockquote,
    /// `0x0D` -- preformatted text, to be shown in a fixed-pitch font.
    Preformatted,
    /// `0x0F` -- optional metadata, such as a signature over the rest of the
    /// document. A client that does not understand it ignores it.
    Metadata,
    /// A type this crate does not know. Carried rather than dropped, because
    /// the format is a draft and a reader must not lose blocks it cannot name.
    Unknown(u8),
}

impl BlockType {
    /// The low-nibble value this type is written as.
    pub fn value(self) -> u8 {
        match self {
            Self::Paragraph => 0x00,
            Self::Heading(level) => level.clamp(1, 6),
            Self::Link => 0x08,
            Self::InputLink => 0x09,
            Self::InteractiveLink => 0x0A,
            Self::AlternateService => 0x0B,
            Self::Blockquote => 0x0C,
            Self::Preformatted => 0x0D,
            Self::Metadata => 0x0F,
            Self::Unknown(value) => value & 0x0F,
        }
    }

    fn from_value(value: u8) -> Self {
        match value {
            0x00 => Self::Paragraph,
            0x01..=0x06 => Self::Heading(value),
            0x08 => Self::Link,
            0x09 => Self::InputLink,
            0x0A => Self::InteractiveLink,
            0x0B => Self::AlternateService,
            0x0C => Self::Blockquote,
            0x0D => Self::Preformatted,
            0x0F => Self::Metadata,
            other => Self::Unknown(other),
        }
    }

    /// Whether this block's attribute is a URL.
    pub fn is_link(self) -> bool {
        matches!(
            self,
            Self::Link | Self::InputLink | Self::InteractiveLink | Self::AlternateService
        )
    }
}

/// The character encoding a block's text is in, and its direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Encoding {
    /// `0x00` -- TRON-8, left to right.
    Tron8,
    /// `0x10` -- "PC", left to right. ASCII is a subset.
    Pc,
    /// `0x20` -- ISO 2022, left to right.
    Iso2022,
    /// `0x80` -- TRON-8, right to left.
    Tron8Rtl,
    /// `0xA0` -- ISO 2022, right to left.
    Iso2022Rtl,
    /// A high nibble the specification does not define.
    Unknown(u8),
}

impl Encoding {
    /// The high-nibble value this encoding is written as.
    pub fn value(self) -> u8 {
        match self {
            Self::Tron8 => 0x00,
            Self::Pc => 0x10,
            Self::Iso2022 => 0x20,
            Self::Tron8Rtl => 0x80,
            Self::Iso2022Rtl => 0xA0,
            Self::Unknown(value) => value & 0xF0,
        }
    }

    fn from_value(value: u8) -> Self {
        match value {
            0x00 => Self::Tron8,
            0x10 => Self::Pc,
            0x20 => Self::Iso2022,
            0x80 => Self::Tron8Rtl,
            0xA0 => Self::Iso2022Rtl,
            other => Self::Unknown(other),
        }
    }

    /// Whether this encoding is written right to left.
    pub fn is_rtl(self) -> bool {
        matches!(self, Self::Tron8Rtl | Self::Iso2022Rtl)
    }
}

/// Control codes valid inside a block's text.
pub mod control {
    /// `0x02` -- what precedes it was a section number, item number, or bullet.
    pub const ITEM_MARKER: u8 = 0x02;
    /// `0x05` -- begins a furigana or annotation sub-block.
    pub const ANNOTATION_START: u8 = 0x05;
    /// `0x06` -- separates the data part from the text part of a sub-block.
    pub const SUBBLOCK_SEPARATOR: u8 = 0x06;
    /// `0x07` -- ends a data/text sub-block.
    pub const SUBBLOCK_END: u8 = 0x07;
    /// `0x09` -- tab; only valid inside a preformatted block.
    pub const TAB: u8 = 0x09;
    /// `0x0A` -- line break; only valid inside a preformatted block.
    pub const LINE_BREAK: u8 = 0x0A;
}

/// One block of a Scorpion document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// What this block is.
    pub block_type: BlockType,
    /// The encoding its text is in.
    pub encoding: Encoding,
    /// The attribute: a URL for link blocks, a fragment for headings, empty
    /// for paragraphs and blockquotes.
    pub attribute: Vec<u8>,
    /// The block's text or data.
    pub body: Vec<u8>,
}

impl Block {
    /// A block with an empty attribute.
    pub fn new(block_type: BlockType, encoding: Encoding, body: impl Into<Vec<u8>>) -> Self {
        Self {
            block_type,
            encoding,
            attribute: Vec::new(),
            body: body.into(),
        }
    }

    /// A link block.
    pub fn link(url: impl Into<Vec<u8>>, text: impl Into<Vec<u8>>, encoding: Encoding) -> Self {
        Self {
            block_type: BlockType::Link,
            encoding,
            attribute: url.into(),
            body: text.into(),
        }
    }

    /// The URL of a link block.
    ///
    /// The specification says a link attribute is ASCII, and that "if the
    /// attribute contains a null character, then only the part before the null
    /// character is the URL, and the null character itself and anything
    /// afterward will be ignored". Both rules are applied here; a non-ASCII
    /// attribute yields `None` rather than a lossy guess.
    pub fn url(&self) -> Option<&str> {
        if !self.block_type.is_link() {
            return None;
        }
        let end = self
            .attribute
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(self.attribute.len());
        let url = &self.attribute[..end];
        url.is_ascii()
            .then(|| core::str::from_utf8(url).ok())
            .flatten()
    }

    /// The packed first byte: encoding in the high nibble, type in the low.
    pub fn tag(&self) -> u8 {
        self.encoding.value() | self.block_type.value()
    }

    /// Append this block's bytes to `out`.
    pub fn encode_to(&self, out: &mut Vec<u8>) -> Result<(), DocumentError> {
        let attribute_len =
            u16::try_from(self.attribute.len()).map_err(|_| DocumentError::AttributeTooLong)?;
        if self.body.len() > MAX_BODY {
            return Err(DocumentError::BodyTooLong);
        }
        out.push(self.tag());
        out.extend_from_slice(&attribute_len.to_be_bytes());
        out.extend_from_slice(&self.attribute);
        // A 24-bit big-endian length: the low three bytes of the u32.
        let body_len = (self.body.len() as u32).to_be_bytes();
        out.extend_from_slice(&body_len[1..]);
        out.extend_from_slice(&self.body);
        Ok(())
    }
}

/// The largest body a block can declare: 24 bits of length.
pub const MAX_BODY: usize = 0xFF_FFFF;

/// Why a document could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentError {
    /// The bytes ended part-way through a block.
    Truncated,
    /// An attribute was longer than the 16-bit length field allows.
    AttributeTooLong,
    /// A body was longer than the 24-bit length field allows.
    BodyTooLong,
}

impl fmt::Display for DocumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "document ends part-way through a block",
            Self::AttributeTooLong => "attribute exceeds 65535 bytes",
            Self::BodyTooLong => "body exceeds 16777215 bytes",
        })
    }
}

impl core::error::Error for DocumentError {}

/// Parse a whole document into its blocks.
pub fn parse(bytes: &[u8]) -> Result<Vec<Block>, DocumentError> {
    Blocks::new(bytes).collect()
}

/// Encode blocks into a document.
pub fn encode(blocks: &[Block]) -> Result<Vec<u8>, DocumentError> {
    let mut out = Vec::new();
    for block in blocks {
        block.encode_to(&mut out)?;
    }
    Ok(out)
}

/// A streaming reader over a document's blocks.
///
/// Useful where a document is large enough that collecting every block at once
/// is not wanted; [`parse`] is the convenience over it.
pub struct Blocks<'a> {
    rest: &'a [u8],
}

impl<'a> Blocks<'a> {
    /// Read blocks out of `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }
}

impl Iterator for Blocks<'_> {
    type Item = Result<Block, DocumentError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        Some(self.read())
    }
}

impl Blocks<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], DocumentError> {
        if self.rest.len() < count {
            // Consume the remainder so the iterator ends rather than yielding
            // the same error forever.
            self.rest = &[];
            return Err(DocumentError::Truncated);
        }
        let (head, tail) = self.rest.split_at(count);
        self.rest = tail;
        Ok(head)
    }

    fn read(&mut self) -> Result<Block, DocumentError> {
        let tag = self.take(1)?[0];
        let attribute_len = {
            let bytes = self.take(2)?;
            usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
        };
        let attribute = self.take(attribute_len)?.to_vec();
        let body_len = {
            let bytes = self.take(3)?;
            // 24-bit big-endian, widened through a zero high byte.
            u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize
        };
        let body = self.take(body_len)?.to_vec();

        Ok(Block {
            block_type: BlockType::from_value(tag & 0x0F),
            encoding: Encoding::from_value(tag & 0xF0),
            attribute,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_byte_packs_encoding_over_type() {
        // The rule the whole format hangs on. A right-to-left ISO 2022
        // heading level 3 is 0xA0 | 0x03.
        let block = Block {
            block_type: BlockType::Heading(3),
            encoding: Encoding::Iso2022Rtl,
            attribute: b"sec-3".to_vec(),
            body: b"a heading".to_vec(),
        };
        assert_eq!(block.tag(), 0xA3);

        let round = parse(&encode(std::slice::from_ref(&block)).unwrap()).unwrap();
        assert_eq!(round, vec![block]);
    }

    #[test]
    fn a_non_ascii_encoding_does_not_disguise_the_block_type() {
        // Read the tag flat and 0xA3 is an "unknown type"; read it packed and
        // it is a heading that happens to be right-to-left.
        let blocks = parse(&[0xA3, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(blocks[0].block_type, BlockType::Heading(3));
        assert_eq!(blocks[0].encoding, Encoding::Iso2022Rtl);
        assert!(blocks[0].encoding.is_rtl());
    }

    #[test]
    fn a_body_length_is_twenty_four_bits_big_endian() {
        // 0x01_0000 is 65536: one byte more than a 16-bit length could hold,
        // which is exactly where a wrong-width read would break.
        let body = vec![b'x'; 65536];
        let block = Block::new(BlockType::Paragraph, Encoding::Pc, body.clone());
        let encoded = encode(&[block]).unwrap();
        assert_eq!(&encoded[3..6], &[0x01, 0x00, 0x00]);
        assert_eq!(parse(&encoded).unwrap()[0].body, body);
    }

    #[test]
    fn a_link_url_stops_at_a_null() {
        // "only the part before the null character is the URL".
        let block = Block::link(
            b"scorpion://example.com/page\0ignored".to_vec(),
            b"click".to_vec(),
            Encoding::Pc,
        );
        assert_eq!(block.url(), Some("scorpion://example.com/page"));
    }

    #[test]
    fn a_non_ascii_link_url_is_refused_rather_than_guessed() {
        // The spec pins link attributes to ASCII. Anything else is a broken
        // document, and inventing an interpretation would send a request
        // somewhere the author never wrote.
        let block = Block::link(vec![0xFF, 0xFE], b"click".to_vec(), Encoding::Pc);
        assert_eq!(block.url(), None);
    }

    #[test]
    fn only_link_blocks_have_urls() {
        let paragraph = Block::new(BlockType::Paragraph, Encoding::Pc, b"text".to_vec());
        assert_eq!(paragraph.url(), None);
        assert!(BlockType::AlternateService.is_link());
        assert!(!BlockType::Preformatted.is_link());
    }

    #[test]
    fn an_unknown_block_type_is_carried_not_dropped() {
        // The format is a draft. A reader that silently discarded types it did
        // not recognise would lose content and give no sign of it.
        let blocks = parse(&[0x0E, 0, 0, 0, 0, 1, b'?']).unwrap();
        assert_eq!(blocks[0].block_type, BlockType::Unknown(0x0E));
        assert_eq!(blocks[0].body, b"?");
    }

    #[test]
    fn a_truncated_document_reports_truncation_and_stops() {
        // A declared 300-byte body with two bytes present.
        let mut bytes = vec![0x00, 0, 0];
        bytes.extend_from_slice(&[0x00, 0x01, 0x2C]);
        bytes.extend_from_slice(b"ab");
        assert_eq!(parse(&bytes), Err(DocumentError::Truncated));

        // And the iterator ends rather than repeating the error forever.
        let errors: Vec<_> = Blocks::new(&bytes).collect();
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn several_blocks_round_trip_in_order() {
        let blocks = vec![
            Block {
                block_type: BlockType::Heading(1),
                encoding: Encoding::Pc,
                attribute: b"top".to_vec(),
                body: b"Title".to_vec(),
            },
            Block::new(BlockType::Paragraph, Encoding::Pc, b"Some text.".to_vec()),
            Block::link(
                b"scorpion://example.com/next".to_vec(),
                b"Next".to_vec(),
                Encoding::Pc,
            ),
            Block::new(
                BlockType::Preformatted,
                Encoding::Pc,
                b"line one\nline two".to_vec(),
            ),
        ];
        assert_eq!(parse(&encode(&blocks).unwrap()).unwrap(), blocks);
    }

    #[test]
    fn an_empty_document_holds_no_blocks() {
        assert_eq!(parse(&[]).unwrap(), Vec::new());
    }

    #[test]
    fn an_attribute_too_long_is_refused_at_encode_time() {
        let block = Block {
            block_type: BlockType::Link,
            encoding: Encoding::Pc,
            attribute: vec![b'x'; 65536],
            body: Vec::new(),
        };
        assert_eq!(encode(&[block]), Err(DocumentError::AttributeTooLong));
    }
}
