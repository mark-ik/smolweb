/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use super::MisfinIdentitySpec;

pub(super) fn split_once_whitespace(input: &str) -> (&str, Option<&str>) {
    let Some(index) = input.find(char::is_whitespace) else {
        return (input, None);
    };
    let head = &input[..index];
    let tail = input[index..].trim();
    if tail.is_empty() {
        (head, None)
    } else {
        (head, Some(tail))
    }
}

pub(super) fn identity_path_for_spec(spec: &MisfinIdentitySpec, identity_root: &Path) -> PathBuf {
    identity_root.join(format!(
        "{}.json",
        sanitize_filename(&spec.address.as_addr_spec())
    ))
}

pub(super) fn sanitize_filename(input: &str) -> String {
    input
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '@') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    encode_hex(&digest)
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(nibble_to_hex(byte >> 4));
        output.push(nibble_to_hex(byte & 0x0f));
    }
    output
}

pub(super) fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("Hex payload length must be even.".to_string());
    }

    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let high = from_hex_digit(bytes[index])?;
        let low = from_hex_digit(bytes[index + 1])?;
        output.push((high << 4) | low);
        index += 2;
    }
    Ok(output)
}

pub(super) fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("nibble values must be in 0..=15"),
    }
}

pub(super) fn from_hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("Invalid hex digit '{}'.", byte as char)),
    }
}
