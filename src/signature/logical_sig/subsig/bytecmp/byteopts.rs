/*
 *  Copyright (C) 2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

use super::{Encoding, Endianness};
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug)]
pub struct ByteOptions {
    // The original implementation allows this to be unspecified (!)
    encoding: Option<Encoding>,
    // The original implementation allows this to be unspecified (!)
    endianness: Option<Endianness>,
    evaluate_if_can_extract: bool,
    extract_bytes: u8,
}

#[derive(Debug, Error, PartialEq)]
pub enum ByteOptionsParseError {
    #[error("unrecognized byte option")]
    Unrecognized,

    #[error("incompatible options for encoding and endianness")]
    IncompatibleOptions,

    #[error("missing number of bytes to extract")]
    MissingNumBytes,

    #[error("invalid num_bytes")]
    InvalidNumBytes,
}

impl ByteOptions {
    #[must_use]
    pub fn encoding(&self) -> Option<Encoding> {
        self.encoding
    }

    #[must_use]
    pub fn endianness(&self) -> Option<Endianness> {
        self.endianness
    }

    #[must_use]
    pub fn evaluate_if_can_extract(&self) -> bool {
        self.evaluate_if_can_extract || self.encoding == Some(Encoding::RawBinary)
    }

    #[must_use]
    pub fn extract_bytes(&self) -> u8 {
        self.extract_bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<ByteOptions, ByteOptionsParseError> {
        let mut encoding = None;
        let mut endianness = None;
        let mut evaluate_if_can_extract = false;
        let mut extract_bytes = None;

        for byte in bytes {
            match byte {
                b'h' => encoding = Some(Encoding::Hex),
                b'd' => encoding = Some(Encoding::Decimal),
                b'a' => encoding = Some(Encoding::Automatic),
                b'i' => encoding = Some(Encoding::RawBinary),
                b'l' => endianness = Some(Endianness::Little),
                b'b' => endianness = Some(Endianness::Big),
                b'e' => evaluate_if_can_extract = true,
                b'1'..=b'9' => extract_bytes = Some(byte - b'0'),
                b'0' => return Err(ByteOptionsParseError::InvalidNumBytes),
                _ => return Err(ByteOptionsParseError::Unrecognized),
            }
        }

        let extract_bytes = extract_bytes.ok_or(ByteOptionsParseError::MissingNumBytes)?;

        // Now check sanity
        if encoding == Some(Encoding::Decimal) {
            match endianness {
                Some(Endianness::Little) => return Err(ByteOptionsParseError::IncompatibleOptions),
                None => endianness = Some(Endianness::Big),
                _ => (),
            }
        }
        if encoding == Some(Encoding::RawBinary) && !matches!(extract_bytes, 1 | 2 | 4 | 8) {
            return Err(ByteOptionsParseError::InvalidNumBytes);
        }

        Ok(ByteOptions {
            encoding,
            endianness,
            evaluate_if_can_extract,
            extract_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_binary_accepts_clamav_widths() {
        for width in [b'1', b'2', b'4', b'8'] {
            let options = ByteOptions::from_bytes(&[b'i', width]).expect("parse raw-binary width");
            assert_eq!(options.encoding(), Some(Encoding::RawBinary));
            assert_eq!(options.extract_bytes(), width - b'0');
            assert!(options.evaluate_if_can_extract());
        }
    }

    #[test]
    fn raw_binary_exact_extraction_is_implicit() {
        let options = ByteOptions::from_bytes(b"i4").expect("parse raw-binary byte option");
        assert!(options.evaluate_if_can_extract());
    }

    #[test]
    fn raw_binary_rejects_non_clamav_widths() {
        for width in [b'3', b'5', b'6', b'7', b'9'] {
            assert!(matches!(
                ByteOptions::from_bytes(&[b'i', width]),
                Err(ByteOptionsParseError::InvalidNumBytes)
            ));
        }
    }

    #[test]
    fn text_encodings_keep_extended_fixture_lengths() {
        for encoding in [b'h', b'd', b'a'] {
            let options =
                ByteOptions::from_bytes(&[encoding, b'3']).expect("parse text byte option");
            assert_eq!(options.extract_bytes(), 3);
        }
    }
}
