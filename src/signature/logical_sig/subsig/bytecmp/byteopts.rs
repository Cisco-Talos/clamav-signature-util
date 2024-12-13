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
                b'1' | b'2' | b'4' | b'8' => extract_bytes = Some(byte - b'0'),
                b'0'..=b'9' => return Err(ByteOptionsParseError::InvalidNumBytes),
                _ => return Err(ByteOptionsParseError::Unrecognized),
            }
        }

        let extract_bytes = extract_bytes.ok_or(ByteOptionsParseError::MissingNumBytes)?;

        // Now check sanity
        if encoding == Some(Encoding::Decimal) {
            match endianness {
                Some(Endianness::Little) => return Err(ByteOptionsParseError::IncompatibleOptions),
                None => {
                    if encoding == Some(Encoding::Decimal) {
                        endianness = Some(Endianness::Big);
                    }
                }
                _ => (),
            }
        }

        Ok(ByteOptions {
            encoding,
            endianness,
            evaluate_if_can_extract,
            extract_bytes,
        })
    }
}
