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

use std::num::TryFromIntError;

use super::Encoding;
use crate::util::{parse_number_dec, parse_number_hex, ParseNumberError};
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug)]
pub struct ComparisonSet {
    // this is more of an operator, but the docs call it a symbol
    symbol: ComparisonOp,
    value: i64,
    /// The original encoding of this number in the signature
    encoding: Encoding,
}

#[derive(Debug, Error, PartialEq)]
pub enum ComparisonSetParseError {
    #[error("comparison set empty")]
    Empty,

    #[error("missing operator")]
    MissingOperator,

    #[error("unknown comparison operator")]
    UnknownOperator,

    #[error("parsing value: {0}")]
    ParseValue(ParseNumberError<i64>),

    #[error("parsing value: {0}")]
    ParseHexValue(ParseNumberError<u64>),

    #[error("parsing value: too large for i64")]
    TooLarge(#[from] TryFromIntError),
}

impl TryFrom<&[u8]> for ComparisonSet {
    type Error = ComparisonSetParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (&sym_byte, remainder) = value.split_first().ok_or(ComparisonSetParseError::Empty)?;
        // Be friendly in returning this error.  If the operator doesn't parse because it's a number, just report that the operator was apparently missing.
        let symbol = sym_byte.try_into().map_err(|e| {
            if matches!(e, ComparisonSetParseError::UnknownOperator) && sym_byte.is_ascii_digit() {
                ComparisonSetParseError::MissingOperator
            } else {
                e
            }
        })?;
        let (encoding, value) = if let Some(hex_value_bytes) = remainder.strip_prefix(b"0x") {
            (
                Encoding::Hex,
                i64::try_from(
                    parse_number_hex(hex_value_bytes)
                        .map_err(ComparisonSetParseError::ParseHexValue)?,
                )?,
            )
        } else {
            (
                Encoding::Decimal,
                parse_number_dec::<i64>(remainder).map_err(ComparisonSetParseError::ParseValue)?
                    as i64,
            )
        };

        Ok(Self {
            symbol,
            value,
            encoding,
        })
    }
}

#[derive(Debug)]
pub enum ComparisonOp {
    LessThan,
    Equal,
    GreaterThan,
}

impl TryFrom<u8> for ComparisonOp {
    type Error = ComparisonSetParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            b'<' => ComparisonOp::LessThan,
            b'=' => ComparisonOp::Equal,
            b'>' => ComparisonOp::GreaterThan,
            _ => return Err(ComparisonSetParseError::UnknownOperator),
        })
    }
}
