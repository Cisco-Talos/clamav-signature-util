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

use super::Encoding;
use crate::util::{parse_number_dec, ParseNumberError};
use thiserror::Error;

#[derive(Debug)]
#[allow(dead_code, clippy::struct_field_names)]
pub struct Offset {
    modifier: Modifier,
    offset: isize,
    encoding: Encoding,
}

#[derive(Debug, Error, PartialEq)]
pub enum ParseError {
    #[error("missing offset modifier")]
    MissingOffsetModifier,

    #[error("parsing offset: {0}")]
    ParseNum(#[from] ParseNumberError<isize>),
}

#[derive(Debug)]
pub enum Modifier {
    /// ">>"
    Positive,
    /// "<<"
    Negative,
}

impl TryFrom<&[u8]> for Offset {
    type Error = ParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let modifier;
        let bytes = if let Some(bytes) = bytes.strip_prefix(b">>") {
            modifier = Modifier::Positive;
            bytes
        } else if let Some(bytes) = bytes.strip_prefix(b"<<") {
            modifier = Modifier::Negative;
            bytes
        } else {
            return Err(ParseError::MissingOffsetModifier);
        };
        // TODO: parse hex?
        let offset = parse_number_dec(bytes).map_err(ParseError::ParseNum)?;
        Ok(Offset {
            modifier,
            offset,
            encoding: Encoding::Decimal,
        })
    }
}
