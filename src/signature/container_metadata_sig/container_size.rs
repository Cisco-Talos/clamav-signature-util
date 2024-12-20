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

use crate::{
    sigbytes::AppendSigBytes,
    util::{parse_number_dec, parse_range_inclusive, ParseNumberError, RangeInclusiveParseError},
};
use std::fmt::Write;
use std::ops::RangeInclusive;

#[derive(Debug)]
pub enum ContainerSize {
    Exact(usize),
    Range(RangeInclusive<usize>),
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParseError {
    #[error("parsing range: {0}")]
    ParseRange(#[from] RangeInclusiveParseError<usize>),

    #[error("parsing exact size: {0}")]
    ParseExact(#[from] ParseNumberError<usize>),
}

impl AppendSigBytes for ContainerSize {
    fn append_sigbytes(
        &self,
        sb: &mut crate::sigbytes::SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        match self {
            ContainerSize::Exact(size) => write!(sb, "{size}")?,
            ContainerSize::Range(range) => write!(sb, "{}-{}", range.start(), range.end())?,
        }
        Ok(())
    }
}

impl TryFrom<&[u8]> for ContainerSize {
    type Error = ParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.iter().any(|&b| b == b'-') {
            Ok(ContainerSize::Range(parse_range_inclusive(value)?))
        } else {
            Ok(ContainerSize::Exact(parse_number_dec(value)?))
        }
    }
}

pub fn parse(bytes: &[u8]) -> Result<ContainerSize, ParseError> {
    if bytes.iter().any(|&b| b == b'-') {
        Ok(ContainerSize::Range(parse_range_inclusive(bytes)?))
    } else {
        Ok(ContainerSize::Exact(parse_number_dec(bytes)?))
    }
}

#[cfg(test)]
mod tests {
    use super::ContainerSize;

    #[test]
    fn try_exact() {
        let bytes = r"12345".as_bytes();
        assert!(matches!(bytes.try_into(), Ok(ContainerSize::Exact(12345))));
    }
}
