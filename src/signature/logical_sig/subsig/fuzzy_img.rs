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

use super::{SubSig, SubSigType};
use crate::{
    feature::{EngineReq, Feature, Set},
    sigbytes::{AppendSigBytes},
    signature::logical_sig::SubSigModifier,
    util::{parse_number_dec, ParseNumberError},
};
use std::{fmt::Write};
use thiserror::Error;

#[derive(Debug)]
#[allow(dead_code)]
pub struct FuzzyImgSubSig {
    hash_string: String,
    hamming_distance: Option<isize>,
    modifier: Option<SubSigModifier>,
}

#[derive(Debug, Error, PartialEq)]
pub enum FuzzyImgSubSigParseError {
    #[error("invalid hash string: {0}")]
    InvalidHashString(String),

    #[error("invalid hamming distance: {0}")]
    InvalidHammingDistance(ParseNumberError<isize>),

    #[error("missing fuzzy_img# prefix")]
    MissingFuzzyImgHashPrefix,

    #[error("too few #-delimited fields")]
    TooFewFields,

    #[error("too many #-delimited fields")]
    TooManyFields,
}

impl super::SubSigError for FuzzyImgSubSigParseError {
    fn identified(&self) -> bool {
        !matches!(
            self,
            FuzzyImgSubSigParseError::MissingFuzzyImgHashPrefix
        )
    }
}

impl SubSig for FuzzyImgSubSig {
    fn subsig_type(&self) -> SubSigType {
        SubSigType::FuzzyImg
    }
}

impl EngineReq for FuzzyImgSubSig {
    fn features(&self) -> Set {
        Set::from_static(&[Feature::FuzzyImageMin])
    }
}

impl AppendSigBytes for FuzzyImgSubSig {
    fn append_sigbytes(
        &self,
        sb: &mut crate::sigbytes::SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        let size_hint = "fuzzy_img#".len() + 16 + 1 + 10;
        sb.try_reserve_exact(size_hint)?;
        write!(sb, "fuzzy_img#{}", self.hash_string)?;
        if let Some(distance) = self.hamming_distance {
            write!(sb, "{}", distance)?;
        }
        Ok(())
    }
}

impl FuzzyImgSubSig {
    pub fn from_bytes(
        bytes: &[u8],
        modifier: Option<SubSigModifier>,
    ) -> Result<Self, FuzzyImgSubSigParseError> {

        let mut parts = bytes.splitn(3, |&b| b == b'#');

        // get the first part, which must be "fuzzy_img"
        let fuzzy_img_prefix = parts
            .next()
            .ok_or(FuzzyImgSubSigParseError::MissingFuzzyImgHashPrefix)?;
        // Make sure the first part is "fuzzy_img"
        if fuzzy_img_prefix != b"fuzzy_img" {
            return Err(FuzzyImgSubSigParseError::MissingFuzzyImgHashPrefix);
        }

        // The second part is the hash string, which must be a valid hex string
        let hash_string = parts
            .next()
            .ok_or(FuzzyImgSubSigParseError::TooFewFields)?;
        // Make sure the hash string is valid hex
        let hash_string = std::str::from_utf8(hash_string)
            .map_err(|_| FuzzyImgSubSigParseError::InvalidHashString(
                String::from_utf8_lossy(hash_string).to_string(),
            ))?;
        if !hash_string.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(FuzzyImgSubSigParseError::InvalidHashString(
                hash_string.to_string(),
            ));
        }
        // The hash string must be exactly 16 characters long
        if hash_string.len() != 16 {
            return Err(FuzzyImgSubSigParseError::InvalidHashString(
                format!("Hash string must be exactly 16 characters long, got {}", hash_string.len()),
            ));
        }

        // The third part is the hamming distance. It is optional, but if it is provided it must be a valid integer.
        let hamming_distance = parts
            .next();

        let hamming_distance = if let Some(distance_str) = hamming_distance {
            // Try to parse the hamming distance as an integer
            let distance = parse_number_dec(distance_str)
                .map_err(FuzzyImgSubSigParseError::InvalidHammingDistance)?;
            // If the distance is negative, return an error
            if distance < 0 {
                return Err(FuzzyImgSubSigParseError::InvalidHammingDistance(
                    ParseNumberError::NegativeValue(distance),
                ));
            }
            Some(distance)
        } else {
            None
        };

        // If there are more parts, then this is not a valid fuzzy_img subsig
        if parts.next().is_some() {
            return Err(FuzzyImgSubSigParseError::TooManyFields);
        }

        Ok(FuzzyImgSubSig {
            hash_string: hash_string.to_string(),
            hamming_distance,
            modifier,
        })
    }
}
