use super::{SubSig, SubSigType};
use crate::{
    signature::logical::SubSigModifier,
    util::{parse_number_dec, ParseNumberError},
};
use thiserror::Error;

pub mod compset;
pub use compset::{ComparisonOp, ComparisonSet, ComparisonSetParseError};
pub mod byteopts;
pub use byteopts::{ByteOptions, ByteOptionsParseError};
pub mod offset;
pub use offset::{Offset, OffsetModifier, OffsetParseError};

#[derive(Debug)]
#[allow(dead_code)]
pub struct ByteCmpSubSig {
    subsigid_trigger: u8,
    offset: Offset,
    byte_options: ByteOptions,
    comparisons: [Option<ComparisonSet>; 2],
    modifier: Option<SubSigModifier>,
}

#[derive(Debug, Error)]
pub enum ByteCmpSubSigParseError {
    #[error("missing closing parenthesis")]
    MissingClosingParen,

    #[error("missing subsigid_trigger")]
    MissingSubSigIdTrigger,

    #[error("invalid subsigid_trigger: {0}")]
    InvalidTrigger(ParseNumberError<u8>),

    #[error("invalid offset: {0}")]
    InvalidOffset(ParseNumberError<isize>),

    #[error("missing parameters")]
    MissingParameters,

    #[error("missing offset field")]
    MissingOffset,

    #[error("missing offset modifier")]
    MissingOffsetModifier,

    #[error("missing byte_options field")]
    MissingByteOptions,

    #[error("parsing byte options: {0}")]
    ByteOptionsParse(#[from] ByteOptionsParseError),

    #[error("missing comparisons")]
    MissingComparison,

    #[error("too many comparisons (only 2 permitted)")]
    TooManyComparisons,

    #[error("parsing comparison set: {0}")]
    ComparisonSetParse(#[from] ComparisonSetParseError),

    #[error("parsing offset: {0}")]
    OffsetParse(#[from] OffsetParseError),
}

#[derive(Debug, PartialEq)]
pub enum Encoding {
    Hex,
    Decimal,
    Automatic,
    RawBinary,
}

#[derive(Debug, PartialEq)]
pub enum Endianness {
    Little,
    Big,
}

impl SubSig for ByteCmpSubSig {
    fn subsig_type(&self) -> SubSigType {
        SubSigType::ByteCmp
    }
}

impl ByteCmpSubSig {
    pub fn from_bytes(
        bytes: &[u8],
        modifier: Option<SubSigModifier>,
    ) -> Result<Self, ByteCmpSubSigParseError> {
        let bytes = bytes
            .strip_suffix(b")")
            .ok_or(ByteCmpSubSigParseError::MissingClosingParen)?;
        let mut parts = bytes.splitn(2, |&b| b == b'(');
        let subsigid_trigger = parse_number_dec(
            parts
                .next()
                .ok_or(ByteCmpSubSigParseError::MissingSubSigIdTrigger)?,
        )
        .map_err(ByteCmpSubSigParseError::InvalidTrigger)?;

        // Now parse the three fields within
        let mut params = parts
            .next()
            .ok_or(ByteCmpSubSigParseError::MissingParameters)?
            .splitn(3, |&b| b == b'#');

        let offset = Offset::from_bytes(
            params
                .next()
                .ok_or(ByteCmpSubSigParseError::MissingOffset)?,
        )?;

        let byte_options = ByteOptions::from_bytes(
            params
                .next()
                .ok_or(ByteCmpSubSigParseError::MissingByteOptions)?,
        )?;

        let mut comparisons = [None, None];
        for (idx, bytes) in params
            .next()
            .ok_or(ByteCmpSubSigParseError::MissingComparison)?
            .split(|&b| b == b',')
            .enumerate()
        {
            match idx {
                0 | 1 => comparisons[idx] = Some(bytes.try_into()?),
                _ => return Err(ByteCmpSubSigParseError::TooManyComparisons),
            }
        }

        Ok(ByteCmpSubSig {
            subsigid_trigger,
            offset,
            byte_options,
            comparisons,
            modifier,
        })
    }
}
