use super::{SubSig, SubSigType};
use crate::{
    feature::{EngineReq, Feature, FeatureSet},
    sigbytes::AppendSigBytes,
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

#[derive(Debug, Error, PartialEq)]
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

    #[error("too many #-delimited fields")]
    TooManyFields,

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

impl super::SubSigError for ByteCmpSubSigParseError {
    fn identified(&self) -> bool {
        !matches!(
            self,
            ByteCmpSubSigParseError::MissingClosingParen
                | ByteCmpSubSigParseError::MissingSubSigIdTrigger
                | ByteCmpSubSigParseError::MissingParameters
                | ByteCmpSubSigParseError::MissingOffset
                | ByteCmpSubSigParseError::MissingByteOptions
                | ByteCmpSubSigParseError::MissingComparison
        )
    }
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

impl EngineReq for ByteCmpSubSig {
    fn features(&self) -> FeatureSet {
        FeatureSet::from_static(&[Feature::ByteCompareMin])
    }
}

impl AppendSigBytes for ByteCmpSubSig {
    fn append_sigbytes(
        &self,
        _sb: &mut crate::sigbytes::SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        // TODO: CLAM-1754
        todo!()
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
        let mut parts = bytes.rsplitn(2, |&b| b == b'(');

        // Now parse the three fields within
        let mut params = parts
            .next()
            .ok_or(ByteCmpSubSigParseError::MissingParameters)?
            .splitn(3, |&b| b == b'#');

        // Make sure all three exist before bothering to parse them.  Otherwise, this probably
        // isn't a bytecmp subsig.
        let maybe_offset = params
            .next()
            .ok_or(ByteCmpSubSigParseError::MissingOffset)?;
        let maybe_byte_options = params
            .next()
            .ok_or(ByteCmpSubSigParseError::MissingByteOptions)?;
        let maybe_comparisons = params
            .next()
            .ok_or(ByteCmpSubSigParseError::MissingComparison)?;

        // Don't look at this until it looks pretty much like a bytecmp sig
        let subsigid_trigger = parse_number_dec(
            parts
                .next()
                .ok_or(ByteCmpSubSigParseError::MissingSubSigIdTrigger)?,
        )
        .map_err(ByteCmpSubSigParseError::InvalidTrigger)?;

        // Only three fields should be present
        if params.next().is_some() {
            return Err(ByteCmpSubSigParseError::TooManyFields);
        }

        let offset = maybe_offset.try_into()?;
        let byte_options = ByteOptions::from_bytes(maybe_byte_options)?;

        let mut comparisons = [None, None];
        for (idx, bytes) in maybe_comparisons.split(|&b| b == b',').enumerate() {
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
