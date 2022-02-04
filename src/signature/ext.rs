use crate::util::{parse_number_dec, ParseNumberError};

use super::{
    super::signature::{
        logical::targetdesc::TargetDescParseError, targettype::TargetType, ParseError, Signature,
    },
    bodysig::{BodySig, BodySigParseError},
    logical::subsig::SubSig,
    targettype::TargetTypeParseError,
};
use std::convert::TryFrom;
use std::str;
use thiserror::Error;

#[derive(Debug)]
pub struct ExtendedSig {
    pub(crate) name: Option<String>,
    #[allow(dead_code)]
    pub(crate) target_type: TargetType,
    #[allow(dead_code)]
    pub(crate) offset: Offset,
    pub(crate) body_sig: Option<BodySig>,
}

#[derive(Debug, Error)]
pub enum ExtendedSigParseError {
    #[error("missing TargetType field")]
    MissingTargetType,

    #[error("missing Offset field")]
    MissingOffset,

    #[error("missing HexSignature field")]
    MissingHexSignature,

    #[error("invalid body signature: {0}")]
    BodySig(#[from] BodySigParseError),

    #[error("parsing TargetDesc: {0}")]
    TargetDescParse(#[from] TargetDescParseError),

    #[error("parsing TargetType: {0}")]
    TargetTypeParse(#[from] TargetTypeParseError),

    #[error("Parsing offset: {0}")]
    ParseOffset(#[from] OffsetParseError),
}

#[derive(Debug, Clone, Copy)]
pub enum Offset {
    Normal(OffsetPos),
    Floating(OffsetPos, usize),
}

#[derive(Debug, Error)]
pub enum OffsetParseError {
    #[error("offset missing")]
    Missing,

    #[error("parsing offset pos: {0}")]
    OffsetPosParse(#[from] OffsetPosParseError),

    #[error("parsing MaxShift: {0}")]
    ParseMaxShift(ParseNumberError<usize>),
}

#[derive(Debug, Clone, Copy)]
pub enum OffsetPos {
    Any,
    Absolute(usize),
    FromEOF(usize),
    EP(isize),
    StartOfSection { section_no: usize, offset: usize },
    EntireSection(usize),
    StartOfLastSection(usize),
    PEVersionInfo,
}

#[derive(Debug, Error)]
pub enum OffsetPosParseError {
    #[error("Parsing EOF offset: {0}")]
    ParseEOFOffset(ParseNumberError<usize>),

    #[error("Parsing EP offset: {0}")]
    ParseEPOffset(ParseNumberError<isize>),

    #[error("parsing EntireSection offset: {0}")]
    ParseEntireSectionOffset(ParseNumberError<usize>),

    #[error("parsing StartOfLastSection offset: {0}")]
    ParseStartOfLastSectionOffset(ParseNumberError<usize>),

    #[error("missing section number in offset(SE#+n) format")]
    MissingOffsetSectionNo,

    #[error("parsing SectionNo: {0}")]
    ParseSectionNo(ParseNumberError<usize>),

    #[error("missing offset from section in offset(SE#+n) format")]
    MissingOffsetSectionOffset,

    #[error("parsing SectionOffset: {0}")]
    ParseSectionOffset(ParseNumberError<usize>),

    #[error("parsing AbsoluteOffset: {0}")]
    ParseAbsoluteOffset(ParseNumberError<usize>),
}

impl TryFrom<&[u8]> for ExtendedSig {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut fields = data.split(|b| *b == b':');

        let name = str::from_utf8(fields.next().ok_or(ParseError::MissingName)?)
            .map_err(ParseError::NameNotUnicode)?
            .to_owned();
        let target_type = fields
            .next()
            .ok_or(ExtendedSigParseError::MissingTargetType)?
            .try_into()
            .map_err(ExtendedSigParseError::TargetTypeParse)?;

        let offset = fields
            .next()
            .ok_or(ExtendedSigParseError::MissingOffset)?
            .try_into()
            .map_err(ExtendedSigParseError::ParseOffset)?;
        let body_sig = match fields
            .next()
            .ok_or(ExtendedSigParseError::MissingHexSignature)?
        {
            b"*" => None,
            s => Some(s.try_into().map_err(ExtendedSigParseError::BodySig)?),
        };

        Ok(Self {
            name: Some(name),
            target_type,
            offset,
            body_sig,
        })
    }
}

impl TryFrom<&[u8]> for Offset {
    type Error = OffsetParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut offset_tokens = value.splitn(2, |b| *b == b',');

        let offset_base = offset_tokens
            .next()
            .ok_or(OffsetParseError::Missing)?
            .try_into()
            .map_err(OffsetParseError::OffsetPosParse)?;
        if let Some(maxshift_s) = offset_tokens.next() {
            Ok(Offset::Floating(
                offset_base,
                parse_number_dec(maxshift_s).map_err(OffsetParseError::ParseMaxShift)?,
            ))
        } else {
            Ok(Offset::Normal(offset_base))
        }
    }
}

impl TryFrom<&[u8]> for OffsetPos {
    type Error = OffsetPosParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value == b"*" {
            Ok(OffsetPos::Any)
        } else if let Some(s) = value.strip_prefix(b"EOF-") {
            Ok(OffsetPos::FromEOF(
                parse_number_dec(s).map_err(OffsetPosParseError::ParseEOFOffset)?,
            ))
        } else if let Some(s) = value.strip_prefix(b"EP+") {
            Ok(OffsetPos::EP(
                parse_number_dec(s).map_err(OffsetPosParseError::ParseEPOffset)?,
            ))
        } else if let Some(s) = value.strip_prefix(b"EP-") {
            Ok(OffsetPos::EP(
                0 - parse_number_dec(s).map_err(OffsetPosParseError::ParseEPOffset)?,
            ))
        } else if let Some(s) = value.strip_prefix(b"SE") {
            Ok(OffsetPos::EntireSection(
                parse_number_dec(s).map_err(OffsetPosParseError::ParseEntireSectionOffset)?,
            ))
        } else if let Some(s) = value.strip_prefix(b"SL+") {
            Ok(OffsetPos::StartOfLastSection(parse_number_dec(s).map_err(
                OffsetPosParseError::ParseStartOfLastSectionOffset,
            )?))
        } else if let Some(s) = value.strip_prefix(b"S") {
            let mut parts = s.splitn(2, |b| *b == b'+');
            let section_no: usize = parse_number_dec(
                parts
                    .next()
                    .ok_or(OffsetPosParseError::MissingOffsetSectionNo)?,
            )
            .map_err(OffsetPosParseError::ParseSectionNo)?;
            let offset: usize = parse_number_dec(
                parts
                    .next()
                    .ok_or(OffsetPosParseError::MissingOffsetSectionOffset)?,
            )
            .map_err(OffsetPosParseError::ParseSectionOffset)?;
            Ok(OffsetPos::StartOfSection { section_no, offset })
        } else if value == b"VI" {
            Ok(OffsetPos::PEVersionInfo)
        } else {
            Ok(OffsetPos::Absolute(
                parse_number_dec(value).map_err(OffsetPosParseError::ParseAbsoluteOffset)?,
            ))
        }
    }
}

impl Signature for ExtendedSig {
    fn name(&self) -> &str {
        if let Some(name) = &self.name {
            name
        } else {
            "anonymous"
        }
    }

    fn feature_levels(&self) -> (usize, Option<usize>) {
        if let Some(body_sig) = &self.body_sig {
            (body_sig.min_f_level, None)
        } else {
            (1, None)
        }
    }
}

impl SubSig for ExtendedSig {
    fn subsig_type(&self) -> super::logical::subsig::SubSigType {
        super::logical::subsig::SubSigType::Extended
    }
}
