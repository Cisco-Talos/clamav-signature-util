use super::{
    super::signature::{
        logical::targetdesc::TargetDescParseError, targettype::TargetType, ParseError,
    },
    bodysig::{BodySig, BodySigParseError},
};
use num_traits::FromPrimitive;
use std::convert::TryFrom;
use std::str;
use thiserror::Error;

#[derive(Debug)]
pub struct ExtendedSig {
    name: String,
    #[allow(dead_code)]
    target_type: TargetType,
    #[allow(dead_code)]
    offset: Offset,
    body_sig: Option<BodySig>,
}

#[derive(Debug, Error)]
pub enum ExtendedSigParseError {
    #[error("missing TargetType field")]
    MissingTargetType,

    #[error("missing Offset field")]
    MissingOffset,

    #[error("missing section number in offset(SE#+n) format")]
    MissingOffsetSectionNo,

    #[error("missing offset from section in offset(SE#+n) format")]
    MissingOffsetSectionOffset,

    #[error("missing HexSignature field")]
    MissingHexSignature,

    #[error(transparent)]
    BodySig(#[from] BodySigParseError),
}

#[derive(Debug)]
enum Offset {
    Normal(OffsetPos),
    Floating(OffsetPos, usize),
}

#[derive(Debug)]
pub enum OffsetPos {
    Any,
    Absolute(usize),
    FromEOF(usize),
    EP(isize),
    StartOfSection { section_no: usize, offset: usize },
    EntireSection(usize),
    StartOfLastSection(usize),
}

impl TryFrom<&[u8]> for ExtendedSig {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut fields = data.split(|b| *b == b':');

        let name = str::from_utf8(fields.next().ok_or(ParseError::MissingName)?)?.to_owned();
        let target_type = FromPrimitive::from_usize(
            str::from_utf8(
                fields
                    .next()
                    .ok_or(ExtendedSigParseError::MissingTargetType)?,
            )?
            .parse()?,
        )
        .ok_or(TargetDescParseError::UnknownTargetType)?;

        let offset = fields
            .next()
            .ok_or(ExtendedSigParseError::MissingOffset)?
            .try_into()?;
        let body_sig = match fields
            .next()
            .ok_or(ExtendedSigParseError::MissingHexSignature)?
        {
            b"*" => None,
            s => Some(s.try_into().map_err(ExtendedSigParseError::BodySig)?),
        };

        Ok(Self {
            name,
            target_type,
            offset,
            body_sig,
        })
    }
}

impl TryFrom<&[u8]> for Offset {
    type Error = ParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut offset_tokens = value.splitn(2, |b| *b == b',');

        let offset_base = offset_tokens
            .next()
            .ok_or(ExtendedSigParseError::MissingOffset)?
            .try_into()?;
        if let Some(maxshift_s) = offset_tokens.next() {
            Ok(Offset::Floating(
                offset_base,
                str::from_utf8(maxshift_s)?.parse()?,
            ))
        } else {
            Ok(Offset::Normal(offset_base))
        }
    }
}

impl TryFrom<&[u8]> for OffsetPos {
    type Error = ParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value == b"*" {
            Ok(OffsetPos::Any)
        } else if let Some(s) = value.strip_prefix(b"EOF-") {
            Ok(OffsetPos::FromEOF(str::from_utf8(s)?.parse()?))
        } else if let Some(s) = value.strip_prefix(b"EP+") {
            Ok(OffsetPos::EP(str::from_utf8(s)?.parse()?))
        } else if let Some(s) = value.strip_prefix(b"EP-") {
            Ok(OffsetPos::EP(0 - str::from_utf8(s)?.parse::<isize>()?))
        } else if let Some(s) = value.strip_prefix(b"SE") {
            Ok(OffsetPos::EntireSection(str::from_utf8(s)?.parse()?))
        } else if let Some(s) = value.strip_prefix(b"SL+") {
            Ok(OffsetPos::StartOfLastSection(str::from_utf8(s)?.parse()?))
        } else if let Some(s) = value.strip_prefix(b"S") {
            let mut parts = s.splitn(2, |b| *b == b'+');
            let section_no: usize = str::from_utf8(
                parts
                    .next()
                    .ok_or(ExtendedSigParseError::MissingOffsetSectionNo)?,
            )?
            .parse()?;
            let offset: usize = str::from_utf8(
                parts
                    .next()
                    .ok_or(ExtendedSigParseError::MissingOffsetSectionOffset)?,
            )?
            .parse()?;
            Ok(OffsetPos::StartOfSection { section_no, offset })
        } else {
            Ok(OffsetPos::Absolute(str::from_utf8(value)?.parse()?))
        }
    }
}

impl super::Signature for ExtendedSig {
    fn name(&self) -> &str {
        &self.name
    }

    fn feature_levels(&self) -> (usize, Option<usize>) {
        if let Some(body_sig) = &self.body_sig {
            (body_sig.min_f_level, None)
        } else {
            (1, None)
        }
    }
}
