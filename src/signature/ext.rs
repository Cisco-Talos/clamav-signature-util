use super::{
    super::signature::{
        logical::targetdesc::TargetDescParseError, targettype::TargetType, ParseError, Signature,
    },
    bodysig::{BodySig, BodySigParseError},
    logical::subsig::SubSig,
    targettype::TargetTypeParseError,
};
use crate::{
    feature::{EngineReq, FeatureSet},
    sigbytes::SigBytes,
    util::{parse_number_dec, ParseNumberError},
};
use std::{convert::TryFrom, str};
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

impl Offset {
    pub fn append_sigbytes(
        &self,
        s: &mut SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        use std::fmt::Write;

        if matches!(self, Offset::Normal(OffsetPos::Any)) {
            // Handle the simplest case first
            s.write_char('*')?;
        } else {
            let (pos, maxshift) = match self {
                Offset::Normal(pos) => (pos, None),
                Offset::Floating(pos, maxoffset) => (pos, Some(maxoffset)),
            };
            match pos {
                OffsetPos::Any => unreachable!(),
                OffsetPos::Absolute(n) => write!(s, "{n}")?,
                OffsetPos::FromEOF(n) => write!(s, "EOF-{n}")?,
                OffsetPos::EP(n) => write!(s, "EP{n:+}")?,
                OffsetPos::StartOfSection { section_no, offset } => {
                    write!(s, "S{section_no}+{offset}")?
                }
                OffsetPos::EntireSection(section_no) => write!(s, "SE{section_no}")?,
                OffsetPos::StartOfLastSection(n) => write!(s, "SL+{n}")?,
                OffsetPos::PEVersionInfo => write!(s, "VI")?,
            }
            if let Some(maxshift) = maxshift {
                write!(s, ",{maxshift}").unwrap()
            }
        }
        Ok(())
    }
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

    fn to_sigbytes(&self) -> Result<SigBytes, super::ToSigBytesError> {
        use std::fmt::Write;

        let mut s = SigBytes::new();
        if let Some(name) = &self.name {
            write!(s, "{name}:")?;
        }
        // Add the TargetType as an integer
        self.target_type.append_sigbytes(&mut s)?;
        s.write_char(':')?;
        self.offset.append_sigbytes(&mut s)?;
        if let Some(body_sig) = &self.body_sig {
            s.write_char(':')?;
            body_sig.append_sigbytes(&mut s)?;
            /*
            let body_sig = SigBytes::from(body_sig);
            s.write_all((&body_sig).into())?;
             */
        }

        Ok(s)
    }
}

impl EngineReq for ExtendedSig {
    fn features(&self) -> FeatureSet {
        self.body_sig
            .as_ref()
            .map(BodySig::features)
            .unwrap_or_default()
    }
}

impl SubSig for ExtendedSig {
    fn subsig_type(&self) -> super::logical::subsig::SubSigType {
        super::logical::subsig::SubSigType::Extended
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SIG: &str =
        "AllTheStuff-1:1:EP+78,45:de1e7e*facade??(c0|ff|ee)decafe[5-9]00{3-4}d1{9-}7e{-5}!(0f|f1|ce)(B)(L)a??b";
    #[test]
    fn export() {
        let sig: ExtendedSig = SAMPLE_SIG.as_bytes().try_into().unwrap();
        let exported = sig.to_sigbytes().unwrap().to_string();
        assert_eq!(SAMPLE_SIG, &exported);
    }
}
