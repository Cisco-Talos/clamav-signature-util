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

use super::bodysig::parse::BodySigParseError;
use crate::{
    feature::{EngineReq, Set},
    sigbytes::{AppendSigBytes, FromSigBytes, SigBytes},
    signature::{
        bodysig::BodySig,
        logical_sig::{
            subsig::{SubSig, SubSigModifier},
            targetdesc::TargetDescParseError,
        },
        targettype::{TargetType, TargetTypeParseError},
        FromSigBytesParseError, SigMeta, Signature,
    },
    util::{parse_number_dec, ParseNumberError},
};
use std::{fmt::Write, str};
use thiserror::Error;

#[derive(Debug)]
pub struct ExtendedSig {
    pub(crate) name: Option<String>,

    pub(crate) target_type: TargetType,

    // Note, offset is only optional in sub-signatures
    pub(crate) offset: Option<Offset>,
    pub(crate) body_sig: Option<BodySig>,
    /// Modifier (only applicable when used as a subsig with a logical signature)
    pub(crate) modifier: Option<SubSigModifier>,
}

#[derive(Debug, Error, PartialEq)]
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

    #[error("Parsing min_flevel: {0}")]
    ParseMinFlevel(ParseNumberError<u32>),

    #[error("Parsing max_flevel: {0}")]
    ParseMaxFlevel(ParseNumberError<u32>),
}

impl FromSigBytes for ExtendedSig {
    fn from_sigbytes<'a, SB: Into<&'a SigBytes>>(
        sb: SB,
    ) -> Result<(Box<dyn Signature>, super::SigMeta), FromSigBytesParseError> {
        let mut sigmeta = SigMeta::default();
        let data = sb.into().as_bytes();
        let mut fields = data.split(|b| *b == b':');

        let name = str::from_utf8(fields.next().ok_or(FromSigBytesParseError::MissingName)?)
            .map_err(FromSigBytesParseError::NameNotUnicode)?
            .to_owned();
        let target_type = fields
            .next()
            .ok_or(ExtendedSigParseError::MissingTargetType)?
            .try_into()
            .map_err(ExtendedSigParseError::TargetTypeParse)?;

        let offset = Some(
            fields
                .next()
                .ok_or(ExtendedSigParseError::MissingOffset)?
                .try_into()
                .map_err(ExtendedSigParseError::ParseOffset)?,
        );
        let body_sig = match fields
            .next()
            .ok_or(ExtendedSigParseError::MissingHexSignature)?
        {
            b"*" => None,
            s => Some(s.try_into().map_err(ExtendedSigParseError::BodySig)?),
        };

        // Parse optional min/max flevel
        if let Some(min_flevel) = fields.next() {
            let min_flevel =
                parse_number_dec(min_flevel).map_err(ExtendedSigParseError::ParseMinFlevel)?;

            if let Some(max_flevel) = fields.next() {
                let max_flevel =
                    parse_number_dec(max_flevel).map_err(ExtendedSigParseError::ParseMaxFlevel)?;
                sigmeta.f_level = Some((min_flevel..=max_flevel).into());
            } else {
                sigmeta.f_level = Some((min_flevel..).into());
            }
        }

        Ok((
            Box::new(Self {
                name: Some(name),
                target_type,
                offset,
                body_sig,
                modifier: None,
            }),
            sigmeta,
        ))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Offset {
    Normal(OffsetPos),
    Floating(OffsetPos, usize),
}

#[derive(Debug, Error, PartialEq)]
pub enum OffsetParseError {
    #[error("offset missing")]
    Missing,

    #[error("parsing offset pos: {0}")]
    OffsetPosParse(#[from] OffsetPosParseError),

    #[error("parsing MaxShift: {0}")]
    ParseMaxShift(ParseNumberError<usize>),
}

impl Offset {
    /// Return the offset value if the offset is a normal (non-floating)
    /// offset, and is of OffsetPos::Absolute.  Returns None if the offset is
    /// of any other type.
    #[must_use]
    pub fn absolute(&self) -> Option<usize> {
        if let Offset::Normal(OffsetPos::Absolute(value)) = self {
            Some(*value)
        } else {
            None
        }
    }
}

impl AppendSigBytes for Offset {
    fn append_sigbytes(&self, s: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
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
                    write!(s, "S{section_no}+{offset}")?;
                }
                OffsetPos::EntireSection(section_no) => write!(s, "SE{section_no}")?,
                OffsetPos::StartOfLastSection(n) => write!(s, "SL+{n}")?,
                OffsetPos::PEVersionInfo => write!(s, "VI")?,
            }
            if let Some(maxshift) = maxshift {
                write!(s, ",{maxshift}").unwrap();
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

#[derive(Debug, Error, PartialEq)]
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

    fn validate(&self, sigmeta: &SigMeta) -> Result<(), super::SigValidationError> {
        self.validate_subelements(sigmeta)?;
        self.validate_flevel(sigmeta)?;
        Ok(())
    }

    fn validate_flevel(&self, sigmeta: &SigMeta) -> Result<(), super::SigValidationError> {
        // Check the specified vs. the computed feature level
        if let Some(computed_flevel) = self.computed_feature_level() {
            if let Some(computed_min_flevel) = computed_flevel.start() {
                // Some features within this signature have a minimum feature level.
                // Confirm that the signature specifies it (or a higher level)
                match &sigmeta.f_level {
                    Some(f_level) => match f_level.start() {
                        Some(spec_min_flevel) => {
                            if spec_min_flevel < computed_min_flevel {
                                return Err(super::SigValidationError::SpecifiedMinFLevelTooLow {
                                    spec_min_flevel,
                                    computed_min_flevel,
                                    feature_set: self.features().into(),
                                });
                            }
                        }
                        None => {
                            // This is the [unlikely] case where a *maximum* FLevel
                            // was specified without a minimum, but a minimum is required.
                            return Err(super::SigValidationError::MinFLevelNotSpecified {
                                computed_min_flevel,
                                feature_set: self.features().into(),
                            });
                        }
                    },
                    None => {
                        return Err(super::SigValidationError::MinFLevelNotSpecified {
                            computed_min_flevel,
                            feature_set: self.features().into(),
                        });
                    }
                }
            }
            // TODO: check maximum, as well (but maximums are not presently computed)
        }

        Ok(())
    }
}

impl EngineReq for ExtendedSig {
    fn features(&self) -> Set {
        self.body_sig
            .as_ref()
            .map(BodySig::features)
            .unwrap_or_default()
    }
}

impl AppendSigBytes for ExtendedSig {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        if let Some(name) = &self.name {
            write!(sb, "{name}:")?;
        }
        // Add the TargetType as an integer
        self.target_type.append_sigbytes(sb)?;
        sb.write_char(':')?;
        if let Some(offset) = &self.offset {
            offset.append_sigbytes(sb)?;
        } else {
            debug_assert!(&self.offset.is_none());
        }
        if let Some(body_sig) = &self.body_sig {
            sb.write_char(':')?;
            body_sig.append_sigbytes(sb)?;
        }

        Ok(())
    }
}

impl SubSig for ExtendedSig {
    fn subsig_type(&self) -> super::logical_sig::subsig::SubSigType {
        super::logical_sig::subsig::SubSigType::Extended
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SIG: &str =
        "AllTheStuff-1:1:EP+78,45:de1e7e*facade??(c0|ff|ee)decafe[5-9]00{3-4}d1d2{9-}7e8e{-5}!(0f|f1|ce)(B)(L)a??bccdd";
    const SAMPLE_SIG_WITH_FLEVEL: &str =
        "AllTheStuff-1:1:EP+78,45:de1e7e*facade??(c0|ff|ee)decafe[5-9]00{3-4}d1d2{9-}7e8e{-5}!(0f|f1|ce)(B)(L)a??bccdd:99:101";

    #[test]
    fn export() {
        let (sig, sigmeta) = ExtendedSig::from_sigbytes(&SAMPLE_SIG.into()).unwrap();
        let exported = sig.to_sigbytes().unwrap().to_string();
        assert_eq!(SAMPLE_SIG, &exported);
        assert_eq!(sigmeta, SigMeta::default());
    }

    #[test]
    fn parse_flevels() {
        let (sig, sigmeta) = match ExtendedSig::from_sigbytes(&SAMPLE_SIG_WITH_FLEVEL.into()) {
            Ok(sig_and_sigmeta) => sig_and_sigmeta,
            Err(e) => panic!("{}", e),
        };
        let exported = sig.to_sigbytes().unwrap().to_string();
        assert_eq!(SAMPLE_SIG, &exported);
        assert_eq!(
            sigmeta,
            SigMeta {
                f_level: Some((99..=101).into()),
            }
        );
    }
}
