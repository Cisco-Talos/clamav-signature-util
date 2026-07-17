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

impl ExtendedSig {
    #[must_use]
    pub fn name_opt(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    pub fn target_type(&self) -> TargetType {
        self.target_type
    }

    #[must_use]
    pub fn offset(&self) -> Option<Offset> {
        self.offset
    }

    #[must_use]
    pub fn body_sig(&self) -> Option<&BodySig> {
        self.body_sig.as_ref()
    }

    #[must_use]
    pub fn modifier(&self) -> Option<SubSigModifier> {
        self.modifier
    }
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

    #[must_use]
    pub fn offset_pos(&self) -> OffsetPos {
        match self {
            Offset::Normal(pos) | Offset::Floating(pos, _) => *pos,
        }
    }

    #[must_use]
    pub fn max_shift(&self) -> Option<usize> {
        match self {
            Offset::Normal(_) => None,
            Offset::Floating(_, max_shift) => Some(*max_shift),
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

    const SAMPLE_SIG: &str = "AllTheStuff-1:1:EP+78,45:de1e7e*facade??(c0|ff|ee)decafe[5-9]00{3-4}d1d2{9-}7e8e{-5}!(0f|f1|ce)(B)(L)a??bccdd";
    const SAMPLE_SIG_WITH_FLEVEL: &str = "AllTheStuff-1:1:EP+78,45:de1e7e*facade??(c0|ff|ee)decafe[5-9]00{3-4}d1d2{9-}7e8e{-5}!(0f|f1|ce)(B)(L)a??bccdd:99:101";

    #[test]
    fn export() {
        let (sig, sigmeta) = ExtendedSig::from_sigbytes(&SAMPLE_SIG.into()).unwrap();
        let sig = sig.downcast_ref::<ExtendedSig>().unwrap();
        let exported = sig.to_sigbytes().unwrap().to_string();
        assert_eq!(SAMPLE_SIG, &exported);
        assert_eq!(sigmeta, SigMeta::default());
        assert_eq!(sig.name_opt(), Some("AllTheStuff-1"));
        assert!(matches!(
            sig.target_type(),
            crate::signature::targettype::TargetType::PE
        ));
        assert!(matches!(
            sig.offset(),
            Some(Offset::Floating(OffsetPos::EP(78), 45))
        ));
        assert!(sig.body_sig().is_some());
        assert!(sig.modifier().is_none());
        let offset = sig.offset().unwrap();
        assert!(matches!(offset.offset_pos(), OffsetPos::EP(78)));
        assert_eq!(offset.max_shift(), Some(45));
    }

    #[test]
    fn parse_flevels() {
        let (sig, sigmeta) = match ExtendedSig::from_sigbytes(&SAMPLE_SIG_WITH_FLEVEL.into()) {
            Ok(sig_and_sigmeta) => sig_and_sigmeta,
            Err(e) => panic!("{}", e),
        };
        let sig = sig.downcast_ref::<ExtendedSig>().unwrap();
        let exported = sig.to_sigbytes().unwrap().to_string();
        assert_eq!(SAMPLE_SIG, &exported);
        assert_eq!(
            sigmeta,
            SigMeta {
                f_level: Some((99..=101).into()),
            }
        );
    }

    #[test]
    fn parses_main_ndb_wildcard_heavy_signatures() {
        for input in [
            "Win.Trojan.Obfus-21:1:EP+0,500:6681(a4|84)??????????????6681(a4|84)??????????????6681(a4|84)??????????????{-80}6681(84|a4)??????????????6681(84|a4)??????????????6681(a4|84)??????????????",
            "Win.Trojan.Obfus-23:1:*:6681(a4|84)??????????????6681(a4|84)??????????????6681(a4|84)??{6-300}c68424??????????????????????????c68424??????????????????????????c68424",
            "Win.Trojan.Elkern-2:1:*:9c60e8000000005d8d(b5|bd)(32|2d)(01|02)00008b5c242481e30000e0ff8d(b5|bd)(32|2d)(01|02)0000e8d60000008d(45|4d|55|5d)2b(50|51|52|53)8d(45|4d|55|5d)??(87|89)(ce|de|c6|d6)e8c8000000c381ed",
            "Pdf.Exploit.Agent-35528:0:*:4a4249472333324465636f6465{-100}73747265616d0d0a????????(40|41|42|43|44|45|46|47|48|49|4a|4b|4c|4d|4e|4f)(31|30|29|28|27|26|25|24|23|22|21|20|19|18|17|16|15|14|13|12|11|10|09|08|07|06|05|04|03|02|01|00)??????(10|20|30|40|50|60|70|80|90|a0|b0|c0|d0|e0|f0)",
            "Pdf.Exploit.Agent-35529:0:*:4a4249472333324465636f6465{-100}73747265616d0d0a????????(40|41|42|43|44|45|46|47|48|49|4a|4b|4c|4d|4e|4f)(31|30|29|28|27|26|25|24|23|22|21|20|19|18|17|16|15|14|13|12|11|10|09|08|07|06|05|04|03|02|01|00)??(ba|bb|bc|bd|be|bf|c0|c1|c2|c3|c4|c5|c6|c7|c8|c9|ca|cb|cc|cd|ce|cf|d0|d1|d2|d3|d4|d5|d6|d7|d8|d9|da|db|dc|dd|de|df|e0|e1|e2|e3|e4|e5|e6|e7|e8|e9|ea|eb|ec|ed|ee|ef|f0|f1|f2|f3|f4|f5|f6|f7|f8|f9|fa|fb|fc|fd|fe|ff)",
            "Pdf.Exploit.Agent-35531:0:*:4a4249472333324465636f6465{-100}73747265616d0a????????(40|41|42|43|44|45|46|47|48|49|4a|4b|4c|4d|4e|4f)(31|30|29|28|27|26|25|24|23|22|21|20|19|18|17|16|15|14|13|12|11|10|09|08|07|06|05|04|03|02|01|00)??(b9|ba|bb|bc|bd|be|bf|c0|c1|c2|c3|c4|c5|c6|c7|c8|c9|ca|cb|cc|cd|ce|cf|d0|d1|d2|d3|d4|d5|d6|d7|d8|d9|da|db|dc|dd|de|df|e0|e1|e2|e3|e4|e5|e6|e7|e8|e9|ea|eb|ec|ed|ee|ef|f0|f1|f2|f3|f4|f5|f6|f7|f8|f9|fa|fb|fc|fd|fe|ff)",
        ] {
            ExtendedSig::from_sigbytes(&input.into()).unwrap();
        }
    }
}
