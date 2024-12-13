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

pub mod expression;
pub mod subsig;
pub mod targetdesc;

use self::{
    subsig::{SubSigModifier, SubSigParseError},
    targetdesc::{TargetDescAttr, TargetDescParseError, TargetDescValidationError},
};
use super::bodysig::parse::BodySigParseError;
use crate::{
    feature::EngineReq,
    sigbytes::{AppendSigBytes, FromSigBytes},
    signature::{
        ext_sig::ExtendedSig, FromSigBytesParseError, SigMeta, SigValidationError, Signature,
    },
    util::Range,
};
use std::{fmt::Write, str};
use subsig::SubSig;
use targetdesc::TargetDesc;
use thiserror::Error;

#[derive(Debug)]
pub struct LogicalSig {
    name: String,
    #[allow(dead_code)]
    target_desc: TargetDesc,
    #[allow(dead_code)]
    expression: Box<dyn expression::Element>,
    #[allow(dead_code)]
    sub_sigs: Vec<Box<dyn SubSig>>,
}

#[derive(Debug, Error, PartialEq)]
pub enum ParseError {
    #[error("parsing body signature index {0}: {1}")]
    BodySigParse(usize, BodySigParseError),

    #[error("empty")]
    Empty,

    #[error("missing Expression field")]
    MissingExpression,

    #[error("invalid logical expression: {0}")]
    LogExprParse(#[from] expression::LogExprParseError),

    #[error("missing TargetDesc field")]
    MissingTargetDesc,

    #[error("parsing TargetDesc field: {0}")]
    TargetDesc(#[from] TargetDescParseError),

    #[error("parsing subsig {0}: {1}")]
    SubSigParse(usize, SubSigParseError),
}

#[derive(Debug, Error, PartialEq)]
pub enum ValidationError {
    #[error("validating TargetDesc: {0}")]
    TargetDesc(#[from] TargetDescValidationError),

    #[error("validating extended signature (subsig {idx}): {err}")]
    SubSig {
        idx: usize,
        err: Box<SigValidationError>,
    },
}

impl Signature for LogicalSig {
    fn name(&self) -> &str {
        &self.name
    }

    fn validate_subelements(&self, sigmeta: &SigMeta) -> Result<(), SigValidationError> {
        self.target_desc
            .validate()
            .map_err(ValidationError::TargetDesc)?;
        for (idx, sub_sig) in self.sub_sigs.iter().enumerate() {
            if let Some(extsig) = sub_sig.downcast_ref::<ExtendedSig>() {
                extsig
                    .validate(sigmeta)
                    .map_err(|err| ValidationError::SubSig {
                        idx,
                        err: Box::new(err),
                    })?;
            }
        }

        Ok(())
    }
}

impl FromSigBytes for LogicalSig {
    fn from_sigbytes<'a, SB: Into<&'a crate::sigbytes::SigBytes>>(
        sb: SB,
    ) -> Result<(Box<dyn Signature>, super::SigMeta), FromSigBytesParseError> {
        let mut sigmeta = SigMeta::default();
        let mut fields = sb.into().as_bytes().split(|b| *b == b';');

        let name = str::from_utf8(fields.next().ok_or(FromSigBytesParseError::MissingName)?)
            .map_err(FromSigBytesParseError::NameNotUnicode)?
            .into();
        let target_desc: TargetDesc = fields
            .next()
            .ok_or(ParseError::MissingTargetDesc)?
            .try_into()
            .map_err(ParseError::TargetDesc)?;
        let expression = fields
            .next()
            .ok_or(ParseError::MissingExpression)?
            .try_into()
            .map_err(ParseError::LogExprParse)?;
        let mut sub_sigs = vec![];
        for (subsig_no, subsig_bytes) in fields.enumerate() {
            let (modifier, subsig_bytes) = find_modifier(subsig_bytes);
            sub_sigs.push(
                subsig::parse_bytes(subsig_bytes, modifier)
                    .map_err(|e| ParseError::SubSigParse(subsig_no, e))?,
            );
        }

        if let Some(range) = target_desc.attrs.iter().find_map(|attr| match attr {
            TargetDescAttr::Engine(Range::Inclusive(range)) => Some(range),
            _ => None,
        }) {
            sigmeta.f_level = Some((*range.start()..=*range.end()).into());
        }

        let sig = Self {
            name,
            target_desc,
            expression,
            sub_sigs,
        };

        Ok((Box::new(sig), sigmeta))
    }
}

impl EngineReq for LogicalSig {
    fn features(&self) -> crate::feature::Set {
        // Collect all the features required by the various subsigs
        self.sub_sigs
            .iter()
            .flat_map(|ss| ss.features())
            .chain(self.target_desc.features())
            .into()
    }
}

impl AppendSigBytes for LogicalSig {
    fn append_sigbytes(
        &self,
        sb: &mut crate::sigbytes::SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        write!(sb, "{};", self.name)?;
        self.target_desc.append_sigbytes(sb)?;
        write!(sb, ";{};", self.expression)?;
        for (i, sub_sig) in self.sub_sigs.iter().enumerate() {
            if i > 0 {
                sb.write_char(';')?;
            }
            if let Some(ext_sig) = sub_sig.downcast_ref::<ExtendedSig>() {
                // The extended signature can't be written out directly, as it
                // will also contain the name and offset (which should only be
                // inlcuded if non-default).
                if let Some(offset) = ext_sig.offset {
                    offset.append_sigbytes(sb)?;
                    if ext_sig.body_sig.is_some() {
                        sb.write_char(':')?;
                    }
                }
                if let Some(body_sig) = &ext_sig.body_sig {
                    body_sig.append_sigbytes(sb)?;
                }
                if let Some(modifier) = ext_sig.modifier {
                    sb.write_str("::")?;
                    modifier.append_sigbytes(sb)?;
                }
            } else {
                sub_sig.append_sigbytes(sb)?;
            }
        }
        Ok(())
    }
}

/// Search from the end of a subsignature to find a modifier of the form "::xxx".
///
/// If found, returns the modifier and a subslice (without the modifier).
///
/// If any unknown modifiers are found or the delimiter is missing, returns None
/// and the original slice.
fn find_modifier(haystack: &[u8]) -> (Option<SubSigModifier>, &[u8]) {
    enum State {
        ReadModifier,
        ReadDelimiter,
    }

    let mut modifier = SubSigModifier::default();

    let mut state = State::ReadModifier;
    for (pos, c) in haystack.iter().copied().enumerate().rev() {
        match state {
            State::ReadModifier => match c {
                b'a' => modifier.ascii = true,
                b'i' => modifier.case_insensitive = true,
                b'w' => modifier.widechar = true,
                b'f' => modifier.match_fullword = true,
                b':' => {
                    state = State::ReadDelimiter;
                    continue;
                }
                _ => break,
            },
            State::ReadDelimiter => match c {
                b':' => return (Some(modifier), &haystack[..pos]),
                _ => break,
            },
        }
    }
    (None, haystack)
}

/*
impl TryFrom<&[u8]> for LogicalSig {
    type Error = FromSigBytesParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut fields = data.split(|b| *b == b';');

        let name = str::from_utf8(fields.next().ok_or(FromSigBytesParseError::MissingName)?)
            .map_err(FromSigBytesParseError::NameNotUnicode)?
            .into();
        let target_desc = fields
            .next()
            .ok_or(ParseError::MissingTargetDesc)?
            .try_into()
            .map_err(ParseError::TargetDesc)?;
        let expression = fields
            .next()
            .ok_or(ParseError::MissingExpression)?
            .try_into()
            .map_err(ParseError::LogExprParse)?;
        let mut sub_sigs = vec![];
        for (subsig_no, subsig_bytes) in fields.enumerate() {
            let (modifier, subsig_bytes) = find_modifier(subsig_bytes);
            sub_sigs.push(
                subsig::parse_bytes(subsig_bytes, modifier)
                    .map_err(|e| ParseError::SubSigParse(subsig_no, e))?,
            );
        }

        Ok(Self {
            name,
            target_desc,
            expression,
            sub_sigs,
        })
    }
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SIG: &str = concat!(
        "PUA.Email.Phishing.FedEx-1;Engine:51-255,Target:4;(0&1)&(2|3);",
        "697320656e636c6f73656420746f20746865206c6574746572;",
        "636f6d70656e736174696f6e2066726f6d20796f7520666f722069742773206b656570696e67;",
        "6f637465742d73747265616d3b6e616d653d2246656445785f4c6162656c5f49445f4f72646572;",
        "6f637465742d73747265616d3b6e616d653d224c6162656c5f50617263656c5f46656445785f"
    );

    const SAMPLE_SIG_WITH_PCRE_OFFSET: &str = concat!(
        r#"Win.Packed.Gandcrab-6535413-0;"#,
        r#"Engine:81-255,Target:1;"#,
        r#"4;"#,
        r#"5050505050e8{2}(ffff|0000);"#,
        r#"5353535353535353535353ff15;"#,
        r#"5353535353{7}ff15;"#,
        r#"6d73636f7265652e646c6c::w;"#,
        r#"EOF-32:0&1&2&3/\x00{24}[A-Za-z0-9+/=]{8}/"#
    );

    #[test]
    fn full_sig() {
        let input = SAMPLE_SIG.into();
        let (sig, _) = LogicalSig::from_sigbytes(&input).unwrap();
        dbg!(sig);
    }

    #[test]
    fn test_find_modifier() {
        assert_eq!(
            find_modifier(b"abc"),
            (None::<SubSigModifier>, b"abc".as_ref())
        );
        assert_eq!(
            find_modifier(b"abc:d"),
            (None::<SubSigModifier>, b"abc:d".as_ref())
        );
        assert_eq!(
            find_modifier(b"abc::d"),
            (None::<SubSigModifier>, b"abc::d".as_ref())
        );
        assert_eq!(
            find_modifier(b"abc::a"),
            (
                Some(SubSigModifier {
                    ascii: true,
                    ..Default::default()
                }),
                b"abc".as_ref()
            )
        );
        assert_eq!(
            find_modifier(b"abc::ai"),
            (
                Some(SubSigModifier {
                    ascii: true,
                    case_insensitive: true,
                    ..Default::default()
                }),
                b"abc".as_ref()
            )
        );
        assert_eq!(
            find_modifier(b"blahblahblah::waif"),
            (
                Some(SubSigModifier {
                    ascii: true,
                    case_insensitive: true,
                    widechar: true,
                    match_fullword: true
                }),
                b"blahblahblah".as_ref()
            )
        );
    }

    #[test]
    fn export() {
        let input = SAMPLE_SIG.into();
        let (sig, _) = LogicalSig::from_sigbytes(&input).unwrap();
        let exported = sig.to_sigbytes().unwrap().to_string();
        assert_eq!(SAMPLE_SIG, &exported);
    }

    #[test]
    fn export_with_offset() {
        let input = SAMPLE_SIG_WITH_PCRE_OFFSET.into();
        let (sig, _) = LogicalSig::from_sigbytes(&input).unwrap();
        let exported = sig.to_sigbytes().unwrap().to_string();
        assert_eq!(SAMPLE_SIG_WITH_PCRE_OFFSET, &exported);
    }

    #[test]
    fn get_meta() {
        let input = SAMPLE_SIG.into();
        let (_, sigmeta) = LogicalSig::from_sigbytes(&input).unwrap();
        assert_eq!(
            sigmeta,
            SigMeta {
                f_level: Some((51..=255).into()),
            }
        );
    }

    #[test]
    fn verify_clam_1752() {
        let raw_sig = concat!(
            r#"Win.Trojan.MSShellcode-6360730-0;Engine:81-255,Target:1;1;"#,
            r#"d97424f4(5?|b?);"#,
            r#"0/\xd9\x74\x24\xf4[\x50-\x5f\xb0-\xbf].{0,8}[\x29\x2b\x31\x33]\xc9([\xb0-\xbf]|\x66\xb9)/s"#,
        ).into();
        let (sig, _) = LogicalSig::from_sigbytes(&raw_sig).unwrap();
        let exported = sig.to_sigbytes().unwrap();
        assert_eq!(raw_sig, exported);
    }

    #[test]
    fn validate_min_flevel() {
        // This signature contains a PCRE subsig, which should force a minimum
        // feature level of 81 per the `feature-level.txt` file.
        let raw_sig = br"TestSig;Engine:80-255;0;/foobar/".into();
        let (sig, sigmeta) = LogicalSig::from_sigbytes(&raw_sig).unwrap();
        assert_eq!(
            sig.validate(&sigmeta),
            Err(SigValidationError::SpecifiedMinFLevelTooLow {
                spec_min_flevel: 80,
                computed_min_flevel: 81,
                feature_set: sig.features().into(),
            })
        );
    }
}
