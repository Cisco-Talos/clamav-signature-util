pub mod expression;
pub mod subsig;
pub mod targetdesc;

use self::{
    expression::LogExprParseError,
    subsig::{ByteCmpSubSig, MacroSubSig, PCRESubSig},
    targetdesc::TargetDescParseError,
};
use super::{
    bodysig::BodySigParseError,
    ext::{ExtendedSig, Offset, OffsetPos},
    targettype::TargetType,
    ParseError, Signature,
};
use crate::signature::bodysig::BodySig;
use std::str;
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
    sub_sigs: Vec<Box<dyn SubSig>>,
}

#[derive(Debug, Error)]
pub enum LogicalSigParseError {
    #[error("parsing body signature index {0}: {1}")]
    BodySigParse(usize, BodySigParseError),

    #[error("empty")]
    Empty,

    #[error("missing Expression field")]
    MissingExpression,

    #[error("invalid logical expression: {0}")]
    LogExprParse(#[from] LogExprParseError),

    #[error("missing TargetDescriptionBlock field")]
    MissingTargetDesc,

    #[error("parsing TargetDesc: {0}")]
    TargetDesc(#[from] TargetDescParseError),
}

#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub struct SubSigModifier {
    case_insensitive: bool,
    widechar: bool,
    match_fullword: bool,
    ascii: bool,
}

impl Signature for LogicalSig {
    fn name(&self) -> &str {
        &self.name
    }

    fn feature_levels(&self) -> (usize, Option<usize>) {
        (51, None)
    }
}

/// Search from the end of a subsignature to find a modifier of the form "::xxx".
/// 
/// If found, returns the modifier and a subslice (without the modifier).
/// 
/// If any unknown modifiers are found or the delimiter is missing, returns None
/// and the original slice.
fn find_modifier(haystack: &[u8]) -> (Option<SubSigModifier>, &[u8]) {
    let mut modifier = SubSigModifier::default();

    enum State {
        ReadModifier,
        ReadDelimiter,
    }

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

impl TryFrom<&[u8]> for LogicalSig {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut fields = data.split(|b| *b == b';');

        let name = str::from_utf8(fields.next().ok_or(ParseError::MissingName)?)
            .map_err(ParseError::NameNotUnicode)?
            .into();
        let target_desc = fields
            .next()
            .ok_or(LogicalSigParseError::MissingTargetDesc)?
            .try_into()
            .map_err(LogicalSigParseError::TargetDesc)?;
        let expression = fields
            .next()
            .ok_or(LogicalSigParseError::MissingExpression)?
            .try_into()
            .map_err(LogicalSigParseError::LogExprParse)?;
        let mut sub_sigs = vec![];
        for (subsig_no, subsig_bytes) in fields.enumerate() {
            let (modifier, subsig_bytes) = find_modifier(subsig_bytes);
            sub_sigs.push(
                if let Ok(sig) = MacroSubSig::from_bytes(subsig_bytes, modifier) {
                    Box::new(sig) as Box<dyn SubSig>
                } else if let Ok(sig) = ByteCmpSubSig::from_bytes(subsig_bytes, modifier) {
                    Box::new(sig) as Box<dyn SubSig>
                } else if let Ok(sig) = PCRESubSig::from_bytes(subsig_bytes, modifier) {
                    Box::new(sig) as Box<dyn SubSig>
                } else {
                    // Figure out if this seems to have an offset. If so, parse it, and slice down into the remaining bodysig
                    let (offset, bodysig_bytes) =
                        if let Some(pos) = subsig_bytes.iter().position(|&b| b == b':') {
                            let parts = subsig_bytes.split_at(pos);
                            (Offset::try_from(parts.0)?, &parts.1[1..])
                        } else {
                            (Offset::Normal(OffsetPos::Any), subsig_bytes)
                        };
                    let body_sig = BodySig::try_from(bodysig_bytes)
                        .map_err(|e| LogicalSigParseError::BodySigParse(subsig_no, e))?;
                    let sig = ExtendedSig {
                        name: None,
                        target_type: TargetType::Any,
                        offset,
                        body_sig: Some(body_sig),
                    };
                    Box::new(sig) as Box<dyn SubSig>
                },
            )
        }

        Ok(Self {
            name,
            target_desc,
            expression,
            sub_sigs,
        })
    }
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
