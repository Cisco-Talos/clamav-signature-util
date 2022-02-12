pub mod expression;
pub mod subsig;
pub mod targetdesc;

use self::{
    expression::LogExprParseError,
    subsig::{SubSigModifier, SubSigParseError},
    targetdesc::TargetDescParseError,
};
use super::{bodysig::BodySigParseError, ParseError, Signature};
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
    #[allow(dead_code)]
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

    #[error("parsing subsig {0}: {1}")]
    SubSigParse(usize, SubSigParseError),
}

impl Signature for LogicalSig {
    fn name(&self) -> &str {
        &self.name
    }

    fn features(&self) -> crate::feature::FeatureSet {
        // Collect all the features required by the various subsigs
        self.sub_sigs
            .iter()
            .map(|ss| ss.features())
            .flatten()
            .into()
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
                subsig::parse_bytes(subsig_bytes, modifier)
                    .map_err(|e| LogicalSigParseError::SubSigParse(subsig_no, e))?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_sig() {
        let bytes = concat!(
            "PUA.Email.Phishing.FedEx-1;Engine:51-255,Target:4;(0&1)&(2|3);",
            "697320656e636c6f73656420746f20746865206c6574746572;",
            "636f6d70656e736174696f6e2066726f6d20796f7520666f722069742773206b656570696e67;",
            "6f637465742d73747265616d3b6e616d653d2246656445785f4c6162656c5f49445f4f72646572;",
            "6f637465742d73747265616d3b6e616d653d224c6162656c5f50617263656c5f46656445785f"
        )
        .as_bytes();
        let sig = LogicalSig::try_from(bytes).unwrap();
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
}
