use super::BodySigParseError;
use crate::{
    feature::FeatureSet,
    util::{parse_number_dec, Range},
};
use std::ops::RangeInclusive;

pub enum Match {
    Literal(Vec<u8>),
    AnyBytes(AnyBytes),
    Mask { mask: u8, value: u8 },
    AnyByte,
    ByteRange(Range<usize>),
    CharacterClass(CharacterClass),
    AlternateStrings(AlternateStrings),
}

impl std::fmt::Debug for Match {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Literal(arg0) => write!(f, r#"Literal(hex!("{}"))"#, hex::encode(arg0)),
            Self::AnyBytes(arg0) => f.debug_tuple("AnyBytes").field(arg0).finish(),
            Self::Mask { mask, value } => f
                .debug_struct("Mask")
                .field("mask", mask)
                .field("value", value)
                .finish(),
            Self::AnyByte => write!(f, "AnyByte"),
            Self::ByteRange(arg0) => f.debug_tuple("Range").field(arg0).finish(),
            Self::CharacterClass(arg0) => f.debug_tuple("CharacterClass").field(arg0).finish(),
            Self::AlternateStrings(arg0) => f.debug_tuple("AlternateStrings").field(arg0).finish(),
        }
    }
}

#[derive(Debug)]
pub enum AnyBytes {
    Infinite,
    Range(RangeInclusive<usize>),
}

impl TryFrom<&[u8]> for AnyBytes {
    type Error = BodySigParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut parts = value.splitn(2, |&b| b == b'-');
        let start = parse_number_dec(parts.next().ok_or(BodySigParseError::EmptyAnyByteRange)?)
            .map_err(BodySigParseError::AnyBytesStart)?;
        let end = parse_number_dec(parts.next().ok_or(BodySigParseError::InvalidAnyByteRange)?)
            .map_err(BodySigParseError::AnyBytesEnd)?;
        if start > end {
            return Err(BodySigParseError::AnyBytesRangeOrder(start, end));
        }
        Ok(AnyBytes::Range(start..=end))
    }
}

#[derive(Debug)]
pub enum AlternateStrings {
    FixedWidth {
        negated: bool,
        width: usize,
        data: Vec<u8>,
    },
    VariableWidth {
        ranges: Vec<RangeInclusive<usize>>,
        data: Vec<u8>,
    },
}

impl TryFrom<(bool, &[u8])> for AlternateStrings {
    type Error = BodySigParseError;

    fn try_from(value: (bool, &[u8])) -> Result<Self, Self::Error> {
        let (negated, value) = value;
        debug_assert!(!value.is_empty());

        let mut ranges = vec![];
        let mut data = vec![];
        let mut last_start = 0;
        let mut last_size = None;
        let mut elements_differ_in_size = false;
        for element in value.split(|&b| b == b'|') {
            if !elements_differ_in_size {
                match last_size {
                    None => last_size = Some(element.len()),
                    Some(size) => elements_differ_in_size = size != element.len(),
                }
            }
            ranges.push(last_start..=last_start + element.len());
            last_start += element.len();
            data.extend_from_slice(element);
        }

        if elements_differ_in_size {
            if negated {
                Err(BodySigParseError::NegatedGenAlt)
            } else {
                Ok(AlternateStrings::VariableWidth { ranges, data })
            }
        } else {
            // Negation gets fixed by the receiver
            Ok(AlternateStrings::FixedWidth {
                negated,
                width: last_size.unwrap(),
                data,
            })
        }
    }
}

#[derive(Debug)]
pub enum CharacterClass {
    // B
    WordBoundary,
    // L
    LineOrFileBoundary,
    // W
    NonAlphaChar,
}

impl TryFrom<u8> for CharacterClass {
    type Error = BodySigParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            b'B' => CharacterClass::WordBoundary,
            b'L' => CharacterClass::LineOrFileBoundary,
            b'W' => CharacterClass::NonAlphaChar,
            _ => return Err(BodySigParseError::UnknownCharacterClass),
        })
    }
}

impl Match {
    pub fn features(&self) -> FeatureSet {
        FeatureSet::None
    }
}
