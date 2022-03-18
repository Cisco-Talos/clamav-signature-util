use super::BodySigParseError;
use crate::{
    feature::EngineReq,
    sigbytes::{AppendSigBytes, SigBytes},
    util::{parse_number_dec, Range},
};
use std::{fmt::Write, ops::RangeInclusive};

pub enum Match {
    /// A series of bytes that must match exactly
    Literal(Vec<u8>),

    /// Alternate string.  Matches on any of two or more strings.
    AlternateStrings(AlternateStrings),

    // Many any single byte, represented as `??` in signatures
    AnyByte,

    /// A range of bytes that are ignored, but anchored to a neighboring match.
    /// This is represented in signatures as `[n-m]`
    AnyBytes(AnyBytes),

    /// A range of bytes that are ignored, but anchored to neighboring matches
    /// This is represented in signatures as `*` (for any size); or as `{-n}`,
    /// `{n-}` or `{n-m}` to match inclusive or open-ended ranges.
    ByteRange(Range<usize>),

    /// Other outlying match types (e.g., boundaries, ASCII characgter class,
    /// etc.)
    CharacterClass(CharacterClass),

    /// A match on a portion of a byte.  These are specified in signatures as
    /// `x?` or `?x`, wildcarding either the high or low nyble of the byte. As
    /// such, the computed mask will be either `0xf0` or `0x0f` depending on the
    /// position of the `?`.
    Mask {
        mask: u8,
        value: u8,
    },
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

impl AppendSigBytes for Match {
    fn append_sigbytes(&self, s: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        match self {
            Match::Literal(bytes) => {
                // Is this any faster than using hex::encode (with its allocation)?
                for byte in bytes {
                    write!(s, "{byte:02x}")?
                }
            }
            Match::AlternateStrings(astrs) => astrs.append_sigbytes(s)?,
            Match::AnyByte => s.write_str("??")?,
            Match::AnyBytes(anybytes) => anybytes.append_sigbytes(s)?,
            Match::ByteRange(range) => range.append_sigbytes(s)?,
            Match::CharacterClass(cc) => cc.append_sigbytes(s)?,
            Match::Mask { mask, value } => match mask {
                0x0f => write!(s, "?{:x}", value & mask)?,
                0xf0 => write!(s, "{:x}?", (value & mask) >> 4)?,
                // There aren't any constructors or syntax that provide for any
                // other variations.
                _ => unreachable!(),
            },
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum AnyBytes {
    Infinite,
    Range(RangeInclusive<usize>),
}

impl AppendSigBytes for AnyBytes {
    fn append_sigbytes(&self, s: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        match self {
            AnyBytes::Infinite => s.write_char('*')?,
            AnyBytes::Range(range) => write!(s, "[{}-{}]", range.start(), range.end())?,
        }
        Ok(())
    }
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
            let element = hex::decode(element)?;
            if !elements_differ_in_size {
                match last_size {
                    None => last_size = Some(element.len()),
                    Some(size) => elements_differ_in_size = size != element.len(),
                }
            }
            ranges.push(last_start..=last_start + element.len());
            last_start += element.len();
            data.extend(element);
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

impl AppendSigBytes for AlternateStrings {
    fn append_sigbytes(&self, s: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        match self {
            AlternateStrings::FixedWidth {
                negated,
                width,
                data,
            } => {
                if *negated {
                    s.write_char('!')?;
                }
                for (i, astr) in data.chunks_exact(*width).enumerate() {
                    s.write_char(if i == 0 { '(' } else { '|' }).unwrap();
                    for byte in astr {
                        write!(s, "{byte:02x}")?
                    }
                }
            }
            AlternateStrings::VariableWidth { ranges, data } => {
                for (i, range) in ranges.iter().enumerate() {
                    s.write_char(if i == 0 { '(' } else { '|' }).unwrap();
                    let data = data.get(range.clone()).unwrap();
                    for byte in data {
                        write!(s, "{byte:02x}")?
                    }
                }
            }
        }
        s.write_char(')')?;
        Ok(())
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

impl AppendSigBytes for CharacterClass {
    fn append_sigbytes(&self, s: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        match self {
            CharacterClass::WordBoundary => s.write_str("(B)")?,
            CharacterClass::LineOrFileBoundary => s.write_str("(L)")?,
            CharacterClass::NonAlphaChar => s.write_str("(W)")?,
        }
        Ok(())
    }
}

impl EngineReq for Match {}
