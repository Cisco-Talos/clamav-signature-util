use itertools::Itertools;
use std::convert::TryFrom;
use std::ops::{RangeInclusive, RangeToInclusive};
use std::str;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BodySigParseError {
    #[error("nothing following ? wildcard in low-nybble match")]
    ExpectingLowNyble,

    #[error("invalid char (code {0}) following ? at position {} in HexSignature")]
    InvalidCharAfterQuestionMark(u8, usize),

    #[error("no closing brace found for opening brace at position {0}")]
    MissingClosingBrace(usize),

    #[error("no closing parenthesis found for opening parenthesis at position {0}")]
    MissingClosingParen(usize),

    #[error("nesting is not permitted within alternate strings")]
    NestedParens,

    #[error("empty AnyByte range")]
    EmptyAnyByteRange,

    #[error("AnyByte range missing upper limit")]
    InvalidAnyByteRange,

    #[error("generic alternative strings may not be negated")]
    NegatedGenAlt,

    #[error("unsupported character class")]
    UnknownCharacterClass,

    #[error("no closing square bracket found for opening square bracket at position {0}")]
    MissingClosingBracket(usize),

    #[error("nothing following opening parenthesis to specify character class")]
    MissingCharacterClass,

    #[error("Invalid body signature")]
    InvalidBodySig,

    #[error(transparent)]
    FromHex(#[from] hex::FromHexError),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
}

#[derive(Debug)]
pub struct BodySig {
    // Just encode the raw data for now
    #[allow(dead_code)]
    matches: Vec<Match>,
    pub min_f_level: usize,
}

#[derive(Debug)]
pub enum Match {
    Literal(Vec<u8>),
    AnyBytes(AnyBytes),
    Mask { mask: u8, value: u8 },
    AnyByte,
    ByteRange(ByteRange),
    CharacterClass(CharacterClass),
    AlternateStrings(AlternateStrings),
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
        let start =
            str::from_utf8(parts.next().ok_or(BodySigParseError::EmptyAnyByteRange)?)?.parse()?;
        let end =
            str::from_utf8(parts.next().ok_or(BodySigParseError::InvalidAnyByteRange)?)?.parse()?;
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
pub enum ByteRange {
    // {n}
    Exact(usize),
    // {-n}
    ToInclusive(RangeToInclusive<usize>),
    // {n-}
    From(std::ops::RangeFrom<usize>),
    // {n-m}
    Inclusive(RangeInclusive<usize>),
    HexSig,
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

impl TryFrom<&[u8]> for ByteRange {
    type Error = BodySigParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if let Some(s) = value.strip_prefix(&[b'-']) {
            Ok(Self::ToInclusive(..=str::from_utf8(s)?.parse()?))
        } else if let Some(s) = value.strip_suffix(&[b'-']) {
            Ok(Self::From(str::from_utf8(s)?.parse()?..))
        } else if let Some((sn, sm)) = value.splitn(2, |b| *b == b'-').tuples().next() {
            Ok(Self::Inclusive(
                str::from_utf8(sn)?.parse()?..=str::from_utf8(sm)?.parse()?,
            ))
        } else {
            Ok(Self::Exact(str::from_utf8(value)?.parse()?))
        }
    }
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

impl TryFrom<&[u8]> for BodySig {
    type Error = BodySigParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut min_f_level = 0;
        // eprintln!("parsing {:?}", str::from_utf8(value).unwrap());
        let mut matches = vec![];
        let mut hex_bytes = vec![];
        let mut genbuf = vec![];
        let mut bytes = value.iter().enumerate();
        while let Some((pos, &byte)) = bytes.next() {
            match byte {
                b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => hex_bytes.push(byte),
                b'?' => {
                    // The context here depends on whether we're mid-byte
                    let high_nyble = if hex_bytes.len() % 2 == 1 {
                        hex_bytes.pop()
                    } else {
                        None
                    };
                    // Flush out the current literal, if necessary
                    if !hex_bytes.is_empty() {
                        matches.push(Match::Literal(hex::decode(&hex_bytes)?));
                        hex_bytes.clear();
                    }
                    let mut match_byte = [0u8; 1];
                    if let Some(high_nyble) = high_nyble {
                        // Yes, we're mid-byte -- this is a wildcard match on the high-nyble
                        hex::decode_to_slice(&[high_nyble, b'0'], &mut match_byte)?;
                        matches.push(Match::Mask {
                            mask: 0xf0,
                            value: match_byte[0],
                        });
                    } else {
                        // We're not mid-byte -- get another byte, and it'll be a low-nyble match
                        let (pos, &low_nyble) =
                            bytes.next().ok_or(BodySigParseError::ExpectingLowNyble)?;
                        matches.push(match low_nyble {
                            b'?' => Match::AnyByte,
                            b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                                hex::decode_to_slice(&[b'0', low_nyble], &mut match_byte)?;
                                Match::Mask {
                                    mask: 0x0f,
                                    value: match_byte[0],
                                }
                            }
                            c => {
                                return Err(BodySigParseError::InvalidCharAfterQuestionMark(c, pos))
                            }
                        })
                    }
                }
                other => {
                    if !hex_bytes.is_empty() {
                        matches.push(Match::Literal(hex::decode(&hex_bytes)?));
                        hex_bytes.clear();
                    }
                    match other {
                        b'*' => matches.push(Match::AnyBytes(AnyBytes::Infinite)),
                        b'{' => {
                            genbuf.clear();
                            // Consume until the closing brace is found
                            loop {
                                match bytes.next() {
                                    None => {
                                        return Err(BodySigParseError::MissingClosingBrace(pos))
                                    }
                                    Some((_, b'}')) => {
                                        matches.push(Match::ByteRange(ByteRange::try_from(
                                            &genbuf[..],
                                        )?));
                                        break;
                                    }
                                    Some((_, &byte)) => genbuf.push(byte),
                                }
                            }
                        }
                        // TODO: negation. Ugh -- applies only to character classes?
                        b'!' | b'(' => {
                            let negated = other == b'!';
                            // Character class or Alternate strings
                            // Consume until the closing parenthesis is found
                            genbuf.clear();
                            loop {
                                match bytes.next() {
                                    None => {
                                        return Err(BodySigParseError::MissingClosingParen(pos))
                                    }
                                    Some((_, b'(')) => {
                                        // This is only expected if this clause was negated
                                        if !negated {
                                            return Err(BodySigParseError::NestedParens);
                                        }
                                    }
                                    Some((_, b')')) => {
                                        matches.push(match genbuf.get(0) {
                                            None => panic!(), // empty expression
                                            Some(&c) => {
                                                if genbuf.len() > 1 {
                                                    Match::AlternateStrings(
                                                        AlternateStrings::try_from((
                                                            negated,
                                                            &genbuf[..],
                                                        ))?,
                                                    )
                                                } else {
                                                    Match::CharacterClass(CharacterClass::try_from(
                                                        c,
                                                    )?)
                                                }
                                            }
                                        });
                                        break;
                                    }
                                    Some((_, &byte)) => genbuf.push(byte),
                                }
                            }
                        }
                        b'[' => {
                            genbuf.clear();
                            loop {
                                match bytes.next() {
                                    None => {
                                        return Err(BodySigParseError::MissingClosingBracket(pos))
                                    }
                                    Some((_, b']')) => {
                                        matches.push(Match::AnyBytes(AnyBytes::try_from(
                                            &genbuf[..],
                                        )?));
                                        min_f_level = min_f_level.max(27);
                                        break;
                                    }
                                    Some((_, &byte)) => {
                                        genbuf.push(byte);
                                    }
                                }
                            }
                        }
                        _ => return Err(BodySigParseError::InvalidBodySig),
                    }
                }
            }
        }
        // Body-based signatures are hex-encoded
        // eprintln!("bodysig = {:?}", str::from_utf8(value).unwrap());
        Ok(BodySig {
            matches,
            min_f_level,
        })
    }
}
