pub mod bsmatch;

use crate::util::{ParseNumberError, Range, RangeParseError, SigChar};
use bsmatch::{AlternateStrings, AnyBytes, CharacterClass, Match};
use std::convert::TryFrom;
use thiserror::Error;

/// Body signature.  This is an element of both Extended and Logical signatures,
/// and contains byte match patterns.
#[derive(Debug)]
pub struct BodySig {
    // Just encode the raw data for now
    #[allow(dead_code)]
    matches: Vec<Match>,
    pub min_f_level: usize,
}

// TODO: annotate these errors with their positions within the signature
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

    #[error("invalid character at pos {0}: {1}")]
    InvalidCharacter(usize, SigChar),

    #[error("decoding hex-encoded value: {0}")]
    FromHex(#[from] hex::FromHexError),

    #[error("parsing AnyBytes start: {0}")]
    AnyBytesStart(ParseNumberError<usize>),

    #[error("parsing AnyBytes end: {0}")]
    AnyBytesEnd(ParseNumberError<usize>),

    #[error("AnyBytes range start > end ({0}-{1})")]
    AnyBytesRangeOrder(usize, usize),

    #[error("parsing ByteRange: {0}")]
    ByteRange(RangeParseError<usize>),
}

impl TryFrom<&[u8]> for BodySig {
    type Error = BodySigParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut min_f_level = 0;
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
                                        matches.push(Match::ByteRange(
                                            Range::try_from(&genbuf[..])
                                                .map_err(BodySigParseError::ByteRange)?,
                                        ));
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
                        c => return Err(BodySigParseError::InvalidCharacter(pos, c.into())),
                    }
                }
            }
        }
        if !hex_bytes.is_empty() {
            matches.push(Match::Literal(hex_bytes))
        }
        // Body-based signatures are hex-encoded
        Ok(BodySig {
            matches,
            min_f_level,
        })
    }
}
