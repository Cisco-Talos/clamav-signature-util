#[cfg(test)]
mod tests;

use super::{BodySig, CharacterClass};
use crate::{
    sigbytes::SigChar,
    signature::bodysig::{
        altstr::AlternativeStrings,
        pattern::{ByteAnchorSide, MatchByte, MatchBytes, MatchMask, Pattern},
        PatternModifier,
    },
    util::{hex_nyble, Position, Range},
};
use enumflags2::BitFlags;
use std::ops::RangeInclusive;
use strum_macros::Display;
use thiserror::Error;
use tinyvec::TinyVec;

// The minimum number of bytes that must be adjacent to the wildcard portion of
// an anchored-byte match
const ANCHORED_BYTE_MATCH_STRING_MIN_BYTES: usize = 2;
// The maximum value of either bound in an anchored-byte match wildcard range
const ANCHORED_BYTE_RANGE_MAX: usize = 32;

// These are defined here to prevent IDEs from getting confused on open/close
// braces in match expressions (lookin' at you: VSCode), but also define the
// entire special character set.
const ASTERISK: u8 = b'*';
const BANG: u8 = b'!';
const BRACKET_LEFT: u8 = b'[';
const BRACKET_RIGHT: u8 = b']';
const CURLY_LEFT: u8 = b'{';
const CURLY_RIGHT: u8 = b'}';
const MINUS_SIGN: u8 = b'-';
const PAREN_LEFT: u8 = b'(';
const PAREN_RIGHT: u8 = b')';
const PIPE: u8 = b'|';
const QUESTION_MARK: u8 = b'?';

#[derive(Debug, Error, PartialEq)]
pub enum BodySigParseError {
    /// The anchored-byte expression at the end of a pattern was incomplete
    #[error("expecting single byte {pos} after anchored-byte expression starting {start_pos}")]
    AnchoredByteExpectingSingleByte { start_pos: Position, pos: Position },

    /// The lower range bound for the wildcard portion of an anchored-byte match
    /// exceeds the maximum
    #[error("invalid/missing lower bound {found} for anchored-byte wildcard range opened {bracket_pos} (must be <={ANCHORED_BYTE_RANGE_MAX})")]
    AnchoredByteInvalidLowerBound { bracket_pos: Position, found: usize },

    /// The upper range bound for the wildcard portion of an anchored-byte match
    /// exceeds the maximum
    #[error("invalid/missing upper bound {found} for anchored-byte wildcard range opened {bracket_pos} (must be <={ANCHORED_BYTE_RANGE_MAX} and greater than lower bound {lower})")]
    AnchoredByteInvalidUpperBound {
        bracket_pos: Position,
        found: usize,
        lower: usize,
    },

    /// Anchored-byte patterns must have content on both side of the
    /// bracketed wildcard range
    #[error("no bytes left-adjacent to bracket expression ending {pos}")]
    AnchoredByteNoLeftBytes { pos: Position },

    /// An anchored-byte match must have a single byte on one side of the
    /// wildcard range
    #[error("missing single byte on one side of anchored-byte expression starting {start_pos}")]
    AnchoredByteMissingSingleByte { start_pos: Position },

    /// An anchored-byte match must include a string of minimum size
    #[error("match string for anchored-byte expression starting {start_pos} too small (min {ANCHORED_BYTE_MATCH_STRING_MIN_BYTES} bytes)")]
    AnchoredByteStringTooSmall { start_pos: Position },

    // A square bracket opened at the specified position was not closed
    #[error("bracket opened {start_pos} not closed")]
    BracketNotClosed { start_pos: Position },

    /// Anchored-byte bracket expressions must contain both bounds
    #[error("bracket range opened {start_pos} missing lower bound")]
    BracketRangeMissingLowerBound { start_pos: Position },

    /// Anchored-byte bracket expressions must contain both bounds
    #[error("bracket range opened {start_pos} missing bound(s)")]
    BracketRangeEmpty { start_pos: Position },

    /// Anchored-byte bracket expressions may contain only decimal bounds and an
    /// intermediate hyphen
    #[error("unexpected character {found} {pos} within bracket range")]
    BracketRangeUnexpectedChar { pos: Position, found: SigChar },

    /// Character class is missing its closing parenthesis
    #[error("expected closing parenthesis for character class {pos}, found {found}")]
    CharClassExpectCloseParen { pos: Position, found: SigChar },

    /// Character classes must modify a neighboring string
    #[error("no string adjacent to character class/pattern modifier ending {pos}")]
    CharClassNothingAdjacent { pos: Position },

    /// A character class is missing its closing parenthesis
    #[error("character class opened {start_pos} not closed")]
    CharClassUnterminated { start_pos: Position },

    /// A curly brace opened at the specified position was not closed
    #[error("curly brace opened {start_pos} not closed")]
    CurlyBraceNotClosed { start_pos: Position },

    /// A decimal value is too large to be parsed
    #[error("decimal range value overflowed {pos}")]
    DecimalOverflow { pos: Position },

    /// Signature contains no patterns
    #[error("contains no patterns")]
    Empty,

    /// An empty set of parantheses was found.  Parentheses should contain either
    /// a character class, or a set of alternative strings
    #[error("nothing specified within parentheses opened {pos}")]
    EmptyParens { pos: Position },

    /// An empty brace expression (wildcard byte range) was found
    #[error("empty brace expression opened {start_pos}")]
    EmptyBraces { start_pos: Position },

    /// The parser was expecting the low nyble of a hex-encoded byte, but found
    /// something else
    #[error("expected hex/nyble character {pos}, found {found:?}")]
    ExpectingLowNyble {
        pos: Position,
        found: Option<SigChar>,
    },

    /// The pattern began with an unsized element (a wildcard or fixed byte range
    /// exceeding 128 bytes)
    #[error("may not begin with a wildcard-type pattern (found {pattern:?})")]
    LeadingWildcard { pattern: Pattern },

    /// There must be at least static byte pattern of length 2 or more
    #[error(
        "string starting {start_pos} does not contain static byte pattern of length 2 or greater"
    )]
    MinStaticBytes { start_pos: Position },

    // A generic alternative string set may not be negated
    #[error("generic alternative strings starting {start_pos} negated")]
    NegatedGenericAltStr { start_pos: Position },

    // Negation (`!`) must be followed by a character class or set of alternative
    // strings
    #[error("unexpected character {found} {pos} following negation")]
    NegateUnexpectedChar { pos: Position, found: SigChar },

    // The signature ends with a negation. Negation must be applied to a character
    // class or alternative string set
    #[error("no character class or alternative string set follows negation (`!`)")]
    NegationTargetless,

    /// Only a hyphen (`-`) was found within a brace expression
    #[error("no bounds specified in brace expression opened {start_pos}")]
    NoBraceBounds { start_pos: Position },

    /// Wildcard range bounds must be in order, with the lower bound on the left
    #[error("range {start_pos} has inverted bounds ({end} < {start})")]
    RangeBoundsInverted {
        start_pos: Position,
        start: usize,
        end: usize,
    },

    /// The pattern ended with an unsized element (a wildcard or fixed byte range
    /// exceeding 128 bytes)
    #[error("may not end with a wildcard-type pattern (found {pattern:?})")]
    TrailingUnsizedPattern { pattern: Pattern },

    /// A character was found that doesn't represent any known matching syntax
    #[error("unexpected character {found} {pos} within {context}")]
    UnexpectedChar {
        context: Context,
        pos: Position,
        found: SigChar,
    },

    /// A closing parenthesis was found that has no matching opening parenthesis
    #[error("unmatched closing parenthesis {pos}")]
    UnmatchedClosingParen { pos: Position },

    /// A pipe (`|`) charactr was found outside of an alternative string set
    #[error("pipe (`|`) character not expected {pos}")]
    UnexpectedPipeChar { pos: Position },
}

enum State {
    // Initial state
    HighNyble,
    // Expecting low hex-encoded nyble of a byte
    LowNyble,
    // At start of a {curly-brace} expression
    CurlyBraceLower,
    // Expecting the upper value of a curly-brace range
    CurlyBraceUpper,

    // Anchored-byte range parts
    BracketLower,
    BracketUpper,

    // In expression following `!`
    Negate,

    // Obviously in a character class
    CharacterClass,
}

/// Various contexts for error reporting
#[derive(Debug, PartialEq, Display)]
pub enum Context {
    #[strum(serialize = "curly-brace range")]
    CurlyBraceRange,

    #[strum(serialize = "pattern")]
    Pattern,
}

#[derive(Default)]
struct ParseContext {
    // Accumulator for hex-encoded byte being parsed
    cur_byte: u8,

    // Nyble mask for current hex-encoded byte
    mask: MatchMask,

    // Value accumulator for decimal range bounds
    dec_value: Option<usize>,
    // Current range being parsed
    cur_range: Option<Range<usize>>,

    // The current set of patterns
    patterns: Vec<Pattern>,

    // Bytes currently contributing to a match
    match_bytes: TinyVec<[MatchByte; 128]>,
    // Location of the first of the current set of match bytes (outside of alternatives)
    match_bytes_start: usize,
    // The location of the first full byte match. This resets when a nyble wildcard is found
    match_bytes_static_range: Option<(usize, usize)>,
    // The locations of sufficiently-large static strings within the match bytes
    match_bytes_static_ranges: TinyVec<[(usize, usize); 4]>,
    // Accumulated pattern modifier for the current set of match bytes
    pattern_modifier: BitFlags<PatternModifier>,

    // Sub-context for a pending anchored byte
    pending_anchored_byte: Option<PendingAnchoredByte>,
    // Sub-context for a parenthetical expression
    paren_cxt: Option<ParentheticalContext>,

    // Whether negation is in effect (applies to generic alternative strings and match boundaries)
    negated: bool,

    // Location of the most-recent left bracket
    left_bracket_pos: usize,

    // Location of the most-recent left curly brace
    left_brace_pos: usize,

    // Location of the most-recent left parenthesis
    left_paren_pos: usize,
}

impl ParseContext {
    // Append the current accumulation of match bytes into the pattern set
    fn flush_match_bytes(&mut self) -> Result<(), BodySigParseError> {
        if let Some(pa) = &mut self.paren_cxt {
            if pa.flushed {
                return Ok(());
            } else {
                pa.flushed = true;
            }
        }
        if !self.match_bytes.is_empty() {
            self.push_pattern(Pattern::String {
                match_bytes: MatchBytes {
                    bytes: self.match_bytes.to_vec(),
                },
                pattern_modifier: self.pattern_modifier,
            })?;
            self.match_bytes.clear();
            self.pattern_modifier = Default::default();
        }

        Ok(())
    }

    fn flush_static_range(&mut self) {
        if let Some((start, end)) = self.match_bytes_static_range.take() {
            dbg!(start, end);
            if end - start >= 2 {
                self.match_bytes_static_ranges.push((start, end));
            }
        } else {
            dbg!();
        }
    }

    fn handle_anchored_byte_range(&mut self, pos: usize) -> Result<State, BodySigParseError> {
        if let Some(Range::From(std::ops::RangeFrom { start })) = self.cur_range.take() {
            let end = self.dec_value.take().unwrap_or(start);

            if !(1..=ANCHORED_BYTE_RANGE_MAX).contains(&end) || end < start {
                return Err(BodySigParseError::AnchoredByteInvalidUpperBound {
                    bracket_pos: self.left_bracket_pos.into(),
                    found: end,
                    lower: start,
                });
            }
            let range = (start as u8)..=(end as u8);
            // Now, determine if the current match_bytes contains one element
            // If it does, move it into this bracket-match structure as the anchor byte. The next series of bytes will
            // If it contains more than one
            match self.match_bytes.len() {
                0 => return Err(BodySigParseError::AnchoredByteNoLeftBytes { pos: pos.into() }),
                1 => {
                    // This is the anchor byte
                    self.pending_anchored_byte = Some(PendingAnchoredByte::HaveByte {
                        start_pos: self.left_bracket_pos - 2,
                        byte: self.match_bytes.pop().unwrap(),
                        range,
                    });
                }
                len => {
                    self.pending_anchored_byte = Some(PendingAnchoredByte::HaveString {
                        start_pos: self.left_bracket_pos - len * 2,
                        string: self.match_bytes.to_vec().into(),
                        range,
                    });
                    self.match_bytes.clear();
                }
            }
            Ok(State::HighNyble)
        } else {
            Err(BodySigParseError::BracketRangeEmpty {
                start_pos: self.left_bracket_pos.into(),
            })
        }
    }

    // Handle the closure of a character class
    #[inline]
    fn handle_cc_close(&mut self) -> State {
        let pa = self.paren_cxt.take().unwrap();
        if let Some(character_class) = &pa.character_class {
            // If this was the 'B' character class, the partial
            // byte value associated with it will be discarded
            // when the state transitions back to HighNyble.

            // Assign this character class and the current negation to the correct side.
            // The assumption is left if match_bytes is empty.
            self.pattern_modifier |=
                character_class.pattern_modifier(self.match_bytes.is_empty(), self.negated);
            self.negated = false;
        }
        State::HighNyble
    }

    // This function is called whenever the state is about to transition
    // from the default state due to finding a non-hex or non-nyble-wildcard
    // ('?') character
    fn handle_non_matchbyte(
        &mut self,
        pos_and_byte: Option<(usize, u8)>,
    ) -> Result<State, BodySigParseError> {
        // Check to see if we were handling the other side of an anchored byte first
        if let Some(pending_anchored_byte) = self.pending_anchored_byte.take() {
            match pending_anchored_byte {
                PendingAnchoredByte::HaveByte {
                    start_pos,
                    byte,
                    range,
                } => {
                    if self.match_bytes.len() < ANCHORED_BYTE_MATCH_STRING_MIN_BYTES {
                        return Err(BodySigParseError::AnchoredByteStringTooSmall {
                            start_pos: start_pos.into(),
                        });
                    }
                    self.push_pattern(Pattern::AnchoredByte {
                        anchor_side: ByteAnchorSide::Left,
                        byte,
                        range,
                        string: self.match_bytes.to_vec().into(),
                    })
                    // There are no failures currently possible here, so
                    // `.unwrap()` to make code coverage happy.
                    .unwrap();
                    self.match_bytes.clear();
                }
                PendingAnchoredByte::HaveString {
                    start_pos,
                    string,
                    range,
                } => {
                    if let Some(&byte) = self.match_bytes.first() {
                        if self.match_bytes.len() > 1 {
                            return Err(BodySigParseError::AnchoredByteMissingSingleByte {
                                start_pos: start_pos.into(),
                            });
                        }
                        self.push_pattern(Pattern::AnchoredByte {
                            anchor_side: ByteAnchorSide::Right,
                            byte,
                            range,
                            string,
                        })
                        // There are no failures currently possible here, so
                        // `.unwrap()` to make code coverage happy.
                        .unwrap();
                    } else {
                        return Err(BodySigParseError::AnchoredByteExpectingSingleByte {
                            start_pos: (self.left_bracket_pos - string.len() * 2).into(),
                            pos: pos_and_byte.map(|(pos, _)| pos).into(),
                        });
                    }
                }
            }
            self.match_bytes.clear();
        }

        if let Some((pos, byte)) = pos_and_byte {
            // Any other character changes state
            match byte {
                ASTERISK => {
                    // TODO: return error if wildcard begins signature
                    self.flush_match_bytes().unwrap();
                    self.push_pattern(Pattern::Wildcard)?;
                    Ok(State::HighNyble)
                }
                CURLY_LEFT => {
                    self.left_brace_pos = pos;
                    self.dec_value = None;
                    Ok(State::CurlyBraceLower)
                }
                BRACKET_LEFT => {
                    self.left_bracket_pos = pos;
                    self.dec_value = None;
                    Ok(State::BracketLower)
                }
                PAREN_LEFT => {
                    self.flush_match_bytes()?;
                    self.left_paren_pos = pos;
                    self.paren_cxt = Some(ParentheticalContext {
                        start_pos: pos,
                        ..ParentheticalContext::default()
                    });
                    Ok(State::HighNyble)
                }
                BANG => Ok(State::Negate),
                PIPE => {
                    if let Some(pa) = &mut self.paren_cxt {
                        pa.push_alternative_string(&mut self.match_bytes, false)?;
                        Ok(State::HighNyble)
                    } else {
                        Err(BodySigParseError::UnexpectedPipeChar { pos: pos.into() })
                    }
                }
                PAREN_RIGHT => {
                    if let Some(pa) = &mut self.paren_cxt.take() {
                        pa.push_alternative_string(&mut self.match_bytes, true)?;
                        let first_range = pa.ranges.first().unwrap();
                        if pa.is_generic {
                            self.push_pattern(Pattern::AlternativeStrings(
                                AlternativeStrings::Generic {
                                    data: pa.astr_data.to_vec().into(),
                                    ranges: pa.ranges.to_vec(),
                                },
                            ))?;
                        } else {
                            // + 1 here to account for the fact that
                            // inclusive ranges reference the upper *index*
                            let width = first_range.end;
                            self.push_pattern(Pattern::AlternativeStrings(
                                AlternativeStrings::FixedWidth {
                                    negated: self.negated,
                                    width,
                                    data: pa.astr_data.to_vec().into(),
                                },
                            ))
                            // There are no failures currently possible here, so
                            // `.unwrap()` to make code coverage happy.
                            .unwrap();
                        }
                        self.negated = false;
                        Ok(State::HighNyble)
                    } else {
                        Err(BodySigParseError::UnmatchedClosingParen { pos: pos.into() })
                    }
                }
                other => Err(BodySigParseError::UnexpectedChar {
                    context: Context::Pattern,
                    pos: pos.into(),
                    found: other.into(),
                }),
            }
        } else {
            Ok(State::HighNyble)
        }
    }

    // Contribute a byte to the current set of match bytes
    //
    // Note that `start_pos` should be set to the location of the *high* nyble or the
    // opening curly brace (for small multi-byte wildcards) so that error reporting
    // is correct.
    fn push_matchbyte(&mut self, mb: MatchByte, start_pos: usize) -> Result<(), BodySigParseError> {
        if self.paren_cxt.is_none() && self.match_bytes.is_empty() {
            self.match_bytes_start = start_pos;
        }
        self.match_bytes.push(mb);
        if let Some(paren_cxt) = &mut self.paren_cxt {
            if !matches!(mb, MatchByte::Full(_)) {
                paren_cxt.is_generic = true;
            }
        } else if matches!(mb, MatchByte::Full(_)) {
            let len = self.match_bytes.len();
            // Set a default, or replace the second value with the new bound
            self.match_bytes_static_range
                .get_or_insert((len - 1, len))
                .1 = len;
        } else {
            self.flush_static_range();
        }

        Ok(())
    }

    // Push a new match criteria with error checking
    fn push_pattern(&mut self, pattern: Pattern) -> Result<(), BodySigParseError> {
        match &pattern {
            Pattern::String { .. } => {
                self.flush_static_range();
                if self.match_bytes_static_ranges.is_empty() {
                    // This occurs when the string contained no static bytes at all
                    return Err(BodySigParseError::MinStaticBytes {
                        start_pos: self.match_bytes_start.into(),
                    });
                } else {
                    // Just flush these for now, but they might be worth attaching to the string later
                    self.match_bytes_static_range = None;
                    self.match_bytes_static_ranges.clear();
                }
            }
            // No additional error checking required for AnchoredByte
            Pattern::AnchoredByte { .. } => (),
            Pattern::AlternativeStrings(altstr) => {
                match altstr {
                    // No additional checking required
                    AlternativeStrings::FixedWidth { .. } => (),
                    AlternativeStrings::Generic { .. } => {
                        if self.negated {
                            return Err(BodySigParseError::NegatedGenericAltStr {
                                start_pos: self.left_paren_pos.into(),
                            });
                        }
                    }
                }
            }
            Pattern::ByteRange(_) | Pattern::Wildcard => {
                // Body signatures must begin with a sized pattern
                if self.patterns.is_empty() {
                    return Err(BodySigParseError::LeadingWildcard { pattern });
                }
            }
        }

        self.patterns.push(pattern);
        Ok(())
    }

    // Contribute a digit to an accumulating decimal value
    #[inline]
    fn update_dec_value(&mut self, byte: u8, pos: usize) -> Result<(), BodySigParseError> {
        self.dec_value = Some(
            self.dec_value
                .unwrap_or_default()
                .checked_mul(10)
                .ok_or(BodySigParseError::DecimalOverflow { pos: pos.into() })?
                .checked_add((byte - b'0') as usize)
                .ok_or(BodySigParseError::DecimalOverflow { pos: pos.into() })?,
        );
        Ok(())
    }
}

// When reading an anchored byte subpattern, it can be in one of two states after the range is read
enum PendingAnchoredByte {
    HaveByte {
        start_pos: usize,
        byte: MatchByte,
        range: RangeInclusive<u8>,
    },
    HaveString {
        start_pos: usize,
        string: MatchBytes,
        range: RangeInclusive<u8>,
    },
}

// A subcontext for operating within a parenthetical expression. These
// are tricky, as they can wrap either alternative strings (which
// constitute a standalone pattern), or represent modifiers that apply
// to neighboring patterns.
#[derive(Default)]
struct ParentheticalContext {
    // The starting position of the expression (for error reporting)
    start_pos: usize,

    // Whether a byte pattern flush has been performed. This is done
    // conditially due to one of the possible character classes being `B`
    flushed: bool,

    // Alternative string data.  This is kept all together, with a set of
    // ranges to track heterogenous segments
    astr_data: Vec<MatchByte>,
    ranges: Vec<std::ops::Range<usize>>,

    // Whether an alternative string has already been determined to be
    // generic due to differing range sizes or nyble wildcards
    is_generic: bool,

    // The discovered character class (if the expression is determined to
    // contain one rather than alternative strings)
    character_class: Option<CharacterClass>,
}

impl ParentheticalContext {
    // Append the current accumulation of match bytes into the alternative string set
    fn push_alternative_string(
        &mut self,
        match_bytes: &mut TinyVec<[MatchByte; 128]>,
        is_final: bool,
    ) -> Result<(), BodySigParseError> {
        if match_bytes.is_empty() {
            if is_final && self.astr_data.is_empty() {
                return Err(BodySigParseError::EmptyParens {
                    pos: self.start_pos.into(),
                });
            } else {
                // Presence of an empty alternative string automatically implies
                // the set is generic.
                self.is_generic = true;
            }
        }
        let this_range_start = self.astr_data.len();
        self.astr_data.extend_from_slice(match_bytes);
        let this_range_end = self.astr_data.len();
        if !self.is_generic {
            if let Some(first_range) = self.ranges.first() {
                // See if ranges differ at all
                if first_range.end - first_range.start != this_range_end - this_range_start {
                    self.is_generic = true
                }
            }
        }
        self.ranges.push(this_range_start..this_range_end);
        match_bytes.clear();
        Ok(())
    }
}

impl TryFrom<&[u8]> for BodySig {
    type Error = BodySigParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut pc = ParseContext::default();

        let mut state = State::HighNyble;

        for (pos, &byte) in value.iter().enumerate() {
            match state {
                State::HighNyble => {
                    match byte {
                        b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                            // TODO: make sure no right-side pattern modifiers have been set
                            pc.mask = MatchMask::None;
                            pc.cur_byte = hex_nyble(byte, true);
                            if let Some(pa) = &mut pc.paren_cxt {
                                if byte == b'B' {
                                    // This *might* be a character class.  Note it.
                                    pa.character_class = Some(CharacterClass::WordBoundary);
                                }
                            }
                            state = State::LowNyble;
                        }
                        b'L' | b'W' => {
                            // b'B' is handled as part of of a pending byte
                            if let Some(pa) = &mut pc.paren_cxt {
                                pa.character_class = Some(CharacterClass::try_from(byte).unwrap());
                                state = State::CharacterClass;
                            }
                        }
                        // byte-level wildcard.  May cover an entire byte or just one nyble
                        QUESTION_MARK => {
                            pc.cur_byte = 0;
                            pc.mask = MatchMask::High;
                            state = State::LowNyble;
                        }
                        _ => state = pc.handle_non_matchbyte(Some((pos, byte)))?,
                    }
                }
                State::LowNyble => {
                    match byte {
                        b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                            if pc.paren_cxt.is_some() {
                                // This byte completes the low nybble of a new byte.
                                // If we were inside a parenthetical expression, any
                                // bytes need to be flushed to the prior match first.

                                // This never fails in parenthetical context
                                pc.flush_match_bytes().unwrap();
                            }
                            pc.cur_byte |= hex_nyble(byte, false);
                        }
                        QUESTION_MARK => {
                            if pc.paren_cxt.is_some() {
                                // This never fails in parenthetical context
                                pc.flush_match_bytes().unwrap();
                            }
                            pc.mask = if let MatchMask::High = pc.mask {
                                // ??
                                MatchMask::Full
                            } else {
                                // x?
                                MatchMask::Low
                            };
                        }
                        PAREN_RIGHT => {
                            state = pc.handle_cc_close();
                            continue;
                        }
                        other => {
                            return Err(BodySigParseError::ExpectingLowNyble {
                                pos: pos.into(),
                                found: Some(other.into()),
                            })
                        }
                    }
                    pc.push_matchbyte(
                        match pc.mask {
                            MatchMask::None => MatchByte::Full(pc.cur_byte),
                            MatchMask::High => MatchByte::LowNyble(pc.cur_byte),
                            MatchMask::Low => MatchByte::HighNyble(pc.cur_byte),
                            MatchMask::Full => MatchByte::Any,
                        },
                        pos - 1,
                    )
                    // There are no failures currently possible here, so
                    // `.unwrap()` to make code coverage happy.
                    .unwrap();
                    state = State::HighNyble;
                }
                State::CurlyBraceLower => match byte {
                    b'0'..=b'9' => {
                        pc.update_dec_value(byte, pos)?;
                    }
                    MINUS_SIGN => {
                        pc.cur_range = pc.dec_value.take().map(|dec_value| (dec_value..).into());
                        state = State::CurlyBraceUpper;
                    }
                    CURLY_RIGHT => {
                        if let Some(dec_value) = pc.dec_value.take() {
                            pc.cur_range = Some(Range::Exact(dec_value))
                        } else {
                            return Err(BodySigParseError::EmptyBraces {
                                start_pos: pc.left_brace_pos.into(),
                            });
                        }
                        match pc.cur_range.take().unwrap() {
                            Range::Exact(size) if size <= 128 => pc.push_matchbyte(
                                MatchByte::WildcardMany {
                                    size: (size).try_into().unwrap(),
                                },
                                pc.left_brace_pos,
                            )?,
                            range => {
                                pc.flush_match_bytes()?;
                                pc.push_pattern(Pattern::ByteRange(range))?;
                                pc.cur_range.take();
                            }
                        }
                        state = State::HighNyble;
                    }
                    other => {
                        return Err(BodySigParseError::UnexpectedChar {
                            context: Context::CurlyBraceRange,
                            pos: pos.into(),
                            found: other.into(),
                        })
                    }
                },
                State::CurlyBraceUpper =>
                // This state is in effect on the other side of a `-` within a curly-brace range
                {
                    match byte {
                        b'0'..=b'9' => {
                            pc.update_dec_value(byte, pos)?;
                        }
                        CURLY_RIGHT => {
                            let range = if let Some(Range::From(range_from)) = pc.cur_range.take() {
                                // Lower bound was specified
                                if let Some(dec_value) = pc.dec_value.take() {
                                    // Upper bound was specified
                                    if dec_value < range_from.start {
                                        return Err(BodySigParseError::RangeBoundsInverted {
                                            start_pos: pc.left_brace_pos.into(),
                                            start: range_from.start,
                                            end: dec_value,
                                        });
                                    }
                                    (range_from.start..=dec_value).into()
                                } else {
                                    // Only lower bound was specified
                                    range_from.into()
                                }
                            } else {
                                // No lower bound was specified
                                if let Some(dec_value) = pc.dec_value.take() {
                                    (..=dec_value).into()
                                } else {
                                    return Err(BodySigParseError::NoBraceBounds {
                                        start_pos: pc.left_brace_pos.into(),
                                    });
                                }
                            };
                            pc.flush_match_bytes().unwrap();
                            pc.push_pattern(Pattern::ByteRange(range))?;
                            state = State::HighNyble;
                        }
                        other => {
                            return Err(BodySigParseError::UnexpectedChar {
                                context: Context::CurlyBraceRange,
                                pos: pos.into(),
                                found: other.into(),
                            })
                        }
                    }
                }
                State::BracketLower =>
                // This state is in effect on the other side of a `-` within a square-bracket range
                {
                    match byte {
                        b'0'..=b'9' => {
                            pc.update_dec_value(byte, pos)?;
                        }
                        MINUS_SIGN | BRACKET_RIGHT => {
                            // FIXME: logic is screwy here.  Notice the repetition below
                            if let Some(dec_value) = pc.dec_value.take() {
                                if dec_value > ANCHORED_BYTE_RANGE_MAX {
                                    return Err(BodySigParseError::AnchoredByteInvalidLowerBound {
                                        bracket_pos: pc.left_bracket_pos.into(),
                                        found: dec_value,
                                    });
                                }
                                pc.cur_range = Some((dec_value..).into());
                                state = State::BracketUpper;
                            } else if byte == MINUS_SIGN {
                                return Err(BodySigParseError::BracketRangeMissingLowerBound {
                                    start_pos: pc.left_bracket_pos.into(),
                                });
                            } else {
                                // Found closing bracket
                                state = pc.handle_anchored_byte_range(pos)?;
                            }
                            if byte == BRACKET_RIGHT {
                                // No upper bound specified, which is apparently OK
                                state = pc.handle_anchored_byte_range(pos)?;
                            }
                        }
                        other => {
                            return Err(BodySigParseError::BracketRangeUnexpectedChar {
                                pos: pos.into(),
                                found: other.into(),
                            })
                        }
                    }
                }
                State::BracketUpper => match byte {
                    b'0'..=b'9' => {
                        pc.update_dec_value(byte, pos)?;
                    }
                    BRACKET_RIGHT => state = pc.handle_anchored_byte_range(pos)?,
                    other => {
                        return Err(BodySigParseError::BracketRangeUnexpectedChar {
                            pos: pos.into(),
                            found: other.into(),
                        })
                    }
                },
                State::Negate => match byte {
                    PAREN_LEFT => {
                        pc.left_paren_pos = pos;
                        pc.negated = true;
                        pc.paren_cxt = Some(ParentheticalContext {
                            start_pos: pos,
                            ..Default::default()
                        });
                        state = State::HighNyble;
                    }
                    other => {
                        return Err(BodySigParseError::NegateUnexpectedChar {
                            pos: pos.into(),
                            found: other.into(),
                        })
                    }
                },
                State::CharacterClass => {
                    if byte == PAREN_RIGHT {
                        state = pc.handle_cc_close();
                    } else {
                        return Err(BodySigParseError::CharClassExpectCloseParen {
                            pos: pos.into(),
                            found: byte.into(),
                        });
                    }
                }
            }
        }

        // Check final state
        match state {
            State::HighNyble => {
                pc.handle_non_matchbyte(None)?;
                pc.flush_match_bytes()?;
            }
            State::LowNyble => {
                return Err(BodySigParseError::ExpectingLowNyble {
                    pos: Position::End,
                    found: None,
                })
            }
            State::CurlyBraceLower | State::CurlyBraceUpper => {
                return Err(BodySigParseError::CurlyBraceNotClosed {
                    start_pos: pc.left_brace_pos.into(),
                })
            }
            State::BracketLower | State::BracketUpper => {
                return Err(BodySigParseError::BracketNotClosed {
                    start_pos: pc.left_bracket_pos.into(),
                })
            }
            State::Negate => return Err(BodySigParseError::NegationTargetless),
            State::CharacterClass => {
                return Err(BodySigParseError::CharClassUnterminated {
                    start_pos: pc.left_paren_pos.into(),
                })
            }
        }

        // There shouldn't be a pending pattern modifier
        if !pc.pattern_modifier.is_empty() {
            return Err(BodySigParseError::CharClassNothingAdjacent { pos: Position::End });
        }

        match pc.patterns.last() {
            // The signature shouldn't be empty
            None => return Err(BodySigParseError::Empty),
            // The signature shouldn't end with a wildcard or other unsized pattern
            Some(pattern) if pattern.is_wildcard() => {
                return Err(BodySigParseError::TrailingUnsizedPattern {
                    pattern: pc.patterns.pop().unwrap(),
                })
            }
            Some(_) => (),
        }

        Ok(BodySig {
            patterns: pc.patterns,
        })
    }
}
