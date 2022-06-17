use super::{altstr::AlternativeStrings, PatternModifier};
use crate::{
    feature::EngineReq,
    sigbytes::{AppendSigBytes, SigBytes},
    util::Range,
};
use enumflags2::BitFlags;
use std::{fmt::Write, ops::RangeInclusive};

#[derive(Debug, PartialEq)]
pub enum ByteAnchorSide {
    Left,
    Right,
}

#[derive(PartialEq)]
pub enum Pattern {
    /// A series of bytes, possible containing fixed-size wildcards. Represented
    /// as `xx`, `x?`, `?x` or `??`, where `x` is a hexadecimal digit, and `?` is
    /// a nyble that will be ignored.
    String(MatchBytes, BitFlags<PatternModifier>),

    /// An "anchored byte" expression (represented as `BY[n-m]HEXSIG` or `HEXSIG[n-m]BY`)
    AnchoredByte {
        anchor_side: ByteAnchorSide,
        byte: MatchByte,
        range: RangeInclusive<u8>,
        string: MatchBytes,
    },

    /// Alternative strings.  A parenthetical group of one or more strings
    /// separated with the pipe (`|`) character
    AlternativeStrings(AlternativeStrings),

    /// A range of bytes that are ignored, but anchored to neighboring matches
    /// This is represented in signatures as `*` (for any size); or as `{-n}`,
    /// `{n-}` or `{n-m}` to match inclusive or open-ended ranges.
    ByteRange(Range<usize>),

    /// An unbounded range of bytes (represented as `*`)
    Wildcard,
}

#[derive(Clone, Copy, PartialEq)]
pub enum MatchByte {
    // A match of the full byte value (e.g., "af")
    Full(u8),

    // A match that ignores the high nyble, matching only the low nyble (e.g., "?f")
    LowNyble(u8),

    // A match that ignores the low nyble, matching only the high nyble (e.g., "f?")
    HighNyble(u8),

    // A match that ignores the entire byte (e.g., "??")
    Any,

    // A match that ignores a fixed, small set of bytes (represented as `{n}`)
    //
    // This is included as a MatchByte variation because, internally, these tend
    // to get expanded into a series of full-byte wildcards when given to matcher
    // (provided the size is <=128).
    WildcardMany { size: u8 },
}

impl From<u8> for MatchByte {
    fn from(byte: u8) -> Self {
        MatchByte::Full(byte)
    }
}

#[derive(Default, PartialEq)]
pub struct MatchBytes {
    pub bytes: Vec<MatchByte>,
}

impl From<&[u8]> for MatchBytes {
    fn from(bytes: &[u8]) -> Self {
        MatchBytes {
            bytes: bytes.iter().cloned().map(MatchByte::Full).collect(),
        }
    }
}

impl<const N: usize> From<[u8; N]> for MatchBytes {
    fn from(bytes: [u8; N]) -> Self {
        MatchBytes {
            bytes: bytes.iter().cloned().map(MatchByte::Full).collect(),
        }
    }
}

impl From<Vec<MatchByte>> for MatchBytes {
    fn from(mb: Vec<MatchByte>) -> Self {
        MatchBytes { bytes: mb }
    }
}

impl std::ops::Deref for MatchBytes {
    type Target = Vec<MatchByte>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl std::fmt::Debug for MatchBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MatchBytes(\"{}\")", self)
    }
}

impl AppendSigBytes for MatchBytes {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        // Same as Display
        write!(sb, "{}", self).map_err(crate::signature::ToSigBytesError::Fmt)
    }
}

impl std::fmt::Display for MatchBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.iter() {
            write!(f, "{:?}", byte)?;
        }
        Ok(())
    }
}

pub enum MatchMask {
    // Match any value
    None,
    // Match only the high nyble
    High,
    // Match only the low nyble
    Low,
    // Match the entire byte
    Full,
}

impl Default for MatchMask {
    fn default() -> Self {
        MatchMask::None
    }
}

impl Default for MatchByte {
    fn default() -> Self {
        MatchByte::Any
    }
}

impl std::fmt::Debug for MatchByte {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full(byte) => write!(f, "{:02x}", byte),
            Self::LowNyble(low) => write!(f, "?{:x}", low & 0x0f),
            Self::HighNyble(high) => write!(f, "{:x}?", high >> 4 & 0x0f),
            Self::Any => write!(f, "??"),
            Self::WildcardMany { size } => write!(f, "{{{size}}}"),
        }
    }
}

impl Pattern {
    /// Whether or not this pattern is a wildcard type (which can't appear at the
    /// beginning of a signature)
    pub fn is_wildcard(&self) -> bool {
        matches!(self, Pattern::Wildcard | Pattern::ByteRange(..))
    }
}

impl std::fmt::Debug for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(mbs, pmod) => {
                let mut tfmt = f.debug_tuple("String");
                tfmt.field(mbs);
                if !pmod.is_empty() {
                    tfmt.field(pmod);
                };
                tfmt.finish()
            }
            Self::Wildcard => f.write_str("Wildcard"),
            Self::AnchoredByte {
                anchor_side,
                byte,
                range,
                string,
            } => f
                .debug_struct("AnchoredByte")
                .field("anchor_side", anchor_side)
                .field("byte", byte)
                .field("range", range)
                .field("string", string)
                .finish(),
            Self::ByteRange(arg0) => f.debug_tuple("Range").field(arg0).finish(),
            Self::AlternativeStrings(arg0) => f.debug_tuple("AltStrs").field(arg0).finish(),
        }
    }
}

impl AppendSigBytes for Pattern {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        match self {
            Pattern::String(s, pmod) => {
                for pm in PatternModifier::left_flags().intersection_c(*pmod) {
                    pm.append_sigbytes(sb)?;
                }
                s.append_sigbytes(sb)?;
            }
            Pattern::Wildcard => sb.write_char('*')?,
            Pattern::AnchoredByte {
                anchor_side,
                byte,
                range,
                string,
            } => match anchor_side {
                ByteAnchorSide::Left => {
                    write!(sb, "{byte:?}[{}-{}]{string}", range.start(), range.end())?
                }
                ByteAnchorSide::Right => {
                    write!(sb, "{string}[{}-{}]{byte:?}", range.start(), range.end())?
                }
            },
            Pattern::ByteRange(range) => {
                sb.write_char('{')?;
                range.append_sigbytes(sb)?;
                sb.write_char('}')?;
            }
            Pattern::AlternativeStrings(astrs) => match astrs {
                AlternativeStrings::FixedWidth {
                    negated,
                    width,
                    data,
                } => {
                    if *negated {
                        sb.write_char('!')?;
                    }
                    sb.write_char('(')?;
                    for (pos, bytes) in data.chunks(*width).enumerate() {
                        if pos > 0 {
                            sb.write_char('|')?;
                        }
                        for byte in bytes {
                            write!(sb, "{:?}", byte)?;
                        }
                    }
                    sb.write_char(')')?;
                }
                AlternativeStrings::Generic { ranges, data } => {
                    sb.write_char('(')?;
                    for (pos, range) in ranges.iter().enumerate() {
                        if pos > 0 {
                            sb.write_char('|')?;
                        }
                        for byte in data.get(range.clone()).unwrap() {
                            write!(sb, "{:?}", byte)?;
                        }
                    }
                    sb.write_char(')')?;
                }
            },
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum AnyBytes {
    Infinite,
    Range(RangeInclusive<usize>),
}

impl AppendSigBytes for AnyBytes {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        match self {
            AnyBytes::Infinite => sb.write_char('*')?,
            AnyBytes::Range(range) => write!(sb, "[{}-{}]", range.start(), range.end())?,
        }
        Ok(())
    }
}

impl EngineReq for Pattern {}
