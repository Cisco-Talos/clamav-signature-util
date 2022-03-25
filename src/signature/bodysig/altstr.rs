use crate::{
    sigbytes::{AppendSigBytes, SigBytes},
    signature::intmask::IntWithMask,
};
use std::{
    fmt::Write,
    ops::{RangeInclusive, Shl},
};
use thiserror::Error;

/// A structure describing a set of alternative strings.
#[derive(Debug)]
pub enum AlternateStrings {
    /// A set of fixed-width alternative strings, possibly negated
    FixedWidth {
        negated: bool,
        width: usize,
        data: Vec<u8>,
    },
    /// A set of generic alternative strings, which may be of variable length
    /// and/or contain wildcard bytes
    Generic {
        astrs: Vec<GenAltString>,
        data: Vec<u8>,
    },
}

/// Generic alternative string
#[derive(Debug, Clone)]
pub enum GenAltString {
    /// An alternative string comprised only of literal bytes
    Literal(RangeInclusive<usize>),
    /// An alternative string comprised of a single wildcard byte
    Wildcard(IntWithMask<u8>),
    /// An alternative string containing a mix of both literal and wildcard bytes
    Mixed(Vec<AltStrSegment>),
}

/// A segment within an alternative string
#[derive(Debug, Clone)]
pub enum AltStrSegment {
    /// A literal byte segment, referencing a range in the data vector
    Literal(RangeInclusive<usize>),
    /// A byte-sized match with one or both nybles wildcarded
    Wildcard(IntWithMask<u8>),
}

#[derive(Debug, Error)]
pub enum AlternateStringsParseError {
    #[error("parsing alternative string {0} hex value: {1}")]
    FromHex(usize, hex::FromHexError),

    #[error("generic alternative strings may not be negated")]
    NegatedGenAlt,
}

impl TryFrom<(bool, &[u8])> for AlternateStrings {
    type Error = AlternateStringsParseError;

    fn try_from(value: (bool, &[u8])) -> Result<Self, Self::Error> {
        let (negated, value) = value;
        debug_assert!(!value.is_empty());

        // Running data vector -- all literals reference a portion of this
        let mut data = vec![];

        // Track whether the sequence consists of identically-sized elements
        let mut first_len = None;

        // Determines whether the generic variant must be used rather than
        // the fixed-width variant.
        let mut is_generic = false;

        // Collected alterantive strings (which may be composite)
        let mut astrs = vec![];

        for (asidx, element) in value.split(|&b| b == b'|').enumerate() {
            // Quickly scan forward to find out how this value will have to be
            // encoded.  If any ?'s are found, it has to be broken up into its
            // generic and wildcard elements.
            if !element.iter().any(|&b| b == b'?') {
                // Just a literal
                let element = hex::decode(element)
                    .map_err(|e| AlternateStringsParseError::FromHex(asidx, e))?;

                if !is_generic {
                    match first_len {
                        None => first_len = Some(element.len()),
                        // The first variation triggers the generic case
                        Some(len) if len != element.len() => is_generic = true,
                        _ => (),
                    }
                }

                let start = data.len();
                data.extend(element);
                astrs.push(GenAltString::Literal(start..=(data.len() - 1)));
            } else {
                // Record that the astrs vector will need to be used due to the
                // presence of wildcards
                is_generic = true;
                let mut this_astr = vec![];
                let mut literal_segment = vec![];

                for hexbyte in element.chunks(2) {
                    let this_byte = parse_byte_from_hex(hexbyte)
                        .map_err(|e| AlternateStringsParseError::FromHex(asidx, e))?;

                    match this_byte {
                        ParsedByte::Literal(byte) => literal_segment.push(byte),
                        ParsedByte::Wildcard(wc) => {
                            // Flush the current literal portion
                            if !literal_segment.is_empty() {
                                let start = data.len();
                                data.append(&mut literal_segment);
                                let end = data.len();
                                this_astr.push(AltStrSegment::Literal(start..=(end - 1)));
                            }
                            this_astr.push(AltStrSegment::Wildcard(wc))
                        }
                    }
                }

                // Flush any remaining literal string
                if !literal_segment.is_empty() {
                    let start = data.len();
                    data.append(&mut literal_segment);
                    let end = data.len();
                    this_astr.push(AltStrSegment::Literal(start..=(end - 1)));
                }

                astrs.push(if this_astr.len() > 1 {
                    GenAltString::Mixed(this_astr)
                } else {
                    match this_astr.remove(0) {
                        // This should never happen, since this alternative
                        // string was already determined to contain '?'s
                        AltStrSegment::Literal(_) => unreachable!(),
                        AltStrSegment::Wildcard(wc) => GenAltString::Wildcard(wc),
                    }
                });
            }
        }

        if is_generic {
            if negated {
                Err(AlternateStringsParseError::NegatedGenAlt)
            } else {
                Ok(AlternateStrings::Generic { astrs, data })
            }
        } else {
            // Negation gets fixed by the receiver
            Ok(AlternateStrings::FixedWidth {
                negated,
                width: first_len.unwrap(),
                data,
            })
        }
    }
}

// A structure to classify one parsed byte
enum ParsedByte {
    Literal(u8),
    Wildcard(IntWithMask<u8>),
}

/// Examine two bytes that are presumably the hex-encoded value of a byte, and
/// determine whether they represent a literal byte, or a byte with one or both
/// nybles wildcarded, returning the raw byte or an integer with its mask.
fn parse_byte_from_hex(hexbyte: &[u8]) -> Result<ParsedByte, hex::FromHexError> {
    Ok(match hexbyte {
        b"??" => ParsedByte::Wildcard(IntWithMask {
            mask: 0xff,
            value: 0,
        }),

        // Wildcard high nyble
        &[b'?', c] if (b'0'..b'9').contains(&c) => ParsedByte::Wildcard(IntWithMask {
            mask: 0xf0,
            value: c - b'0',
        }),
        &[b'?', c] if (b'a'..b'f').contains(&c) => ParsedByte::Wildcard(IntWithMask {
            mask: 0xf0,
            value: c - b'a' + 0x0a,
        }),
        &[b'?', c] if (b'A'..b'F').contains(&c) => ParsedByte::Wildcard(IntWithMask {
            mask: 0xf0,
            value: c - b'A' + 0x0a,
        }),

        // Wildcard low nyble
        &[c, b'?'] if (b'0'..b'9').contains(&c) => ParsedByte::Wildcard(IntWithMask {
            mask: 0x0f,
            value: (c - b'0').shl(4),
        }),
        &[c, b'?'] if (b'a'..b'f').contains(&c) => ParsedByte::Wildcard(IntWithMask {
            mask: 0x0f,
            value: (c - b'a' + 0x0a).shl(4),
        }),
        &[c, b'?'] if (b'A'..b'F').contains(&c) => ParsedByte::Wildcard(IntWithMask {
            mask: 0x0f,
            value: (c - b'A' + 0x0a).shl(4),
        }),

        value => {
            let mut byte = [0u8];
            hex::decode_to_slice(value, &mut byte)?;
            ParsedByte::Literal(byte[0])
        }
    })
}

impl AppendSigBytes for AlternateStrings {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        match self {
            AlternateStrings::FixedWidth {
                negated,
                width,
                data,
            } => {
                for (i, astr) in data.chunks_exact(*width).enumerate() {
                    if i > 0 {
                        sb.write_char('|')?;
                    }
                    for byte in astr {
                        write!(sb, "{byte:02x}")?
                    }
                }
            }
            AlternateStrings::Generic {
                astrs: genalts,
                data,
            } => {
                for (i, astr) in genalts.iter().enumerate() {
                    if i > 0 {
                        sb.write_char('|')?;
                    }
                    match astr {
                        GenAltString::Literal(range) => {
                            append_hex(sb, data.get(range.clone()).unwrap())?
                        }
                        GenAltString::Mixed(genalts) => {
                            for genalt in genalts {
                                match genalt {
                                    AltStrSegment::Literal(range) => {
                                        append_hex(sb, data.get(range.clone()).unwrap())?
                                    }
                                    AltStrSegment::Wildcard(wc) => write!(sb, "{:x}", wc)?,
                                }
                            }
                        }
                        GenAltString::Wildcard(wc) => write!(sb, "{:x}", wc)?,
                    }
                }
            }
        }
        Ok(())
    }
}

fn append_hex(sb: &mut SigBytes, data: &[u8]) -> std::fmt::Result {
    for byte in data {
        write!(sb, "{byte:02x}")?
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_bytes() {
        const TEST_ASTR: &str = "55|aa|ff|d2";
        let astr = AlternateStrings::try_from((false, TEST_ASTR.as_bytes())).unwrap();
        dbg!(&astr);
        let mut sb = SigBytes::new();
        astr.append_sigbytes(&mut sb).unwrap();
        assert_eq!(sb.as_bytes(), TEST_ASTR.as_bytes());
    }

    #[test]
    fn multi_byte_fixed() {
        const TEST_ASTR: &str = "55aa|ffd2|8080";
        let astr = AlternateStrings::try_from((false, TEST_ASTR.as_bytes())).unwrap();
        dbg!(&astr);
        let mut sb = SigBytes::new();
        astr.append_sigbytes(&mut sb).unwrap();
        assert_eq!(sb.as_bytes(), TEST_ASTR.as_bytes());
    }

    #[test]
    fn generic_variable() {
        const TEST_ASTR: &str = "55aa|ff|d2|8080";
        let astr = AlternateStrings::try_from((false, TEST_ASTR.as_bytes())).unwrap();
        dbg!(&astr);
        let mut sb = SigBytes::new();
        astr.append_sigbytes(&mut sb).unwrap();
        assert_eq!(sb.as_bytes(), TEST_ASTR.as_bytes());
    }

    #[test]
    fn altstr_generic_with_nyble_wildcard() {
        const TEST_ASTR: &str = "5?|?b|ff|d2|f00f|e??e|abcde?f01?2345??";
        let astr = AlternateStrings::try_from((false, TEST_ASTR.as_bytes())).unwrap();
        dbg!(&astr);
        let mut sb = SigBytes::new();
        astr.append_sigbytes(&mut sb).unwrap();
        eprintln!("sb = {sb}");
        assert_eq!(sb.as_bytes(), TEST_ASTR.as_bytes());
    }
}
