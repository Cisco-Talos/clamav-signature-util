use crate::sigbytes::AppendSigBytes;
use std::{fmt::Write, str};
use thiserror::Error;

/// A wrapper for a regular expression that retains its source
#[derive(Debug)]
pub struct RegexpMatch {
    /// The regular expression source
    pub raw: Vec<u8>,
    // TODO: add compiled form
}

#[derive(Debug, Error)]
pub enum RegexpMatchParseError {
    #[error("regexp is not unicode: {0}")]
    NotUnicode(#[from] str::Utf8Error),

    #[error("invalid hexdecimal escape at pos {0}: {1}")]
    FromHex(usize, hex::FromHexError),

    #[error("no character following escape")]
    MidEscape,

    #[error("incomplete hex character escape")]
    MidHexEscape,

    #[error("unescaped slash at pos {0}")]
    UnescapedSlash(usize),
}

impl RegexpMatch {
    /// Import a regular expression as represented in a logical signature PCRE
    /// subsignature. This un-escapes any forward slashes ("\/") or escaped
    /// semicolons ("\x3b")
    pub fn from_pcre_subsig(bytes: &[u8]) -> Result<Self, RegexpMatchParseError> {
        enum State {
            Initial,
            Escape,
            HexEscape,
        }

        let mut raw = vec![];
        let mut state = State::Initial;
        let mut hexbytes: Option<[u8; 2]> = None;
        let mut hexpos = 0;

        for (pos, &byte) in bytes.iter().enumerate() {
            match state {
                State::Initial => match byte {
                    b'\\' => state = State::Escape,
                    b'/' => return Err(RegexpMatchParseError::UnescapedSlash(pos)),
                    b => raw.push(b),
                },
                State::Escape if byte == b'x' => {
                    state = State::HexEscape;
                }
                State::Escape => {
                    match byte {
                        b'/' => {
                            // Slashes get unescaped
                            raw.push(b'/');
                        }
                        b => {
                            // Preserve the original escape and this byte
                            raw.push(b'\\');
                            raw.push(b);
                        }
                    }
                    state = State::Initial;
                }
                State::HexEscape => {
                    if let Some(bytes) = &mut hexbytes {
                        let mut value = [0u8; 1];
                        bytes[1] = byte;
                        state = State::Initial;
                        hex::decode_to_slice(&bytes, &mut value)
                            .map_err(|e| RegexpMatchParseError::FromHex(hexpos, e))?;
                        // Is this an escaped semicolon?
                        if &value == b";" {
                            // Then just retain the semicolon
                            raw.push(b';')
                        } else {
                            // Otherwise, preserve the original encoded expression
                            raw.extend_from_slice(br#"\x"#);
                            raw.extend_from_slice(bytes);
                        }
                        hexbytes = None;
                    } else {
                        hexpos = pos;
                        hexbytes = Some([byte, 0]);
                    }
                }
            }
        }

        match state {
            State::Initial => Ok(Self { raw }),
            State::Escape => Err(RegexpMatchParseError::MidEscape),
            State::HexEscape => Err(RegexpMatchParseError::MidHexEscape),
        }
    }

    /// Export a RegexpMatch into the provided SigBytes buffer, escaping as
    /// required for a PCRE subsignature (i.e., escaping slashes and semicolons)
    pub fn append_pcre_subsig(
        &self,
        sb: &mut crate::sigbytes::SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        for byte in self.raw.iter() {
            match byte {
                b'/' => sb.write_str(r#"\/"#)?,
                b';' => sb.write_str(r#"\x3B"#)?,
                &b => sb.write_char(char::from_u32(b as u32).unwrap())?,
            }
        }
        Ok(())
    }
}

impl AppendSigBytes for RegexpMatch {
    fn append_sigbytes(
        &self,
        sb: &mut crate::sigbytes::SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        for byte in self.raw.iter() {
            match byte {
                b'/' => sb.write_str(r#"\/"#)?,
                &b => sb.write_char(char::from_u32(b as u32).unwrap())?,
            }
        }
        Ok(())
    }
}

impl TryFrom<&[u8]> for RegexpMatch {
    type Error = RegexpMatchParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        // TODO: compile and check regular expression
        Ok(RegexpMatch {
            raw: value.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_pcre_subsig() {
        let input = br#"How\/now\x3bbrown\x20cow\x3b"#;
        let regexp = RegexpMatch::from_pcre_subsig(input).unwrap();
        assert_eq!(&regexp.raw, &br#"How/now;brown\x20cow;"#);
    }

    #[test]
    fn unterm_escape() {
        let input = br#"How\/now\x3bbrown\x20cow\x3b\"#;
        let result = RegexpMatch::from_pcre_subsig(input);
        assert!(matches!(result, Err(RegexpMatchParseError::MidEscape)));
    }

    #[test]
    fn unterm_hexescape() {
        let input = br#"How\/now\x3bbrown\x20cow\x3b\x"#;
        let result = RegexpMatch::from_pcre_subsig(input);
        assert!(matches!(result, Err(RegexpMatchParseError::MidHexEscape)));

        let input = br#"How\/now\x3bbrown\x20cow\x3b\x5"#;
        let result = RegexpMatch::from_pcre_subsig(input);
        assert!(matches!(result, Err(RegexpMatchParseError::MidHexEscape)));
    }

    #[test]
    fn invalid_hex() {
        let input = br#"How\/now\x3bbrown\x20cow\x3b\x5q"#;
        let result = RegexpMatch::from_pcre_subsig(input);
        assert!(matches!(result, Err(RegexpMatchParseError::FromHex(..))));

        // Hex decoding doesn't occur until both characters are received
        let input = br#"How\/now\x3bbrown\x20cow\x3b\xq5"#;
        let result = RegexpMatch::from_pcre_subsig(input);
        assert!(matches!(result, Err(RegexpMatchParseError::FromHex(..))));
    }
}
