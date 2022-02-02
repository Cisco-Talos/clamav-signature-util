use crate::signature::logical::{expression, SubSigModifier};
use std::str;
use thiserror::Error;

use super::{SubSig, SubSigType};

#[derive(Debug)]
pub struct PCRESubSig {
    trigger_expr: Box<dyn expression::Element>,
    pattern: String,
    // TODO: find a more-compact representation
    flags: Vec<Flag>,
    modifier: Option<SubSigModifier>,
}

impl SubSig for PCRESubSig {
    fn subsig_type(&self) -> SubSigType {
        SubSigType::Pcre
    }
}

#[derive(Debug)]
pub enum Flag {
    Global,
    Rolling,
    Encompass,
    PcreCaseless,
    PcreDotAll,
    PcreMultiline,
    PcreExtended,
    PcreAnchored,
    PcreDollarEndOnly,
    PcreUngreedy,
}

#[derive(Debug, Error)]
pub enum PCRESubSigParseError {
    #[error("empty")]
    Empty,

    #[error("empty pattern")]
    EmptyPattern,

    #[error("unknown PCRE flag")]
    UnknownFlag,

    #[error("regexp not unicode: {0}")]
    NotUnicode(str::Utf8Error),

    #[error("parsing logical expression: {0}")]
    ParseLogExpr(#[from] expression::LogExprParseError),

    #[cfg(validate_regex)]
    #[error("compiling regular expression: {0}")]
    CompileRegex(#[from] regex::Error),
}

impl PCRESubSig {
    pub fn from_bytes(
        bytes: &[u8],
        modifier: Option<SubSigModifier>,
    ) -> Result<PCRESubSig, PCRESubSigParseError> {
        // Due to escaping of slashes, we can't simply split on them
        let mut parts = bytes.splitn(2, |&b| b == b'/');
        let maybe_logexpr = parts.next().ok_or(PCRESubSigParseError::Empty)?;
        let remainder = parts.next().ok_or(PCRESubSigParseError::EmptyPattern)?;
        let trigger_expr: Box<dyn expression::Element> = maybe_logexpr.try_into()?;

        // Now look back from the tail
        let mut parts = remainder.rsplitn(2, |&b| b == b'/');
        // If this part is None, it means no '/' was found
        let flags: Vec<Flag> = parts
            .next()
            .ok_or(PCRESubSigParseError::EmptyPattern)?
            .iter()
            .copied()
            .map(Flag::try_from)
            .collect::<Result<Vec<Flag>, _>>()?;

        let pattern = str::from_utf8(parts.next().ok_or(PCRESubSigParseError::EmptyPattern)?)
            .map_err(PCRESubSigParseError::NotUnicode)?;
        // Clean up the pattern a bit.  Un-escape slashes
        let pattern = pattern.replace("\\/", "/");
        // Restore the semicolons
        let pattern = pattern.replace("\\x3B", ";");

        // Maybe make it compatible with the regex crate?
        let pattern = pattern.replace("\\'", "'");

        #[cfg(validate_regex)]
        {
            // Validate using the regex crate, which is *not* PCRE-compatible
            let mut regex = regex::RegexBuilder::new(&pattern);
            for flag in &flags {
                match flag {
                    Flag::Global => (),
                    Flag::Rolling => todo!(),
                    Flag::Encompass => todo!(),
                    Flag::PcreCaseless => {
                        regex.case_insensitive(true);
                    }
                    Flag::PcreDotAll => {
                        regex.dot_matches_new_line(true);
                    }
                    Flag::PcreMultiline => {
                        regex.multi_line(true);
                    }
                    Flag::PcreExtended => todo!(),
                    Flag::PcreAnchored => todo!(),
                    Flag::PcreDollarEndOnly => todo!(),
                    Flag::PcreUngreedy => {
                        regex.swap_greed(true);
                    }
                };
            }
            regex.build()?;
        }

        Ok(Self {
            trigger_expr,
            pattern,
            flags,
            modifier,
        })
    }
}

impl TryFrom<u8> for Flag {
    type Error = PCRESubSigParseError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Ok(match byte {
            b'g' => Flag::Global,
            b'r' => Flag::Rolling,
            b'e' => Flag::Encompass,
            b'i' => Flag::PcreCaseless,
            b's' => Flag::PcreDotAll,
            b'm' => Flag::PcreMultiline,
            b'x' => Flag::PcreExtended,
            b'A' => Flag::PcreAnchored,
            b'E' => Flag::PcreDollarEndOnly,
            b'U' => Flag::PcreUngreedy,
            _ => return Err(PCRESubSigParseError::UnknownFlag),
        })
    }
}
