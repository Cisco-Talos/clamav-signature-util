mod bytecmp;
mod macrosig;
mod pcre;

pub use bytecmp::{ByteCmpSubSig, ByteCmpSubSigParseError};
pub use macrosig::{MacroSubSig, MacroSubSigParseError};
pub use pcre::{PCRESubSig, PCRESubSigParseError};

use crate::{
    feature::EngineReq,
    sigbytes::AppendSigBytes,
    signature::{
        bodysig::{parse::BodySigParseError, BodySig},
        ext::{ExtendedSig, ExtendedSigParseError, Offset, OffsetParseError},
        targettype::TargetType,
    },
};
use downcast_rs::{impl_downcast, Downcast};
use std::fmt::Write;

use thiserror::Error;

/// These are all boxed to avoid the overhead of the largest variation
#[derive(Debug)]
pub enum SubSigType {
    Extended,
    Macro,
    ByteCmp,
    Pcre,
}

#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub struct SubSigModifier {
    pub case_insensitive: bool,
    pub widechar: bool,
    pub match_fullword: bool,
    pub ascii: bool,
}

impl AppendSigBytes for SubSigModifier {
    fn append_sigbytes(
        &self,
        sb: &mut crate::sigbytes::SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        if self.ascii {
            sb.write_char('a')?;
        }
        if self.match_fullword {
            sb.write_char('f')?;
        }
        if self.case_insensitive {
            sb.write_char('i')?;
        }
        if self.widechar {
            sb.write_char('w')?;
        }

        Ok(())
    }
}

pub trait SubSig: std::fmt::Debug + EngineReq + AppendSigBytes + Downcast {
    fn subsig_type(&self) -> SubSigType;
}

impl_downcast!(SubSig);

pub trait SubSigError: std::error::Error {
    /// Whether or not the error pertains to a signature that was identified as
    /// being of the specified type, but failed to pass a deeper validation.
    /// E.g., a regular expression where the `/` bounds were found, but the
    ///  expression itself has an error.
    fn identified(&self) -> bool;
}

#[derive(Debug, Error, PartialEq)]
pub enum SubSigParseError {
    #[error("parsing Macro subsig: {0}")]
    MacroSubSigParse(#[from] MacroSubSigParseError),

    #[error("parsing byte-compare subsig: {0}")]
    ByteCmpSubSigParse(#[from] ByteCmpSubSigParseError),

    #[error("parsing PCRE subsig: {0}")]
    PCRESubSigParse(#[from] PCRESubSigParseError),

    #[error("parsing extended subsig: {0}")]
    ExtendedSigParse(#[from] ExtendedSigParseError),

    #[error("parsing subsig offset: {0}")]
    OffsetParse(#[from] OffsetParseError),

    #[error("parsing body subsig: {0}")]
    BodySigParse(#[from] BodySigParseError),
}

pub fn parse_bytes(
    subsig_bytes: &[u8],
    modifier: Option<SubSigModifier>,
) -> Result<Box<dyn SubSig>, SubSigParseError> {
    // Is it a macro subsig?
    match MacroSubSig::from_bytes(subsig_bytes, modifier) {
        Ok(sig) => return Ok(Box::new(sig) as Box<dyn SubSig>),
        Err(e) => {
            if e.identified() {
                return Err(e.into());
            }
        }
    }

    // Is it a byte-compare subsig?
    match ByteCmpSubSig::from_bytes(subsig_bytes, modifier) {
        Ok(sig) => return Ok(Box::new(sig) as Box<dyn SubSig>),
        Err(e) => {
            if e.identified() {
                return Err(e.into());
            }
        }
    }

    // Both extended signatures and PCRE sub-signatures can be prefixed with an offset.  This isn't documented for PCRE

    // Figure out if this seems to have an offset. If so, parse it, and slice down into the remaining bodysig
    let (offset, bodysig_bytes) = if let Some(pos) = subsig_bytes
        .iter()
        // Don't look any more than 16 characters in
        .take(32)
        // And stop looking if we see a PCRE pattern begin
        .take_while(|&b| *b != b'/')
        .position(|&b| b == b':')
    {
        let parts = subsig_bytes.split_at(pos);
        (Some(Offset::try_from(parts.0)?), &parts.1[1..])
    } else {
        (None, subsig_bytes)
    };

    // Is it a PCRE sub-sig?
    match PCRESubSig::from_bytes(bodysig_bytes, modifier, offset) {
        Ok(sig) => return Ok(Box::new(sig) as Box<dyn SubSig>),
        Err(e) => {
            if e.identified() {
                // This looked enough like a PCRE subsig to just stop here
                eprintln!("Failed to parse PCRESubSig: {}", e);
                return Err(e.into());
            }
        }
    }

    // Fall through to extended signature
    let body_sig = BodySig::try_from(bodysig_bytes).map_err(SubSigParseError::BodySigParse)?;
    let sig = ExtendedSig {
        name: None,
        target_type: TargetType::Any,
        offset,
        body_sig: Some(body_sig),
        modifier,
    };
    Ok(Box::new(sig) as Box<dyn SubSig>)
}

#[cfg(test)]
mod tests {
    use super::parse_bytes;

    #[test]
    fn test_pcre_without_offset_interior_colon() {
        let subsig_bytes = concat!(
            r#"0/Target=(\x22|\x27|)"#,
            r#"(file|ftp|http|https):"#,
            r#"//(?!(10|172\.(1[6-9]|2[0-9]|3[0-2])|192\.168))"#,
            r#"(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.)"#,
            r#"{3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))/"#
        )
        .as_bytes();
        match parse_bytes(subsig_bytes, None) {
            Ok(sig) => eprintln!("sig = {:?}", sig),
            Err(e) => eprintln!("error: {}", e),
        }
    }

    #[test]
    fn test_bytecmp_ok() {
        let subsig_bytes = b"0(<<6#hb2#=0)";
        match parse_bytes(subsig_bytes, None) {
            Ok(sig) => eprintln!("sig = {:#?}", sig),
            Err(e) => eprintln!("error: {}", e),
        }
    }

    #[test]
    fn test_bytecmp_invalid_num_bytes() {
        let subsig_bytes = b"0(<<6#hb3#=0)";
        match parse_bytes(subsig_bytes, None) {
            Ok(sig) => eprintln!("sig = {:?}", sig),
            Err(e) => eprintln!("error: {}", e),
        }
    }
}
