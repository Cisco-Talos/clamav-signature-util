use crate::util;
use std::{convert::TryFrom, ffi::OsStr, path::Path};
use thiserror::Error;

pub mod bodysig;
pub mod ext;
pub mod filehash;
pub mod hash;
pub mod logical;
pub mod pehash;
pub mod targettype;

/// Signature types
#[derive(Debug, Clone, Copy)]
pub enum SigType {
    Extended,
    Logical,
    ContainerMetadata,
    Bytecode,
    PhishingURL,
    FileHash,
    PESectionHash,
    Yara,
}

impl SigType {
    /// Return the signature type as specified by the extension the specified
    /// file path.  Returns `None` if the file has no extension, or the extension
    /// is not known to map to a signature type.
    pub fn from_file_path<'a, P: Into<&'a Path>>(path: P) -> Option<Self> {
        let path: &Path = path.into();
        if let Some(extension) = path.extension().map(OsStr::to_str).flatten() {
            Self::from_file_extension(extension)
        } else {
            None
        }
    }

    /// Return the signature type implied by the provided file extension
    pub fn from_file_extension(ext: &str) -> Option<Self> {
        Some(match ext {
            //
            // Body-based signatures
            //

            // Extended signatures
            "ndb" | "ndu" => SigType::Extended,
            // Logical signatures
            "ldb" | "ldu" => SigType::Logical,
            // Container metadata signatures
            "cdb" => SigType::ContainerMetadata,
            // Bytecode sigantures
            "cbc" => SigType::Bytecode,
            // Phishing URL signatures
            "pdb" | "gdb" | "wdb" => SigType::PhishingURL,

            //
            // Hash-based signatures
            //

            // File hash signatures
            "hdb" | "hsb" | "hdu" | "hsu" => SigType::FileHash,
            // PE section has signatures
            "mdb" | "msb" | "mdu" | "msu" => SigType::PESectionHash,

            _ => return None,
        })
    }
}

pub trait Signature: std::fmt::Debug {
    /// Signature name
    fn name(&self) -> &str;

    /// Return the minimum and optional maximum feature levels for which this
    /// signature is supported
    fn feature_levels(&self) -> (usize, Option<usize>);
}

pub fn parse(sig_type: SigType, data: &[u8]) -> Result<Box<dyn Signature>, ParseError> {
    match sig_type {
        SigType::Extended => Ok(Box::new(ext::ExtendedSig::try_from(data)?)),
        SigType::Logical => Ok(Box::new(logical::LogicalSig::try_from(data)?)),
        SigType::FileHash => Ok(Box::new(filehash::FileHashSig::try_from(data)?)),
        SigType::PESectionHash => Ok(Box::new(pehash::PESectionHashSig::try_from(data)?)),
        _ => Err(ParseError::UnsupportedSigType),
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("unsupported signature type")]
    UnsupportedSigType,

    #[error("missing Name field")]
    MissingName,

    #[error(transparent)]
    HashSigError(#[from] hash::HashSigError),

    #[error(transparent)]
    ExtendedSigParseError(#[from] ext::ExtendedSigParseError),

    #[error("missing TargetDescriptionBlock field")]
    MissingTargetDesc,

    #[error("missing Expression field")]
    MissingExpression,

    #[error(
        "character class opened at position {0} not immediately closed with closing parenthesis"
    )]
    CharacterClassNotClosed(usize),

    // NOTE: this error is specific to parsing ranges into usize
    #[error("Invalid inclusive range speicification")]
    InvalidInclusiveRange(#[from] util::RangeInclusiveParseError<usize>),

    #[error("non-unicode content found")]
    NotUnicode(#[from] std::str::Utf8Error),

    #[error("number not parseable")]
    UnparseableNum(#[from] std::num::ParseIntError),

    #[error(transparent)]
    ParseHash(#[from] crate::util::ParseHashError),

    #[error(transparent)]
    ParseHex(#[from] hex::FromHexError),

    #[error(transparent)]
    LogicalExpression(#[from] logical::expression::LogExprError),

    #[error(transparent)]
    TargetDescParse(#[from] logical::targetdesc::TargetDescParseError),
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
