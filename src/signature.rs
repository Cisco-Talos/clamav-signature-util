/// Body signatures, typically found in extended signatures
pub mod bodysig;
/// Container Metadata signature support
pub mod container_metadata;
/// Extended signature support
pub mod ext;
/// File hash signature support
pub mod filehash;
/// Common functionality for hash-based signatures
pub mod hash;
/// Logical signature support
pub mod logical;
/// Hash-based signature support for Portable Executable files
pub mod pehash;
/// Enumeration of signature types
pub mod sigtype;
/// Enumeration of target types (typically found in logical and extended signatures)
pub mod targettype;

use crate::{feature::EngineReq, SigType};
use thiserror::Error;

/// Required functionality for a Signature.
pub trait Signature: std::fmt::Debug + EngineReq {
    /// Signature name
    fn name(&self) -> &str;
}

/// Parse a CVD-style (single-line) signature from a CVD database. Since each
/// signature type has its own format, the format must be specified.
pub fn parse_from_cvd(sig_type: SigType, data: &[u8]) -> Result<Box<dyn Signature>, ParseError> {
    match sig_type {
        SigType::Extended => Ok(Box::new(ext::ExtendedSig::try_from(data)?)),
        SigType::Logical => Ok(Box::new(logical::LogicalSig::try_from(data)?)),
        SigType::FileHash => Ok(Box::new(filehash::FileHashSig::try_from(data)?)),
        SigType::PESectionHash => Ok(Box::new(pehash::PESectionHashSig::try_from(data)?)),
        SigType::ContainerMetadata => Ok(Box::new(
            container_metadata::ContainerMetadataSig::try_from(data)?,
        )),
        _ => Err(ParseError::UnsupportedSigType),
    }
}

/// Errors that can be encountered while parsing signature input
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("unsupported signature type")]
    UnsupportedSigType,

    #[error("missing Name field")]
    MissingName,

    #[error("signature name not unicode")]
    NameNotUnicode(std::str::Utf8Error),

    #[error("error decoding hash-based signature: {0}")]
    HashSigError(#[from] hash::HashSigParseError),

    #[error("error parsing extended signature: {0}")]
    ExtendedSigParseError(#[from] ext::ExtendedSigParseError),

    #[error("parsing hash signature: {0}")]
    ParseHash(#[from] crate::util::ParseHashError),

    #[error("invalid logical signature: {0}")]
    LogicalSigParse(#[from] logical::LogicalSigParseError),

    #[error("invalid container metadata signature: {0}")]
    ContainerMetaParse(#[from] container_metadata::ContainerMetadataSigParseError),
}
