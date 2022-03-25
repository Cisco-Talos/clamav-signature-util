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
pub mod intmask;
/// Logical signature support
pub mod logical;
/// Hash-based signature support for Portable Executable files
pub mod pehash;
/// Phishing Signatures
pub mod phishing;
/// Enumeration of signature types
pub mod sigtype;
/// Enumeration of target types (typically found in logical and extended signatures)
pub mod targettype;

use crate::{
    feature::EngineReq,
    sigbytes::{AppendSigBytes, SigBytes},
    SigType,
};
use std::collections::TryReserveError;
use thiserror::Error;

/// Required functionality for a Signature.
pub trait Signature: std::fmt::Debug + EngineReq + AppendSigBytes {
    /// Signature name
    fn name(&self) -> &str;

    /// Return ClamAV signature, as would be expected in a CVD
    fn to_sigbytes(&self) -> Result<SigBytes, ToSigBytesError> {
        // Since this doesn't immediately allocate, implementations will still
        // have the opportunity to specify an allocation hint.
        let mut sb = SigBytes::new();
        self.append_sigbytes(&mut sb)?;
        Ok(sb)
    }
}

/// Errors that can be encountered when exporting a Signature to its CVD format
#[derive(Debug, Error)]
pub enum ToSigBytesError {
    /// An error occurred while formatting the signature
    #[error("formatting: {0}")]
    Fmt(#[from] std::fmt::Error),

    /// Formatting error that occurred while writing raw data to buffer
    #[error("writing: {0}")]
    Io(#[from] std::io::Error),

    /// Signature type is not supported within CVDs
    #[error("not supported within CVDs")]
    Unsupported,

    #[error("reserving memory: {0}")]
    TryReserve(#[from] TryReserveError),
}

/// Parse a CVD-style (single-line) signature from a CVD database. Since each
/// signature type has its own format, the format must be specified.
///
/// # Arguments
///
/// * `sig_type` - the signature type being provided
/// * `data` - signature content
///
/// # Examples
/// ```
/// use clam_sigutil::{
///     signature::{self, Signature},
///     SigType,
/// };
/// let sigdata = b"44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature";
/// let sig = clam_sigutil::signature::parse_from_cvd(SigType::FileHash, sigdata)
///     .expect("parsed signature");
/// println!("sig name = {}", sig.name());
/// ```
pub fn parse_from_cvd(sig_type: SigType, data: &[u8]) -> Result<Box<dyn Signature>, ParseError> {
    match sig_type {
        SigType::Extended => Ok(Box::new(ext::ExtendedSig::try_from(data)?)),
        SigType::Logical => Ok(Box::new(logical::LogicalSig::try_from(data)?)),
        SigType::FileHash => Ok(Box::new(filehash::FileHashSig::try_from(data)?)),
        SigType::PESectionHash => Ok(Box::new(pehash::PESectionHashSig::try_from(data)?)),
        SigType::ContainerMetadata => Ok(Box::new(
            container_metadata::ContainerMetadataSig::try_from(data)?,
        )),
        SigType::PhishingURL => Ok(Box::new(phishing::PhishingSig::try_from(data)?)),
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

    #[error("invalid phishing URL signature: {0}")]
    PhishingSigParse(#[from] phishing::PhishingSigParseError),
}
