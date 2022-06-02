/// Body signatures, typically found in extended signatures
pub mod bodysig;
/// Container Metadata signature support
pub mod container_metadata;
/// Extended signature support
pub mod ext;
/// File hash signature support
pub mod filehash;
/// Filetype Magic signatures
pub mod ftmagic;
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

use self::logical::LogicalSigValidationError;
use crate::{
    feature::{EngineReq, FeatureSetWithMinFlevel},
    sigbytes::{AppendSigBytes, FromSigBytes, SigBytes},
    util::Range,
    SigType,
};
use downcast_rs::{impl_downcast, Downcast};
use std::collections::TryReserveError;
use thiserror::Error;

/// Required functionality for a Signature.
pub trait Signature: std::fmt::Debug + EngineReq + AppendSigBytes + Downcast {
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

    /// Perform all specified validation steps for a signature.
    fn validate(&self, sigmeta: &SigMeta) -> Result<(), SigValidationError> {
        self.validate_subelements(sigmeta)?;
        self.validate_flevel(sigmeta)?;
        Ok(())
    }

    /// Validate a signature's constitute elements and/or their relationship to
    /// one another.
    fn validate_subelements(&self, _sigmeta: &SigMeta) -> Result<(), SigValidationError> {
        Ok(())
    }

    /// Validate a signature's elements, additional verifying that its metadata
    /// (i.e., specified min/max feature levels) doesn't conflict with any of the
    /// elements' constraints
    fn validate_flevel(&self, sigmeta: &SigMeta) -> Result<(), SigValidationError> {
        // Check the specified vs. the computed feature level
        if let Some(computed_flevel) = self.computed_feature_level() {
            if let Some(computed_min_flevel) = computed_flevel.start() {
                // Some features within this signature have a minimum feature level.
                // Confirm that the signature specifies it (or a higher level)
                match &sigmeta.f_level {
                    Some(f_level) => match f_level.start() {
                        Some(spec_min_flevel) => {
                            if spec_min_flevel < computed_min_flevel {
                                return Err(SigValidationError::SpecifiedMinFLevelTooLow {
                                    spec_min_flevel,
                                    computed_min_flevel,
                                    feature_set: self.features().into(),
                                });
                            }
                        }
                        None => {
                            // This is the [unlikely] case where a *maximum* FLevel
                            // was specified without a minimum, but a minimum is required.
                            return Err(SigValidationError::MinFLevelNotSpecified {
                                computed_min_flevel,
                                feature_set: self.features().into(),
                            });
                        }
                    },
                    None => {
                        return Err(SigValidationError::MinFLevelNotSpecified {
                            computed_min_flevel,
                            feature_set: self.features().into(),
                        });
                    }
                }
            }
            // TODO: check maximum, as well (but maximums are not presently computed)
        }

        Ok(())
    }
}

impl_downcast!(Signature);

pub trait Validate {
    /// Perform additional validation on a signature element
    fn validate(&self) -> Result<(), SigValidationError> {
        Ok(())
    }
}

/// Additional data obtained from a signature when being parsed, but not
/// necessary for operation of the signature
#[derive(Default, Debug, PartialEq)]
pub struct SigMeta {
    /// Minimum feature level, or range of valid levels
    pub f_level: Option<Range<u32>>,
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
/// let sigdata = b"44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature".into();
/// let sig = clam_sigutil::signature::parse_from_cvd(SigType::FileHash, &sigdata)
///     .expect("parsed signature");
/// println!("sig name = {}", sig.name());
/// ```
pub fn parse_from_cvd(
    sig_type: SigType,
    data: &SigBytes,
) -> Result<Box<dyn Signature>, FromSigBytesParseError> {
    Ok(parse_from_cvd_with_meta(sig_type, data)?.0)
}

/// Parse a CVD-style (single-line) signature from a CVD database, returning the
/// associated metadata encoded into the record. Since each signature type has
/// its own format, the format must be specified.
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
/// let sigdata = b"44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature:51:255".into();
/// let (sig, meta) = clam_sigutil::signature::parse_from_cvd_with_meta(SigType::FileHash, &sigdata)
///     .expect("parsed signature");
/// println!("sig name = {}", sig.name());
/// println!("metadata = {:?}", meta);
/// ```
pub fn parse_from_cvd_with_meta(
    sig_type: SigType,
    data: &SigBytes,
) -> Result<(Box<dyn Signature>, SigMeta), FromSigBytesParseError> {
    let (sig, sigmeta) = match sig_type {
        SigType::Extended => ext::ExtendedSig::from_sigbytes(data)?,
        SigType::Logical => logical::LogicalSig::from_sigbytes(data)?,
        SigType::FileHash => filehash::FileHashSig::from_sigbytes(data)?,
        SigType::PESectionHash => pehash::PESectionHashSig::from_sigbytes(data)?,
        SigType::ContainerMetadata => {
            container_metadata::ContainerMetadataSig::from_sigbytes(data)?
        }
        SigType::PhishingURL => phishing::PhishingSig::from_sigbytes(data)?,
        SigType::FTMagic => ftmagic::FTMagicSig::from_sigbytes(data)?,
        _ => return Err(FromSigBytesParseError::UnsupportedSigType),
    };

    Ok((sig, sigmeta))
}

/// Errors that can be encountered while parsing signature input
#[derive(Error, Debug, PartialEq)]
pub enum FromSigBytesParseError {
    #[error("unsupported signature type")]
    UnsupportedSigType,

    #[error("missing Name field")]
    MissingName,

    #[error("signature name not unicode")]
    NameNotUnicode(std::str::Utf8Error),

    #[error("parsing hash-based signature: {0}")]
    HashSig(#[from] hash::HashSigParseError),

    #[error("parsing extended signature: {0}")]
    ExtendedSig(#[from] ext::ExtendedSigParseError),

    #[error("parsing logical signature: {0}")]
    LogicalSig(#[from] logical::LogicalSigParseError),

    #[error("parsing container metadata signature: {0}")]
    ContainerMetaSig(#[from] container_metadata::ContainerMetadataSigParseError),

    #[error("parsing phishing URL signature: {0}")]
    PhishingSig(#[from] phishing::PhishingSigParseError),

    #[error("parsing file type magic signature: {0}")]
    FTMagicSig(#[from] ftmagic::FTMagicParseError),
}

#[derive(Error, Debug, PartialEq)]
pub enum SigValidationError {
    #[error("validating hash-based signature: {0}")]
    HashSig(#[from] hash::HashSigValidationError),

    #[error("validating logical signature: {0}")]
    LogicalSig(#[from] LogicalSigValidationError),

    #[error("validating container metadata signature: {0}")]
    ContainerMetaSig(#[from] container_metadata::ContainerMetadataSigValidationError),

    #[error("specified minimum feature level ({spec_min_flevel}) is lower than computed ({computed_min_flevel}), requires features {feature_set:?}")]
    SpecifiedMinFLevelTooLow {
        spec_min_flevel: u32,
        computed_min_flevel: u32,
        feature_set: FeatureSetWithMinFlevel,
    },

    #[error("minimum feature level unspecified; must be at least ({computed_min_flevel}), requires features {feature_set:?}")]
    MinFLevelNotSpecified {
        computed_min_flevel: u32,
        feature_set: FeatureSetWithMinFlevel,
    },
}
