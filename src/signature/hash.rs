use crate::util::ParseNumberError;
use thiserror::Error;

/// Errors common to hash-based signatures
#[derive(Debug, Error, PartialEq)]
pub enum HashSigParseError {
    #[error("missing FileSize field")]
    MissingFileSize,

    #[error("missing HashString field")]
    MissingHashString,

    #[error("parsing size: {0}")]
    ParseSize(ParseNumberError<usize>),

    #[error("Parsing min_flevel: {0}")]
    ParseMinFlevel(ParseNumberError<u32>),

    #[error("Parsing max_flevel: {0}")]
    ParseMaxFlevel(ParseNumberError<u32>),

    #[error("Parsing hash signature: {0}")]
    ParseHash(#[from] crate::util::ParseHashError),
}

#[derive(Debug, Error, PartialEq)]
pub enum HashSigValidationError {}
