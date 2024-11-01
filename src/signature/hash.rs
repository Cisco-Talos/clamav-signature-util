use crate::util::ParseNumberError;

/// Errors common to hash-based signatures
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParseError {
    #[error("missing FileSize field")]
    MissingFileSize,

    #[error("invalid value for field: {0}")]
    InvalidValueFor(String),

    #[error("missing field: {0}")]
    MissingField(String),

    #[error("parsing size: {0}")]
    ParseSize(ParseNumberError<usize>),

    #[error("Parsing min_flevel: {0}")]
    ParseMinFlevel(ParseNumberError<u32>),

    #[error("Parsing max_flevel: {0}")]
    ParseMaxFlevel(ParseNumberError<u32>),

    #[error("Parsing hash signature: {0}")]
    ParseHash(#[from] crate::util::ParseHashError),
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ValidationError {}
