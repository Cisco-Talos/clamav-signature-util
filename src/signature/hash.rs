use crate::util::ParseNumberError;
use thiserror::Error;

/// Errors common to hash-based signatures
#[derive(Debug, Error)]
pub enum HashSigParseError {
    #[error("missing FileSize field")]
    MissingFileSize,

    #[error("missing HashString field")]
    MissingHashString,

    #[error("parsing size: {0}")]
    ParseSize(ParseNumberError<usize>),
}
