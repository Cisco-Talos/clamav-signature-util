use thiserror::Error;

/// Errors common to hash-based signatures
#[derive(Debug, Error)]
pub enum HashSigError {
    #[error("missing FileSize field")]
    MissingFileSize,

    #[error("missing HashString field")]
    MissingHashString,
}
