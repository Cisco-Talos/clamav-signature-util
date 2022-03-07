use std::str;
use thiserror::Error;

/// A wrapper for a regular expression that retains its source
#[derive(Debug)]
pub struct RegexpMatch {
    /// The regular expression source
    pub raw: String,
    // TODO: add compiled form
}

#[derive(Debug, Error)]
pub enum RegexpMatchParseError {
    #[error("regexp is not unicode: {0}")]
    NotUnicode(#[from] str::Utf8Error),
}

impl TryFrom<&[u8]> for RegexpMatch {
    type Error = RegexpMatchParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let raw = str::from_utf8(value)?.to_owned();
        // TODO: compile and check regular expression
        Ok(RegexpMatch { raw })
    }
}
