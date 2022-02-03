use super::Encoding;
use crate::util::{parse_number_dec, ParseNumberError};
use thiserror::Error;

#[derive(Debug)]
#[allow(dead_code)]
pub struct Offset {
    modifier: OffsetModifier,
    offset: isize,
    encoding: Encoding,
}

#[derive(Debug, Error)]
pub enum OffsetParseError {
    #[error("missing offset modifier")]
    MissingOffsetModifier,

    #[error("parsing offset: {0}")]
    ParseNum(#[from] ParseNumberError<isize>),
}

#[derive(Debug)]
pub enum OffsetModifier {
    /// ">>"
    Positive,
    /// "<<"
    Negative,
}

impl Offset {
    pub fn from_bytes(bytes: &[u8]) -> Result<Offset, OffsetParseError> {
        let modifier;
        let bytes = if let Some(bytes) = bytes.strip_prefix(b">>") {
            modifier = OffsetModifier::Positive;
            bytes
        } else if let Some(bytes) = bytes.strip_prefix(b"<<") {
            modifier = OffsetModifier::Negative;
            bytes
        } else {
            return Err(OffsetParseError::MissingOffsetModifier);
        };
        // TODO: parse hex?
        let offset = parse_number_dec(bytes).map_err(OffsetParseError::ParseNum)?;
        Ok(Offset {
            modifier,
            offset,
            encoding: Encoding::Decimal,
        })
    }
}
