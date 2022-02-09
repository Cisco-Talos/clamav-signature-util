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

impl TryFrom<&[u8]> for Offset {
    type Error = OffsetParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
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
