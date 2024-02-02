use super::Encoding;
use crate::util::{parse_number_dec, ParseNumberError};
use thiserror::Error;

#[derive(Debug)]
#[allow(dead_code, clippy::struct_field_names)]
pub struct Offset {
    modifier: Modifier,
    offset: isize,
    encoding: Encoding,
}

#[derive(Debug, Error, PartialEq)]
pub enum ParseError {
    #[error("missing offset modifier")]
    MissingOffsetModifier,

    #[error("parsing offset: {0}")]
    ParseNum(#[from] ParseNumberError<isize>),
}

#[derive(Debug)]
pub enum Modifier {
    /// ">>"
    Positive,
    /// "<<"
    Negative,
}

impl TryFrom<&[u8]> for Offset {
    type Error = ParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let modifier;
        let bytes = if let Some(bytes) = bytes.strip_prefix(b">>") {
            modifier = Modifier::Positive;
            bytes
        } else if let Some(bytes) = bytes.strip_prefix(b"<<") {
            modifier = Modifier::Negative;
            bytes
        } else {
            return Err(ParseError::MissingOffsetModifier);
        };
        // TODO: parse hex?
        let offset = parse_number_dec(bytes).map_err(ParseError::ParseNum)?;
        Ok(Offset {
            modifier,
            offset,
            encoding: Encoding::Decimal,
        })
    }
}
