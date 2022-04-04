use super::Encoding;
use crate::util::{parse_number_dec, parse_number_hex, ParseNumberError};
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug)]
pub struct ComparisonSet {
    // this is more of an operator, but the docs call it a symbol
    symbol: ComparisonOp,
    value: isize,
    /// The original encoding of this number in the signature
    encoding: Encoding,
}

#[derive(Debug, Error, PartialEq)]
pub enum ComparisonSetParseError {
    #[error("comparison set empty")]
    Empty,

    #[error("missing operator")]
    MissingOperator,

    #[error("unknown comparison operator")]
    UnknownOperator,

    #[error("parsing value: {0}")]
    ParseValue(ParseNumberError<i64>),

    #[error("parsing value: {0}")]
    ParseHexValue(ParseNumberError<u64>),
}

impl TryFrom<&[u8]> for ComparisonSet {
    type Error = ComparisonSetParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (&sym_byte, remainder) = value.split_first().ok_or(ComparisonSetParseError::Empty)?;
        // Be friendly in returning this error.  If the operator doesn't parse because it's a number, just report that the operator was apparently missing.
        let symbol = sym_byte.try_into().map_err(|e| {
            if matches!(e, ComparisonSetParseError::UnknownOperator)
                && matches!(sym_byte, b'0'..=b'9')
            {
                ComparisonSetParseError::MissingOperator
            } else {
                e
            }
        })?;
        let (encoding, value) = if let Some(hex_value_bytes) = remainder.strip_prefix(b"0x") {
            (
                Encoding::Hex,
                parse_number_hex(hex_value_bytes).map_err(ComparisonSetParseError::ParseHexValue)?
                    as isize,
            )
        } else {
            (
                Encoding::Decimal,
                parse_number_dec::<i64>(remainder).map_err(ComparisonSetParseError::ParseValue)?
                    as isize,
            )
        };

        Ok(Self {
            symbol,
            value,
            encoding,
        })
    }
}

#[derive(Debug)]
pub enum ComparisonOp {
    LessThan,
    Equal,
    GreaterThan,
}

impl TryFrom<u8> for ComparisonOp {
    type Error = ComparisonSetParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            b'<' => ComparisonOp::LessThan,
            b'=' => ComparisonOp::Equal,
            b'>' => ComparisonOp::GreaterThan,
            _ => return Err(ComparisonSetParseError::UnknownOperator),
        })
    }
}
