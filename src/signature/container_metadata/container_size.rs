use crate::util::{
    parse_number_dec, parse_usize_range_inclusive, ParseNumberError, RangeInclusiveParseError,
};
use std::{ops::RangeInclusive, };
use thiserror::Error;

#[derive(Debug)]
pub enum ContainerSize {
    Exact(usize),
    Range(RangeInclusive<usize>),
}

#[derive(Debug, Error)]
pub enum ContainerSizeParseError {
    #[error("parsing range: {0}")]
    ParseRange(#[from] RangeInclusiveParseError<usize>),

    #[error("parsing exact size: {0}")]
    ParseExact(#[from] ParseNumberError<usize>),
}

impl TryFrom<&[u8]> for ContainerSize {
    type Error = ContainerSizeParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.iter().any(|&b| b == b'-') {
            Ok(ContainerSize::Range(parse_usize_range_inclusive(value)?))
        } else {
            Ok(ContainerSize::Exact(parse_number_dec(value)?))
        }
    }
}

pub fn parse_container_size(bytes: &[u8]) -> Result<ContainerSize, ContainerSizeParseError> {
    if bytes.iter().any(|&b| b == b'-') {
        Ok(ContainerSize::Range(parse_usize_range_inclusive(bytes)?))
    } else {
        Ok(ContainerSize::Exact(parse_number_dec(bytes)?))
    }
}

#[cfg(test)]
mod tests {
    use super::ContainerSize;

    #[test]
    fn try_exact() {
        let bytes = r#"12345"#.as_bytes();
        assert!(matches!(bytes.try_into(), Ok(ContainerSize::Exact(12345))));
    }
}
