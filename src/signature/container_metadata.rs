mod container_size;
mod container_type;

use container_size::parse_container_size;
    use container_type::{ContainerType, ContainerTypeParseError};

use super::{ParseError, Signature};
use crate::{
    util::{
        opt_field_value, parse_bool_from_int, parse_number_dec, parse_wildcard_field,
        unescaped_element, ParseBoolFromIntError, ParseNumberError,
    },
};
use container_size::{ContainerSize, ContainerSizeParseError};
use std::str;
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug)]
pub struct ContainerMetadataSig {
    name: String,
    container_type: Option<ContainerType>,
    container_size: Option<ContainerSize>,
    filename_regexp_src: String,
    file_size_in_container: Option<usize>,
    file_size_real: Option<usize>,
    is_encrypted: Option<bool>,
    file_pos: Option<usize>,
    res1: Option<u32>,
}

#[derive(Debug, Error)]
pub enum ContainerMetadataSigParseError {
    #[error("missing ContainerType field")]
    MissingContainerType,

    #[error("parsing ContainerType: {0}")]
    ContainerType(#[from] ContainerTypeParseError),

    #[error("missing ContainerSize field")]
    MissingContainerSize,

    #[error("parsing ContainerType: {0}")]
    ContainerSize(#[from] ContainerSizeParseError),

    #[error("missing FileNameREGEX field")]
    MissingFilenameRegexp,

    #[error("missing FileSizeInContainer field")]
    MissingFSIC,

    #[error("invalid FileSizeInContainer field: {0}")]
    InvalidFSIC(ParseNumberError<usize>),

    #[error("missing FileSizeReal field")]
    MissingFSReal,

    #[error("invalid FileSizeReal field: {0}")]
    InvalidFSReal(ParseNumberError<usize>),

    #[error("missing IsEncrypted field")]
    MissingIsEnc,

    #[error("invalid IsEncrypted field: {0}")]
    InvalidIsEnc(ParseBoolFromIntError),

    #[error("missing FilePos field")]
    MissingFilePos,

    #[error("invalid FilePos field: {0}")]
    InvalidFilePos(ParseNumberError<usize>),

    #[error("missing Res1 field")]
    MissingRes1,

    #[error("invalid Res1 field: {0}")]
    InvalidRes1(ParseNumberError<u32>),

    #[error("missing Res2 field")]
    MissingRes2,

    #[error("invalid Res2 field: {0}")]
    InvalidRes2(ParseNumberError<isize>),
}

impl TryFrom<&[u8]> for ContainerMetadataSig {
    type Error = ParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        // Split on colons, but taking care to ignore escaped ones in case the regexp contains some
        let mut fields = value.split(unescaped_element(b'\\', b':'));

        let name = str::from_utf8(fields.next().ok_or(ParseError::MissingName)?)
            .map_err(ParseError::NameNotUnicode)?
            .to_owned();

        let container_type = parse_wildcard_field!(
            fields,
            ContainerType::try_from,
            ContainerMetadataSigParseError::MissingContainerType,
            ContainerMetadataSigParseError::from
        )?;

        let container_size = parse_wildcard_field!(
            fields,
            parse_container_size,
            ContainerMetadataSigParseError::MissingContainerSize,
            ContainerMetadataSigParseError::from
        )?;

        let filename_regexp_src = fields
            .next()
            .ok_or(ContainerMetadataSigParseError::MissingFilenameRegexp)?;

        let file_size_in_container = parse_wildcard_field!(
            fields,
            parse_number_dec,
            ContainerMetadataSigParseError::MissingFSIC,
            ContainerMetadataSigParseError::InvalidFSIC
        )?;

        let file_size_real = parse_wildcard_field!(
            fields,
            parse_number_dec,
            ContainerMetadataSigParseError::MissingFSReal,
            ContainerMetadataSigParseError::InvalidFSReal
        )?;

        let is_encrypted = parse_wildcard_field!(
            fields,
            parse_bool_from_int,
            ContainerMetadataSigParseError::MissingIsEnc,
            ContainerMetadataSigParseError::InvalidIsEnc
        )?;

        let file_pos = parse_wildcard_field!(
            fields,
            parse_number_dec,
            ContainerMetadataSigParseError::MissingFilePos,
            ContainerMetadataSigParseError::InvalidFilePos
        )?;

        let res1 = parse_wildcard_field!(
            fields,
            parse_number_dec::<u32>,
            ContainerMetadataSigParseError::MissingRes1,
            ContainerMetadataSigParseError::InvalidRes1
        )?;

        Ok(Self {
            name,
            container_type,
            container_size,
            filename_regexp_src: String::from_utf8(filename_regexp_src.to_owned()).unwrap(),
            file_size_in_container,
            file_size_real,
            is_encrypted,
            file_pos,
            res1,
        })
    }
}

impl Signature for ContainerMetadataSig {
    fn name(&self) -> &str {
        todo!()
    }

    fn feature_levels(&self) -> (usize, Option<usize>) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::ContainerMetadataSig;

    #[test]
    fn full_sig() {
        let bytes = r#"Email.Trojan.Toa-1:CL_TYPE_ZIP:*:Courrt.{1,15}\.scr$:*:*:*:*:*:"#.as_bytes();
        let sig = ContainerMetadataSig::try_from(bytes).unwrap();
        dbg!(sig);
    }
}
