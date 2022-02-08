mod container_size;
mod container_type;

use super::{ParseError, Signature};
use crate::util::{
    parse_bool_from_int, parse_number_dec, parse_wildcard_field, unescaped_element,
    ParseBoolFromIntError, ParseNumberError, Range, RangeParseError,
};
use container_size::parse_container_size;
use container_size::{ContainerSize, ContainerSizeParseError};
use container_type::{ContainerType, ContainerTypeParseError};
use std::str;
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug)]
pub struct ContainerMetadataSig {
    name: String,
    container_type: Option<ContainerType>,
    container_size: Option<ContainerSize>,
    filename_regexp_src: Option<String>,
    file_size_in_container: Option<Range<usize>>,
    file_size_real: Option<Range<usize>>,
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

    #[error("FileNameREGEX not unicode: {0}")]
    FilenameRegexpNotUnicode(std::string::FromUtf8Error),

    #[error("missing FileSizeInContainer field")]
    MissingFSIC,

    #[error("invalid FileSizeInContainer field: {0}")]
    InvalidFSIC(RangeParseError<usize>),

    #[error("invalid FileSizeInContainer field: only exact or inclusive ranges allowed")]
    FSICRangeType,

    #[error("missing FileSizeReal field")]
    MissingFSReal,

    #[error("invalid FileSizeReal field: {0}")]
    InvalidFSReal(RangeParseError<usize>),

    #[error("invalid FileSizeReal field: only exact or inclusive ranges allowed")]
    FSRealRangeType,

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

        // Field 1
        let name = str::from_utf8(fields.next().ok_or(ParseError::MissingName)?)
            .map_err(ParseError::NameNotUnicode)?
            .to_owned();

        // Field 2
        let container_type = parse_wildcard_field!(
            fields,
            ContainerType::try_from,
            ContainerMetadataSigParseError::MissingContainerType,
            ContainerMetadataSigParseError::from
        )?;

        // Field 3
        let container_size = parse_wildcard_field!(
            fields,
            parse_container_size,
            ContainerMetadataSigParseError::MissingContainerSize,
            ContainerMetadataSigParseError::from
        )?;

        // Field 4
        let filename_regexp_src = parse_wildcard_field!(
            fields,
            |bytes| String::from_utf8(bytes.to_owned()),
            ContainerMetadataSigParseError::MissingFilenameRegexp,
            ContainerMetadataSigParseError::FilenameRegexpNotUnicode
        )?;

        // Field 5
        let file_size_in_container = parse_wildcard_field!(
            fields,
            Range::try_from,
            ContainerMetadataSigParseError::MissingFSIC,
            ContainerMetadataSigParseError::InvalidFSIC
        )?;
        if !matches!(
            file_size_in_container,
            None | Some(Range::Exact(_) | Range::Inclusive(_))
        ) {
            dbg!(file_size_in_container);
            return Err(ContainerMetadataSigParseError::FSICRangeType.into());
        }

        // Field 6
        let file_size_real = parse_wildcard_field!(
            fields,
            Range::try_from,
            ContainerMetadataSigParseError::MissingFSReal,
            ContainerMetadataSigParseError::InvalidFSReal
        )?;
        if !matches!(
            file_size_real,
            None | Some(Range::Exact(_) | Range::Inclusive(_))
        ) {
            dbg!(file_size_real);
            return Err(ContainerMetadataSigParseError::FSRealRangeType.into());
        }

        // Field 7
        let is_encrypted = parse_wildcard_field!(
            fields,
            parse_bool_from_int,
            ContainerMetadataSigParseError::MissingIsEnc,
            ContainerMetadataSigParseError::InvalidIsEnc
        )?;

        // Field 8
        let file_pos = parse_wildcard_field!(
            fields,
            parse_number_dec,
            ContainerMetadataSigParseError::MissingFilePos,
            ContainerMetadataSigParseError::InvalidFilePos
        )?;

        // Field 9
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
            filename_regexp_src,
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

    #[test]
    fn bad_filename_regex() {
        // This signature has an 8-bit ASCII '¢' sign in the regexp
        let bytes: &[u8] = &[
            0x53, 0x61, 0x6e, 0x65, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x46,
            0x6f, 0x78, 0x68, 0x6f, 0x6c, 0x65, 0x2e, 0x5a, 0x69, 0x70, 0x5f, 0x66, 0x73, 0x31,
            0x30, 0x32, 0x37, 0x3a, 0x43, 0x4c, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x5a, 0x49,
            0x50, 0x3a, 0x2a, 0x3a, 0x28, 0x3f, 0x69, 0x29, 0x77, 0x68, 0x61, 0x74, 0x73, 0x61,
            0x70, 0x70, 0x20, 0x68, 0x69, 0x73, 0x74, 0xa2, 0x72, 0x69, 0x63, 0x6f, 0x20, 0x64,
            0x65, 0x20, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x2e, 0x7b, 0x30, 0x2c,
            0x32, 0x30, 0x7d, 0x5c, 0x2e, 0x65, 0x78, 0x65, 0x24, 0x3a, 0x2a, 0x3a, 0x2a, 0x3a,
            0x2a, 0x3a, 0x31, 0x3a, 0x2a, 0x3a, 0x2a, 0x0a,
        ];
        if let Err(e) = ContainerMetadataSig::try_from(bytes) {
            eprintln!("{}", e)
        }
    }
}
