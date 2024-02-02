mod container_size;
mod container_type;

use crate::{
    feature::{EngineReq, Set},
    regexp::Match,
    sigbytes::{AppendSigBytes, FromSigBytes},
    signature::{FromSigBytesParseError, SigMeta, Signature},
    util::{
        parse_bool_from_int, parse_field, parse_number_dec, unescaped_element,
        ParseBoolFromIntError, ParseNumberError, Range, RangeParseError,
    },
    Feature,
};
use container_size::{parse, ContainerSize};
use container_type::ContainerType;
use std::{fmt::Write, str};
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug)]
pub struct ContainerMetadataSig {
    name: String,
    container_type: Option<ContainerType>,
    container_size: Option<ContainerSize>,
    filename_regexp: Option<Match>,
    file_size_in_container: Option<Range<usize>>,
    file_size_real: Option<Range<usize>>,
    is_encrypted: Option<bool>,
    file_pos: Option<usize>,
    res1: Option<u32>,
}

#[derive(Debug, Error, PartialEq)]
pub enum ParseError {
    #[error("missing ContainerType field")]
    MissingContainerType,

    #[error("parsing ContainerType: {0}")]
    ContainerType(#[from] container_type::ParseError),

    #[error("missing ContainerSize field")]
    MissingContainerSize,

    #[error("parsing ContainerType: {0}")]
    ContainerSize(#[from] container_size::ParseError),

    #[error("missing FileNameREGEX field")]
    MissingFilenameRegexp,

    #[error("FileNameREGEX not unicode: {0}")]
    FilenameRegexp(crate::regexp::ParseError),

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

    #[error("Parsing min_flevel: {0}")]
    ParseMinFlevel(ParseNumberError<u32>),

    #[error("Parsing max_flevel: {0}")]
    ParseMaxFlevel(ParseNumberError<u32>),
}

#[derive(Debug, Error, PartialEq)]
pub enum ValidationError {}

impl FromSigBytes for ContainerMetadataSig {
    #[allow(clippy::too_many_lines)]
    fn from_sigbytes<'a, SB: Into<&'a crate::sigbytes::SigBytes>>(
        sb: SB,
    ) -> Result<(Box<dyn Signature>, super::SigMeta), FromSigBytesParseError> {
        let mut sigmeta = SigMeta::default();

        // Split on colons, but taking care to ignore escaped ones in case the regexp contains some
        let mut fields = sb.into().as_bytes().split(unescaped_element(b'\\', b':'));

        // Field 1
        let name = str::from_utf8(fields.next().ok_or(FromSigBytesParseError::MissingName)?)
            .map_err(FromSigBytesParseError::NameNotUnicode)?
            .to_owned();

        // Field 2
        let container_type = parse_field!(
            OPTIONAL
            fields,
            ContainerType::try_from,
            ParseError::MissingContainerType,
            ParseError::from
        )?;

        // Field 3
        let container_size = parse_field!(
            OPTIONAL
            fields,
            parse,
            ParseError::MissingContainerSize,
            ParseError::from
        )?;

        // Field 4
        let filename_regexp = parse_field!(
            OPTIONAL
            fields,
            Match::try_from,
            ParseError::MissingFilenameRegexp,
            ParseError::FilenameRegexp
        )?;

        // Field 5
        let file_size_in_container = parse_field!(
            OPTIONAL
            fields,
            Range::try_from,
            ParseError::MissingFSIC,
            ParseError::InvalidFSIC
        )?;
        if !matches!(
            file_size_in_container,
            None | Some(Range::Exact(_) | Range::Inclusive(_))
        ) {
            dbg!(file_size_in_container);
            return Err(ParseError::FSICRangeType.into());
        }

        // Field 6
        let file_size_real = parse_field!(
            OPTIONAL
            fields,
            Range::try_from,
            ParseError::MissingFSReal,
            ParseError::InvalidFSReal
        )?;
        if !matches!(
            file_size_real,
            None | Some(Range::Exact(_) | Range::Inclusive(_))
        ) {
            dbg!(file_size_real);
            return Err(ParseError::FSRealRangeType.into());
        }

        // Field 7
        let is_encrypted = parse_field!(
            OPTIONAL
            fields,
            parse_bool_from_int,
            ParseError::MissingIsEnc,
            ParseError::InvalidIsEnc
        )?;

        // Field 8
        let file_pos = parse_field!(
            OPTIONAL
            fields,
            parse_number_dec,
            ParseError::MissingFilePos,
            ParseError::InvalidFilePos
        )?;

        // Field 9
        let res1 = parse_field!(
            OPTIONAL
            fields,
            parse_number_dec::<u32>,
            ParseError::MissingRes1,
            ParseError::InvalidRes1
        )?;

        // Parse optional min/max flevel
        if let Some(min_flevel) = fields.next() {
            if !min_flevel.is_empty() {
                let min_flevel =
                    parse_number_dec(min_flevel).map_err(ParseError::ParseMinFlevel)?;

                if let Some(max_flevel) = fields.next() {
                    let max_flevel =
                        parse_number_dec(max_flevel).map_err(ParseError::ParseMaxFlevel)?;
                    sigmeta.f_level = Some((min_flevel..=max_flevel).into());
                } else {
                    sigmeta.f_level = Some((min_flevel..).into());
                }
            }
        }

        Ok((
            Box::new(Self {
                name,
                container_type,
                container_size,
                filename_regexp,
                file_size_in_container,
                file_size_real,
                is_encrypted,
                file_pos,
                res1,
            }),
            sigmeta,
        ))
    }
}

impl Signature for ContainerMetadataSig {
    fn name(&self) -> &str {
        &self.name
    }
}

impl EngineReq for ContainerMetadataSig {
    fn features(&self) -> crate::feature::Set {
        Set::from_static(&[Feature::ContentMetadataSig])
    }
}

impl AppendSigBytes for ContainerMetadataSig {
    fn append_sigbytes(
        &self,
        sb: &mut crate::sigbytes::SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        sb.write_str(&self.name)?;
        sb.write_char(':')?;

        if let Some(container_type) = &self.container_type {
            container_type.append_sigbytes(sb)?;
        } else {
            sb.write_char('*')?;
        }
        sb.write_char(':')?;

        if let Some(container_size) = &self.container_size {
            container_size.append_sigbytes(sb)?;
        } else {
            sb.write_char('*')?;
        }
        sb.write_char(':')?;

        if let Some(filename_regexp) = &self.filename_regexp {
            filename_regexp.append_sigbytes(sb)?;
        } else {
            sb.write_char('*')?;
        }
        sb.write_char(':')?;

        if let Some(file_size_in_container) = &self.file_size_in_container {
            file_size_in_container.append_sigbytes(sb)?;
        } else {
            sb.write_char('*')?;
        }
        sb.write_char(':')?;

        if let Some(file_size_real) = &self.file_size_real {
            file_size_real.append_sigbytes(sb)?;
        } else {
            sb.write_char('*')?;
        }
        sb.write_char(':')?;

        sb.write_char(if let Some(is_encrypted) = self.is_encrypted {
            if is_encrypted {
                '1'
            } else {
                '0'
            }
        } else {
            '*'
        })?;
        sb.write_char(':')?;

        if let Some(file_pos) = &self.file_pos {
            write!(sb, "{file_pos}")?;
        } else {
            sb.write_char('*')?;
        }
        sb.write_char(':')?;

        if let Some(res1) = &self.res1 {
            write!(sb, "{res1}")?;
        } else {
            sb.write_char('*')?;
        }

        // Notice: colon intentially output here so that `Res2` can be present,
        // but empty.  Res2 is not yet supported at all (since it has no
        // function).  However, it will need to be included once FLevel min/max
        // are appended.
        sb.write_char(':')?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigbytes::SigBytes;

    const SAMPLE_SIG: &[u8] =
        br"Email.Trojan.Toa-1:CL_TYPE_ZIP:1337:Courrt.{1,15}\.scr$:220-221:2008:0:2010:*:99:101";

    const SAMPLE_SIG_WITHOUT_FLEVEL: &[u8] =
        br"Email.Trojan.Toa-1:CL_TYPE_ZIP:1337:Courrt.{1,15}\.scr$:220-221:2008:0:2010:*:";

    #[test]
    fn full_sig() {
        let bytes = SAMPLE_SIG.into();
        let (sig, meta) = ContainerMetadataSig::from_sigbytes(&bytes).unwrap();
        dbg!(sig);
        assert_eq!(
            meta,
            SigMeta {
                f_level: Some((99..=101).into()),
            }
        );
    }

    #[test]
    fn bad_filename_regex() {
        // This signature has an 8-bit ASCII '¢' sign in the regexp
        let bytes = SigBytes::from(&[
            0x53u8, 0x61, 0x6e, 0x65, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x46,
            0x6f, 0x78, 0x68, 0x6f, 0x6c, 0x65, 0x2e, 0x5a, 0x69, 0x70, 0x5f, 0x66, 0x73, 0x31,
            0x30, 0x32, 0x37, 0x3a, 0x43, 0x4c, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x5a, 0x49,
            0x50, 0x3a, 0x2a, 0x3a, 0x28, 0x3f, 0x69, 0x29, 0x77, 0x68, 0x61, 0x74, 0x73, 0x61,
            0x70, 0x70, 0x20, 0x68, 0x69, 0x73, 0x74, 0xa2, 0x72, 0x69, 0x63, 0x6f, 0x20, 0x64,
            0x65, 0x20, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x2e, 0x7b, 0x30, 0x2c,
            0x32, 0x30, 0x7d, 0x5c, 0x2e, 0x65, 0x78, 0x65, 0x24, 0x3a, 0x2a, 0x3a, 0x2a, 0x3a,
            0x2a, 0x3a, 0x31, 0x3a, 0x2a, 0x3a, 0x2a, 0x0a,
        ]);
        if let Err(e) = ContainerMetadataSig::from_sigbytes(&bytes) {
            eprintln!("{e}");
        }
    }

    #[test]
    fn export() {
        let input = SAMPLE_SIG_WITHOUT_FLEVEL.into();
        let (sig, _) = ContainerMetadataSig::from_sigbytes(&input).unwrap();
        let exported = sig.to_sigbytes().unwrap();
        assert_eq!(&input, &exported);
    }
}
