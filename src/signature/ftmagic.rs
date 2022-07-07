use super::{
    bodysig::parse::BodySigParseError,
    ext::{Offset, OffsetParseError},
    FromSigBytesParseError, SigMeta,
};
use crate::{
    feature::{EngineReq, FeatureSet},
    filetype::{FileType, FileTypeParseError},
    sigbytes::{AppendSigBytes, FromSigBytes},
    signature::bodysig::BodySig,
    util::{parse_field, parse_number_dec, ParseNumberError},
    Signature,
};
use std::{fmt::Write, str};
use thiserror::Error;

/// A FileType Magic signature.  Used to identify file types either through
/// simple identification of byte sequences at expected locations, or via execution
/// of a BodySig.
#[derive(Debug)]
pub struct FTMagicSig {
    pub name: String,
    pub rtype: FileType,
    pub file_type: FileType,
    pub magic_bytes: MagicBytes,
}

#[derive(Debug)]
pub enum MagicBytes {
    /// Direct memory comparison of `magicbytes` for file types (0)
    DirectMemory { offset: usize, literal: Vec<u8> },
    /// The `magicbytes` use the body-based content matching format (1)
    BodySig {
        offset: Option<Offset>,
        bodysig: BodySig,
    },
    /// Direct memory comparision of `magicbytes` for partiion types (HFS+, HFSX)
    DMPartition { offset: usize, literal: Vec<u8> },
}

#[derive(Debug, Error, PartialEq)]
pub enum FTMagicParseError {
    #[error("missing magictype")]
    MagicTypeMissing,

    #[error("missing offset")]
    OffsetMissing,

    #[error("parsing exact offset: {0}")]
    ExactOffsetParse(ParseNumberError<usize>),

    #[error("parsing bodysig offset: {0}")]
    OffsetParse(OffsetParseError),

    #[error("missing magicbytes")]
    MagicBytesMissing,

    #[error("missing rtype")]
    RtypeMissing,

    #[error("parsing rtype: {0}")]
    Rtype(FileTypeParseError),

    #[error("missing type")]
    TypeMissing,

    #[error("parsing type: {0}")]
    Type(FileTypeParseError),

    #[error("Parsing min_flevel: {0}")]
    ParseMinFlevel(ParseNumberError<u32>),

    #[error("Parsing max_flevel: {0}")]
    ParseMaxFlevel(ParseNumberError<u32>),

    #[error("Unkown magictype")]
    UnknownMagicType,

    #[error("decoding magicbytes for direct memory comparison: {0}")]
    DirectMemoryDecode(hex::FromHexError),

    #[error("decoding body signature from magicbytes: {0}")]
    BodySig(BodySigParseError),

    #[error("decoding magicbytes for direct memory (partition) comparison: {0}")]
    DMPartitionDecode(hex::FromHexError),

    /// Offset specified for DirectMemory or DMPartition file type is not an
    /// exact value (floating, and computed offsets are supported only for
    /// BodySig-based file typing).
    #[error("offset specified is not exact")]
    WrongOffsetType,
}

impl Signature for FTMagicSig {
    fn name(&self) -> &str {
        &self.name
    }
}

impl FromSigBytes for FTMagicSig {
    fn from_sigbytes<'a, SB: Into<&'a crate::sigbytes::SigBytes>>(
        sb: SB,
    ) -> Result<(Box<dyn Signature>, SigMeta), FromSigBytesParseError> {
        let mut sigmeta = SigMeta::default();

        // Split on colons
        let mut fields = sb.into().as_bytes().split(|&b| b == b':');

        // Field 1
        let magic_type = fields.next().ok_or(FTMagicParseError::MagicTypeMissing)?;

        // Field 2
        let offset = parse_field!(OPTIONAL fields, Offset::try_from, FTMagicParseError::OffsetMissing, FTMagicParseError::OffsetParse)?;

        // Field 3
        let magic_bytes_content = fields.next().ok_or(FTMagicParseError::MagicBytesMissing)?;

        // Field 4
        let name = str::from_utf8(fields.next().ok_or(FromSigBytesParseError::MissingName)?)
            .map_err(FromSigBytesParseError::NameNotUnicode)?
            .to_owned();

        // Field 5
        let rtype = parse_field!(
            fields,
            FileType::try_from,
            FTMagicParseError::RtypeMissing,
            FTMagicParseError::Rtype
        )?;

        // Field 6
        let file_type = parse_field!(
            fields,
            FileType::try_from,
            FTMagicParseError::TypeMissing,
            FTMagicParseError::Type
        )?;

        // Parse optional min/max flevel
        if let Some(min_flevel) = fields.next() {
            let min_flevel = if !min_flevel.is_empty() {
                Some(parse_number_dec(min_flevel).map_err(FTMagicParseError::ParseMinFlevel)?)
            } else {
                None
            };

            let max_flevel = if let Some(max_flevel) = fields.next() {
                Some(parse_number_dec(max_flevel).map_err(FTMagicParseError::ParseMaxFlevel)?)
            } else {
                None
            };

            match (min_flevel, max_flevel) {
                (Some(min), None) => sigmeta.f_level = Some((min..).into()),
                (None, Some(max)) => sigmeta.f_level = Some((..=max).into()),
                (Some(min), Some(max)) => sigmeta.f_level = Some((min..=max).into()),
                (None, None) => (),
            }
        }

        let magic_bytes = match magic_type {
            b"0" => MagicBytes::DirectMemory {
                offset: offset
                    .ok_or(FTMagicParseError::OffsetMissing)?
                    .absolute()
                    .ok_or(FTMagicParseError::WrongOffsetType)?,
                literal: hex::decode(magic_bytes_content)
                    .map_err(FTMagicParseError::DirectMemoryDecode)?,
            },
            b"1" => MagicBytes::BodySig {
                offset,
                bodysig: BodySig::try_from(magic_bytes_content)
                    .map_err(FTMagicParseError::BodySig)?,
            },
            b"4" => MagicBytes::DMPartition {
                offset: offset
                    .ok_or(FTMagicParseError::OffsetMissing)?
                    .absolute()
                    .ok_or(FTMagicParseError::WrongOffsetType)?,
                literal: hex::decode(magic_bytes_content)
                    .map_err(FTMagicParseError::DMPartitionDecode)?,
            },
            _ => return Err(FTMagicParseError::UnknownMagicType.into()),
        };

        Ok((
            Box::new(FTMagicSig {
                name,
                magic_bytes,
                rtype,
                file_type,
            }) as Box<dyn Signature>,
            sigmeta,
        ))
    }
}

impl AppendSigBytes for FTMagicSig {
    fn append_sigbytes(
        &self,
        sb: &mut crate::sigbytes::SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        match &self.magic_bytes {
            MagicBytes::DirectMemory { offset, .. } => write!(sb, "1:{offset}")?,
            MagicBytes::DMPartition { offset, .. } => write!(sb, "4:{offset}")?,
            MagicBytes::BodySig { offset, .. } => {
                sb.write_str("1:")?;
                if let Some(offset) = offset {
                    offset.append_sigbytes(sb)?;
                } else {
                    sb.write_char('*')?;
                }
            }
        }
        sb.write_char(':')?;

        match &self.magic_bytes {
            MagicBytes::DirectMemory { literal, .. } | MagicBytes::DMPartition { literal, .. } => {
                literal.as_slice().append_sigbytes(sb)?;
            }
            MagicBytes::BodySig { bodysig, .. } => bodysig.append_sigbytes(sb)?,
        }
        sb.write_char(':')?;

        write!(sb, "{}", self.name)?;
        sb.write_char(':')?;
        self.rtype.append_sigbytes(sb)?;
        sb.write_char(':')?;
        self.file_type.append_sigbytes(sb)?;

        Ok(())
    }
}

impl EngineReq for FTMagicSig {
    fn features(&self) -> crate::feature::FeatureSet {
        FeatureSet::from(
            self.rtype
                .features()
                .into_iter()
                .chain(self.file_type.features().into_iter()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigbytes::SigBytes;
    use crate::signature::ext::{Offset, OffsetPos};

    #[test]
    fn good_ftm_dm_sig() {
        let input = SigBytes::from("0:0:ffd8ff:JPEG:CL_TYPE_ANY:CL_TYPE_GRAPHICS::121");
        let (sig, sigmeta) = FTMagicSig::from_sigbytes(&input).unwrap();
        assert_eq!(sigmeta.f_level, Some((..=121).into()));
        let sig = sig.downcast_ref::<FTMagicSig>().unwrap();
        assert_eq!(&sig.name, "JPEG");
        assert_eq!(sig.rtype, FileType::CL_TYPE_ANY);
        assert_eq!(sig.file_type, FileType::CL_TYPE_GRAPHICS);
        assert!(matches!(
            sig.magic_bytes,
            MagicBytes::DirectMemory { offset: 0, .. }
        ));
        if let MagicBytes::DirectMemory { literal, .. } = &sig.magic_bytes {
            assert_eq!(&literal.as_slice(), &[0xff, 0xd8, 0xff]);
        }
    }

    #[test]
    fn good_ftm_bs_sig() {
        let input = SigBytes::from(
            "1:0:cafebabe0000000?:Universal Binary:CL_TYPE_ANY:CL_TYPE_MACHO_UNIBIN:75",
        );
        let (sig, sigmeta) = FTMagicSig::from_sigbytes(&input).unwrap();
        assert_eq!(sigmeta.f_level, Some((75..).into()));
        let sig = sig.downcast_ref::<FTMagicSig>().unwrap();
        assert_eq!(&sig.name, "Universal Binary");
        assert_eq!(sig.rtype, FileType::CL_TYPE_ANY);
        assert_eq!(sig.file_type, FileType::CL_TYPE_MACHO_UNIBIN);
        assert!(matches!(
            sig.magic_bytes,
            MagicBytes::BodySig {
                offset: Some(Offset::Normal(OffsetPos::Absolute(0))),
                bodysig: _
            }
        ));
    }

    #[test]
    fn good_ftm_dmpart_sig() {
        let input = SigBytes::from(
            "4:1024:482B0004:HFS+ partition:CL_TYPE_PART_ANY:CL_TYPE_PART_HFSPLUS:75",
        );
        let (sig, sigmeta) = FTMagicSig::from_sigbytes(&input).unwrap();
        assert_eq!(sigmeta.f_level, Some((75..).into()));
        let sig = sig.downcast_ref::<FTMagicSig>().unwrap();
        assert_eq!(&sig.name, "HFS+ partition");
        assert_eq!(sig.rtype, FileType::CL_TYPE_PART_ANY);
        assert_eq!(sig.file_type, FileType::CL_TYPE_PART_HFSPLUS);
        assert!(matches!(
            sig.magic_bytes,
            MagicBytes::DMPartition { offset: 1024, .. }
        ));
        if let MagicBytes::DMPartition { literal, .. } = &sig.magic_bytes {
            assert_eq!(&literal.as_slice(), &[0x48, 0x2b, 0x00, 0x04]);
        }
    }
}
