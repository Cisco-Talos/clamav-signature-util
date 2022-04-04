use super::super::targettype::TargetType;
use crate::{
    feature::{EngineReq, FeatureSet},
    filetype::FileType,
    sigbytes::{AppendSigBytes, SigBytes},
    signature::ToSigBytesError,
    util::{self, parse_number_dec, ParseNumberError, Range},
};
use num_traits::{FromPrimitive, ToPrimitive};
use std::{fmt::Write, str, str::FromStr};
use thiserror::Error;

#[derive(Debug, Default)]
pub struct TargetDesc {
    pub(crate) attrs: Vec<TargetDescAttr>,
}

#[derive(Debug, Error, PartialEq)]
pub enum TargetDescParseError {
    #[error("unknown TargetDescription attribute: {0}")]
    UnknownTargetDescAttr(SigBytes),

    #[error("TargetDescription contains empty attribute")]
    TargetDescAttrEmpty,

    #[error("TargetDescription {0} attribute missing value")]
    TargetDescAttrMissingValue(&'static str),

    #[error("unknown target type value")]
    UnknownTargetType,

    #[error("unknown FileType")]
    UnknownFileType,

    #[error("parsing EngineRange")]
    EngineRange(util::RangeInclusiveParseError<u32>),

    #[error("parsing FileSize")]
    FileSize(util::RangeInclusiveParseError<usize>),

    #[error("parsing EntryPoint")]
    EntryPoint(util::RangeInclusiveParseError<usize>),

    #[error("parsing NumberOfSections")]
    NumberOfSections(util::RangeInclusiveParseError<usize>),

    #[error("parsing container value: {0}")]
    Container(std::str::Utf8Error),

    #[error("parsing container value: {0}")]
    HandlerType(std::str::Utf8Error),

    #[error("parsing IconGroup1 value: {0}")]
    IconGroup1(std::str::Utf8Error),

    #[error("parsing IconGroup2 value: {0}")]
    IconGroup2(std::str::Utf8Error),

    #[error("parsing target_type: {0}")]
    TargetType(ParseNumberError<usize>),
}

impl AppendSigBytes for TargetDesc {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), ToSigBytesError> {
        for (i, attr) in self.attrs.iter().enumerate() {
            if i > 0 {
                sb.write_char(',')?;
            }
            attr.append_sigbytes(sb)?;
        }

        Ok(())
    }
}

impl TryFrom<&[u8]> for TargetDesc {
    type Error = TargetDescParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut tdesc = TargetDesc::default();
        for attr in value.split(|&b| b == b',') {
            let mut attr_pair = attr.splitn(2, |&b| b == b':');
            let attr_name = attr_pair
                .next()
                .ok_or(TargetDescParseError::TargetDescAttrEmpty)?;
            let value = attr_pair.next();
            // eprintln!("attr_name = {}", str::from_utf8(attr_name)?);
            match attr_name {
                b"Target" => {
                    let target_type =
                        FromPrimitive::from_usize(
                            parse_number_dec(value.ok_or(
                                TargetDescParseError::TargetDescAttrMissingValue("Target"),
                            )?)
                            .map_err(TargetDescParseError::TargetType)?,
                        )
                        .ok_or(TargetDescParseError::UnknownTargetType)?;
                    tdesc.attrs.push(TargetDescAttr::TargetType(target_type));
                }
                b"Engine" => {
                    let f_level = util::parse_range_inclusive(
                        value.ok_or(TargetDescParseError::TargetDescAttrMissingValue("Engine"))?,
                    )
                    .map_err(TargetDescParseError::EngineRange)?;
                    tdesc
                        .attrs
                        .push(TargetDescAttr::Engine(Range::Inclusive(f_level)));
                }
                b"FileSize" => {
                    let file_size = util::parse_range_inclusive(
                        value
                            .ok_or(TargetDescParseError::TargetDescAttrMissingValue("FileSize"))?,
                    )
                    .map_err(TargetDescParseError::FileSize)?;
                    tdesc
                        .attrs
                        .push(TargetDescAttr::FileSize(Range::Inclusive(file_size)));
                }
                b"EntryPoint" => {
                    let entry_point = util::parse_range_inclusive(value.ok_or(
                        TargetDescParseError::TargetDescAttrMissingValue("EntryPoint"),
                    )?)
                    .map_err(TargetDescParseError::EntryPoint)?;
                    tdesc
                        .attrs
                        .push(TargetDescAttr::EntryPoint(Range::Inclusive(entry_point)));
                }

                b"NumberOfSections" => {
                    let number_of_sections = util::parse_range_inclusive(value.ok_or(
                        TargetDescParseError::TargetDescAttrMissingValue("EntryPoint"),
                    )?)
                    .map_err(TargetDescParseError::NumberOfSections)?;
                    tdesc
                        .attrs
                        .push(TargetDescAttr::NumberOfSections(Range::Inclusive(
                            number_of_sections,
                        )));
                }

                b"Container" => {
                    let container = FileType::from_str(
                        str::from_utf8(value.ok_or(
                            TargetDescParseError::TargetDescAttrMissingValue("Container"),
                        )?)
                        .map_err(TargetDescParseError::Container)?,
                    )
                    .map_err(|_| TargetDescParseError::UnknownFileType)?;
                    tdesc.attrs.push(TargetDescAttr::Container(container));
                }
                b"Intermediates" => panic!("Intermediates"),
                b"IconGroup1" => {
                    let icon_group_1 = str::from_utf8(value.ok_or(
                        TargetDescParseError::TargetDescAttrMissingValue("IconGroup1"),
                    )?)
                    .map_err(TargetDescParseError::IconGroup1)?
                    .into();
                    tdesc.attrs.push(TargetDescAttr::IconGroup1(icon_group_1));
                }
                b"IconGroup2" => {
                    let icon_group_2 = str::from_utf8(value.ok_or(
                        TargetDescParseError::TargetDescAttrMissingValue("IconGroup2"),
                    )?)
                    .map_err(TargetDescParseError::IconGroup2)?
                    .into();
                    tdesc.attrs.push(TargetDescAttr::IconGroup2(icon_group_2));
                }
                b"HandlerType" => {
                    let handler_type = FileType::from_str(
                        str::from_utf8(value.ok_or(
                            TargetDescParseError::TargetDescAttrMissingValue("Container"),
                        )?)
                        .map_err(TargetDescParseError::HandlerType)?,
                    )
                    .map_err(|_| TargetDescParseError::UnknownFileType)?;
                    tdesc.attrs.push(TargetDescAttr::HandlerType(handler_type));
                }
                s => return Err(TargetDescParseError::UnknownTargetDescAttr(s.into())),
            }
        }

        Ok(tdesc)
    }
}

impl EngineReq for TargetDesc {
    fn features(&self) -> FeatureSet {
        self.attrs
            .iter()
            .find_map(|attr| {
                if let TargetDescAttr::TargetType(target_type) = attr {
                    Some(target_type.features())
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }
}

#[derive(Debug)]
pub enum TargetDescAttr {
    Engine(Range<u32>),
    TargetType(TargetType),
    FileSize(Range<usize>),
    EntryPoint(Range<usize>),
    NumberOfSections(Range<usize>),
    Container(FileType),
    // Undocumented
    HandlerType(FileType),
    IconGroup1(String),
    IconGroup2(String),
}

impl AppendSigBytes for TargetDescAttr {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        match self {
            TargetDescAttr::Engine(range) => {
                write!(sb, "Engine:")?;
                range.append_sigbytes(sb)?;
            }
            TargetDescAttr::TargetType(target_type) => {
                write!(sb, "Target:{}", target_type.to_usize().unwrap())?
            }
            TargetDescAttr::FileSize(range) => {
                write!(sb, "FileSize:")?;
                range.append_sigbytes(sb)?;
            }
            TargetDescAttr::EntryPoint(range) => {
                write!(sb, "EntryPoint:")?;
                range.append_sigbytes(sb)?;
            }
            TargetDescAttr::NumberOfSections(range) => {
                write!(sb, "NumberOfSections:")?;
                range.append_sigbytes(sb)?;
            }
            TargetDescAttr::Container(file_type) => {
                write!(sb, "Container:{file_type}")?;
            }
            TargetDescAttr::HandlerType(file_type) => {
                write!(sb, "HandlerType:{file_type}")?;
            }
            TargetDescAttr::IconGroup1(s) => write!(sb, "IconGroup1:{}", s)?,
            TargetDescAttr::IconGroup2(s) => write!(sb, "IconGroup2:{}", s)?,
        }
        Ok(())
    }
}
