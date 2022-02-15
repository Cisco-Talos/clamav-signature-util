use super::super::targettype::TargetType;
use crate::{
    feature::{EngineReq, FeatureSet},
    filetype::FileType,
    util::{self, parse_number_dec, ParseNumberError},
};
use num_traits::FromPrimitive;
use std::{ops::RangeInclusive, str, str::FromStr};
use thiserror::Error;

#[derive(Debug, Default)]
pub struct TargetDesc {
    /// Target
    target_type: Option<TargetType>,

    /// Engine
    f_level: Option<RangeInclusive<usize>>,
    /// FileSize
    file_size: Option<RangeInclusive<usize>>,
    /// EntryPoint
    entry_point: Option<RangeInclusive<usize>>,
    /// NumberOfSections
    number_of_sections: Option<RangeInclusive<usize>>,
    /// Container
    container: Option<FileType>,
    // Undocumented
    handler_type: Option<FileType>,
    // IconGroup1
    icon_group_1: Option<String>,
    // IconGroup2
    icon_group_2: Option<String>,
}

#[derive(Debug, Error)]
pub enum TargetDescParseError {
    #[error("unknown TargetDescription attribute: {0}")]
    UnknownTargetDescAttr(String),

    #[error("TargetDescription contains empty attribute")]
    TargetDescAttrEmpty,

    #[error("TargetDescription {0} attribute missing value")]
    TargetDescAttrMissingValue(&'static str),

    #[error("unknown target type value")]
    UnknownTargetType,

    #[error("unknown FileType")]
    UnknownFileType,

    #[error("parsing engine range")]
    EngineRange(#[from] util::RangeInclusiveParseError<usize>),

    #[error("parsing container value: {0}")]
    Container(#[from] std::str::Utf8Error),

    #[error("parsing target_type: {0}")]
    TargetType(#[from] ParseNumberError<usize>),
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
                    tdesc.target_type = Some(
                        FromPrimitive::from_usize(
                            parse_number_dec(value.ok_or(
                                TargetDescParseError::TargetDescAttrMissingValue("Target"),
                            )?)
                            .map_err(TargetDescParseError::TargetType)?,
                        )
                        .ok_or(TargetDescParseError::UnknownTargetType)?,
                    )
                }
                b"Engine" => {
                    tdesc.f_level =
                        Some(
                            util::parse_usize_range_inclusive(value.ok_or(
                                TargetDescParseError::TargetDescAttrMissingValue("Engine"),
                            )?)
                            .map_err(TargetDescParseError::EngineRange)?,
                        );
                }
                b"FileSize" => {
                    tdesc.file_size = Some(util::parse_usize_range_inclusive(
                        value
                            .ok_or(TargetDescParseError::TargetDescAttrMissingValue("FileSize"))?,
                    )?);
                }
                b"EntryPoint" => {
                    tdesc.entry_point = Some(util::parse_usize_range_inclusive(value.ok_or(
                        TargetDescParseError::TargetDescAttrMissingValue("EntryPoint"),
                    )?)?)
                }

                b"NumberOfSections" => {
                    tdesc.number_of_sections =
                        Some(util::parse_usize_range_inclusive(value.ok_or(
                            TargetDescParseError::TargetDescAttrMissingValue("EntryPoint"),
                        )?)?)
                }

                b"Container" => {
                    tdesc.container = Some(
                        FileType::from_str(
                            str::from_utf8(value.ok_or(
                                TargetDescParseError::TargetDescAttrMissingValue("Container"),
                            )?)
                            .map_err(TargetDescParseError::Container)?,
                        )
                        .map_err(|_| TargetDescParseError::UnknownFileType)?,
                    )
                }
                b"Intermediates" => panic!("Intermediates"),
                b"IconGroup1" => {
                    tdesc.icon_group_1 = Some(
                        str::from_utf8(value.ok_or(
                            TargetDescParseError::TargetDescAttrMissingValue("IconGroup1"),
                        )?)?
                        .into(),
                    )
                }
                b"IconGroup2" => {
                    tdesc.icon_group_2 = Some(
                        str::from_utf8(value.ok_or(
                            TargetDescParseError::TargetDescAttrMissingValue("IconGroup2"),
                        )?)?
                        .into(),
                    )
                }
                b"HandlerType" => {
                    tdesc.handler_type = Some(
                        FileType::from_str(str::from_utf8(value.ok_or(
                            TargetDescParseError::TargetDescAttrMissingValue("Container"),
                        )?)?)
                        .map_err(|_| TargetDescParseError::UnknownFileType)?,
                    )
                }
                s => {
                    return Err(TargetDescParseError::UnknownTargetDescAttr(
                        str::from_utf8(s)?.to_owned(),
                    ))
                }
            }
        }

        Ok(tdesc)
    }
}

impl EngineReq for TargetDesc {
    fn features(&self) -> FeatureSet {
        self.target_type
            .as_ref()
            .map(TargetType::features)
            .unwrap_or_default()
    }
}
