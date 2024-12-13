/*
 *  Copyright (C) 2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

use super::super::targettype::TargetType;
use crate::{
    feature::{EngineReq, Set},
    filetype::{FileType, FileTypeParseError},
    sigbytes::{AppendSigBytes, SigBytes},
    signature::ToSigBytesError,
    util::{self, parse_number_dec, ParseNumberError, Range},
    Feature,
};
use num_traits::{FromPrimitive, ToPrimitive};
use std::{fmt::Write, str};
use thiserror::Error;

// The minimum Engine (flevel) that must be present when the Engine attribute is
// specified
const MINIMUM_ENGINE_SPEC: u32 = 51;

#[derive(Debug, Default, PartialEq)]
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
    Container(FileTypeParseError),

    #[error("parsing Intermediate container element: {0}")]
    IntermediateContainer(FileTypeParseError),

    #[error("parsing container value: {0}")]
    HandlerType(FileTypeParseError),

    #[error("parsing IconGroup1 value: {0}")]
    IconGroup1(std::str::Utf8Error),

    #[error("parsing IconGroup2 value: {0}")]
    IconGroup2(std::str::Utf8Error),

    #[error("parsing target_type: {0}")]
    TargetType(ParseNumberError<usize>),
}

#[derive(Debug, Error, PartialEq)]
pub enum TargetDescValidationError {
    #[error("Engine attribute present, but not first TargetDesc attribute")]
    EnginePresentNotFirst,

    #[error("Engine minimum ({found}) is lower than allowed minimum ({MINIMUM_ENGINE_SPEC})")]
    EngineNotMinimum { found: u32 },

    #[error("TargetDesc {found:?} attr requires Engine attr")]
    AttrRequiresEngine { found: TargetDescAttr },

    #[error("{attr} disallowed without native executable Target")]
    AttrRequiresNativeExecTarget { attr: &'static str },

    #[error("IconGroup1/2 requires PE Target (found {target_type:?})")]
    IconGroupRequiresTargetTypePE { target_type: Option<TargetType> },
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

    #[allow(clippy::too_many_lines)]
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
                        TargetDescParseError::TargetDescAttrMissingValue("NumberOfSections"),
                    )?)
                    .map_err(TargetDescParseError::NumberOfSections)?;
                    tdesc
                        .attrs
                        .push(TargetDescAttr::NumberOfSections(Range::Inclusive(
                            number_of_sections,
                        )));
                }

                b"Container" => {
                    let container = value
                        .ok_or(TargetDescParseError::TargetDescAttrMissingValue(
                            "Container",
                        ))?
                        .try_into()
                        .map_err(TargetDescParseError::Container)?;
                    tdesc.attrs.push(TargetDescAttr::Container(container));
                }
                b"Intermediates" => {
                    let mut containers = vec![];
                    for container in value
                        .ok_or(TargetDescParseError::TargetDescAttrMissingValue(
                            "Intermediates",
                        ))?
                        .split(|&b| b == b'>')
                    {
                        containers.push(
                            container
                                .try_into()
                                .map_err(TargetDescParseError::IntermediateContainer)?,
                        );
                    }
                    tdesc.attrs.push(TargetDescAttr::Intermediates(containers));
                }
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
                    let handler_type = value
                        .ok_or(TargetDescParseError::TargetDescAttrMissingValue(
                            "Container",
                        ))?
                        .try_into()
                        .map_err(TargetDescParseError::HandlerType)?;
                    tdesc.attrs.push(TargetDescAttr::HandlerType(handler_type));
                }
                s => return Err(TargetDescParseError::UnknownTargetDescAttr(s.into())),
            }
        }

        Ok(tdesc)
    }
}

impl EngineReq for TargetDesc {
    fn features(&self) -> Set {
        Set::from(
            self.attrs
                .iter()
                .filter_map(|attr| match attr {
                    TargetDescAttr::TargetType(target_type) => Some(target_type.features()),
                    TargetDescAttr::Container(file_type)
                    | TargetDescAttr::HandlerType(file_type) => Some(file_type.features()),
                    _ => None,
                })
                .flatten()
                .collect::<Vec<Feature>>()
                .into_iter(),
        )
    }
}

impl TargetDesc {
    pub(crate) fn validate(&self) -> Result<(), TargetDescValidationError> {
        self.validate_engine()?;
        self.validate_native_exec_attrs()?;
        self.validate_icongroup()?;
        Ok(())
    }

    fn validate_engine(&self) -> Result<(), TargetDescValidationError> {
        // See CLAM-1742 for additional details.

        // Search for the Engine attribute (along with its index)
        if let Some((pos, range)) = self.attrs.iter().enumerate().find_map(|(pos, attr)| {
            if let TargetDescAttr::Engine(range) = attr {
                Some((pos, range))
            } else {
                None
            }
        }) {
            if pos != 0 {
                // Engine must be in first position when present
                return Err(TargetDescValidationError::EnginePresentNotFirst);
            }
            if let Range::Inclusive(range) = range {
                // This is the only range variant currently used for Engine
                if *range.start() < MINIMUM_ENGINE_SPEC {
                    // Engine must be in first position when present
                    return Err(TargetDescValidationError::EngineNotMinimum {
                        found: *range.start(),
                    });
                }
            } else {
                // No other range variants are used in Engine attrs
                unreachable!();
            }
        } else {
            // Engine attr not present. Any attrs incompatible with this?
            if let Some(attr) = self.attrs.iter().find(|attr| {
                matches!(
                    attr,
                    TargetDescAttr::TargetType(_) | TargetDescAttr::Intermediates(_)
                )
            }) {
                return Err(TargetDescValidationError::AttrRequiresEngine {
                    found: attr.clone(),
                });
            }
        }

        Ok(())
    }

    // Verify that the EntryPoint and NumberOfSections attributes are present
    // only when a native executable target is specified.
    fn validate_native_exec_attrs(&self) -> Result<(), TargetDescValidationError> {
        let mut is_native_exec = false;
        let mut found_attr = None;

        for attr in &self.attrs {
            match attr {
                TargetDescAttr::TargetType(target_type) => {
                    is_native_exec = target_type.is_native_executable();
                }
                TargetDescAttr::EntryPoint(_) => found_attr = Some("EntryPoint"),
                TargetDescAttr::NumberOfSections(_) => found_attr = Some("NumberOfSections"),
                _ => (),
            }
        }

        if let Some(attr) = found_attr {
            if !is_native_exec {
                return Err(TargetDescValidationError::AttrRequiresNativeExecTarget { attr });
            }
        }

        Ok(())
    }

    // IconGroup1/2 are only allowed when the TargetType is "PE"
    fn validate_icongroup(&self) -> Result<(), TargetDescValidationError> {
        let mut found_icongroup = false;
        let mut target_type = None;

        for attr in &self.attrs {
            match attr {
                TargetDescAttr::TargetType(TargetType::PE) => return Ok(()),
                TargetDescAttr::TargetType(tt) => {
                    target_type = Some(*tt);
                    if found_icongroup {
                        break;
                    }
                }
                TargetDescAttr::IconGroup1(_) | TargetDescAttr::IconGroup2(_) => {
                    found_icongroup = true;
                    if target_type.is_some() {
                        break;
                    }
                }
                _ => (),
            }
        }

        // This is only reached if no TargetType was present, or the TargetType wasn't PE
        if found_icongroup {
            Err(TargetDescValidationError::IconGroupRequiresTargetTypePE { target_type })
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TargetDescAttr {
    Engine(Range<u32>),
    TargetType(TargetType),
    FileSize(Range<usize>),
    EntryPoint(Range<usize>),
    NumberOfSections(Range<usize>),
    Container(FileType),
    Intermediates(Vec<FileType>),
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
                write!(sb, "Target:{}", target_type.to_usize().unwrap())?;
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
            TargetDescAttr::Intermediates(file_types) => {
                for (i, file_type) in file_types.iter().enumerate() {
                    if i > 0 {
                        sb.write_char('>')?;
                    }
                    write!(sb, "{file_type}")?;
                }
            }
            TargetDescAttr::HandlerType(file_type) => {
                write!(sb, "HandlerType:{file_type}")?;
            }
            TargetDescAttr::IconGroup1(s) => write!(sb, "IconGroup1:{s}")?,
            TargetDescAttr::IconGroup2(s) => write!(sb, "IconGroup2:{s}")?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intermediates_from_sigbytes() {
        let bytes = b"Intermediates:CL_TYPE_ZIP>CL_TYPE_RAR>CL_TYPE_GRAPHICS".as_ref();
        let desc = TargetDesc::try_from(bytes).unwrap();
        assert_eq!(
            desc,
            TargetDesc {
                attrs: vec![TargetDescAttr::Intermediates(vec![
                    FileType::CL_TYPE_ZIP,
                    FileType::CL_TYPE_RAR,
                    FileType::CL_TYPE_GRAPHICS,
                ])],
            }
        );
    }

    #[test]
    fn export_intermediates() {
        let desc = TargetDesc {
            attrs: vec![TargetDescAttr::Intermediates(vec![
                FileType::CL_TYPE_ZIP,
                FileType::CL_TYPE_RAR,
                FileType::CL_TYPE_GRAPHICS,
            ])],
        };
        let mut exported = SigBytes::default();
        desc.append_sigbytes(&mut exported).unwrap();
        assert_eq!(
            exported.to_string(),
            "CL_TYPE_ZIP>CL_TYPE_RAR>CL_TYPE_GRAPHICS"
        );
    }

    #[test]
    fn clam_1742_first_attr() {
        let desc = TargetDesc {
            attrs: vec![
                TargetDescAttr::FileSize((99..=101).into()),
                TargetDescAttr::Engine((51..=99).into()),
            ],
        };
        assert_eq!(
            desc.validate(),
            Err(TargetDescValidationError::EnginePresentNotFirst)
        );
    }

    #[test]
    fn clam_1742_engine_min() {
        let desc = TargetDesc {
            attrs: vec![
                TargetDescAttr::Engine((49..=99).into()),
                TargetDescAttr::FileSize((99..=101).into()),
            ],
        };
        assert_eq!(
            desc.validate(),
            Err(TargetDescValidationError::EngineNotMinimum { found: 49 })
        );
    }

    #[test]
    fn clam_1742_attr_requires_engine() {
        const ATTR: TargetDescAttr = TargetDescAttr::TargetType(TargetType::Graphics);
        let desc = TargetDesc { attrs: vec![ATTR] };
        let result = desc.validate();
        assert_eq!(
            result,
            Err(TargetDescValidationError::AttrRequiresEngine { found: ATTR })
        );
    }

    #[test]
    fn clam_1749_disallow_ep_without_binary_target() {
        let desc = TargetDesc {
            attrs: vec![TargetDescAttr::EntryPoint((5..).into())],
        };
        let result = desc.validate();
        assert_eq!(
            result,
            Err(TargetDescValidationError::AttrRequiresNativeExecTarget { attr: "EntryPoint" })
        );
    }

    #[test]
    fn clam_1749_disallow_nos_without_binary_target() {
        let desc = TargetDesc {
            attrs: vec![TargetDescAttr::NumberOfSections((5..).into())],
        };
        let result = desc.validate();
        assert_eq!(
            result,
            Err(TargetDescValidationError::AttrRequiresNativeExecTarget {
                attr: "NumberOfSections"
            })
        );
    }

    #[test]
    fn clam_1741_icongroup_requires_pe_target() {
        let desc = TargetDesc {
            attrs: vec![
                TargetDescAttr::Engine((51..=99).into()),
                TargetDescAttr::TargetType(TargetType::Any),
                TargetDescAttr::IconGroup1("test".into()),
            ],
        };
        let result = desc.validate();
        assert_eq!(
            result,
            Err(TargetDescValidationError::IconGroupRequiresTargetTypePE {
                target_type: Some(TargetType::Any)
            })
        );

        // Reverse the attributes to test the alternative logic
        let desc = TargetDesc {
            attrs: vec![
                TargetDescAttr::Engine((51..=99).into()),
                TargetDescAttr::IconGroup1("test".into()),
                TargetDescAttr::TargetType(TargetType::Any),
            ],
        };
        let result = desc.validate();
        assert_eq!(
            result,
            Err(TargetDescValidationError::IconGroupRequiresTargetTypePE {
                target_type: Some(TargetType::Any)
            })
        );

        // And test with no TargetType at all
        let desc = TargetDesc {
            attrs: vec![
                TargetDescAttr::Engine((51..=99).into()),
                TargetDescAttr::IconGroup1("test".into()),
            ],
        };
        let result = desc.validate();
        assert_eq!(
            result,
            Err(TargetDescValidationError::IconGroupRequiresTargetTypePE { target_type: None })
        );
    }
}
