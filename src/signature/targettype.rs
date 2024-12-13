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

use crate::{
    feature::{EngineReq, Set},
    sigbytes::{AppendSigBytes, SigBytes},
    util::{parse_number_dec, ParseNumberError},
    Feature,
};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use thiserror::Error;

#[derive(Copy, Clone, Debug, PartialEq, FromPrimitive, ToPrimitive)]
pub enum TargetType {
    /// Any file
    Any = 0,
    /// Portable Executable, both 32- and 64-bit
    PE = 1,
    /// OLE2 containers, including specific macros. Primarily used by MS Office and MSI installation files
    OLE2 = 2,
    /// HTML (normalized)
    HTML = 3,
    /// Mail file
    Mail = 4,
    /// Graphics
    Graphics = 5,
    /// ELF
    ELF = 6,
    /// ASCII text file (normalized)
    Text = 7,
    /// Unused
    Unused = 8,
    /// Mach-O files
    MachO = 9,
    /// PDF files
    PDF = 10,
    /// Flash files
    Flash = 11,
    /// Java class files
    Java = 12,
}

#[derive(Debug, Error, PartialEq)]
pub enum TargetTypeParseError {
    #[error("invalid number: {0}")]
    ParseNumUsize(#[from] ParseNumberError<usize>),

    #[error("unknown TargetType ID")]
    Unknown,
}

impl TryFrom<&[u8]> for TargetType {
    type Error = TargetTypeParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        FromPrimitive::from_usize(parse_number_dec(value)?).ok_or(TargetTypeParseError::Unknown)
    }
}

impl EngineReq for TargetType {
    fn features(&self) -> Set {
        Set::from_static(match self {
            TargetType::PDF => &[Feature::TargetTypePdf],
            TargetType::Flash => &[Feature::TargetTypeFlash],
            TargetType::Java => &[Feature::TargetTypeJava],
            _ => return Set::default(),
        })
    }
}

impl AppendSigBytes for TargetType {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        use std::fmt::Write;
        if let Some(n) = self.to_usize() {
            Ok(write!(sb, "{n}")?)
        } else {
            unreachable!()
        }
    }
}

impl TargetType {
    /// Whether the specified TargetType is a directly executable format (i.e.,
    /// does not require an interpreter or intermediate loader such as a Java
    /// runtime, shell, etc.)
    #[must_use]
    pub fn is_native_executable(&self) -> bool {
        matches!(self, TargetType::PE | TargetType::ELF | TargetType::MachO)
    }
}
