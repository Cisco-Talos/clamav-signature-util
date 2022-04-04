use crate::{
    feature::{EngineReq, FeatureSet},
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
    fn features(&self) -> FeatureSet {
        FeatureSet::from_static(match self {
            TargetType::PDF => &[Feature::TargetTypePdf],
            TargetType::Flash => &[Feature::TargetTypeFlash],
            TargetType::Java => &[Feature::TargetTypeJava],
            _ => return FeatureSet::default(),
        })
    }
}

impl AppendSigBytes for TargetType {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        use std::fmt::Write;
        if let Some(n) = self.to_usize() {
            Ok(write!(sb, "{}", n)?)
        } else {
            unreachable!()
        }
    }
}
