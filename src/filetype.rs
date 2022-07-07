use num_derive::{FromPrimitive, ToPrimitive};
use std::{
    fmt::Write,
    str::{self, FromStr, Utf8Error},
};
use strum_macros::{Display, EnumString};
use thiserror::Error;

use crate::{
    feature::{EngineReq, Feature, FeatureSet},
    sigbytes::AppendSigBytes,
};

// enum FileType
// These are autogenerated at build time
include!(concat!(env!("OUT_DIR"), "/filetypes-c_const"));

#[derive(Debug, Error, PartialEq)]
pub enum FileTypeParseError {
    #[error("not UTF-8: {0}")]
    UTF8(#[from] Utf8Error),

    #[error("parsing FileType: {0}")]
    Unknown(#[from] strum::ParseError),
}

impl TryFrom<&[u8]> for FileType {
    type Error = FileTypeParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(FileType::from_str(str::from_utf8(bytes)?)?)
    }
}

impl AppendSigBytes for FileType {
    fn append_sigbytes(
        &self,
        sb: &mut crate::sigbytes::SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        Ok(write!(sb, "{}", self)?)
    }
}

impl EngineReq for FileType {
    fn features(&self) -> crate::feature::FeatureSet {
        let feature_tag = include!(concat!(
            env!("OUT_DIR"),
            "/filetypes-match-filetype-to-feature_tag.rs"
        ));
        if let Some(feature_tag) = feature_tag {
            FeatureSet::from(vec![feature_tag].into_iter())
        } else {
            FeatureSet::Empty
        }
    }
}
