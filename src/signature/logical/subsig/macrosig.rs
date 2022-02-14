use super::{SubSig, SubSigType};
use crate::{
    feature::EngineReq,
    signature::logical::SubSigModifier,
    util::{parse_number_dec, ParseNumberError},
};
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug)]
pub struct MacroSubSig {
    min: usize,
    max: usize,
    macro_id: usize,
    modifier: Option<SubSigModifier>,
}

#[derive(Debug, Error)]
pub enum MacroSubSigParseError {
    #[error("missing range")]
    MissingRange,

    #[error("missing macro ID")]
    MissingMacroID,

    #[error("missing prefix")]
    MissingPrefix,

    #[error("missing suffix")]
    MissingSuffix,

    #[error("missing range minimum")]
    MissingRangeMin,

    #[error("missing range maxiumum")]
    MissingRangeMax,

    #[error("parsing macro_id: {0}")]
    ParseMacroID(ParseNumberError<usize>),

    #[error("parsing RangeMin: {0}")]
    ParseRangeMin(ParseNumberError<usize>),

    #[error("parsing RangeMax: {0}")]
    ParseRangeMax(ParseNumberError<usize>),
}

impl super::SubSigError for MacroSubSigParseError {
    fn identified(&self) -> bool {
        !matches!(
            self,
            MacroSubSigParseError::MissingPrefix | MacroSubSigParseError::MissingSuffix
        )
    }
}

impl SubSig for MacroSubSig {
    fn subsig_type(&self) -> SubSigType {
        SubSigType::Macro
    }
}

impl EngineReq for MacroSubSig {}

impl MacroSubSig {
    pub fn from_bytes(
        bytes: &[u8],
        modifier: Option<SubSigModifier>,
    ) -> Result<Self, MacroSubSigParseError> {
        if let Some(bytes) = bytes.strip_prefix(b"${") {
            if let Some(bytes) = bytes.strip_suffix(&[b'$']) {
                let mut tokens = bytes.splitn(2, |&b| b == b'}');
                let range = tokens.next().ok_or(MacroSubSigParseError::MissingRange)?;

                let macro_id =
                    parse_number_dec(tokens.next().ok_or(MacroSubSigParseError::MissingMacroID)?)
                        .map_err(MacroSubSigParseError::ParseMacroID)?;

                let mut range_tokens = range.splitn(2, |&b| b == b'-');

                let min = parse_number_dec(
                    range_tokens
                        .next()
                        .ok_or(MacroSubSigParseError::MissingRangeMin)?,
                )
                .map_err(MacroSubSigParseError::ParseRangeMin)?;

                let max = parse_number_dec(
                    range_tokens
                        .next()
                        .ok_or(MacroSubSigParseError::MissingRangeMax)?,
                )
                .map_err(MacroSubSigParseError::ParseRangeMax)?;

                Ok(Self {
                    min,
                    max,
                    macro_id,
                    modifier,
                })
            } else {
                Err(MacroSubSigParseError::MissingSuffix)
            }
        } else {
            Err(MacroSubSigParseError::MissingPrefix)
        }
    }
}
