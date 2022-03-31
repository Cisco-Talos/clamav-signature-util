use crate::{
    feature::{EngineReq, FeatureSet},
    regexp::{RegexpMatch, RegexpMatchParseError},
    sigbytes::AppendSigBytes,
    signature::logical::{expression, SubSigModifier},
    Feature,
};
use std::{fmt::Write, str};
use thiserror::Error;

use super::{SubSig, SubSigType};

#[allow(dead_code)]
#[derive(Debug)]
pub struct PCRESubSig {
    trigger_expr: Box<dyn expression::Element>,
    regexp: RegexpMatch,
    // TODO: find a more-compact representation
    flags: Vec<Flag>,
    offset: Option<crate::signature::ext::Offset>,
    modifier: Option<SubSigModifier>,
}

impl SubSig for PCRESubSig {
    fn subsig_type(&self) -> SubSigType {
        SubSigType::Pcre
    }
}

impl EngineReq for PCRESubSig {
    fn features(&self) -> crate::feature::FeatureSet {
        FeatureSet::from_static(&[Feature::SubSigPcre])
    }
}

impl AppendSigBytes for PCRESubSig {
    fn append_sigbytes(
        &self,
        sb: &mut crate::sigbytes::SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        if let Some(offset) = self.offset {
            offset.append_sigbytes(sb)?;
            sb.write_char(':')?;
        }
        write!(sb, "{expr}/", expr = self.trigger_expr)?;
        self.regexp.append_pcre_subsig(sb)?;
        sb.write_char('/')?;
        for flag in &self.flags {
            sb.write_char(match flag {
                Flag::Global => 'g',
                Flag::Rolling => 'r',
                Flag::Encompass => 'e',
                Flag::PcreCaseless => 'i',
                Flag::PcreDotAll => 's',
                Flag::PcreMultiline => 'm',
                Flag::PcreExtended => 'x',
                Flag::PcreAnchored => 'A',
                Flag::PcreDollarEndOnly => 'E',
                Flag::PcreUngreedy => 'U',
            })?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum Flag {
    Global,
    Rolling,
    Encompass,
    PcreCaseless,
    PcreDotAll,
    PcreMultiline,
    PcreExtended,
    PcreAnchored,
    PcreDollarEndOnly,
    PcreUngreedy,
}

#[derive(Debug, Error)]
pub enum PCRESubSigParseError {
    #[error("empty")]
    Empty,

    #[error("empty pattern")]
    EmptyPattern,

    #[error("unknown PCRE flag")]
    UnknownFlag,

    #[error("regexp not unicode: {0}")]
    NotUnicode(str::Utf8Error),

    #[error("parsing logical expression: {0}")]
    ParseLogExpr(#[from] expression::LogExprParseError),

    #[error("loading pattern: {0}")]
    RegexpMatch(#[from] RegexpMatchParseError),

    #[cfg(validate_regex)]
    #[error("compiling regular expression: {0}")]
    CompileRegex(#[from] regex::Error),
}

impl super::SubSigError for PCRESubSigParseError {
    fn identified(&self) -> bool {
        matches!(
            self,
            PCRESubSigParseError::ParseLogExpr(..)
                | PCRESubSigParseError::NotUnicode(..)
                | PCRESubSigParseError::UnknownFlag
        )
    }
}

impl PCRESubSig {
    pub fn from_bytes(
        bytes: &[u8],
        modifier: Option<SubSigModifier>,
        offset: Option<crate::signature::ext::Offset>,
    ) -> Result<PCRESubSig, PCRESubSigParseError> {
        // Due to escaping of slashes, we can't simply split on them
        let mut parts = bytes.splitn(2, |&b| b == b'/');
        let maybe_logexpr = parts.next().ok_or(PCRESubSigParseError::Empty)?;
        let remainder = parts.next().ok_or(PCRESubSigParseError::EmptyPattern)?;
        let trigger_expr: Box<dyn expression::Element> = maybe_logexpr.try_into()?;

        // Now look back from the tail
        let mut parts = remainder.rsplitn(2, |&b| b == b'/');
        // If this part is None, it means no '/' was found
        let flags: Vec<Flag> = parts
            .next()
            .ok_or(PCRESubSigParseError::EmptyPattern)?
            .iter()
            .copied()
            .map(Flag::try_from)
            .collect::<Result<Vec<Flag>, _>>()?;

        let regexp =
            RegexpMatch::from_pcre_subsig(parts.next().ok_or(PCRESubSigParseError::EmptyPattern)?)?;

        #[cfg(validate_regex)]
        {
            // Validate using the regex crate, which is *not* PCRE-compatible
            let mut regex = regex::RegexBuilder::new(&pattern);
            for flag in &flags {
                match flag {
                    Flag::Global => (),
                    Flag::Rolling => todo!(),
                    Flag::Encompass => todo!(),
                    Flag::PcreCaseless => {
                        regex.case_insensitive(true);
                    }
                    Flag::PcreDotAll => {
                        regex.dot_matches_new_line(true);
                    }
                    Flag::PcreMultiline => {
                        regex.multi_line(true);
                    }
                    Flag::PcreExtended => todo!(),
                    Flag::PcreAnchored => todo!(),
                    Flag::PcreDollarEndOnly => todo!(),
                    Flag::PcreUngreedy => {
                        regex.swap_greed(true);
                    }
                };
            }
            regex.build()?;
        }

        Ok(Self {
            trigger_expr,
            regexp,
            flags,
            modifier,
            offset,
        })
    }
}

impl TryFrom<u8> for Flag {
    type Error = PCRESubSigParseError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Ok(match byte {
            b'g' => Flag::Global,
            b'r' => Flag::Rolling,
            b'e' => Flag::Encompass,
            b'i' => Flag::PcreCaseless,
            b's' => Flag::PcreDotAll,
            b'm' => Flag::PcreMultiline,
            b'x' => Flag::PcreExtended,
            b'A' => Flag::PcreAnchored,
            b'E' => Flag::PcreDollarEndOnly,
            b'U' => Flag::PcreUngreedy,
            _ => return Err(PCRESubSigParseError::UnknownFlag),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::PCRESubSig;
    use crate::sigbytes::{AppendSigBytes, SigBytes};
    const SAMPLE_SIG: &str = concat!(
        r#"0/willReadFrequently.*?(?P<source_img>(\w+|\w+\x5B\w+\x5D))"#,
        r#"\.createImageData.*?(?P<target_img>(\w+|\w+\x5B\w+\x5D))\s*\x3D\s*"#,
        r#"(?P=source_img)\.getImageData.*?(?P=source_img)\.putImageData\s*\x28\s*(?P=target_img)/si"#
    );

    #[test]
    fn logical_expr() {
        let subsig_bytes = b"0&1&2/function\\s[a-z0-9]+\x28\x29\\s\x7B\\svar\\s[a-z0-9]+=(\"[0-9a-z]{300,400}\"\x2B\\s){10}/";
        let _sig = PCRESubSig::from_bytes(subsig_bytes, None, None).unwrap();
    }

    #[test]
    fn export() {
        let bytes = SAMPLE_SIG.as_bytes();
        let sig = PCRESubSig::from_bytes(bytes, None, None).unwrap();
        let mut sb = SigBytes::new();
        sig.append_sigbytes(&mut sb).unwrap();
        let exported = sb.to_string();
        assert_eq!(SAMPLE_SIG, &exported);
    }
}
