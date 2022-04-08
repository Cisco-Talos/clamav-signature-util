use crate::{
    feature::EngineReq,
    regexp::{RegexpMatch, RegexpMatchParseError},
    sigbytes::{AppendSigBytes, FromSigBytes, SigBytes},
    signature::{SigMeta, ToSigBytesError},
    util::{
        parse_field, parse_number_dec, parse_range_inclusive, string_from_bytes, unescaped_element,
        ParseNumberError, RangeInclusiveParseError,
    },
    Signature,
};
use std::{fmt::Write, str};
use thiserror::Error;

#[derive(Debug, Clone, Copy)]
pub enum PhishDBFormat {
    /// URLs/hosts that are the target of phishing attempts
    PDB,
    /// Entries derived from Google "Safe Browsing"
    GDB,
    /// Paired URLs that look suspicious but are safe and should be allowed.
    WDB,
}

#[derive(Debug)]
pub enum PDBMatch {
    /// `R` prefix
    Regexp(UrlRegexpPair),
    /// `H` prefix
    DisplayedHostname(String),
}

#[derive(Debug)]
pub enum WDBMatch {
    /// `X` prefix (regexp)
    Regexp(UrlRegexpPair),
    /// `M` prefix (match hostname)
    MatchHostname { real: String, displayed: String },
}

/// A pair of regular expressions describing a "real" and displayed pair (e.g.,
/// as found in HTML).
#[derive(Debug)]
pub struct UrlRegexpPair {
    real: RegexpMatch,
    displayed: RegexpMatch,
}

#[derive(Debug, Error, PartialEq)]
pub enum PhishingSigParseError {
    #[error("Missing preamble (first) field")]
    MissingPreamble,

    #[error("Unknown prefix: {0}")]
    UnknownPrefix(SigBytes),

    #[error("Missing RealHostname field")]
    MissingRealHostname,

    #[error("Missing DisplayedHostname field")]
    MissingDisplayedHostname,

    #[error("DisplayedHostname not unicode: {0}")]
    DisplayedHostnameNotUnicode(std::str::Utf8Error),

    #[error("Missing RealURL field")]
    MissingRealUrl,

    #[error("Parsing RealURL field:{0}")]
    RealUrlRegexpParse(RegexpMatchParseError),

    #[error("Missing DisplayedURL field")]
    MissingDisplayedUrl,

    #[error("Parsing DisplayedURL field:{0}")]
    DisplayedUrlRegexpParse(RegexpMatchParseError),

    #[error("Parsing FuncLevelSpec range: {0}")]
    FLevelRange(RangeInclusiveParseError<u32>),

    #[error("Parsing FuncLevelSpec minimum: {0}")]
    FLevelMin(ParseNumberError<u32>),
}

#[derive(Debug, Error, PartialEq)]
pub enum PhishingSigValidationError {}

#[derive(Debug)]
pub enum PhishingSig {
    PDB(PDBMatch),
    GDB,
    WDB(WDBMatch),
}

impl Signature for PhishingSig {
    fn name(&self) -> &str {
        // phishing signatures don't have names
        "?"
    }
}

impl EngineReq for PhishingSig {
    fn features(&self) -> crate::feature::FeatureSet {
        // TODO: Figure out when Phishing signatures appeared
        crate::feature::FeatureSet::default()
    }
}

impl AppendSigBytes for PhishingSig {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> std::result::Result<(), ToSigBytesError> {
        match self {
            PhishingSig::PDB(psig) => match psig {
                PDBMatch::Regexp(UrlRegexpPair { real, displayed }) => {
                    sb.write_str("R:")?;
                    real.append_sigbytes(sb)?;
                    sb.write_char(':')?;
                    displayed.append_sigbytes(sb)?;
                }
                PDBMatch::DisplayedHostname(host) => {
                    write!(sb, "H:{host}")?;
                }
            },
            PhishingSig::GDB => todo!(),
            PhishingSig::WDB(wsig) => match wsig {
                WDBMatch::Regexp(UrlRegexpPair { real, displayed }) => {
                    sb.write_str("X:")?;
                    real.append_sigbytes(sb)?;
                    sb.write_char(':')?;
                    displayed.append_sigbytes(sb)?;
                }
                WDBMatch::MatchHostname { real, displayed } => {
                    write!(sb, "M:{real}:{displayed}")?;
                }
            },
        }

        Ok(())
    }
}

impl FromSigBytes for PhishingSig {
    fn from_sigbytes<'a, SB: Into<&'a SigBytes>>(
        sb: SB,
    ) -> Result<(Box<dyn Signature>, super::SigMeta), super::FromSigBytesParseError> {
        let mut sigmeta = SigMeta::default();
        let mut fields = sb.into().as_bytes().split(unescaped_element(b'\\', b':'));

        let prefix = fields
            .next()
            .ok_or(PhishingSigParseError::MissingPreamble)?;

        // `R` and `H` may include a filter which is (per specification) ignored
        let sig = if prefix.starts_with(&[b'R']) {
            Ok(PhishingSig::PDB(PDBMatch::Regexp(make_url_regexp_pair(
                &mut fields,
            )?)))
        } else if prefix.starts_with(&[b'H']) {
            make_pdbmatch_hostname(&mut fields)
        } else {
            match prefix {
                // TODO: handle GDB format.  There are no examples in the current DB
                b"S" | b"S1" | b"S2" => Ok(PhishingSig::GDB),
                b"X" => Ok(PhishingSig::WDB(WDBMatch::Regexp(make_url_regexp_pair(
                    &mut fields,
                )?))),
                b"M" => make_wdbmatch_hostname(&mut fields),
                bytes => Err(PhishingSigParseError::UnknownPrefix(bytes.into())),
            }
        }?;

        // Parse optional min/max flevel
        //
        // Unlike other signatures types, this is specified in a single field,
        // and as either a minimum value (n), or an inclusive range (n-m).
        if let Some(s) = fields.next() {
            if s.contains(&b'-') {
                let range = parse_range_inclusive(s).map_err(PhishingSigParseError::FLevelRange)?;
                sigmeta.f_level = Some(range.into());
            } else {
                let min_flevel = parse_number_dec(s).map_err(PhishingSigParseError::FLevelMin)?;
                sigmeta.f_level = Some((min_flevel..).into());
            }
        }

        Ok((Box::new(sig), sigmeta))
    }
}

fn make_url_regexp_pair<'a, I: Iterator<Item = &'a [u8]>>(
    fields: &mut I,
) -> Result<UrlRegexpPair, PhishingSigParseError> {
    let real = parse_field!(
        fields,
        RegexpMatch::try_from,
        PhishingSigParseError::MissingRealUrl,
        PhishingSigParseError::RealUrlRegexpParse
    )?;
    let displayed = parse_field!(
        fields,
        RegexpMatch::try_from,
        PhishingSigParseError::MissingDisplayedUrl,
        PhishingSigParseError::DisplayedUrlRegexpParse
    )?;
    Ok(UrlRegexpPair { real, displayed })
}

fn make_pdbmatch_hostname<'a, I: Iterator<Item = &'a [u8]>>(
    fields: &mut I,
) -> Result<PhishingSig, PhishingSigParseError> {
    let hostname = parse_field!(
        fields,
        string_from_bytes,
        PhishingSigParseError::MissingDisplayedHostname,
        PhishingSigParseError::DisplayedHostnameNotUnicode
    )?;
    Ok(PhishingSig::PDB(PDBMatch::DisplayedHostname(hostname)))
}

fn make_wdbmatch_hostname<'a, I: Iterator<Item = &'a [u8]>>(
    fields: &mut I,
) -> Result<PhishingSig, PhishingSigParseError> {
    let real = parse_field!(
        fields,
        string_from_bytes,
        PhishingSigParseError::MissingRealHostname,
        PhishingSigParseError::DisplayedHostnameNotUnicode
    )?;
    let displayed = parse_field!(
        fields,
        string_from_bytes,
        PhishingSigParseError::MissingDisplayedHostname,
        PhishingSigParseError::DisplayedHostnameNotUnicode
    )?;
    Ok(PhishingSig::WDB(WDBMatch::MatchHostname {
        real,
        displayed,
    }))
}

#[cfg(test)]
mod tests {
    use crate::signature::FromSigBytesParseError;

    // We lacked examples of PDBs with regular expressions, which is why there
    // are already tests here.  There should be *more* tests -- this was just not
    // covered via test data.
    use super::*;

    #[test]
    fn pdb_valid() {
        let input = br"R:.*\.com:.*\.org:99-105".into();
        let (sig, sigmeta) = PhishingSig::from_sigbytes(&input).unwrap();
        assert_eq!(
            sigmeta,
            SigMeta {
                f_level: Some((99..=105).into()),
            }
        );
        let sig = sig.downcast_ref::<PhishingSig>().unwrap();
        assert!(matches!(sig, PhishingSig::PDB(PDBMatch::Regexp { .. })));
    }

    #[test]
    fn pdb_valid_with_filter() {
        let input = br"Rignored:.*\.com:.*\.org".into();
        let (sig, sigmeta) = PhishingSig::from_sigbytes(&input).unwrap();
        assert_eq!(sigmeta, SigMeta::default(),);
        let sig = sig.downcast_ref::<PhishingSig>().unwrap();
        assert!(matches!(sig, PhishingSig::PDB(PDBMatch::Regexp { .. })));
    }

    #[test]
    fn pdb_missing_real() {
        let input = br"R".into();
        let result = PhishingSig::from_sigbytes(&input);
        assert!(matches!(
            result,
            Err(FromSigBytesParseError::PhishingSig(
                PhishingSigParseError::MissingRealUrl
            ))
        ));
    }

    #[test]
    fn pdb_missing_disp() {
        let input = br"R:foo".into();
        let result = PhishingSig::from_sigbytes(&input);
        assert!(matches!(
            result,
            Err(FromSigBytesParseError::PhishingSig(
                PhishingSigParseError::MissingDisplayedUrl
            ))
        ));
    }
}
