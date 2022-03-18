use super::ToSigBytesError;
use std::str;
use thiserror::Error;

use crate::{
    feature::EngineReq,
    regexp::{RegexpMatch, RegexpMatchParseError},
    sigbytes::{AppendSigBytes, SigBytes},
    util::{parse_field, string_from_bytes, unescaped_element},
    Signature,
};

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

#[derive(Debug, Error)]
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
}

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
    fn append_sigbytes(&self, _: &mut SigBytes) -> std::result::Result<(), ToSigBytesError> {
        todo!()
    }
}

impl TryFrom<&[u8]> for PhishingSig {
    type Error = PhishingSigParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut fields = value.split(unescaped_element(b'\\', b':'));

        let prefix = fields
            .next()
            .ok_or(PhishingSigParseError::MissingPreamble)?;

        // `R` and `H` may include a filter which is (per specification) ignored
        if prefix.starts_with(&[b'R']) {
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
        }
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
    // We lacked examples of PDBs with regular expressions, which is why there
    // are already tests here.  There should be *more* tests -- this was just not
    // covered via test data.
    use super::*;

    #[test]
    fn pdb_valid() {
        let sig: PhishingSig = br"R:.*\.com:.*\.org".as_ref().try_into().unwrap();
        assert!(matches!(sig, PhishingSig::PDB(PDBMatch::Regexp { .. })));
    }

    #[test]
    fn pdb_valid_with_filter() {
        let sig: PhishingSig = br"Rignored:.*\.com:.*\.org".as_ref().try_into().unwrap();
        assert!(matches!(sig, PhishingSig::PDB(PDBMatch::Regexp { .. })));
    }

    #[test]
    fn pdb_missing_real() {
        let result: Result<PhishingSig, PhishingSigParseError> = br"R".as_ref().try_into();
        assert!(matches!(result, Err(PhishingSigParseError::MissingRealUrl)));
    }

    #[test]
    fn pdb_real_not_unicode() {
        let result: Result<PhishingSig, PhishingSigParseError> = b"R:\x80".as_ref().try_into();
        assert!(matches!(
            result,
            Err(PhishingSigParseError::RealUrlRegexpParse(_))
        ));
    }

    #[test]
    fn pdb_missing_disp() {
        let result: Result<PhishingSig, PhishingSigParseError> = br"R:foo".as_ref().try_into();
        assert!(matches!(
            result,
            Err(PhishingSigParseError::MissingDisplayedUrl)
        ));
    }

    #[test]
    fn pdb_disp_not_unicode() {
        let result: Result<PhishingSig, PhishingSigParseError> = b"R:.com:\x80".as_ref().try_into();
        assert!(matches!(
            result,
            Err(PhishingSigParseError::DisplayedUrlRegexpParse(_))
        ));
    }
}
