use crate::{
    feature::EngineReq,
    regexp,
    sigbytes::{AppendSigBytes, FromSigBytes, SigBytes},
    signature::{SigMeta, ToSigBytesError},
    util::{
        parse_field, parse_hash, parse_number_dec, parse_range_inclusive, string_from_bytes,
        unescaped_element, Hash, ParseHashError, ParseNumberError, RangeInclusiveParseError,
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
    GSB,
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
    real: regexp::Match,
    displayed: regexp::Match,
}

/// A Google Safe Browsing match type
#[derive(Debug)]
pub enum GSBMatchType {
    /// "S:[PF]" type: malware sites
    Malware,
    /// "S:W" type: local allow
    Allow,
    /// "S1" type: phishing sites that yield a virus name of "Phishing.URL.Blocked"
    PhishingBlock1,
    /// "S2" type: phishing sites (?)
    PhishingBlock2,
}

/// A Google Safe Browsing predicate
#[derive(Debug, PartialEq)]
pub enum GSBPred {
    /// 4-byte prefix of the SHA2-256 hash of the last 2 or 3 components of the hostname
    HostPrefixHash([u8; 4]),
    /// SHA2-256 hash of the canonicalized URL, or a SHA2-256 hash of its
    /// prefix/suffix according to the Google Safe Browsing “Performing Lookups” rules
    Hash(Hash),
}

#[derive(Debug, Error, PartialEq)]
pub enum ParseError {
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

    #[error("Parsing RealURL field: {0}")]
    RealUrlRegexpParse(regexp::ParseError),

    #[error("Missing DisplayedURL field")]
    MissingDisplayedUrl,

    #[error("Parsing DisplayedURL field: {0}")]
    DisplayedUrlRegexpParse(regexp::ParseError),

    #[error("Google Safe Browsing signature missing predicate type field")]
    MissingGSBPredType,

    #[error("Google Safe Browsing signature missing predicate field")]
    MissingGSBPredicate,

    #[error("Google Safe Browsing \"allow\" predicate type only allowed for \"S\" match type")]
    AllowNotAllowed,

    #[error("Invalid Google Safe Browsing host prefix: {0}")]
    InvalidGSBHostPrefix(hex::FromHexError),

    #[error("Invalid Google Safe Browsing hash: {0}")]
    InvalidGSBHash(ParseHashError),

    #[error("Invalid Google Safe Browsing hash size: must be SHA2-256")]
    InvalidGSBHashType,

    #[error("Invalid Google Safe Browsing predicate type: {pred_type}")]
    InvalidPredicateType { pred_type: SigBytes },

    #[error("Parsing FuncLevelSpec range: {0}")]
    FLevelRange(RangeInclusiveParseError<u32>),

    #[error("Parsing FuncLevelSpec minimum: {0}")]
    FLevelMin(ParseNumberError<u32>),
}

#[derive(Debug)]
pub enum PhishingSig {
    PDB(PDBMatch),
    GSB {
        match_type: GSBMatchType,
        pred: GSBPred,
    },
    WDB(WDBMatch),
}

impl Signature for PhishingSig {
    fn name(&self) -> &str {
        // Mostphishing signatures don't have names
        match self {
            // This is the only signature with a defined name
            PhishingSig::GSB {
                match_type: GSBMatchType::PhishingBlock1,
                ..
            } => "Phishing.URL.Blocked",
            _ => "?",
        }
    }
}

impl EngineReq for PhishingSig {
    fn features(&self) -> crate::feature::Set {
        // TODO: Figure out when Phishing signatures appeared
        crate::feature::Set::default()
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
            PhishingSig::GSB { match_type, pred } => {
                match match_type {
                    GSBMatchType::Malware | GSBMatchType::Allow => sb.write_str("S:")?,
                    GSBMatchType::PhishingBlock1 => sb.write_str("S1:")?,
                    GSBMatchType::PhishingBlock2 => sb.write_str("S2:")?,
                }
                match pred {
                    GSBPred::HostPrefixHash(bytes) => {
                        sb.write_str("P:")?;
                        bytes.as_slice().append_sigbytes(sb)?;
                    }
                    GSBPred::Hash(hash) => {
                        if let GSBMatchType::Allow = match_type {
                            sb.write_str("W:")?;
                        } else {
                            sb.write_str("F:")?;
                        }
                        hash.append_sigbytes(sb)?;
                    }
                }
            }
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

        let prefix = fields.next().ok_or(ParseError::MissingPreamble)?;

        // `R` and `H` may include a filter which is (per specification) ignored
        let sig = if prefix.starts_with(&[b'R']) {
            Ok(PhishingSig::PDB(PDBMatch::Regexp(make_url_regexp_pair(
                &mut fields,
            )?)))
        } else if prefix.starts_with(&[b'H']) {
            make_pdbmatch_hostname(&mut fields)
        } else {
            match prefix {
                // These all have the same rough format
                b"S" | b"S1" | b"S2" => {
                    let mut match_type = match prefix {
                        // This changes if "W" is found in the next field
                        b"S" => GSBMatchType::Malware,
                        b"S1" => GSBMatchType::PhishingBlock1,
                        b"S2" => GSBMatchType::PhishingBlock2,
                        _ => unreachable!(),
                    };
                    let pred_type = fields.next().ok_or(ParseError::MissingGSBPredType)?;
                    let pred_str = fields.next().ok_or(ParseError::MissingGSBPredicate)?;
                    let pred = match pred_type {
                        b"P" => {
                            let mut bytes = [0; 4];
                            hex::decode_to_slice(pred_str, &mut bytes)
                                .map_err(ParseError::InvalidGSBHostPrefix)?;
                            GSBPred::HostPrefixHash(bytes)
                        }
                        // These both contain the same hash field type
                        b"F" | b"W" => {
                            let hash = parse_hash(pred_str).map_err(ParseError::InvalidGSBHash)?;
                            if !matches!(hash, Hash::Sha2_256(_)) {
                                return Err(ParseError::InvalidGSBHashType.into());
                            }
                            // Special handling for allow type
                            if pred_type == b"W" {
                                // Override the match type as an "allow" type
                                if prefix == b"S" {
                                    match_type = GSBMatchType::Allow;
                                } else {
                                    // 'W' ("allow") only allowed for "S" sigs, not S1/S2
                                    return Err(ParseError::AllowNotAllowed.into());
                                }
                            }
                            GSBPred::Hash(hash)
                        }
                        _ => {
                            return Err(ParseError::InvalidPredicateType {
                                pred_type: pred_type.into(),
                            }
                            .into())
                        }
                    };
                    Ok(PhishingSig::GSB { match_type, pred })
                }
                b"X" => Ok(PhishingSig::WDB(WDBMatch::Regexp(make_url_regexp_pair(
                    &mut fields,
                )?))),
                b"M" => make_wdbmatch_hostname(&mut fields),
                bytes => Err(ParseError::UnknownPrefix(bytes.into())),
            }
        }?;

        // Parse optional min/max flevel
        //
        // Unlike other signatures types, this is specified in a single field,
        // and as either a minimum value (n), or an inclusive range (n-m).
        if let Some(s) = fields.next() {
            if s.contains(&b'-') {
                let range = parse_range_inclusive(s).map_err(ParseError::FLevelRange)?;
                sigmeta.f_level = Some(range.into());
            } else {
                let min_flevel = parse_number_dec(s).map_err(ParseError::FLevelMin)?;
                sigmeta.f_level = Some((min_flevel..).into());
            }
        }

        Ok((Box::new(sig), sigmeta))
    }
}

fn make_url_regexp_pair<'a, I: Iterator<Item = &'a [u8]>>(
    fields: &mut I,
) -> Result<UrlRegexpPair, ParseError> {
    let real = parse_field!(
        fields,
        regexp::Match::try_from,
        ParseError::MissingRealUrl,
        ParseError::RealUrlRegexpParse
    )?;
    let displayed = parse_field!(
        fields,
        regexp::Match::try_from,
        ParseError::MissingDisplayedUrl,
        ParseError::DisplayedUrlRegexpParse
    )?;
    Ok(UrlRegexpPair { real, displayed })
}

fn make_pdbmatch_hostname<'a, I: Iterator<Item = &'a [u8]>>(
    fields: &mut I,
) -> Result<PhishingSig, ParseError> {
    let hostname = parse_field!(
        fields,
        string_from_bytes,
        ParseError::MissingDisplayedHostname,
        ParseError::DisplayedHostnameNotUnicode
    )?;
    Ok(PhishingSig::PDB(PDBMatch::DisplayedHostname(hostname)))
}

fn make_wdbmatch_hostname<'a, I: Iterator<Item = &'a [u8]>>(
    fields: &mut I,
) -> Result<PhishingSig, ParseError> {
    let real = parse_field!(
        fields,
        string_from_bytes,
        ParseError::MissingRealHostname,
        ParseError::DisplayedHostnameNotUnicode
    )?;
    let displayed = parse_field!(
        fields,
        string_from_bytes,
        ParseError::MissingDisplayedHostname,
        ParseError::DisplayedHostnameNotUnicode
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
                ParseError::MissingRealUrl
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
                ParseError::MissingDisplayedUrl
            ))
        ));
    }

    #[test]
    fn gsb_valid_s_p() {
        let input = br"S:P:fdcbe054:98".into();
        let (sig, sigmeta) = PhishingSig::from_sigbytes(&input).unwrap();
        assert_eq!(
            sigmeta,
            SigMeta {
                f_level: Some((98..).into()),
            }
        );
        let sig = sig.downcast_ref::<PhishingSig>().unwrap();
        assert!(matches!(
            sig,
            PhishingSig::GSB {
                match_type: GSBMatchType::Malware,
                pred: GSBPred::HostPrefixHash(_)
            }
        ));
    }

    #[test]
    fn gsb_valid_s_w() {
        let input = br"S:W:00111810e04eaf02975558467f74ec430ee0698a6d82bed1ff7a0fd772dfe863".into();
        let (sig, sigmeta) = PhishingSig::from_sigbytes(&input).unwrap();
        assert_eq!(sigmeta, SigMeta::default());
        let sig = sig.downcast_ref::<PhishingSig>().unwrap();
        assert!(matches!(
            sig,
            PhishingSig::GSB {
                match_type: GSBMatchType::Allow,
                pred: GSBPred::Hash(_)
            }
        ));
    }

    #[test]
    fn gsb_valid_s1_f() {
        let input =
            br"S1:F:00111810e04eaf02975558467f74ec430ee0698a6d82bed1ff7a0fd772dfe863:92-94".into();
        let (sig, sigmeta) = PhishingSig::from_sigbytes(&input).unwrap();
        assert_eq!(
            sigmeta,
            SigMeta {
                f_level: Some((92..=94).into())
            }
        );
        let sig = sig.downcast_ref::<PhishingSig>().unwrap();
        assert!(matches!(
            sig,
            PhishingSig::GSB {
                match_type: GSBMatchType::PhishingBlock1,
                pred: GSBPred::Hash(_),
            }
        ));
    }

    #[test]
    fn gsb_valid_s2_p() {
        let input = br"S2:P:e5172364".into();
        let (sig, sigmeta) = PhishingSig::from_sigbytes(&input).unwrap();
        assert_eq!(sigmeta, SigMeta::default());
        let sig = sig.downcast_ref::<PhishingSig>().unwrap();
        assert!(matches!(
            sig,
            PhishingSig::GSB {
                match_type: GSBMatchType::PhishingBlock2,
                pred: GSBPred::HostPrefixHash(_)
            }
        ));
    }

    #[test]
    fn gsb_unknown_prefix() {
        let input = br"Q:".into();
        let result = PhishingSig::from_sigbytes(&input);
        assert!(matches!(
            result,
            Err(FromSigBytesParseError::PhishingSig(
                ParseError::UnknownPrefix(_)
            ))
        ));
    }

    #[test]
    fn gsb_invalid_w_prefix() {
        let input =
            br"S1:W:00111810e04eaf02975558467f74ec430ee0698a6d82bed1ff7a0fd772dfe863".into();
        let result = PhishingSig::from_sigbytes(&input);
        assert!(matches!(
            result,
            Err(FromSigBytesParseError::PhishingSig(
                ParseError::AllowNotAllowed
            ))
        ));
    }

    #[test]
    fn gsb_invalid_hash_type() {
        let input = br"S1:F:00111810e04eaf02975558467f74ec43".into();
        let result = PhishingSig::from_sigbytes(&input);
        assert!(matches!(
            result,
            Err(FromSigBytesParseError::PhishingSig(
                ParseError::InvalidGSBHashType
            ))
        ));
    }

    #[test]
    fn gsb_invalid_pred_type() {
        let input =
            br"S1:Q:00111810e04eaf02975558467f74ec430ee0698a6d82bed1ff7a0fd772dfe863".into();
        let result = PhishingSig::from_sigbytes(&input);
        assert!(matches!(
            result,
            Err(FromSigBytesParseError::PhishingSig(
                ParseError::InvalidPredicateType { .. }
            ))
        ));
    }

    #[test]
    fn names() {
        let sig = PhishingSig::GSB {
            match_type: GSBMatchType::PhishingBlock1,
            pred: GSBPred::HostPrefixHash([0; 4]),
        };
        assert_eq!(sig.name(), "Phishing.URL.Blocked");

        let sig = PhishingSig::PDB(PDBMatch::DisplayedHostname("example.com".into()));
        assert_eq!(sig.name(), "?");
    }

    #[test]
    fn export() {
        let input = br"S:P:fdcbe054".into();
        let (sig, _) = PhishingSig::from_sigbytes(&input).unwrap();
        assert_eq!(sig.to_sigbytes().unwrap(), input);

        let input = br"S:W:00111810e04eaf02975558467f74ec430ee0698a6d82bed1ff7a0fd772dfe863".into();
        let (sig, _) = PhishingSig::from_sigbytes(&input).unwrap();
        assert_eq!(sig.to_sigbytes().unwrap(), input);

        let input =
            br"S1:F:00111810e04eaf02975558467f74ec430ee0698a6d82bed1ff7a0fd772dfe863".into();
        let (sig, _) = PhishingSig::from_sigbytes(&input).unwrap();
        assert_eq!(sig.to_sigbytes().unwrap(), input);

        let input = br"S2:P:e5172364".into();
        let (sig, _) = PhishingSig::from_sigbytes(&input).unwrap();
        assert_eq!(sig.to_sigbytes().unwrap(), input);
    }
}
