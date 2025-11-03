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
    feature::{EngineReq, Feature, Set},
    sigbytes::{AppendSigBytes, FromSigBytes, SigBytes},
    signature::{
        hash::{ParseError, ValidationError},
        FromSigBytesParseError, SigMeta,
    },
    util::{self, parse_field, parse_number_dec, Hash},
    Signature,
};
use std::{fmt::Write, str};

/// A signature based on file hash
#[derive(Debug)]
pub struct FileHashSig {
    name: String,
    hash: Hash,
    file_size: Option<usize>,
}

impl Signature for FileHashSig {
    fn name(&self) -> &str {
        &self.name
    }

    fn validate(&self, sigmeta: &SigMeta) -> Result<(), super::SigValidationError> {
        // Verify appropriate flevels for wildcard file size and hash type
        if self.file_size.is_none() {
            match &self.hash {
                Hash::Md5(_) => {
                    // wildcard md5's only allowed when the max flevel is specified and is less than 230 (i.e. before ClamAV 1.5.0)
                    if let Some(flevel_range) = &sigmeta.f_level {
                        if flevel_range.max().unwrap_or(u32::MAX) >= 230 {
                            return Err(super::SigValidationError::HashSig(
                                ValidationError::HashSig("MD5 hashes with unknown file size require a maximum feature level less than 230".to_string()),
                            ));
                        } else if flevel_range.start().unwrap_or(0) < 73 {
                            return Err(super::SigValidationError::HashSig(
                                ValidationError::HashSig("MD5 hashes with unknown file size require a minimum feature level of at least 73".to_string()),
                            ));
                        }
                    } else {
                        return Err(super::SigValidationError::HashSig(
                            ValidationError::HashSig("MD5 hashes with unknown file size require a maximum feature level less than 230".to_string()),
                        ));
                    }
                }
                Hash::Sha1(_) => {
                    // wildcard sha1's are not allowed.
                    return Err(super::SigValidationError::HashSig(
                        ValidationError::HashSig(
                            "SHA1 hashes must specify the file size".to_string(),
                        ),
                    ));
                }
                Hash::Sha2_256(_) => {
                    // wildcard sha256's only allowed when the max flevel is specified and is greater than or equal to 230 (i.e. ClamAV 1.5.0 and newer)
                    if let Some(flevel_range) = &sigmeta.f_level {
                        if flevel_range.start().unwrap_or(0) < 230 {
                            return Err(super::SigValidationError::HashSig(
                                ValidationError::HashSig("SHA2-256 hashes with unknown file size require a maximum feature level of at least 230".to_string()),
                            ));
                        }
                    } else {
                        return Err(super::SigValidationError::HashSig(
                            ValidationError::HashSig("SHA2-256 hashes with unknown file size require a maximum feature level of at least 230".to_string()),
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

impl EngineReq for FileHashSig {
    fn features(&self) -> Set {
        Set::from_static(match (self.file_size, &self.hash) {
            (None, Hash::Sha1(_)) => &[Feature::HashSizeUnknown, Feature::HashSha1],
            (None, Hash::Sha2_256(_)) => &[Feature::HashSizeUnknown, Feature::HashSha256],
            (Some(_), Hash::Sha1(_)) => &[Feature::HashSha1][..],
            (Some(_), Hash::Sha2_256(_)) => &[Feature::HashSha256][..],
            _ => return Set::default(),
        })
    }
}

impl AppendSigBytes for FileHashSig {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        let size_hint = self.name.len() + self.hash.size() * 2 + 10;
        sb.try_reserve_exact(size_hint)?;
        write!(sb, "{}:", self.hash)?;
        if let Some(size) = self.file_size {
            write!(sb, "{size}:")?;
        } else {
            sb.write_char('*')?;
        }
        write!(sb, "{}", self.name)?;

        // determine if we need to write min/max flevel
        if self.file_size.is_none() {
            // wildcard file size, so the min must be at least 73, and may be higher.
            // the max must be 229 or lower, for md5 hashes.
            match &self.hash {
                Hash::Md5(_) => {
                    // flevel for wildcard md5 must be capped at flevel 229 (i.e. before ClamAV 1.5.0)
                    write!(sb, ":73:229")?;
                }
                Hash::Sha1(_) => {
                    // wildcard sha1's are not allowed.
                    return Err(crate::signature::ToSigBytesError::UnsupportedValue(
                        "SHA1 hashes must specify the file size".to_string(),
                    ));
                }
                Hash::Sha2_256(_) => {
                    // flevel for wildcard sha256 must be at least 230 (i.e. ClamAV 1.5.0 and newer)
                    write!(sb, ":230")?;
                }
            }
        }

        Ok(())
    }
}

impl FromSigBytes for FileHashSig {
    fn from_sigbytes<'a, SB: Into<&'a SigBytes>>(
        sb: SB,
    ) -> Result<(Box<dyn crate::Signature>, super::SigMeta), FromSigBytesParseError> {
        let mut sigmeta = SigMeta::default();
        let mut fields = sb.into().as_bytes().split(|b| *b == b':');

        let hash = util::parse_hash(
            fields
                .next()
                .ok_or(ParseError::MissingField("hash_string".to_string()))?,
        )
        .map_err(ParseError::ParseHash)?;
        let file_size = parse_field!(
            OPTIONAL
            fields,
            parse_number_dec,
            ParseError::MissingFileSize,
            ParseError::ParseSize
        )?;
        let name = str::from_utf8(fields.next().ok_or(FromSigBytesParseError::MissingName)?)
            .map_err(FromSigBytesParseError::NameNotUnicode)?
            .to_owned();

        // Parse optional min/max flevel
        if let Some(min_flevel) = fields.next() {
            let min_flevel = parse_number_dec(min_flevel).map_err(ParseError::ParseMinFlevel)?;

            if file_size.is_none() && min_flevel < 73 {
                return Err(FromSigBytesParseError::HashSig(
                    ParseError::InvalidValueFor(format!(
                        "invalid min_flevel {min_flevel} for hash with unknown file size: {hash}"
                    )),
                ));
            }

            if let Some(max_flevel) = fields.next() {
                let max_flevel =
                    parse_number_dec(max_flevel).map_err(ParseError::ParseMaxFlevel)?;
                sigmeta.f_level = Some((min_flevel..=max_flevel).into());
            } else {
                sigmeta.f_level = Some((min_flevel..).into());
            }
        } else {
            // min flevel is missing. If the file size is unknown, this is an error.
            if file_size.is_none() {
                return Err(FromSigBytesParseError::HashSig(
                    ParseError::InvalidValueFor(format!(
                        "missing min_flevel for hash with unknown file size: {hash}"
                    )),
                ));
            } else {
                // If no flevel is specified, use the minimum flevel for a SHA2-256 hash signature.
                let min_flevel = crate::Feature::HashSha256.min_flevel();
                sigmeta.f_level = Some((min_flevel..).into());
            }
        }

        Ok((
            Box::new(Self {
                name,
                hash,
                file_size,
            }),
            sigmeta,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn eicar() {
        let bytes = b"44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature".into();
        let (sig, _) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<FileHashSig>().unwrap();
        assert_eq!(sig.name, "Eicar-Test-Signature");
        assert_eq!(sig.file_size, Some(68));
        assert_eq!(
            sig.hash,
            util::Hash::Md5(hex!("44d88612fea8a8f36de82e1278abb02f"))
        );
    }

    #[test]
    fn md5_good() {
        let bytes = b"aa15bcf478d165efd2065190eb473bcb:544:md5_good".into();
        let (sig, _) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<FileHashSig>().unwrap();
        assert_eq!(sig.name, "md5_good");
        assert_eq!(sig.file_size, Some(544));
        assert_eq!(
            sig.hash,
            util::Hash::Md5(hex!("aa15bcf478d165efd2065190eb473bcb"))
        );
    }

    #[test]
    fn md5_should_fail_missing_min_and_max() {
        let bytes =
            b"aa15bcf478d165efd2065190eb473bcb:*:md5_should_fail_missing_min_and_max".into();
        let result = FileHashSig::from_sigbytes(&bytes);
        // Should fail to even parse because ClamAV requires min flevel 73 for wildcard sigs.
        assert!(result.is_err());
    }

    #[test]
    fn md5_should_fail_missing_max() {
        let bytes = b"aa15bcf478d165efd2065190eb473bcb:*:md5_should_fail_missing_max:73".into();
        let (sig, sig_meta) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<FileHashSig>().unwrap();
        assert_eq!(sig.name, "md5_should_fail_missing_max");
        assert_eq!(sig.file_size, None);
        assert_eq!(
            sig.hash,
            util::Hash::Md5(hex!("aa15bcf478d165efd2065190eb473bcb"))
        );
        let validate_result = sig.validate(&sig_meta);
        // result should be Err since max flevel is missing
        assert!(validate_result.is_err());
    }

    #[test]
    fn md5_good_wildcard() {
        let bytes = b"aa15bcf478d165efd2065190eb473bcb:*:md5_good_wildcard:73:229".into();
        let (sig, sig_meta) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<FileHashSig>().unwrap();
        assert_eq!(sig.name, "md5_good_wildcard");
        assert_eq!(sig.file_size, None);
        assert_eq!(
            sig.hash,
            util::Hash::Md5(hex!("aa15bcf478d165efd2065190eb473bcb"))
        );
        let validate_result = sig.validate(&sig_meta);
        // result should be Ok since flevel range is valid
        assert!(validate_result.is_ok());
    }

    #[test]
    fn md5_should_fail_max_too_high() {
        let bytes =
            b"aa15bcf478d165efd2065190eb473bcb:*:md5_should_fail_max_too_high:73:230".into();
        let (sig, sig_meta) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<FileHashSig>().unwrap();
        assert_eq!(sig.name, "md5_should_fail_max_too_high");
        assert_eq!(sig.file_size, None);
        assert_eq!(
            sig.hash,
            util::Hash::Md5(hex!("aa15bcf478d165efd2065190eb473bcb"))
        );
        let validate_result = sig.validate(&sig_meta);
        // result should be Err since max flevel is too high
        assert!(validate_result.is_err());
    }

    #[test]
    fn sha1_good() {
        let bytes = b"62dd70f5e7530e0239901ac186f1f9ae39292561:544:sha1_good".into();
        let (sig, _) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<FileHashSig>().unwrap();
        assert_eq!(sig.name, "sha1_good");
        assert_eq!(sig.file_size, Some(544));
        assert_eq!(
            sig.hash,
            util::Hash::Sha1(hex!("62dd70f5e7530e0239901ac186f1f9ae39292561"))
        );
    }

    #[test]
    fn sha1_should_fail_missing_min_and_max() {
        let bytes =
            b"62dd70f5e7530e0239901ac186f1f9ae39292561:*:sha1_should_fail_missing_min_and_max"
                .into();
        let result = FileHashSig::from_sigbytes(&bytes);
        // Should fail to even parse because ClamAV requires min flevel 73 for wildcard sigs.
        assert!(result.is_err());
    }

    #[test]
    fn sha1_should_fail_missing_max() {
        let bytes =
            b"62dd70f5e7530e0239901ac186f1f9ae39292561:*:sha1_should_fail_missing_max:73".into();
        let (sig, sig_meta) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<FileHashSig>().unwrap();
        assert_eq!(sig.name, "sha1_should_fail_missing_max");
        assert_eq!(sig.file_size, None);
        assert_eq!(
            sig.hash,
            util::Hash::Sha1(hex!("62dd70f5e7530e0239901ac186f1f9ae39292561"))
        );
        let validate_result = sig.validate(&sig_meta);
        // result should be Err since max flevel is missing
        assert!(validate_result.is_err());
    }

    #[test]
    fn sha1_should_fail_wildcard_not_allowed() {
        let bytes = b"62dd70f5e7530e0239901ac186f1f9ae39292561:*:sha1_should_fail_wildcard_not_allowed:73:229".into();
        let (sig, sig_meta) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<FileHashSig>().unwrap();
        assert_eq!(sig.name, "sha1_should_fail_wildcard_not_allowed");
        assert_eq!(sig.file_size, None);
        assert_eq!(
            sig.hash,
            util::Hash::Sha1(hex!("62dd70f5e7530e0239901ac186f1f9ae39292561"))
        );
        let validate_result = sig.validate(&sig_meta);
        // result should be Err since wildcard sha1's are not allowed
        assert!(validate_result.is_err());
    }

    #[test]
    fn sha1_should_fail_max_too_high() {
        let bytes =
            b"62dd70f5e7530e0239901ac186f1f9ae39292561:*:sha1_should_fail_max_too_high:73:230"
                .into();
        let (sig, sig_meta) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<FileHashSig>().unwrap();
        assert_eq!(sig.name, "sha1_should_fail_max_too_high");
        assert_eq!(sig.file_size, None);
        assert_eq!(
            sig.hash,
            util::Hash::Sha1(hex!("62dd70f5e7530e0239901ac186f1f9ae39292561"))
        );
        let validate_result = sig.validate(&sig_meta);
        // result should be Err since max flevel is too high
        assert!(validate_result.is_err());
    }

    #[test]
    fn sha256_good() {
        let bytes =
            b"71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495:544:sha256_good"
                .into();
        let (sig, _) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<FileHashSig>().unwrap();
        assert_eq!(sig.name, "sha256_good");
        assert_eq!(sig.file_size, Some(544));
        assert_eq!(
            sig.hash,
            util::Hash::Sha2_256(hex!(
                "71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495"
            ))
        );
    }

    #[test]
    fn sha256_should_fail_missing_min_and_max() {
        let bytes = b"71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495:*:sha256_should_fail_missing_min_and_max".into();
        let result = FileHashSig::from_sigbytes(&bytes);
        // Should fail to even parse because ClamAV requires min flevel 73 for wildcard sigs.
        assert!(result.is_err());
    }

    #[test]
    fn sha256_should_fail_min_too_low() {
        let bytes = b"71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495:*:sha256_should_fail_min_too_low:73".into();
        let (sig, sig_meta) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<FileHashSig>().unwrap();
        assert_eq!(sig.name, "sha256_should_fail_min_too_low");
        assert_eq!(sig.file_size, None);
        assert_eq!(
            sig.hash,
            util::Hash::Sha2_256(hex!(
                "71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495"
            ))
        );
        let validate_result = sig.validate(&sig_meta);
        // result should be Err since max flevel is missing
        assert!(validate_result.is_err());
    }

    #[test]
    fn sha256_should_fail_min_still_too_low() {
        let bytes = b"71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495:*:sha256_should_fail_min_still_too_low:229".into();
        let (sig, sig_meta) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<FileHashSig>().unwrap();
        assert_eq!(sig.name, "sha256_should_fail_min_still_too_low");
        assert_eq!(sig.file_size, None);
        assert_eq!(
            sig.hash,
            util::Hash::Sha2_256(hex!(
                "71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495"
            ))
        );
        let validate_result = sig.validate(&sig_meta);
        // result should be Err since max flevel is missing
        assert!(validate_result.is_err());
    }

    #[test]
    fn sha256_good_wildcard() {
        let bytes = b"71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495:*:sha256_good_wildcard:230".into();
        let (sig, sig_meta) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<FileHashSig>().unwrap();
        assert_eq!(sig.name, "sha256_good_wildcard");
        assert_eq!(sig.file_size, None);
        assert_eq!(
            sig.hash,
            util::Hash::Sha2_256(hex!(
                "71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495"
            ))
        );
        let validate_result = sig.validate(&sig_meta);
        // result should be Ok since flevel range is valid
        assert!(validate_result.is_ok());
    }

    #[test]
    fn export() {
        let bytes = b"44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature".into();
        let (sig, _) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let exported = sig.to_sigbytes().unwrap();
        assert_eq!(&bytes, &exported);
    }
}
