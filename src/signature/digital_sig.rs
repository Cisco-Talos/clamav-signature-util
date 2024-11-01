use crate::{
    feature::{EngineReq, Feature, Set},
    sigbytes::{AppendSigBytes, FromSigBytes, SigBytes},
    signature::{hash::ParseError, FromSigBytesParseError, SigMeta},
    util::parse_number_dec,
    Signature,
};
use std::io::Write;
use std::str;

use openssl::pkcs7::Pkcs7;

/// A list of supported digital signature formats
pub enum DigitalSig {
    Pkcs7(Pkcs7),
}

// Pkcs7 does not implement Debug, so we have to implement it ourselves
impl std::fmt::Debug for DigitalSig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DigitalSig::Pkcs7(pkcs7) => {
                if let Ok(pem) = pkcs7.to_pem() {
                    if let Ok(pem) = std::string::String::from_utf8(pem) {
                        if f.alternate() {
                            // strip the trailing newline
                            let pem = &pem[..pem.len() - 1];
                            // add a tab to each line
                            let pem = pem
                                .split(|c| c == '\n')
                                .map(|line| format!("    {}\n", line))
                                .collect::<String>();
                            write!(f, "PKCS7::PEM(\n{})", pem)
                        } else {
                            // strip out the newlines
                            let pem = pem
                                .split(|c| c == '\n')
                                .map(|line| format!("{}", line))
                                .collect::<String>();
                            write!(f, "PKCS7::PEM({})", pem)
                        }
                    } else {
                        write!(f, "PKCS7::PEM(Invalid)")
                    }
                } else {
                    write!(f, "PKCS7::PEM(Invalid)")
                }
            }
        }
    }
}

impl Signature for DigitalSig {
    fn name(&self) -> &str {
        "Digital Signature"
    }
}

impl AppendSigBytes for DigitalSig {
    /// Write out a digital signature line in a .sign file
    /// The format is:
    /// flevel_min:flevel_max:signature_format:signature_bytes
    /// where:
    /// - flevel_min and flevel_max are the minimum and maximum feature levels
    ///   - flevel_min is required.
    ///   - flevel_max is optional.
    /// - signature_format is the format of the signature
    /// - signature_bytes is the signature itself
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        match &self {
            DigitalSig::Pkcs7(pkcs7) => {
                // write out the flevel_min and flevel_max
                sb.write(b"220::")?;

                // write out the signature format
                sb.write(b"pkcs7-pem:")?;

                // write out the base64 encoded bit of the PEM encoded PKCS#7 signature as the signature bytes
                let pem = pkcs7
                    .to_pem()
                    .map_err(|e| crate::signature::ToSigBytesError::EncodingError(e.to_string()))?;

                // remove any line that contains "-----BEGIN PKCS7-----" or "-----END PKCS7-----"
                let pem = pem
                    .split(|b| *b == b'\n')
                    .filter_map(|line| {
                        if line.starts_with(b"-----BEGIN PKCS7-----")
                            || line.starts_with(b"-----END PKCS7-----")
                        {
                            None
                        } else {
                            Some(line)
                        }
                    })
                    .flat_map(|line| line.iter().copied())
                    .collect::<Vec<u8>>();

                // Remove the newline characters
                let pem = pem
                    .iter()
                    .filter(|b| **b != b'\n')
                    .copied()
                    .collect::<Vec<u8>>();

                // write out the signature bytes
                sb.write(&pem)?;
            }
        }
        Ok(())
    }
}

impl FromSigBytes for DigitalSig {
    /// Read a digital signature line from a .sign file
    /// The format is:
    /// flevel_min:flevel_max:signature_format:signature_bytes
    /// where:
    /// - flevel_min and flevel_max are the minimum and maximum feature levels
    ///   - flevel_min is required.
    ///   - flevel_max is optional.
    /// - signature_format is the format of the signature
    /// - signature_bytes is the signature itself
    fn from_sigbytes<'a, SB: Into<&'a SigBytes>>(
        sb: SB,
    ) -> Result<(Box<dyn crate::Signature>, super::SigMeta), FromSigBytesParseError> {
        let mut sigmeta = SigMeta::default();
        let mut fields = sb.into().as_bytes().split(|b| *b == b':');

        // Read the flevel_min. If it is missing, return an error.
        let min_flevel = if let Some(min_flevel) = fields.next() {
            parse_number_dec(min_flevel).map_err(ParseError::ParseMinFlevel)?
        } else {
            return Err(FromSigBytesParseError::MissingField(
                "min_flevel".to_string(),
            ));
        };

        // Read the flevel_max. If it is empty, set it to None. If it is missing, return an error.
        // If it is a number, parse it.
        if let Some(max_flevel) = fields.next() {
            if max_flevel == b"" {
                sigmeta.f_level = Some((min_flevel..).into());
            } else {
                let max_flevel =
                    parse_number_dec(max_flevel).map_err(ParseError::ParseMaxFlevel)?;
                sigmeta.f_level = Some((min_flevel..=max_flevel).into());
            }
        } else {
            return Err(FromSigBytesParseError::MissingField(
                "max_flevel".to_string(),
            ));
        };

        // parse the signature format
        let signature_format = fields
            .next()
            .ok_or(ParseError::MissingField("signature_format".to_string()))?;
        match signature_format {
            // if it is pkcs7-pem, read the signature bytes
            b"pkcs7-pem" => {
                let signature_bytes = fields
                    .next()
                    .ok_or(ParseError::MissingField("signature_bytes".to_string()))?
                    .to_vec();

                let pem_string = format!(
                    "-----BEGIN PKCS7-----\n{}\n-----END PKCS7-----",
                    str::from_utf8(&signature_bytes).unwrap()
                );
                let pkcs7 = Pkcs7::from_pem(pem_string.as_bytes())
                    .map_err(|_| ParseError::InvalidValueFor("PKCS#7 PEM string".to_string()))?;

                Ok((Box::new(DigitalSig::Pkcs7(pkcs7)), sigmeta))
            }
            _ => Err(FromSigBytesParseError::UnsupportedSigType),
        }
    }
}

impl EngineReq for DigitalSig {
    fn features(&self) -> Set {
        Set::from_static(match &self {
            DigitalSig::Pkcs7(_) => &[Feature::DigitalSignaturePkcs7Pem],
        })
    }
}
