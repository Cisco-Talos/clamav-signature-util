use super::{hash::HashSigParseError, FromSigBytesParseError, Signature};
use crate::{
    feature::{EngineReq, Feature, FeatureSet},
    sigbytes::{AppendSigBytes, SigBytes},
    util::{self, parse_field, parse_number_dec, Hash},
};
use std::{convert::TryFrom, fmt::Write, str};

/// Hash-based signatures
#[derive(Debug)]
pub struct PESectionHashSig {
    name: String,
    size: Option<usize>,
    hash: Hash,
}

impl Signature for PESectionHashSig {
    fn name(&self) -> &str {
        &self.name
    }
}

impl EngineReq for PESectionHashSig {
    fn features(&self) -> FeatureSet {
        FeatureSet::from_static(match (self.size, &self.hash) {
            (None, Hash::Sha1(_)) => &[Feature::HashSizeUnknown, Feature::HashSha1],
            (None, Hash::Sha2_256(_)) => &[Feature::HashSizeUnknown, Feature::HashSha256],
            (Some(_), Hash::Sha1(_)) => &[Feature::HashSha1],
            (Some(_), Hash::Sha2_256(_)) => &[Feature::HashSha256],
            _ => return FeatureSet::default(),
        })
    }
}

impl AppendSigBytes for PESectionHashSig {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        let size_hint = self.name.len() + self.hash.len() * 2 + 10;
        sb.try_reserve_exact(size_hint)?;

        if let Some(size) = self.size {
            write!(sb, "{}", size)?
        } else {
            sb.write_char('*')?
        }

        write!(sb, ":{}:{}", self.hash, self.name)?;
        Ok(())
    }
}

impl TryFrom<&[u8]> for PESectionHashSig {
    type Error = FromSigBytesParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut fields = data.split(|b| *b == b':');
        let size = parse_field!(
            OPTIONAL
            fields,
            parse_number_dec,
            HashSigParseError::MissingFileSize,
            HashSigParseError::ParseSize
        )?;
        let hash = util::parse_hash(fields.next().ok_or(HashSigParseError::MissingHashString)?)?;
        let name = str::from_utf8(fields.next().ok_or(FromSigBytesParseError::MissingName)?)
            .map_err(FromSigBytesParseError::NameNotUnicode)?
            .to_owned();

        Ok(Self { name, hash, size })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn eicar() {
        let bytes = "45056:f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16:Win.Test.EICAR_MSB-1".as_bytes();
        let sig: PESectionHashSig = bytes.try_into().unwrap();
        assert_eq!(sig.name, "Win.Test.EICAR_MSB-1");
        assert_eq!(sig.size, Some(45056));
        assert_eq!(
            sig.hash,
            crate::util::Hash::Sha2_256(hex!(
                "f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16"
            ))
        );
    }

    #[test]
    fn export() {
        let bytes = "45056:f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16:Win.Test.EICAR_MSB-1";
        let sig: PESectionHashSig = bytes.as_bytes().try_into().unwrap();
        let exported = sig.to_sigbytes().unwrap().to_string();
        assert_eq!(bytes, &exported);
    }
}
