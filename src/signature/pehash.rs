use super::{hash::HashSigParseError, ParseError, Signature};
use crate::util::{self, parse_number_dec, parse_wildcard_field, Hash};
use std::convert::TryFrom;
use std::str;

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

    fn feature_levels(&self) -> (usize, Option<usize>) {
        let min = if self.size.is_none() || matches!(self.hash, Hash::Sha1(_) | Hash::Sha2_256(_)) {
            73
        } else {
            1
        };
        (min, None)
    }
}

impl TryFrom<&[u8]> for PESectionHashSig {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut fields = data.split(|b| *b == b':');
        let size = parse_wildcard_field!(
            fields,
            parse_number_dec,
            HashSigParseError::MissingFileSize,
            HashSigParseError::ParseSize
        )?;
        let hash = util::parse_hash(fields.next().ok_or(HashSigParseError::MissingHashString)?)?;
        let name = str::from_utf8(fields.next().ok_or(ParseError::MissingName)?)
            .map_err(ParseError::NameNotUnicode)?
            .to_owned();

        Ok(Self { name, hash, size })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eicar() {
        let bytes = "45056:f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16:Win.Test.EICAR_MSB-1".as_bytes();
        let sig: PESectionHashSig = bytes.try_into().unwrap();
        assert_eq!(sig.name, "Win.Test.EICAR_MSB-1");
        assert_eq!(sig.size, Some(45056));
        assert_eq!(
            sig.hash,
            crate::util::Hash::Sha2_256(
                hex::decode("f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16")
                    .unwrap()
                    .try_into()
                    .unwrap()
            )
        );
    }
}
