use crate::signature::{hash::HashSigError, ParseError};
use crate::util::{self, Hash};
use std::convert::TryFrom;
use std::str;

/// Hash-based signatures
#[derive(Debug)]
pub struct PESectionHashSig {
    name: String,
    size: Option<usize>,
    hash: Hash,
}

impl super::Signature for PESectionHashSig {
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
        let size = match fields.next().ok_or(HashSigError::MissingFileSize)? {
            b"*" => None,
            s => Some(str::from_utf8(s)?.parse()?),
        };
        let hash = util::parse_hash(fields.next().ok_or(HashSigError::MissingHashString)?)?;
        let name = str::from_utf8(fields.next().ok_or(ParseError::MissingName)?)?.to_owned();

        Ok(Self { name, hash, size })
    }
}
