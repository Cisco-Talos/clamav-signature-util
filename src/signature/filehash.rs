use crate::{
    signature::{hash::HashSigParseError, ParseError},
    util::{self, parse_number_dec, parse_wildcard_field, Hash},
};
use std::{convert::TryFrom, str};

/// A signature based on file hash
#[derive(Debug)]
pub struct FileHashSig {
    name: String,
    hash: Hash,
    file_size: Option<usize>,
}

impl super::Signature for FileHashSig {
    fn name(&self) -> &str {
        &self.name
    }

    fn feature_levels(&self) -> (usize, Option<usize>) {
        let min =
            if self.file_size.is_none() || matches!(self.hash, Hash::Sha1(_) | Hash::Sha2_256(_)) {
                73
            } else {
                1
            };
        (min, None)
    }
}

impl TryFrom<&[u8]> for FileHashSig {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut fields = data.split(|b| *b == b':');

        let hash = util::parse_hash(fields.next().ok_or(HashSigParseError::MissingHashString)?)?;
        let file_size = parse_wildcard_field!(
            fields,
            parse_number_dec,
            HashSigParseError::MissingFileSize,
            HashSigParseError::ParseSize
        )?;
        let name = str::from_utf8(fields.next().ok_or(ParseError::MissingName)?)
            .map_err(ParseError::NameNotUnicode)?
            .to_owned();

        Ok(Self {
            name,
            hash,
            file_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn eicar() {
        let bytes = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature".as_bytes();
        let sig: FileHashSig = bytes.try_into().unwrap();
        assert_eq!(sig.name, "Eicar-Test-Signature");
        assert_eq!(sig.file_size, Some(68));
        assert_eq!(
            sig.hash,
            util::Hash::Md5(hex!("44d88612fea8a8f36de82e1278abb02f"))
        );
    }
}
