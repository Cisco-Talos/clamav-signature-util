use crate::{
    feature::{EngineReq, Feature, FeatureSet},
    signature::{hash::HashSigParseError, ParseError, ToSigBytesError},
    util::{self, parse_field, parse_number_dec, Hash},
};
use std::{convert::TryFrom, fmt::Write, str};

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

    fn to_sigbytes(&self) -> Result<util::SigBytes, ToSigBytesError> {
        let mut result = String::with_capacity(self.name.len() + self.hash.len() * 2 + 16);

        write!(result, "{}:", self.hash)?;
        if let Some(size) = self.file_size {
            write!(result, "{}:", size)?
        } else {
            result.write_char('*')?
        }
        write!(result, "{}", self.name)?;
        Ok(result.into())
    }
}

impl EngineReq for FileHashSig {
    fn features(&self) -> FeatureSet {
        FeatureSet::from_static(match (self.file_size, &self.hash) {
            (None, Hash::Sha1(_)) => &[Feature::HashSizeUnknown, Feature::HashSha1],
            (None, Hash::Sha2_256(_)) => &[Feature::HashSizeUnknown, Feature::HashSha256],
            (Some(_), Hash::Sha1(_)) => &[Feature::HashSha1][..],
            (Some(_), Hash::Sha2_256(_)) => &[Feature::HashSha256][..],
            _ => return FeatureSet::default(),
        })
    }
}

impl TryFrom<&[u8]> for FileHashSig {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut fields = data.split(|b| *b == b':');

        let hash = util::parse_hash(fields.next().ok_or(HashSigParseError::MissingHashString)?)?;
        let file_size = parse_field!(
            OPTIONAL
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
    use crate::Signature;

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

    #[test]
    fn export() {
        let bytes = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature";
        let sig: FileHashSig = bytes.as_bytes().try_into().unwrap();
        let exported = sig.to_sigbytes().unwrap().to_string();
        assert_eq!(bytes, &exported);
    }
}
