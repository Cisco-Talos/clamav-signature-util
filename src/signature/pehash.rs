use crate::{
    feature::{EngineReq, Feature, Set},
    sigbytes::{AppendSigBytes, FromSigBytes, SigBytes},
    signature::{hash::ParseError, FromSigBytesParseError, SigMeta, Signature},
    util::{self, parse_field, parse_number_dec, Hash},
};
use std::{fmt::Write, str};

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
    fn features(&self) -> Set {
        Set::from_static(match (self.size, &self.hash) {
            (None, Hash::Sha1(_)) => &[Feature::HashSizeUnknown, Feature::HashSha1],
            (None, Hash::Sha2_256(_)) => &[Feature::HashSizeUnknown, Feature::HashSha256],
            (Some(_), Hash::Sha1(_)) => &[Feature::HashSha1],
            (Some(_), Hash::Sha2_256(_)) => &[Feature::HashSha256],
            _ => return Set::default(),
        })
    }
}

impl AppendSigBytes for PESectionHashSig {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        let size_hint = self.name.len() + self.hash.size() * 2 + 10;
        sb.try_reserve_exact(size_hint)?;

        if let Some(size) = self.size {
            write!(sb, "{size}")?;
        } else {
            sb.write_char('*')?;
        }

        write!(sb, ":{}:{}", self.hash, self.name)?;
        Ok(())
    }
}

impl FromSigBytes for PESectionHashSig {
    fn from_sigbytes<'a, SB: Into<&'a SigBytes>>(
        sb: SB,
    ) -> Result<(Box<dyn crate::Signature>, super::SigMeta), FromSigBytesParseError> {
        let mut sigmeta = SigMeta::default();
        let mut fields = sb.into().as_bytes().split(|b| *b == b':');
        let size = parse_field!(
            OPTIONAL
            fields,
            parse_number_dec,
            ParseError::MissingFileSize,
            ParseError::ParseSize
        )?;
        let hash = util::parse_hash(fields.next().ok_or(ParseError::MissingHashString)?)
            .map_err(ParseError::ParseHash)?;
        let name = str::from_utf8(fields.next().ok_or(FromSigBytesParseError::MissingName)?)
            .map_err(FromSigBytesParseError::NameNotUnicode)?
            .to_owned();

        // Parse optional min/max flevel
        if let Some(min_flevel) = fields.next() {
            let min_flevel = parse_number_dec(min_flevel).map_err(ParseError::ParseMinFlevel)?;

            if let Some(max_flevel) = fields.next() {
                let max_flevel =
                    parse_number_dec(max_flevel).map_err(ParseError::ParseMaxFlevel)?;
                sigmeta.f_level = Some((min_flevel..=max_flevel).into());
            } else {
                sigmeta.f_level = Some((min_flevel..).into());
            }
        }

        Ok((Box::new(Self { name, size, hash }), sigmeta))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn eicar() {
        let bytes = b"45056:f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16:Win.Test.EICAR_MSB-1".into();
        let (sig, _) = PESectionHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<PESectionHashSig>().unwrap();
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
        let bytes = b"45056:f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16:Win.Test.EICAR_MSB-1".into();
        let (sig, _) = PESectionHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<PESectionHashSig>().unwrap();
        let exported = sig.to_sigbytes().unwrap();
        assert_eq!(&bytes, &exported);
    }
}
