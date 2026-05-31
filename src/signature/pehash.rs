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

impl PESectionHashSig {
    #[must_use]
    pub fn size(&self) -> Option<usize> {
        self.size
    }

    #[must_use]
    pub fn hash(&self) -> &Hash {
        &self.hash
    }
}

/// Hash signatures over a PE import table (`.imp`).
#[derive(Debug)]
pub struct PEImportHashSig {
    name: String,
    size: Option<usize>,
    hash: Hash,
}

impl PEImportHashSig {
    #[must_use]
    pub fn size(&self) -> Option<usize> {
        self.size
    }

    #[must_use]
    pub fn hash(&self) -> &Hash {
        &self.hash
    }
}

impl Signature for PEImportHashSig {
    fn name(&self) -> &str {
        &self.name
    }
}

impl EngineReq for PEImportHashSig {
    fn features(&self) -> Set {
        Set::from_static(match (self.size, &self.hash) {
            (None, Hash::Md5(_)) => &[Feature::HashSizeUnknown],
            (None, Hash::Sha1(_)) => &[Feature::HashSizeUnknown, Feature::HashSha1],
            (None, Hash::Sha2_256(_)) => &[Feature::HashSizeUnknown, Feature::HashSha256],
            (Some(_), Hash::Md5(_)) => &[],
            (Some(_), Hash::Sha1(_)) => &[Feature::HashSha1],
            (Some(_), Hash::Sha2_256(_)) => &[Feature::HashSha256],
        })
    }
}

impl AppendSigBytes for PEImportHashSig {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        append_pe_hash_sigbytes(sb, self.size, &self.hash, &self.name)
    }
}

impl FromSigBytes for PEImportHashSig {
    fn from_sigbytes<'a, SB: Into<&'a SigBytes>>(
        sb: SB,
    ) -> Result<(Box<dyn crate::Signature>, super::SigMeta), FromSigBytesParseError> {
        let (name, size, hash, sigmeta) = parse_pe_hash_sigbytes(sb)?;
        Ok((Box::new(Self { name, size, hash }), sigmeta))
    }
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
        append_pe_hash_sigbytes(sb, self.size, &self.hash, &self.name)
    }
}

impl FromSigBytes for PESectionHashSig {
    fn from_sigbytes<'a, SB: Into<&'a SigBytes>>(
        sb: SB,
    ) -> Result<(Box<dyn crate::Signature>, super::SigMeta), FromSigBytesParseError> {
        let (name, size, hash, sigmeta) = parse_pe_hash_sigbytes(sb)?;
        Ok((Box::new(Self { name, size, hash }), sigmeta))
    }
}

fn append_pe_hash_sigbytes(
    sb: &mut SigBytes,
    size: Option<usize>,
    hash: &Hash,
    name: &str,
) -> Result<(), crate::signature::ToSigBytesError> {
    let size_hint = name.len() + hash.size() * 2 + 10;
    sb.try_reserve_exact(size_hint)?;

    if let Some(size) = size {
        write!(sb, "{size}")?;
    } else {
        sb.write_char('*')?;
    }

    write!(sb, ":{hash}:{name}")?;
    Ok(())
}

fn parse_pe_hash_sigbytes<'a, SB: Into<&'a SigBytes>>(
    sb: SB,
) -> Result<(String, Option<usize>, Hash, super::SigMeta), FromSigBytesParseError> {
    let mut sigmeta = SigMeta::default();
    let mut fields = sb.into().as_bytes().split(|b| *b == b':');
    let size = parse_field!(
        OPTIONAL
        fields,
        parse_number_dec,
        ParseError::MissingFileSize,
        ParseError::ParseSize
    )?;
    let hash = util::parse_hash(
        fields
            .next()
            .ok_or(ParseError::MissingField("hash_string".to_string()))?,
    )
    .map_err(ParseError::ParseHash)?;
    let name = str::from_utf8(fields.next().ok_or(FromSigBytesParseError::MissingName)?)
        .map_err(FromSigBytesParseError::NameNotUnicode)?
        .to_owned();

    // Parse optional min/max flevel
    if let Some(min_flevel) = fields.next() {
        let min_flevel = parse_number_dec(min_flevel).map_err(ParseError::ParseMinFlevel)?;

        if let Some(max_flevel) = fields.next() {
            let max_flevel = parse_number_dec(max_flevel).map_err(ParseError::ParseMaxFlevel)?;
            sigmeta.f_level = Some((min_flevel..=max_flevel).into());
        } else {
            sigmeta.f_level = Some((min_flevel..).into());
        }
    }

    Ok((name, size, hash, sigmeta))
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
        assert_eq!(sig.size(), Some(45056));
        assert_eq!(
            sig.hash,
            crate::util::Hash::Sha2_256(hex!(
                "f9b304ced34fcce3ab75c6dc58ad59e4d62177ffed35494f79f09bc4e8986c16"
            ))
        );
        assert_eq!(
            sig.hash(),
            &crate::util::Hash::Sha2_256(hex!(
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

    #[test]
    fn import_hash() {
        let bytes = b"*:44d88612fea8a8f36de82e1278abb02f:Win.Test.IMP-1".into();
        let (sig, _) = PEImportHashSig::from_sigbytes(&bytes).unwrap();
        let sig = sig.downcast_ref::<PEImportHashSig>().unwrap();
        assert_eq!(sig.name(), "Win.Test.IMP-1");
        assert_eq!(sig.size(), None);
        assert_eq!(
            sig.hash(),
            &crate::util::Hash::Md5(hex!("44d88612fea8a8f36de82e1278abb02f"))
        );
        let exported = sig.to_sigbytes().unwrap();
        assert_eq!(&bytes, &exported);
    }
}
