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
    signature::{hash::ParseError, FromSigBytesParseError, SigMeta},
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
        Ok(())
    }
}

impl FromSigBytes for FileHashSig {
    fn from_sigbytes<'a, SB: Into<&'a SigBytes>>(
        sb: SB,
    ) -> Result<(Box<dyn crate::Signature>, super::SigMeta), FromSigBytesParseError> {
        let mut sigmeta = SigMeta::default();
        let mut fields = sb.into().as_bytes().split(|b| *b == b':');

        let hash = util::parse_hash(fields.next().ok_or(ParseError::MissingField("hash_string".to_string()))?)
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

            if let Some(max_flevel) = fields.next() {
                let max_flevel =
                    parse_number_dec(max_flevel).map_err(ParseError::ParseMaxFlevel)?;
                sigmeta.f_level = Some((min_flevel..=max_flevel).into());
            } else {
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
    fn export() {
        let bytes = b"44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature".into();
        let (sig, _) = FileHashSig::from_sigbytes(&bytes).unwrap();
        let exported = sig.to_sigbytes().unwrap();
        assert_eq!(&bytes, &exported);
    }
}
