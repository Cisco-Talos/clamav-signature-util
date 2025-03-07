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

use std::{ffi::OsStr, path::Path, str::FromStr};
use thiserror::Error;

/// Signature types
#[derive(Debug, Clone, Copy)]
pub enum SigType {
    /// [Extended signature](crate::signature::ext::ExtendedSig)
    Extended,
    /// [Logical signature](crate::signature::logical_sig::LogicalSig)
    Logical,
    /// [Container Metadata signature](crate::signature::container_metadata::ContainerMetadataSig)
    ContainerMetadata,
    /// Bytecode signature
    Bytecode,
    /// Phishing URL
    PhishingURL,
    /// [File Hash signature](crate::signature::filehash::FileHashSig)
    FileHash,
    /// [Filetype Magic signature](crate::signature::filetype_magic::FTMagic)
    FTMagic,
    /// [Portable Executable Section Hash signature](crate::signature::pehash::PESectionHashSig)
    PESectionHash,
    /// Yara signature
    Yara,
    /// [Digital signature](crate::signature::digital_signature::DigitalSignature)
    DigitalSignature,
}

#[derive(Debug, Error)]
pub enum SigTypeParseError {
    #[error("unknown signature type")]
    Unknown,
}

impl SigType {
    /// Return the signature type as specified by the extension the specified
    /// file path.  Returns `None` if the file has no extension, or the extension
    /// is not known to map to a signature type.
    pub fn from_file_path<'a, P: Into<&'a Path>>(path: P) -> Option<Self> {
        let path: &Path = path.into();
        if let Some(extension) = path.extension().and_then(OsStr::to_str) {
            Self::from_file_extension(extension)
        } else {
            None
        }
    }

    /// Return the signature type implied by the provided file extension, or None
    /// if the extension is not recognized.
    #[must_use]
    pub fn from_file_extension(ext: &str) -> Option<Self> {
        Some(match ext {
            //
            // Body-based signatures
            //

            // Extended signatures
            "ndb" | "ndu" | "sdb" => SigType::Extended,
            // Logical signatures
            "ldb" | "ldu" => SigType::Logical,
            // Container metadata signatures
            "cdb" => SigType::ContainerMetadata,
            // Bytecode sigantures
            "cbc" => SigType::Bytecode,
            // Phishing URL signatures
            "pdb" | "gdb" | "wdb" => SigType::PhishingURL,

            //
            // Hash-based signatures
            //

            // File hash signatures
            "hdb" | "hsb" | "hdu" | "hsu" => SigType::FileHash,
            // PE section has signatures
            "mdb" | "msb" | "mdu" | "msu" => SigType::PESectionHash,

            // Filetype Magic signatures
            "ftm" => SigType::FTMagic,

            // Trusted and Revoked Certificates
            "crb" => {
                println!("Support for .crb is not yet implemented.");
                return None;
            }

            // False positive list
            "sfp" | "fp" => {
                println!("Support for .sfp and .fp is not yet implemented.");
                return None;
            }

            "info" => {
                println!("Support for .info is not yet implemented.");
                return None;
            }

            // Icon signatures
            "idb" => {
                println!("Support for .idb is not yet implemented.");
                return None;
            }

            // Deprecated types
            "zmd" | "rmd" | "db" => {
                println!(
                    "Support for deprecated types .zmd, .rmd, and .db are not yet implemented."
                );
                return None;
            }

            // Configuration
            "cfg" => {
                println!("Support for .cfg is not yet implemented.");
                return None;
            }

            // Imp hash
            "imp" => {
                println!("Support for .imp is not yet implemented.");
                return None;
            }

            //
            // Digital signatures
            //
            "sign" => SigType::DigitalSignature,

            _ => return None,
        })
    }
}

impl FromStr for SigType {
    type Err = SigTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SigType::from_file_extension(s).ok_or(SigTypeParseError::Unknown)
    }
}
