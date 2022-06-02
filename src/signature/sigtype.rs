use std::{ffi::OsStr, path::Path, str::FromStr};
use thiserror::Error;

/// Signature types
#[derive(Debug, Clone, Copy)]
pub enum SigType {
    /// [Extended signature](crate::signature::ext::ExtendedSig)
    Extended,
    /// [Logical signature](crate::signature::logical::LogicalSig)
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
    pub fn from_file_extension(ext: &str) -> Option<Self> {
        Some(match ext {
            //
            // Body-based signatures
            //

            // Extended signatures
            "ndb" | "ndu" => SigType::Extended,
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
            "crb" => todo!(),

            // False positive list
            "sfp" | "fp" => todo!(),

            "info" => todo!(),

            // Icon signatures
            "idb" => todo!(),

            // Deprecated types
            "zmd" | "rmd" | "db" => todo!(),

            // Configuration
            "cfg" => todo!(),

            // Oh crap
            "sdb" => todo!(),

            // Imp hash
            "imp" => todo!(),

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
