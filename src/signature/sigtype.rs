use std::{ffi::OsStr, path::Path};

/// Signature types
#[derive(Debug, Clone, Copy)]
pub enum SigType {
    Extended,
    Logical,
    ContainerMetadata,
    Bytecode,
    PhishingURL,
    FileHash,
    PESectionHash,
    Yara,
}

impl SigType {
    /// Return the signature type as specified by the extension the specified
    /// file path.  Returns `None` if the file has no extension, or the extension
    /// is not known to map to a signature type.
    pub fn from_file_path<'a, P: Into<&'a Path>>(path: P) -> Option<Self> {
        let path: &Path = path.into();
        if let Some(extension) = path.extension().map(OsStr::to_str).flatten() {
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

            _ => return None,
        })
    }
}
