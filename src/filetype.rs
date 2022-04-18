use num_derive::{FromPrimitive, ToPrimitive};
use std::{
    fmt::Write,
    str::{self, FromStr, Utf8Error},
};
use strum_macros::{Display, EnumString};
use thiserror::Error;

use crate::sigbytes::AppendSigBytes;

///
/// File types that ClamAV knows about
///

const CL_TYPENO: isize = 500;

#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Display, EnumString, FromPrimitive, ToPrimitive)]
pub enum FileType {
    CL_TYPE_ANY = 0,
    CL_TYPE_TEXT_ASCII = CL_TYPENO, /* X3.4, ISO-8859, non-ISO ext. ASCII */
    CL_TYPE_TEXT_UTF8,
    CL_TYPE_TEXT_UTF16LE,
    CL_TYPE_TEXT_UTF16BE,
    CL_TYPE_BINARY_DATA,
    /* Please do not add any new types above this line */
    CL_TYPE_ERROR,
    CL_TYPE_MSEXE,
    CL_TYPE_ELF,
    CL_TYPE_MACHO,
    CL_TYPE_MACHO_UNIBIN,
    CL_TYPE_POSIX_TAR,
    CL_TYPE_OLD_TAR,
    CL_TYPE_CPIO_OLD,
    CL_TYPE_CPIO_ODC,
    CL_TYPE_CPIO_NEWC,
    CL_TYPE_CPIO_CRC,
    CL_TYPE_GZ,
    CL_TYPE_ZIP,
    CL_TYPE_BZ,
    CL_TYPE_RAR,
    CL_TYPE_ARJ,
    CL_TYPE_MSSZDD,
    CL_TYPE_MSOLE2,
    CL_TYPE_MSCAB,
    CL_TYPE_MSCHM,
    CL_TYPE_SIS,
    CL_TYPE_SCRENC,
    CL_TYPE_GRAPHICS,
    CL_TYPE_GIF,
    CL_TYPE_PNG,
    CL_TYPE_JPEG,
    CL_TYPE_TIFF,
    CL_TYPE_RIFF,
    CL_TYPE_BINHEX,
    CL_TYPE_TNEF,
    CL_TYPE_CRYPTFF,
    CL_TYPE_PDF,
    CL_TYPE_UUENCODED,
    CL_TYPE_SCRIPT,
    CL_TYPE_HTML_UTF16,
    CL_TYPE_RTF,
    CL_TYPE_7Z,
    CL_TYPE_SWF,
    CL_TYPE_JAVA,
    CL_TYPE_XAR,
    CL_TYPE_XZ,
    CL_TYPE_OOXML_WORD,
    CL_TYPE_OOXML_PPT,
    CL_TYPE_OOXML_XL,
    CL_TYPE_INTERNAL,
    CL_TYPE_HWP3,
    CL_TYPE_OOXML_HWP,
    CL_TYPE_PS,
    CL_TYPE_EGG,

    /* Section for partition types */
    CL_TYPE_PART_ANY, /* unknown partition type */
    CL_TYPE_PART_HFSPLUS,

    /* bigger numbers have higher priority (in o-t-f detection) */
    CL_TYPE_MBR,
    CL_TYPE_HTML,   /* on the fly */
    CL_TYPE_MAIL,   /* magic + on the fly */
    CL_TYPE_SFX,    /* foo SFX marker */
    CL_TYPE_ZIPSFX, /* on the fly */
    CL_TYPE_RARSFX, /* on the fly */
    CL_TYPE_7ZSFX,
    CL_TYPE_CABSFX,
    CL_TYPE_ARJSFX,
    CL_TYPE_EGGSFX,
    CL_TYPE_NULSFT, /* on the fly */
    CL_TYPE_AUTOIT,
    CL_TYPE_ISHIELD_MSI,
    CL_TYPE_ISO9660,
    CL_TYPE_DMG,
    CL_TYPE_GPT,
    CL_TYPE_APM,
    CL_TYPE_XDP,
    CL_TYPE_XML_WORD,
    CL_TYPE_XML_XL,
    CL_TYPE_XML_HWP,
    CL_TYPE_HWPOLE2,
    CL_TYPE_MHTML,
    CL_TYPE_LNK,

    CL_TYPE_OTHER,   /* on-the-fly, used for target 14 (OTHER) */
    CL_TYPE_IGNORED, /* please don't add anything below */
}

#[derive(Debug, Error, PartialEq)]
pub enum FileTypeParseError {
    #[error("not UTF-8: {0}")]
    UTF8(#[from] Utf8Error),

    #[error("parsing FileType: {0}")]
    Unknown(#[from] strum::ParseError),
}

impl<'a> TryFrom<&[u8]> for FileType {
    type Error = FileTypeParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(FileType::from_str(str::from_utf8(bytes)?)?)
    }
}

impl AppendSigBytes for FileType {
    fn append_sigbytes(
        &self,
        sb: &mut crate::sigbytes::SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        Ok(write!(sb, "{}", self)?)
    }
}
