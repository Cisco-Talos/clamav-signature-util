use enum_variants_strings::EnumVariantsStrings;
use num_derive::{FromPrimitive, ToPrimitive};
use std::str;
use thiserror::Error;

const CL_TYPENO: isize = 500;

#[derive(Debug, FromPrimitive, ToPrimitive, EnumVariantsStrings)]
#[enum_variants_strings_transform(transform = "none")]
#[allow(non_camel_case_types)]
pub enum ContainerType {
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

#[derive(Debug, Error)]
pub enum ContainerTypeParseError {
    #[error("not valid unicode: {0}")]
    NotUnicode(#[from] str::Utf8Error),

    #[error("unknown ContainerType ID")]
    Unknown,
}

impl TryFrom<&[u8]> for ContainerType {
    type Error = ContainerTypeParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        ContainerType::from_str(str::from_utf8(value)?)
            .map_err(|_| ContainerTypeParseError::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid() {
        assert!(matches!(
            "CL_TYPE_HTML".as_bytes().try_into(),
            Ok(ContainerType::CL_TYPE_HTML)
        ));
    }

    #[test]
    fn not_unicode() {
        assert!(matches!(
            ContainerType::try_from(&[0x80u8][..]),
            Err(ContainerTypeParseError::NotUnicode(_))
        ));
    }

    #[test]
    fn unknown() {
        assert!(matches!(
            ContainerType::try_from("CL_TYPE_XYZZY".as_bytes()),
            Err(ContainerTypeParseError::Unknown)
        ));
    }
}
