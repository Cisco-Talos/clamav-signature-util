use std::{collections::TryReserveError, str};

use crate::{
    signature::{FromSigBytesParseError, SigMeta},
    Signature,
};

pub const BYTE_DISP_PREFIX: &str = "<|";
pub const BYTE_DISP_SUFFIX: &str = "|>";

/// A type wrapper around a series of bytes found in a signature.  Allows
/// implementing `Display` to work around potential unicode problems.
#[derive(Debug, Default, PartialEq)]
pub struct SigBytes(Vec<u8>);

impl SigBytes {
    pub fn new() -> Self {
        SigBytes::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        SigBytes(Vec::with_capacity(capacity))
    }

    pub fn try_reserve_exact(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.0.try_reserve(additional)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A trait implemented by entities that can format themselves into the format
/// used in ClamAV signature databases
pub trait AppendSigBytes {
    /// Append ClamAV database-style value into the specified SigBytes container
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError>;
}

pub trait FromSigBytes {
    fn from_sigbytes<'a, SB: Into<&'a SigBytes>>(
        sb: SB,
    ) -> Result<(Box<dyn Signature>, SigMeta), FromSigBytesParseError>;
}

impl std::fmt::Display for SigBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes = self.0.as_slice();
        loop {
            match str::from_utf8(bytes) {
                Ok(s) => {
                    f.write_str(s)?;
                    break Ok(());
                }
                Err(e) => {
                    let (valid, after_valid) = bytes.split_at(e.valid_up_to());
                    unsafe {
                        // This portion is known to be valid
                        f.write_str(str::from_utf8_unchecked(valid))
                    }?;
                    match e.error_len() {
                        Some(len) => {
                            f.write_str(BYTE_DISP_PREFIX)?;
                            after_valid[0..len]
                                .iter()
                                .try_for_each(|&b| write!(f, "{:02x}", b))?;
                            f.write_str(BYTE_DISP_SUFFIX)?;
                            bytes = &after_valid[len..];
                        }
                        None => break Ok(()),
                    }
                }
            }
        }
    }
}

impl From<Vec<u8>> for SigBytes {
    fn from(bytes: Vec<u8>) -> Self {
        SigBytes(bytes)
    }
}

impl<'a> From<&'a SigBytes> for &'a [u8] {
    fn from(sigbytes: &'a SigBytes) -> Self {
        &sigbytes.0
    }
}

impl From<String> for SigBytes {
    fn from(s: String) -> Self {
        SigBytes(s.into_bytes())
    }
}

impl From<&str> for SigBytes {
    fn from(s: &str) -> Self {
        SigBytes(s.as_bytes().to_owned())
    }
}

impl From<&[u8]> for SigBytes {
    fn from(bytes: &[u8]) -> Self {
        SigBytes(bytes.to_owned())
    }
}

// This allows easy transforms from constants like `b"abc"` without slicing
impl<const N: usize> From<&[u8; N]> for SigBytes {
    fn from(bytes: &[u8; N]) -> Self {
        SigBytes(bytes.to_vec())
    }
}

/// A type wrapper around a single byte found in a signature. Allows implementing
/// `Display` to work around potential unicode problems
#[derive(Debug, PartialEq)]
pub struct SigChar(pub u8);

/// Convert a byte to its character representation, or a symbol indicating
/// invalid unicode
impl std::fmt::Display for SigChar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match str::from_utf8(&[self.0]) {
            Ok(s) => write!(f, "'{}'", s),
            Err(_) => write!(f, "{}{:x}{}", BYTE_DISP_PREFIX, self.0, BYTE_DISP_SUFFIX),
        }
    }
}

impl From<u8> for SigChar {
    fn from(c: u8) -> Self {
        Self(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigchar_display() {
        assert_eq!(format!("{}", SigChar(b'x')), "'x'");
        assert_eq!(format!("{}", SigChar(b'\x80')), "<|80|>");
    }

    #[test]
    fn sigbytes_valid() {
        const INPUT: &[u8] = b"how now brown cow";
        let bytes: SigBytes = INPUT.into();
        assert_eq!(
            format!("{}", bytes),
            String::from_utf8(INPUT.to_owned()).unwrap()
        );
    }

    #[test]
    fn sigbytes_invalid_short_end() {
        let bytes: SigBytes = b"how now brown cow\x80".into();
        assert_eq!(format!("{}", bytes), "how now brown cow<|80|>");
    }

    #[test]
    fn sigbytes_invalid_long_end() {
        let bytes: SigBytes = b"how now brown cow\xa0\xa1".into();
        assert_eq!(format!("{}", bytes), "how now brown cow<|a0|><|a1|>");
    }

    #[test]
    fn sigbytes_invalid_long_intermediate() {
        let bytes: SigBytes = b"how now\xa0\xa1brown cow".into();
        assert_eq!(format!("{}", bytes), "how now<|a0|><|a1|>brown cow");
    }
}

impl std::io::Write for SigBytes {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl std::fmt::Write for SigBytes {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        use std::io::Write;
        self.0
            .write(s.as_bytes())
            .map(|_| ())
            .map_err(|_| std::fmt::Error)
    }
}
