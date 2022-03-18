use crate::sigbytes::SigBytes;
use itertools::Itertools;
use std::ops::{RangeFrom, RangeInclusive, RangeToInclusive};
use std::str;
use thiserror::Error;

pub const MD5_LEN: usize = 16;
pub const SHA1_LEN: usize = 20;
pub const SHA2_256_LEN: usize = 32;

/// Generic hash digest container
#[derive(Debug, PartialEq)]
pub enum Hash {
    Md5([u8; MD5_LEN]),
    Sha1([u8; SHA1_LEN]),
    Sha2_256([u8; SHA2_256_LEN]),
}

impl Hash {
    /// Return the size of the hash (in its binary form)
    pub fn len(&self) -> usize {
        match self {
            Self::Md5(hash) => hash.len(),
            Self::Sha1(hash) => hash.len(),
            Self::Sha2_256(hash) => hash.len(),
        }
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // This is designed to operate without additional allocations
        // hex::encode_to_slice is guaranteed to write only `[0-9a-f]`, and
        // buffers are guaranteed to be the correct size.
        match self {
            Hash::Md5(data) => {
                let mut out = [0; MD5_LEN * 2];
                hex::encode_to_slice(data, &mut out).unwrap();
                f.write_str(unsafe { str::from_utf8_unchecked(&out) })
            }
            Hash::Sha1(data) => {
                let mut out = [0; SHA1_LEN * 2];
                hex::encode_to_slice(data, &mut out).unwrap();
                f.write_str(unsafe { str::from_utf8_unchecked(&out) })
            }
            Hash::Sha2_256(data) => {
                let mut out = [0; SHA2_256_LEN * 2];
                hex::encode_to_slice(data, &mut out).unwrap();
                f.write_str(unsafe { str::from_utf8_unchecked(&out) })
            }
        }
    }
}

/// Errors that can be encountered while parsing a hash from hex-encoded format
#[derive(Debug, Error)]
pub enum ParseHashError {
    #[error("unable to convert from hex: {0}")]
    InvalidHexChar(#[from] hex::FromHexError),

    #[error("unsupported hex-encoded hash length ({0})")]
    UnsupportedHashLength(usize),
}

/// Decode a hex-encoded byte sequence of given SIZE
pub fn decode_hex<T: AsRef<[u8]>, const SIZE: usize>(
    hex: T,
) -> Result<[u8; SIZE], hex::FromHexError> {
    let mut out = [0; SIZE];
    hex::decode_to_slice(hex, &mut out)?;
    Ok(out)
}

/// Parse a hex-encoded byte sequence into an appropriate digest container
pub fn parse_hash(hex: &[u8]) -> Result<Hash, ParseHashError> {
    match hex.len() / 2 {
        MD5_LEN => Ok(Hash::Md5(decode_hex(hex)?)),
        SHA1_LEN => Ok(Hash::Sha1(decode_hex(hex)?)),
        SHA2_256_LEN => Ok(Hash::Sha2_256(decode_hex(hex)?)),
        len => Err(ParseHashError::UnsupportedHashLength(len)),
    }
}

/// Errors that can occur when parsing a number when represented as &[u8] decimal number
#[derive(Debug, Error)]
pub enum ParseNumberError<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    #[error("not parseable: {0:?}")]
    Unparseable(<T as std::str::FromStr>::Err),

    #[error("not valid unicode: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
}

/// Errors that can be encountered while trying to parse an inclusive range
#[derive(Debug, Error)]
pub enum RangeInclusiveParseError<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    #[error("range missing upper bound")]
    MissingUpperBound,

    #[error("range missing lower bound")]
    MissingLowerBound,

    #[error("unable to parse bound: {0}")]
    BoundParse(#[from] ParseNumberError<T>),
}

/// Parse a decimal number from &[u8]
pub fn parse_number_dec<T>(s: &[u8]) -> Result<T, ParseNumberError<T>>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    str::from_utf8(s)?
        .parse()
        .map_err(|e| ParseNumberError::Unparseable(e))
}

/// Parse a hexadecimal number from &[u8]
pub fn parse_number_hex(s: &[u8]) -> Result<u64, ParseNumberError<u64>>
where {
    u64::from_str_radix(str::from_utf8(s)?.trim_start_matches("0x"), 16)
        .map_err(ParseNumberError::Unparseable)
}

/// Parse an inclusive range from `&[u8]` representing "lower-upper"
pub fn parse_usize_range_inclusive<T>(
    s: &[u8],
) -> Result<RangeInclusive<T>, RangeInclusiveParseError<T>>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    let mut values = s.splitn(2, |&b| b == b'-');

    let lower = parse_number_dec(
        values
            .next()
            .ok_or(RangeInclusiveParseError::MissingLowerBound)?,
    )?;
    let upper = parse_number_dec(
        values
            .next()
            .ok_or(RangeInclusiveParseError::MissingUpperBound)?,
    )?;
    Ok(lower..=upper)
}

#[derive(Debug, Error)]
#[error("invalid boolean value (must be 0 or 1)")]
pub struct ParseBoolFromIntError;

pub fn parse_bool_from_int(bytes: &[u8]) -> Result<bool, ParseBoolFromIntError> {
    match bytes {
        b"0" => Ok(false),
        b"1" => Ok(true),
        _ => Err(ParseBoolFromIntError),
    }
}

/// Return a predicate usable for splitting a byte slice on the specified
/// character, but not if it is preceded with an escape character.  The escape
/// character may escape any other character (including itself).
pub fn unescaped_element<T: PartialEq + Copy>(
    escape_element: T,
    needle: T,
) -> impl FnMut(&T) -> bool {
    let mut escaped = false;

    move |&b| {
        if escaped {
            escaped = false;
            false
        } else if b == escape_element {
            escaped = true;
            false
        } else if !escaped && b == needle {
            true
        } else {
            escaped = false;
            false
        }
    }
}

/// Detect whether the a field has a wildcard (`*`) value, returning None if it
/// does, or Some(orig_field_value) if it doesn't.
pub fn opt_field_value(bytes: &[u8]) -> Option<&[u8]> {
    if bytes == b"*" {
        None
    } else {
        Some(bytes)
    }
}

/// Pull the next value from an iterator.  If no values remain, throw
/// `$missing_err`.  Otherwise, pass the value to `$parser` and map any error it
/// returns to `$invalid_err`.
///
/// If the `OPTIONAL` prefix is specified, returns an `Option`, substituting
/// `None` for a literal field value of "`*`" rather than passing the value to
/// the parser.
macro_rules! parse_field {
    ( OPTIONAL $field_iter:expr, $parser:expr, $missing_err:expr, $parse_err:expr) => {
        crate::util::opt_field_value($field_iter.next().ok_or($missing_err)?)
            .map($parser)
            .transpose()
            .map_err($parse_err)
    };
    ( $field_iter:expr, $parser:expr, $missing_err:expr, $parse_err:expr) => {
        $parser($field_iter.next().ok_or($missing_err)?).map_err($parse_err)
    };
}
pub(crate) use parse_field;

/// Generic container for any range of usize
#[derive(Debug)]
pub enum Range<T: std::str::FromStr> {
    // {n}
    Exact(T),
    // {-n}
    ToInclusive(RangeToInclusive<T>),
    // {n-}
    From(RangeFrom<T>),
    // {n-m}
    Inclusive(RangeInclusive<T>),
}

#[derive(Debug, Error)]
pub enum RangeParseError<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    #[error("parsing size range start: {0}")]
    Start(ParseNumberError<T>),

    #[error("parsing size range end: {0}")]
    End(ParseNumberError<T>),

    #[error("parsing exact size: {0}")]
    Exact(ParseNumberError<T>),
}

impl<T: std::str::FromStr + std::fmt::Display> Range<T> {
    pub fn append_sigbytes(
        &self,
        s: &mut SigBytes,
    ) -> Result<(), crate::signature::ToSigBytesError> {
        use std::fmt::Write;

        match self {
            Range::Exact(n) => write!(s, "{{{n}}}")?,
            Range::ToInclusive(RangeToInclusive { end }) => write!(s, "{{-{end}}}")?,
            Range::From(RangeFrom { start }) => write!(s, "{{{start}-}}")?,
            Range::Inclusive(range) => write!(s, "{{{}-{}}}", range.start(), range.end())?,
        }

        Ok(())
    }
}

impl<T> TryFrom<&[u8]> for Range<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    type Error = RangeParseError<T>;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if let Some(s) = value.strip_prefix(&[b'-']) {
            Ok(Self::ToInclusive(
                ..=parse_number_dec(s).map_err(RangeParseError::End)?,
            ))
        } else if let Some(s) = value.strip_suffix(&[b'-']) {
            Ok(Self::From(
                parse_number_dec(s).map_err(RangeParseError::Start)?..,
            ))
        } else if let Some((sn, sm)) = value.splitn(2, |b| *b == b'-').tuples().next() {
            Ok(Self::Inclusive(
                parse_number_dec(sn).map_err(RangeParseError::Start)?
                    ..=parse_number_dec(sm).map_err(RangeParseError::End)?,
            ))
        } else {
            Ok(Self::Exact(
                parse_number_dec(value).map_err(RangeParseError::Exact)?,
            ))
        }
    }
}

impl<T: std::str::FromStr + std::fmt::Display> From<&Range<T>> for SigBytes {
    fn from(range: &Range<T>) -> Self {
        match range {
            Range::Exact(n) => format!("{{{n}}}").into(),
            Range::ToInclusive(RangeToInclusive { end }) => format!("{{-{end}}}").into(),
            Range::From(RangeFrom { start }) => format!("{{{start}-}}").into(),
            Range::Inclusive(range) => format!("{{{}-{}}}", range.start(), range.end()).into(),
        }
    }
}

/// Attempt to convert a `&[u8]` into a string.  The standard library doesn't
/// provide this specific variation.
///
/// Note that a `std::str::Utf8Error` is returned rather than a
/// `std::string::FromUtf8Error` since validation is performed prior to
/// allocation.
pub fn string_from_bytes(bytes: &[u8]) -> Result<String, std::str::Utf8Error> {
    Ok(std::str::from_utf8(bytes)?.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_on_escaped_delimiter() {
        let bytes = r#"abc:def\:ghi:hij\:\::klm"#.as_bytes();
        let mut fields = bytes.split(unescaped_element(b'\\', b':'));
        assert_eq!(fields.next(), Some(r#"abc"#.as_bytes()));
        assert_eq!(fields.next(), Some(r#"def\:ghi"#.as_bytes()));
        assert_eq!(fields.next(), Some(r#"hij\:\:"#.as_bytes()));
        assert_eq!(fields.next(), Some(r#"klm"#.as_bytes()));
    }
}
