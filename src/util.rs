use std::ops::RangeInclusive;
use std::str;
use thiserror::Error;

pub const MD5_LEN: usize = 16;
pub const SHA1_LEN: usize = 20;
pub const SHA2_256_LEN: usize = 32;

/// Generic hash digest container
#[derive(Debug)]
pub enum Hash {
    Md5([u8; MD5_LEN]),
    Sha1([u8; SHA1_LEN]),
    Sha2_256([u8; SHA2_256_LEN]),
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

/// A type wrapper around a single byte found in a signature. Allows implementing
/// `Display` to work around potential unicode problems
#[derive(Debug)]
pub struct SigChar(pub u8);

/// Convert a byte to its character representation, or a symbol indicating
/// invalid unicode
impl std::fmt::Display for SigChar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match str::from_utf8(&[self.0]) {
            Ok(s) => write!(f, "'{}'", s),
            Err(_) => write!(f, "{{0x{:x}}}", self.0),
        }
    }
}

impl From<u8> for SigChar {
    fn from(c: u8) -> Self {
        Self(c)
    }
}

#[test]
fn test_sichar_display() {
    assert_eq!(format!("{}", SigChar(b'x')), "x");
}
