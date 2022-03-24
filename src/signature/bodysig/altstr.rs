use std::{fmt::Write, ops::RangeInclusive};
use thiserror::Error;

use crate::sigbytes::{AppendSigBytes, SigBytes};

#[derive(Debug)]
pub enum AlternateStrings {
    FixedWidth {
        negated: bool,
        width: usize,
        data: Vec<u8>,
    },
    VariableWidth {
        ranges: Vec<RangeInclusive<usize>>,
        data: Vec<u8>,
    },
}

#[derive(Debug, Error)]
pub enum AlternateStringsParseError {
    #[error("parsing alternative string {0} hex value: {1}")]
    FromHex(usize, hex::FromHexError),

    #[error("generic alternative strings may not be negated")]
    NegatedGenAlt,
}

impl TryFrom<(bool, &[u8])> for AlternateStrings {
    type Error = AlternateStringsParseError;

    fn try_from(value: (bool, &[u8])) -> Result<Self, Self::Error> {
        let (negated, value) = value;
        debug_assert!(!value.is_empty());

        let mut ranges = vec![];
        let mut data = vec![];
        let mut last_start = 0;
        let mut last_size = None;
        let mut elements_differ_in_size = false;
        for (asidx, element) in value.split(|&b| b == b'|').enumerate() {
            let element =
                hex::decode(element).map_err(|e| AlternateStringsParseError::FromHex(asidx, e))?;
            if !elements_differ_in_size {
                match last_size {
                    None => last_size = Some(element.len()),
                    Some(size) => elements_differ_in_size = size != element.len(),
                }
            }
            ranges.push(last_start..=(last_start + element.len() - 1));
            last_start += element.len();
            data.extend(element);
        }

        if elements_differ_in_size {
            if negated {
                Err(AlternateStringsParseError::NegatedGenAlt)
            } else {
                Ok(AlternateStrings::VariableWidth { ranges, data })
            }
        } else {
            // Negation gets fixed by the receiver
            Ok(AlternateStrings::FixedWidth {
                negated,
                width: last_size.unwrap(),
                data,
            })
        }
    }
}

impl AppendSigBytes for AlternateStrings {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        match self {
            AlternateStrings::FixedWidth {
                negated,
                width,
                data,
            } => {
                if *negated {
                    sb.write_char('!')?;
                }
                for (i, astr) in data.chunks_exact(*width).enumerate() {
                    sb.write_char(if i == 0 { '(' } else { '|' }).unwrap();
                    for byte in astr {
                        write!(sb, "{byte:02x}")?
                    }
                }
            }
            AlternateStrings::VariableWidth { ranges, data } => {
                for (i, range) in ranges.iter().enumerate() {
                    sb.write_char(if i == 0 { '(' } else { '|' })?;
                    let data = data.get(range.clone()).unwrap();
                    for byte in data {
                        write!(sb, "{byte:02x}")?
                    }
                }
            }
        }
        sb.write_char(')')?;
        Ok(())
    }
}
