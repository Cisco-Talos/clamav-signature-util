use std::{fmt, ops::RangeInclusive};
use thiserror::Error;

use crate::sigbytes::SigChar;

/// A position within the expression to report the error, either relative to the
/// start of the expression or at the end (after all characters have been processed)
#[derive(Debug)]
pub enum Position {
    End,
    Relative(usize),
    Range(RangeInclusive<usize>),
}

#[derive(Debug, Error)]
pub enum LogExprParseError {
    #[error("invalid character at {0}: {1}")]
    InvalidCharacter(Position, SigChar),

    #[error("unexpected operator at {0}")]
    UnexpectedOperator(Position),

    #[error("modifier value specified at {0} is too large")]
    ModifierMatchValueOverflow(Position),

    #[error("no value following `,` in modifier expression at {0}")]
    ModifierMatchUniqMissing(Position),

    #[error("modifier match requirement missing after modifier operator at {0}")]
    ModifierMatchReqMissing(Position),
}

impl std::fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Position::End => write!(f, "end of expression"),
            Position::Relative(pos) => write!(f, "pos({}) within logical expr", pos + 1),
            Position::Range(range) => write!(
                f,
                "pos({}-{}) within logical expr",
                range.start() + 1,
                range.end() + 1,
            ),
        }
    }
}

// The stream iteration iterates over position and byte. This conversion makes
// it simple to just extract out the position, or report end-of-stream.
impl From<Option<(usize, u8)>> for Position {
    fn from(value: Option<(usize, u8)>) -> Self {
        if let Some((pos, _)) = value {
            Position::Relative(pos)
        } else {
            Position::End
        }
    }
}

impl From<usize> for Position {
    fn from(value: usize) -> Self {
        Position::Relative(value)
    }
}

impl From<RangeInclusive<usize>> for Position {
    fn from(range: RangeInclusive<usize>) -> Self {
        Position::Range(range)
    }
}
