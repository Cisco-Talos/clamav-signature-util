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

use std::{fmt, ops::RangeInclusive};
use thiserror::Error;

use crate::sigbytes::SigChar;

/// A position within the expression to report the error, either relative to the
/// start of the expression or at the end (after all characters have been processed)
#[derive(Debug, PartialEq)]
pub enum Position {
    End,
    Relative(usize),
    Range(RangeInclusive<usize>),
}

#[derive(Debug, Error, PartialEq)]
pub enum Parse {
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
