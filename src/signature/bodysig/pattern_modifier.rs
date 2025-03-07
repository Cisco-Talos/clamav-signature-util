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

use std::fmt::Write;

use enumflags2::{bitflags, make_bitflags, BitFlags};

use crate::sigbytes::{AppendSigBytes, SigBytes};

/// Character classes, as they attach to strings. Combined with a negation flag,
/// they can contribute to a PatternModifier.  This maps directly to the way
/// ClamAV associates these with byte patterns.
#[bitflags]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PatternModifier {
    BoundaryLeft = 0x0001,
    BoundaryLeftNegative = 0x0002,
    BoundaryRight = 0x0004,
    BoundaryRightNegative = 0x0008,
    LineMarkerLeft = 0x0010,
    LineMarkerLeftNegative = 0x0020,
    LineMarkerRight = 0x0040,
    LineMarkerRightNegative = 0x0080,
    WordMarkerLeft = 0x0100,
    WordMarkerLeftNegative = 0x0200,
    WordMarkerRight = 0x0400,
    WordMarkerRightNegative = 0x0800,
}

impl PatternModifier {
    /// Return a mask containing all left-side pattern modifiers
    #[must_use]
    pub const fn left_flags() -> BitFlags<PatternModifier> {
        make_bitflags!(PatternModifier::{ BoundaryLeft | BoundaryLeftNegative | LineMarkerLeft |LineMarkerLeftNegative | WordMarkerLeft | WordMarkerLeftNegative})
    }

    /// Return a mask containing all right-side pattern modifiers
    #[must_use]
    pub const fn right_flags() -> BitFlags<PatternModifier> {
        make_bitflags!(PatternModifier::{ BoundaryRight | BoundaryRightNegative | LineMarkerRight |LineMarkerRightNegative | WordMarkerRight | WordMarkerRightNegative})
    }

    /// Return a mask containing all negated pattern modifiers
    #[must_use]
    pub const fn negative_flags() -> BitFlags<PatternModifier> {
        make_bitflags!(PatternModifier::{
         BoundaryLeftNegative | LineMarkerLeftNegative | WordMarkerLeftNegative |
         BoundaryRightNegative | LineMarkerRightNegative | WordMarkerRightNegative
        })
    }
}

impl AppendSigBytes for PatternModifier {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        if PatternModifier::negative_flags().contains(*self) {
            sb.write_char('!')?;
        }
        sb.write_char('(')?;
        sb.write_char(match self {
            PatternModifier::BoundaryLeft
            | PatternModifier::BoundaryLeftNegative
            | PatternModifier::BoundaryRight
            | PatternModifier::BoundaryRightNegative => 'B',
            PatternModifier::LineMarkerLeft
            | PatternModifier::LineMarkerLeftNegative
            | PatternModifier::LineMarkerRight
            | PatternModifier::LineMarkerRightNegative => 'L',
            PatternModifier::WordMarkerLeft
            | PatternModifier::WordMarkerLeftNegative
            | PatternModifier::WordMarkerRight
            | PatternModifier::WordMarkerRightNegative => 'W',
        })?;
        sb.write_char(')')?;
        Ok(())
    }
}
