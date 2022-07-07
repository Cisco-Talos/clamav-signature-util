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
    pub const fn left_flags() -> BitFlags<PatternModifier> {
        make_bitflags!(PatternModifier::{ BoundaryLeft | BoundaryLeftNegative | LineMarkerLeft |LineMarkerLeftNegative | WordMarkerLeft | WordMarkerLeftNegative})
    }

    /// Return a mask containing all right-side pattern modifiers
    pub const fn right_flags() -> BitFlags<PatternModifier> {
        make_bitflags!(PatternModifier::{ BoundaryRight | BoundaryRightNegative | LineMarkerRight |LineMarkerRightNegative | WordMarkerRight | WordMarkerRightNegative})
    }

    /// Return a mask containing all negated pattern modifiers
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
