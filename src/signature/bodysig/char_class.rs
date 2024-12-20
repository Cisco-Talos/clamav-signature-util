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

use crate::{
    sigbytes::{AppendSigBytes, SigBytes, SigChar},
    signature::bodysig::pattern_modifier::PatternModifier,
};
use enumflags2::BitFlags;
use std::fmt::Write;
use thiserror::Error;

/// Body signature "character classes".  These are markers that can appear to
/// the left or right of a hex signature, and further constrain the match.  They
/// may be negated when considered as part of a PatternModifier.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CharacterClass {
    /// Word Boundary (B).  Matches any non-word character
    WordBoundary,
    /// Line-or-File boundary (L).  Matches the beginning or ending of a line or a file
    LineOrFileBoundary,
    /// (W)
    NonAlphaChar,
}

#[derive(Debug, PartialEq, Error)]
pub enum CharacterClassParseError {
    #[error("{byte} not a known character class")]
    Unknown { byte: SigChar },
}

impl CharacterClass {
    /// Map a character class, side, and negation flag into the appropriate bit flag
    pub(crate) fn pattern_modifier(
        self,
        is_left_side: bool,
        negated: bool,
    ) -> BitFlags<PatternModifier> {
        use self::CharacterClass::{LineOrFileBoundary, NonAlphaChar, WordBoundary};

        match (self, is_left_side, negated) {
            (WordBoundary, true, false) => PatternModifier::BoundaryLeft.into(),
            (WordBoundary, true, true) => PatternModifier::BoundaryLeftNegative.into(),
            (LineOrFileBoundary, true, false) => PatternModifier::LineMarkerLeft.into(),
            (LineOrFileBoundary, true, true) => PatternModifier::LineMarkerLeftNegative.into(),
            (NonAlphaChar, true, false) => PatternModifier::WordMarkerLeft.into(),
            (NonAlphaChar, true, true) => PatternModifier::WordMarkerLeftNegative.into(),

            (WordBoundary, false, false) => PatternModifier::BoundaryRight.into(),
            (WordBoundary, false, true) => PatternModifier::BoundaryRightNegative.into(),
            (LineOrFileBoundary, false, false) => PatternModifier::LineMarkerRight.into(),
            (LineOrFileBoundary, false, true) => PatternModifier::LineMarkerRightNegative.into(),
            (NonAlphaChar, false, false) => PatternModifier::WordMarkerRight.into(),
            (NonAlphaChar, false, true) => PatternModifier::WordMarkerRightNegative.into(),
        }
    }
}

impl TryFrom<u8> for CharacterClass {
    type Error = CharacterClassParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            b'B' => CharacterClass::WordBoundary,
            b'L' => CharacterClass::LineOrFileBoundary,
            b'W' => CharacterClass::NonAlphaChar,
            byte => return Err(CharacterClassParseError::Unknown { byte: byte.into() }),
        })
    }
}

impl AppendSigBytes for CharacterClass {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        match self {
            CharacterClass::WordBoundary => sb.write_str("(B)")?,
            CharacterClass::LineOrFileBoundary => sb.write_str("(L)")?,
            CharacterClass::NonAlphaChar => sb.write_str("(W)")?,
        }
        Ok(())
    }
}
