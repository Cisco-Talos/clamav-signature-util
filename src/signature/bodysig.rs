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

pub mod altstr;
pub mod char_class;
pub mod parse;
pub mod pattern;
pub mod pattern_modifier;

use crate::{
    feature::{EngineReq, Set},
    sigbytes::{AppendSigBytes, SigBytes},
};
pub use char_class::CharacterClass;
pub use pattern::Pattern;
pub use pattern_modifier::PatternModifier;

/// Body signature.  This is an element of both Extended and Logical signatures,
/// and contains byte match patterns.
#[derive(Debug, PartialEq)]
pub struct BodySig {
    // Just encode the raw data for now
    #[allow(dead_code)]
    /// Different elements that must be matched for the signature itself to match
    pub patterns: Vec<Pattern>,
}

impl AppendSigBytes for BodySig {
    fn append_sigbytes(&self, sb: &mut SigBytes) -> Result<(), crate::signature::ToSigBytesError> {
        for pattern in &self.patterns {
            pattern.append_sigbytes(sb)?;
        }
        Ok(())
    }
}

impl EngineReq for BodySig {
    fn features(&self) -> Set {
        let x = self
            .patterns
            .iter()
            .map(Pattern::features)
            .flat_map(Set::into_iter)
            .into();
        x
    }
}
