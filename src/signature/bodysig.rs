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
