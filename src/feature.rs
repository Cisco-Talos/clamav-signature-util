// Pull in the auto-generated feature enumerations and "flevel" mappings
mod features {
    include!(concat!(env!("OUT_DIR"), "/features.rs"));
}

use crate::util::Range;
pub use features::Feature;

/// A trait that allows definition of a set of engine features (and an associated
/// minimum feature level) necessary to utilize a particular signature or
/// signature element.
pub trait EngineReq {
    /// Engine features required to utilize a particular element
    fn features(&self) -> Set {
        Set::default()
    }

    /// The range of feature levels for which this signature is supported (as
    /// derived from the required features)
    fn computed_feature_level(&self) -> Option<Range<u32>> {
        self.features()
            .into_iter()
            .map(|f| f.min_flevel())
            .max()
            .map(|start| (start..).into())
    }
}

/// A wrapper around a set of features identifiers, which may be known at compile
/// time or computed after examining signature content.
#[derive(PartialEq)]
pub enum Set {
    Empty,
    Static(&'static [Feature]),
    Built(Vec<Feature>),
}

impl Default for Set {
    fn default() -> Self {
        Self::Empty
    }
}

impl IntoIterator for Set {
    type Item = Feature;

    type IntoIter = Box<dyn Iterator<Item = Feature>>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Set::Empty => Box::new(std::iter::empty()),
            Set::Static(features) => Box::new(features.iter().copied()),
            Set::Built(features) => Box::new(features.into_iter()),
        }
    }
}

impl<I> From<I> for Set
where
    I: Iterator<Item = Feature>,
{
    fn from(features: I) -> Self {
        Self::Built(features.collect())
    }
}

impl Set {
    /// Create an empty feature Set
    #[must_use]
    pub fn empty() -> Self {
        Self::Empty
    }

    /// Obtain a feature Set from a static slice
    #[must_use]
    pub fn from_static(features: &'static [Feature]) -> Self {
        Self::Static(features)
    }
}

impl std::fmt::Debug for Set {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "None"),
            Self::Static(features) => write!(f, "{features:?}"),
            Self::Built(features) => write!(f, "{features:?}"),
        }
    }
}

impl std::fmt::Display for Feature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let min_flevel = self.min_flevel();
        // f.debug_
        write!(f, "{self:?}<{min_flevel}>")
    }
}

/// A wrapper type for a Feature that includes the minimum feature FLEVEL in
/// debug formatting
struct WithMinFlevel(Feature);

impl std::fmt::Debug for WithMinFlevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let feature = &self.0;
        let min_flevel = self.0.min_flevel();
        write!(f, "{feature:?}:{min_flevel}")
    }
}

/// A wrapper type for a FeatureSet that includes the minimum feature FLEVEL in
/// debug formatting
#[derive(PartialEq)]
pub struct SetWithMinFlevel(Set);

impl From<Set> for SetWithMinFlevel {
    fn from(fs: Set) -> Self {
        SetWithMinFlevel(fs)
    }
}

impl std::fmt::Debug for SetWithMinFlevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Set::Empty => f.debug_list().finish(),
            Set::Static(features) => f
                .debug_list()
                .entries(features.iter().copied().map(WithMinFlevel))
                .finish(),
            Set::Built(features) => f
                .debug_list()
                .entries(features.iter().copied().map(WithMinFlevel))
                .finish(),
        }
    }
}
