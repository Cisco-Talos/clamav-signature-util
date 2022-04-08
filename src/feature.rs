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
    fn features(&self) -> FeatureSet {
        FeatureSet::default()
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
pub enum FeatureSet {
    Empty,
    Static(&'static [Feature]),
    Built(Vec<Feature>),
}

impl Default for FeatureSet {
    fn default() -> Self {
        Self::Empty
    }
}

impl IntoIterator for FeatureSet {
    type Item = Feature;

    type IntoIter = Box<dyn Iterator<Item = Feature>>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            FeatureSet::Empty => Box::new(std::iter::empty()),
            FeatureSet::Static(features) => Box::new(features.iter().copied()),
            FeatureSet::Built(features) => Box::new(features.into_iter()),
        }
    }
}

impl<I> From<I> for FeatureSet
where
    I: Iterator<Item = Feature>,
{
    fn from(features: I) -> Self {
        Self::Built(features.collect())
    }
}

impl FeatureSet {
    /// Create an empty FeatureSet
    pub fn empty() -> Self {
        Self::Empty
    }

    /// Obtain a FeatureSet from a static slice
    pub fn from_static(features: &'static [Feature]) -> Self {
        Self::Static(features)
    }
}

impl std::fmt::Debug for FeatureSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "None"),
            Self::Static(arg0) => write!(f, "{:?}", arg0),
            Self::Built(arg0) => write!(f, "{:?}", arg0),
        }
    }
}
