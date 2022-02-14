// Pull in the auto-generated feature enumerations and "flevel" mappings
mod features {
    include!(concat!(env!("OUT_DIR"), "/features.rs"));
}

pub use features::Feature;

/// A trait that allows definition of a set of engine features (and an associated
/// minimum feature level) necessary to utilize a particular signature or
/// signature element.
pub trait EngineReq {
    /// Engine features required to utilize a particular element
    fn features(&self) -> FeatureSet {
        FeatureSet::None
    }

    /// The minimum and optional maximum feature levels for which this
    /// signature is supported (as derived from the required features)
    fn feature_levels(&self) -> (Option<usize>, Option<usize>) {
        (
            self.features().into_iter().map(|f| f.min_flevel()).max(),
            None,
        )
    }
}

/// A wrapper around a set of features identifiers, which may be known at compile
/// time or computed after examining signature content.
pub enum FeatureSet {
    None,
    Static(&'static [Feature]),
    Built(Vec<Feature>),
}

impl IntoIterator for FeatureSet {
    type Item = Feature;

    type IntoIter = Box<dyn Iterator<Item = Feature>>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            FeatureSet::None => Box::new(std::iter::empty()),
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
    /// Obtain a FeatureSet from a static slice
    pub fn from_static(features: &'static [Feature]) -> Self {
        Self::Static(features)
    }
}

impl std::fmt::Debug for FeatureSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Static(arg0) => write!(f, "{:?}", arg0),
            Self::Built(arg0) => write!(f, "{:?}", arg0),
        }
    }
}
