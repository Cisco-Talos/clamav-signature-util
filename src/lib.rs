//! # ClamAV Signature Utilities
//!
//! An API for ingesting and validating ClamAV signatures

#![deny(clippy::mod_module_files)]

/// Functionality associated with engine features
pub mod feature;
/// File type classification
pub mod filetype;
/// Regular expressions
pub mod regexp;
/// Engine signature parsing and examination
pub mod signature;

pub(crate) mod util;

pub use feature::Feature;
pub use signature::sigtype::SigType;
pub use signature::Signature;

#[cfg(test)]
pub(crate) mod test_data {
    include!(concat!(env!("OUT_DIR"), "/logical-exprs.rs"));
}
