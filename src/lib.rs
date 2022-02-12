#![deny(clippy::mod_module_files)]

pub mod feature;
pub mod filetype;
pub mod signature;
pub(crate) mod util;

pub use feature::Feature;
pub use signature::sigtype::SigType;
pub use signature::Signature;

#[cfg(test)]
pub(crate) mod test_data {
    include!(concat!(env!("OUT_DIR"), "/logical-exprs.rs"));
}
