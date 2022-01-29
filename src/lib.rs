#![deny(clippy::mod_module_files)]

pub mod filetype;
pub mod signature;
pub(crate) mod util;

#[cfg(test)]
pub(crate) mod test_data {
    include!(concat!(env!("OUT_DIR"), "/logical-exprs.rs"));
}
