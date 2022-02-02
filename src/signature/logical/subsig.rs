mod macrosig;
pub use macrosig::MacroSubSig;
mod bytecmp;
pub use bytecmp::ByteCmpSubSig;
mod pcre;
pub use pcre::PCRESubSig;

/// These are all boxed to avoid the overhead of the largest variation
#[derive(Debug)]
pub enum SubSigType {
    Extended,
    Macro,
    ByteCmp,
    Pcre,
}

pub trait SubSig: std::fmt::Debug {
    fn subsig_type(&self) -> SubSigType;
}
