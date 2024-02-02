use clam_sigutil::SigType;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Opt {
    /// Files or directory containing files to process
    #[arg(name = "FILE_OR_DIR")]
    pub(crate) paths: Vec<PathBuf>,

    /// Report on each file read
    #[arg(long, short)]
    pub(crate) verbose: bool,

    /// Perform additional validation on signatures
    #[arg(long)]
    pub(crate) validate: bool,

    /// Print original signatures as they're read
    #[arg(long)]
    pub(crate) print_orig: bool,

    /// Dump signatures in debug format
    #[arg(long)]
    pub(crate) dump_debug: bool,

    /// Dump signatures in long debug format
    #[arg(long)]
    pub(crate) dump_debug_long: bool,

    /// Report required features
    #[arg(long)]
    pub(crate) print_features: bool,

    /// Signature type for stdin, specified as file extension
    #[arg(alias = "sigtype", long)]
    pub(crate) sig_type: Option<SigType>,

    /// Re-export signatures after parsing and verify
    #[arg(long)]
    pub(crate) check_export: bool,
}

impl Opt {
    pub fn parse() -> Self {
        <Self as clap::Parser>::parse()
    }
}
