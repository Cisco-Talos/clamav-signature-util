use std::env;
use std::path::PathBuf;

pub fn main() {
    #[allow(unused_variables)]
    let output_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    #[allow(unused_variables)]
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());

    #[cfg(test)]
    {
        use std::fs::File;
        use std::io::{BufRead, BufReader, BufWriter, Write};

        let test_data_dir = manifest_dir.join("test-data");

        // Build in lots of expressions that were derived from the current database.  A few are clinkers.
        let exprs_fh = BufReader::new(File::open(test_data_dir.join("logical-exprs.txt")).unwrap());
        let mut out_fh = BufWriter::new(File::create(output_dir.join("logical-exprs.rs")).unwrap());

        write!(out_fh, "pub const TEST_LOGICAL_EXPRS: &[&[u8]] = &[").unwrap();
        exprs_fh
            .lines()
            .take_while(Result::is_ok)
            .map(Result::unwrap)
            .for_each(|expr| write!(out_fh, "    b\"{}\",", expr).unwrap());
        writeln!(out_fh, "];").unwrap();
    }
}
