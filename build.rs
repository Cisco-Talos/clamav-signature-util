use std::{
    collections::{btree_map::Entry, BTreeMap},
    env,
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

pub fn main() -> Result<(), std::io::Error> {
    #[allow(unused_variables)]
    let output_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    #[allow(unused_variables)]
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());

    build_feature_list(&manifest_dir, &output_dir)?;

    // This is only required for tests, but cargo doesn't provide a means to
    // re-run the build script depending on whether cfg(test) is enabled.
    {
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

    Ok(())
}

// Build the feature level (FLEVEL) translations
pub fn build_feature_list(manifest_dir: &Path, output_dir: &Path) -> Result<(), std::io::Error> {
    println!("cargo:rerun-if-changed=feature-level.txt");
    let ifh = BufReader::new(File::open(manifest_dir.join("feature-level.txt"))?);

    let mut flevel_versions = BTreeMap::new();
    let mut feature_flevel = BTreeMap::new();

    for line in ifh.lines().map(Result::unwrap) {
        let line = line.trim();
        // Skip comments
        if line.starts_with('#') {
            continue;
        }
        let mut flevel: Option<usize> = None;
        let mut versions = vec![];
        let mut features = vec![];

        for element in line.split_ascii_whitespace() {
            if let Some(version) = element.strip_prefix('v') {
                versions.push(version.to_owned());
            } else if let Ok(n) = element.parse() {
                flevel = Some(n)
            } else if element.starts_with('?') {
                // Anything we're trying to figure out
                continue;
            } else {
                features.push(element.to_owned());
            }
        }

        if let Some(flevel) = flevel {
            versions.into_iter().for_each(|version| {
                flevel_versions
                    .entry(flevel)
                    .or_insert_with(Vec::new)
                    .push(version)
            });
            features.into_iter().for_each(|feature| {
                match feature_flevel.entry(feature.to_owned()) {
                    Entry::Occupied(_) => {
                        panic!("Multiple f_levels specified for feature {}", feature)
                    }
                    Entry::Vacant(entry) => entry.insert(flevel),
                };
            })
        }
    }

    let mut ofh = BufWriter::new(File::create(output_dir.join("features.rs"))?);
    writeln!(ofh, "#[derive(Debug, Clone, Copy)]")?;
    writeln!(
        ofh,
        "pub enum Feature {{\n{}\n}}",
        feature_flevel
            .iter()
            .map(|(feature, _)| format!("    {},", feature))
            .collect::<Vec<String>>()
            .join("\n")
    )?;
    writeln!(ofh, "impl Feature {{")?;
    writeln!(ofh, "    pub fn min_flevel(&self) -> usize {{")?;
    writeln!(ofh, "        match self {{")?;
    ofh.write_all(
        feature_flevel
            .iter()
            .map(|(feature, flevel)| format!("        Feature::{} => {},\n", feature, flevel))
            .collect::<Vec<String>>()
            .join("")
            .as_bytes(),
    )?;
    writeln!(ofh, "        }}")?;
    writeln!(ofh, "    }}")?;
    writeln!(ofh, "}}")?;

    Ok(())
}
