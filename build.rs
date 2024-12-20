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
            .for_each(|expr| write!(out_fh, "    b\"{expr}\",").unwrap());
        writeln!(out_fh, "];").unwrap();
    }

    Ok(())
}

// Build the feature level (FLEVEL) translations
pub fn build_feature_list(manifest_dir: &Path, output_dir: &Path) -> Result<(), std::io::Error> {
    println!("cargo:rerun-if-changed=feature-level.txt");
    let fl_input = BufReader::new(File::open(manifest_dir.join("feature-level.txt"))?);

    let mut flevel_versions = BTreeMap::new();
    let mut feature_flevel = BTreeMap::new();

    let filetype_features = load_filetypes(manifest_dir, output_dir)?;

    for line in fl_input.lines().map(Result::unwrap) {
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
                flevel = Some(n);
            } else if element.starts_with('?') {
                // Anything we're trying to figure out
                continue;
            } else {
                features.push(element.to_owned());
            }
        }

        if let Some(flevel) = flevel {
            for version in versions {
                flevel_versions
                    .entry(flevel)
                    .or_insert_with(Vec::new)
                    .push(version);
            }
            for feature in features {
                match feature_flevel.entry(feature.clone()) {
                    Entry::Occupied(_) => {
                        panic!("Multiple f_levels specified for feature {feature}");
                    }
                    Entry::Vacant(entry) => entry.insert(flevel),
                };
            }
        }
    }

    let mut features_rs = BufWriter::new(File::create(output_dir.join("features.rs"))?);
    writeln!(features_rs, "/// An identifier of an engine feature required for parsing and/or matching a particular signature or signature element.")?;
    writeln!(features_rs, "#[derive(Clone, Debug, Copy, PartialEq)]")?;
    writeln!(features_rs, "pub enum Feature {{")?;
    feature_flevel
        .iter()
        .for_each(|(feature, _)| writeln!(features_rs, "    {feature},").unwrap());
    filetype_features
        .iter()
        .for_each(|(feature, _)| writeln!(features_rs, "    {feature},").unwrap());
    writeln!(features_rs, "}}")?;
    writeln!(features_rs, "impl Feature {{")?;
    writeln!(features_rs, "    #[must_use]")?;
    writeln!(features_rs, "    pub fn min_flevel(&self) -> u32 {{")?;
    writeln!(features_rs, "        #[allow(clippy::match_same_arms)]")?;
    writeln!(features_rs, "        match self {{")?;
    for (feature, flevel) in feature_flevel {
        writeln!(features_rs, "        Feature::{feature} => {flevel},")?;
    }
    for (feature, flevel) in filetype_features.iter().filter(|(_, &flevel)| flevel > 0) {
        writeln!(features_rs, "        Feature::{feature} => {flevel},")?;
    }
    writeln!(features_rs, "        }}")?;
    writeln!(features_rs, "    }}")?;
    writeln!(features_rs, "}}")?;

    Ok(())
}

pub fn load_filetypes(
    manifest_dir: &Path,
    output_dir: &Path,
) -> Result<BTreeMap<String, u32>, std::io::Error> {
    println!("cargo:rerun-if-changed=filetypes.txt");
    let ifh = BufReader::new(File::open(manifest_dir.join("filetypes.txt"))?);
    // Mapping of FileType feature tags to minimum FLevel
    let mut filetype_min_flevel = BTreeMap::new();
    // Mapping of the textual (C constant) file types to CamelCase feature tags
    let mut filetype_feature_tag = BTreeMap::new();

    for line in ifh.lines().map(Result::unwrap) {
        let mut flevel: Option<u32> = None;
        let mut these_filetypes = vec![];
        let line = line.trim();

        // Skip comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        for element in line.split_ascii_whitespace() {
            dbg!(&element);
            if let Ok(n) = element.parse() {
                flevel = Some(n);
            } else if element.starts_with("CL_TYPE_") {
                these_filetypes.push(element.to_owned());
            }
        }
        dbg!(&these_filetypes);

        // This should be present on every line
        let flevel = flevel.expect("flevel");

        for ft in these_filetypes {
            let feature_tag = format!(
                "FileType{}",
                change_case::pascal_case(ft.strip_prefix("CL_TYPE_").unwrap())
            );
            if flevel > 0 {
                filetype_min_flevel.insert(feature_tag.clone(), flevel);
            }
            filetype_feature_tag.insert(ft, feature_tag);
        }
    }

    // Write out the C-style constants
    {
        let mut filetypes_c_input =
            BufWriter::new(File::create(output_dir.join("filetypes-c_const"))?);
        writeln!(filetypes_c_input, "#[allow(non_camel_case_types)]")?;
        writeln!(
            filetypes_c_input,
            "#[derive(Clone, Debug, PartialEq, Display, EnumString, FromPrimitive, ToPrimitive)]"
        )?;
        writeln!(filetypes_c_input, "pub enum FileType {{")?;
        for filetype in filetype_feature_tag.keys() {
            writeln!(filetypes_c_input, "{filetype},").unwrap();
        }
        writeln!(filetypes_c_input, "}}")?;
    }

    // Write out string-constant-to-CamelCase match arms
    {
        let mut feature_tag_rs = BufWriter::new(File::create(
            output_dir.join("filetypes-match-filetype-to-feature_tag.rs"),
        )?);
        writeln!(feature_tag_rs, "match self {{")?;
        filetype_feature_tag
            .iter()
            .filter(|(_, feature_tag)| filetype_min_flevel.contains_key(feature_tag.as_str()))
            .for_each(|(filetype, feature_tag)| {
                writeln!(
                    feature_tag_rs,
                    "FileType::{filetype} => Some(Feature::{feature_tag}),"
                )
                .unwrap();
            });
        writeln!(feature_tag_rs, "_ => None,")?;
        writeln!(feature_tag_rs, "}}")?;
    }

    // These will be folded into the feature-tag/feature-level table
    Ok(filetype_min_flevel)
}
