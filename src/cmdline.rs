use anyhow::{anyhow, Result};
use clam_sigutil::SigType;
use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    str,
    time::{Duration, Instant},
};
use structopt::StructOpt;

#[derive(StructOpt)]
#[allow(clippy::struct_excessive_bools)]
struct Opt {
    /// Files or directory containing files to process
    #[structopt(name = "FILE_OR_DIR")]
    paths: Vec<PathBuf>,

    /// Report on each file read
    #[structopt(long, short)]
    verbose: bool,

    /// Perform additional validation on signatures
    #[structopt(long)]
    validate: bool,

    /// Print original signatures as they're read
    #[structopt(long)]
    print_orig: bool,

    /// Dump signatures in debug format
    #[structopt(long)]
    dump_debug: bool,

    /// Dump signatures in long debug format
    #[structopt(long)]
    dump_debug_long: bool,

    /// Report required features
    #[structopt(long)]
    print_features: bool,

    /// Signature type for stdin, specified as file extension
    #[structopt(alias = "sigtype", long, parse(try_from_str))]
    sig_type: Option<SigType>,

    /// Re-export signatures after parsing and verify
    #[structopt(long)]
    check_export: bool,
}

pub fn main() -> Result<()> {
    let opt = Opt::from_args();

    let err_count = if opt.paths.is_empty() {
        match opt.sig_type {
            None => {
                eprintln!("Must specify --sigtype when taking input from stdin");
                std::process::exit(1);
            }
            Some(sig_type) => {
                if opt.verbose {
                    eprint!("<stdin>:");
                }
                match process_sigs(&opt, sig_type, &mut std::io::stdin()) {
                    Ok(()) => 0,
                    Err(_) => 1,
                }
            }
        }
    } else {
        let mut err_count = 0;
        for path in opt.paths.iter().map(PathBuf::as_path) {
            if let Err(e) = process_path(path, &opt) {
                eprintln!("processing {path:?}: {e}");
                err_count += 1;
            }
        }
        err_count
    };

    if err_count > 0 {
        Err(anyhow!("{} errors encountered", err_count))
    } else {
        Ok(())
    }
}

fn process_path(path: &Path, opt: &Opt) -> Result<()> {
    if std::fs::metadata(path)?.is_dir() {
        process_dir(path, opt)
    } else {
        process_file(path, opt)
    }
}

fn process_dir(path: &Path, opt: &Opt) -> Result<()> {
    let dh = std::fs::read_dir(path)
        .map_err(|e| anyhow!("Unable to open directory {:?}: {}", path, e))?;

    let mut err_count = 0;
    for rd_result in dh {
        match rd_result {
            Ok(dirent) => {
                if dirent
                    .path()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with('.')
                {
                    continue;
                }
                if let Err(e) = process_path(&dirent.path(), opt) {
                    println!("Error processing path {:?}: {}", dirent.path(), e);
                    err_count += 1;
                }
            }
            Err(e) => {
                eprintln!("Error reading directory {path:?}: {e}");
                err_count += 1;
            }
        }
    }

    if err_count > 0 {
        Err(anyhow!("{} errors encountered", err_count))
    } else {
        Ok(())
    }
}

fn process_file(path: &Path, opt: &Opt) -> Result<()> {
    if opt.verbose {
        eprint!("{path:?}:");
    }

    let extension = path
        .extension()
        .ok_or_else(|| anyhow!("missing file extension"))?
        .to_str()
        .unwrap();
    if let Some(sig_type) = SigType::from_file_extension(extension) {
        let mut fh = File::open(path)?;
        process_sigs(opt, sig_type, &mut fh)?;
    } else {
        eprintln!(" file extension {extension:?} doesn't map to known signature type");
    }
    Ok(())
}

fn process_sigs<F: Read>(opt: &Opt, sig_type: SigType, fh: &mut F) -> Result<()> {
    let start = Instant::now();
    let mut n_records = 0;
    let mut line_no = 0;
    let mut sigbuf = vec![];
    let mut err_count = 0;

    let mut fh = BufReader::new(fh);

    if opt.verbose {
        println!();
    }
    loop {
        sigbuf.clear();
        if fh.read_until(b'\n', &mut sigbuf)? == 0 {
            break;
        };
        line_no += 1;
        if sigbuf.starts_with(b"#") {
            // comment
            continue;
        }
        let sigbuf = if let Some(sigbuf) = sigbuf.strip_suffix(b"\r\n") {
            sigbuf
        } else if let Some(sigbuf) = sigbuf.strip_suffix(b"\n") {
            sigbuf
        } else {
            return Err(anyhow!("missing final newline or CRLF"));
        };
        n_records += 1;

        if opt.print_orig {
            println!(
                " < {}",
                str::from_utf8(sigbuf).unwrap_or("!!! Not Unicode !!!")
            );
        }
        let sigbuf = sigbuf.into();
        match clam_sigutil::signature::parse_from_cvd_with_meta(sig_type, &sigbuf) {
            Ok((sig, sigmeta)) => {
                if opt.dump_debug_long {
                    println!(" * {:#?} f_level{:?}", sig, sig.computed_feature_level());
                } else if opt.dump_debug {
                    println!(" * {:?} f_level{:?}", sig, sig.computed_feature_level());
                }
                if opt.print_features {
                    println!(" > {:?}", sig.features());
                }

                if opt.validate {
                    if let Err(e) = sig.validate(&sigmeta) {
                        eprintln!(
                            "Signature on line {line_no} failed validation:\n  {sigbuf}\n  Error: {e}\n"
                        );
                        err_count += 1;
                    }
                }

                if opt.check_export {
                    // Note: This naively compares the two signatures after
                    // downcasing to suppress issues with different case of hex
                    // values (a-f/A-F)
                    let exported = sig.to_sigbytes().unwrap();
                    if str::from_utf8(exported.as_bytes()).unwrap().to_lowercase()
                        != str::from_utf8(sigbuf.as_bytes()).unwrap().to_lowercase()
                    {
                        eprintln!("Export mismatch:");
                        eprintln!(" < {sigbuf}");
                        eprintln!(" > {exported}");
                    }
                }
            }
            Err(e) => {
                if !matches!(
                    e,
                    clam_sigutil::signature::FromSigBytesParseError::UnsupportedSigType
                ) {
                    eprintln!("Unable to process line {line_no}:\n  {sigbuf}\n  Error: {e}\n");
                    err_count += 1;
                }
            }
        }
    }

    let elapsed = start.elapsed();
    if n_records > 0 {
        if opt.verbose {
            println!(
                " - {} records in {:?} ({:?}/record)",
                n_records,
                elapsed,
                Duration::from_nanos((elapsed.as_nanos() / n_records).try_into()?)
            );
        }
    } else {
        eprintln!(" - no records");
    }
    if err_count > 0 {
        return Err(anyhow!("{} errors encountered", err_count));
    }
    Ok(())
}
