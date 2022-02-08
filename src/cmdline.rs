use anyhow::{anyhow, Result};
use clam_sigutil::signature::SigType;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::str;
use std::time::{Duration, Instant};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Opt {
    /// Files or directory containing files to process
    #[structopt(name = "FILE_OR_DIR")]
    paths: Vec<PathBuf>,

    /// Report on each file read
    #[structopt(long, short)]
    verbose: bool,

    /// Print original signatures as they're read
    #[structopt(long)]
    print_orig: bool,

    /// Dump signatures in debug format
    #[structopt(long)]
    dump_debug: bool,

    /// Dump signatures in long debug format
    #[structopt(long)]
    dump_debug_long: bool,

    /// Signature type for stdin, specified as file extension
    #[structopt(alias = "sigtype", long, parse(try_from_str))]
    sig_type: Option<SigType>,
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
                    Ok(_) => 0,
                    Err(_) => 1,
                }
            }
        }
    } else {
        opt.paths
            .iter()
            .map(PathBuf::as_path)
            .map(|path| process_path(path, &opt))
            .filter(Result::is_err)
            .count()
    };

    if err_count > 0 {
        Err(anyhow!("{} errors encountered", err_count))
    } else {
        Ok(())
    }
}

fn process_path(path: &Path, opt: &Opt) -> Result<()> {
    if std::fs::metadata(&path)?.is_dir() {
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
                eprintln!("Error reading directory {:?}: {}", path, e);
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
        eprint!("{:?}:", path);
    }

    let extension = path
        .extension()
        .ok_or(anyhow!("missing file extension"))?
        .to_str()
        .unwrap();
    if let Some(sig_type) = SigType::from_file_extension(extension) {
        let mut fh = File::open(path)?;
        process_sigs(opt, sig_type, &mut fh)?;
    } else {
        eprintln!(" file extension doesn't map to known signature type");
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
        match clam_sigutil::signature::parse_from_cvd(sig_type, sigbuf) {
            Ok(sig) => {
                if opt.dump_debug_long {
                    println!(" * {:#?} f_level{:?}", sig, sig.feature_levels());
                } else if opt.dump_debug {
                    println!(" * {:?} f_level{:?}", sig, sig.feature_levels());
                }
            }
            Err(e) => {
                if !matches!(e, clam_sigutil::signature::ParseError::UnsupportedSigType) {
                    eprintln!(
                        "Unable to process line {}:\n  {}\n  Error: {}\n",
                        line_no,
                        str::from_utf8(sigbuf).unwrap_or("Not Unicode"),
                        e
                    );
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
