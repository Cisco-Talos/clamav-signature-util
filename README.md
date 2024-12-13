# ClamAV Signature Util

The ClamAV Signature Util (`clam-sigutil`) project provides:
1. A library for parsing and validating ClamAV signatures to ensure proper syntax, correct functionality levels, etc.
2. An application to inspect or validate ClamAV signature files.

## Installation

Prerequisites for a native build:
- The Rust compiler toolchain
- OpenSSL development library

Alternatively you may build with Docker using the provided Dockerfile.

### Running in Your Local Environment

### Running in a Docker Container

The simplest way to use clam-sigutil is using a Docker container.

To build the image, run:
```sh
docker build . -t clamav-signature-util --load
```

To use clam-sigutil in the container, run like this where you mount the current directory in the host:
```sh
docker run -it --mount type=bind,source=(pwd),target=/pwd \
    clamav-signature-util:latest \
    clam-sigutil --help
```

Then you can use it to validate or inspect signature files from your current directory. For example:
```sh
docker run -it --mount type=bind,source=(pwd),target=/pwd \
    clamav-signature-util:latest \
    clam-sigutil --validate ./regex_sig.ldb

docker run -it --mount type=bind,source=(pwd),target=/pwd \
    clamav-signature-util:latest \
    clam-sigutil --dump-debug ./regex_sig.ldb
```

## Usage

```
USAGE:
    clam-sigutil [FLAGS] [OPTIONS] [FILE_OR_DIR]...

FLAGS:
        --check-export       Re-export signatures after parsing and verify
        --dump-debug         Dump signatures in debug format
        --dump-debug-long    Dump signatures in long debug format
    -h, --help               Prints help information
        --print-features     Report required features
        --print-orig         Print original signatures as they're read
        --validate           Perform additional validation on signatures
    -V, --version            Prints version information
    -v, --verbose            Report on each file read

OPTIONS:
        --sig-type <sig-type>    Signature type for stdin, specified as file extension

ARGS:
    <FILE_OR_DIR>...    Files or directory containing files to process
```

## Contributing

[There are many ways to contribute](CONTRIBUTING.md).

## License

This project is licensed under [the GNU General Public License Version 2](COPYING.txt).
