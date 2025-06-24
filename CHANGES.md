# Notable Changes

> _Note_: Changes should be grouped by release and use these icons:
> - Added: ➕
> - Changed: 🌌
> - Deprecated: 👇
> - Removed: ❌
> - Fixed: 🐛
> - Security: 🛡

## Version 1.2.6

➕Support for Logical Signature Fuzzy Image Hash (`fuzzy_img#`) subsignatures.

## Version 1.2.5

🐛Allow hash sigs with no minimum flevel.

## Version 1.2.4

🌌When loading a hash sig (e.g. `.hsb`), if no minimum flevel is specified, set the minimum flevel to that of a SHA2-256 hash sig. Due to the age of all currently supported hash signature types, it is common practice to omit the minimum flevel and this will successful validation without specifying a hash level. Re-export, however, will add in that minimum flevel.

## Version 1.2.4

🐛Fix the minimum feature level when writing bytes for a new `.sign` digital signature.

## Version 1.2.3

🐛Properly remove the `structopt` dependency (from `Cargo.toml`). It is no longer being used, but must be removed from the list.

🌌Dockerfile: Improvements to reduce the image size and improve readability.

## Version 1.2.2

🐛Add back the `--version` / `-V` option, which disappeared with the switch from `structopt` to `clap`.

## Version 1.2.1

➕Added ClamAV version 1.5.0 with support for CL_TYPE_AI_MODEL.

🌌Upgrade various library dependencies. Notably, drops `structopt` in favor of `clap`, to remove buggy `atty` dependency.

🌌Dockerfile: Upgrade container from Debian Buster (10) to Debian Bullseye (11).

## Version 1.2.0

➕New `compare()` method for custom `Range` class used to represent minimum and maximum functionality levels. This is in support of using the library within ClamAV and verifying that a given signature may be loaded by the current ClamAV version.

➕Support for `.sign` external digital signatures, used for verifying signature archives.

➕Added ClamAV versions 1.4.1, 1.3.2, 1.0.7, and 0.103.12

🌌Changed behavior when encountering unsupported signature types so that it prints a message but not error or panic. In this release, the following signature file formats are not yet supported: .crb, .sfp / .fp, .info, .idb, .zmd / .rmd / .db, .cfg, and .imp.

## Version 1.1.4

🐛Fix `tinyvec::ArrayVec` crash when validating daily.ldb.

🐛Fix crash when validating BodySig's when flushing bytes.

## Version 1.1.3

🐛Fixed a compatibility issue with the `tinyvec` crate version 1.8.

🌌Added a Cargo.lock file to prevent backwards incompatible changes to dependency API's from breaking the build.

## Version 1.1.2

➕Added ClamAV versions 1.3.1, 1.2.3, and 1.0.6.

## Version 1.1.1

➕Added ClamAV versions 1.4.0, 1.3.0, 1.2.2, and 1.0.5 including `ALZ`,  `LHA_LZH`, `ONENOTE`, `UDF`, and `PYTHON_COMPILED` types.

➕Added `Dockerfile`.

➕Added GitHub Actions workflow.

🐛Fixed clippy warnings.

## Version 1.1.0

🐛Temporarily disable minimum static bytes errors, because it isn't working correctly.

➕Support for Google Safe Browsing (phishing) signatures.

➕Implement converting hashes to signature bytes.

🌌Allow single-value anchored-byte ranges.

➕Support for functionality level (FLEVEL) ranges and range validation.

➕Validate that the TargetType is PE when the Target Descriptor Block (TDB) contains IconGroup1/2.

➕Validate that the TargetType is a native executable format (e.g. PE, ELF, Mach-O) when the Target Descriptor Block (TDB) contains EntryPoint or NumberOfSections.

➕Support for File Type Magic (FTM) signatures including FLEVEL validation when file types are used in a logical signature TDB.

➕Add a text file that defines known file types.

➕Expand min-FLEVEL validation errors to include expected levels per-feature.

➕Many assorted improvements.

## Version 1.0.0

First release!
