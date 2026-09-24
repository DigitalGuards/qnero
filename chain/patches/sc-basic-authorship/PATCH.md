# Plain consensus log message

This directory preserves the published `sc-basic-authorship` 0.53.0 crate's
normalized Cargo manifest, README and both Rust source files.

- Registry archive SHA256: `d82f8b0c44c7f00108a8babea46397c3f15f1a90273098ab8b3ebbc7be10585a`.
- Upstream SDK commit: `ac2b0e3fd86a23cc33b2f4d6f46ac9d0ecb05115`.
- License: GPL-3.0-or-later WITH Classpath-exception-2.0, retained from upstream.

The sole source change removes the leading decorative marker from the
`Starting consensus session` log message in `src/basic_authorship.rs`.
The message level, target, arguments and block-authoring behavior are preserved.

The chain workspace patches this exact crate version. It excludes the vendored
package from workspace test selection because the published upstream test
module references SDK-only test helpers absent from the registry manifest.
