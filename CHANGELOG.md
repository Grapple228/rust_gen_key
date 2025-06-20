# Changelog for gen-key

## [0.1.0] - 21 June 2025

### Added

- Initial release of `gen-key` CLI tool.
- Generate RSA key pairs (private and public) with selectable key sizes: `2048`, `3072`, `4096` bits.
- Generate HMAC secret keys with selectable key sizes: `256`, `384`, `512` bits.
- Output keys to files (`--out-dir`) and/or print to stdout (`--stdout`).
- Support for output formats:
  - `PEM` and `DER` for RSA keys.
  - Base64url for HMAC keys.
- Option to control PEM line endings (`--line-ending`): `crlf` (default), `cr`, or `lf`.
- Prevent overwriting existing files unless `--replace` is specified.
- Comprehensive command-line help and usage examples.
- Robust error handling and user-friendly error messages.
- Full integration test suite covering all major features and edge cases.
