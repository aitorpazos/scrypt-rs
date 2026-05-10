# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-11

### Changed

- **Migrated scrypt implementation** from unmaintained `rust-crypto` to RustCrypto's `scrypt` 0.11. Both implement RFC 7914 — **derived keys are identical** for the same inputs.
- **Migrated CLI** from `clap` v3 (legacy macro API) to `clap` v4 (derive API). All flags and defaults are unchanged.
- **Migrated `base64`** from 0.13 to 0.22 (Engine trait API).
- **Migrated `bip39`** from 1.x to 2.x.
- **Replaced `regex`** dependency with `split_whitespace()` for passphrase normalization.
- **Added `anyhow`** for proper error handling (replaces `unwrap`/`expect`).
- Set Rust edition to 2021.
- Restructured code: logic extracted to `src/lib.rs`, thin CLI wrapper in `src/main.rs`.
- Modernized CI workflow (`dtolnay/rust-toolchain`, `actions/checkout@v4`, Rust cache).
- Modernized release workflow with multi-platform builds (Linux amd64/arm64, macOS amd64/arm64) using `softprops/action-gh-release`.
- Improved README with usage examples and option reference.

### Added

- Comprehensive test suite: 26 unit tests + 7 integration tests (33 total).
- Test vectors verified against Python `hashlib.scrypt` (RFC 7914 reference).

### Removed

- `rust-crypto` dependency (unmaintained since 2016, fails to compile on Rust 1.80+).
- `regex` dependency (no longer needed).

## [0.3.1] - 2022-06-10

### Changed

- Upgraded `regex` library to version `1.5.5`.

## [0.3.0] - 2021-04-18

### Changed

- Upgraded `bip39` library to version `1.0.1`.

## [0.2.0] - 2021-03-13

### Added

- `-S` parameter to output only the derived key in hexadecimal.

### Changed

- Output refactored to differentiate more clearly what information are inputs and which ones are outputs.

## [0.1.0] - 2021-03-08

### Added

- Initial release
