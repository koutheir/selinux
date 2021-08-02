# Change log

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2021-08-02

### Changed

- Stopped using `std::slice::strip_prefix()`, in order to reduce the minimum
  supported Rust version for this crate.

## [0.1.2] - 2021-07-28

### Added

- Implemented `Send` for `CAllocatedBlock`.

### Changed

- Updated dependencies: `selinux-sys`, `assert_matches`, `socketpair`.
- Updated nightly compiler version for coverage analysis.

## [0.1.1] - 2021-06-19

### Changed

- Removed dependency on the `arrayvec` crate, and avoided the use
  of `std::io::ErrorKind::Unsupported`.
  These changes allow some dependent crates to reduce their minimum supported
  Rust version.
  This doesn't add any limitations to this crate.

## [0.1.0] - 2021-06-19

### Added

- Initial release.
