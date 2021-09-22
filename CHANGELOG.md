# Change log

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.5] - 2021-09-22

### Changed

- Replaced all shell scripts by an *xtask*.
  
  To generate coverage information, run:
  ```
  $ cargo xtask coverage
  ```

## [0.2.4] - 2021-09-21

### Changed

- Replace each `doc(alias(..))` directive by `doc(alias = ...)` directive.
  This enhances compatibility with older versions of Rust.

  Thank you [*ratmice*](https://github.com/ratmice).
- Updated dependencies: `socketpair`.

## [0.2.3] - 2021-08-22

### Changed

- Replace each single `doc(alias)` directive specifying multiple aliases by
  multiple `doc(alias)` directives each specifying a single alias.
  This reduces the minimum supported Rust version for this crate.

## [0.2.2] - 2021-08-18

### Added

- Added documentation aliases to `libselinux` functions.
  This should make it easier to search in crate functionality by `libselinux` API name.

### Changed

- Updated dependencies: `bitflags`, `socketpair`.

## [0.2.1] - 2021-08-10

### Added

- Added `SecurityContext::to_c_string()` method.

## [0.2.0] - 2021-08-09

### Added

- Added new versions of `set_type()`, `set_range()`, `set_role()` and `set_user()`
  in `OpaqueSecurityContext` where the new value is a `CStr`.

### Changed

- Renamed multiple methods in `OpaqueSecurityContext`:
  - `set_type()` to `set_type_str()`.
  - `set_range()` to `set_range_str()`.
  - `set_role()` to `set_role_str()`.
  - `set_user()` to `set_user_str()`.

  **This is a breaking change.**

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
