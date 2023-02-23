# Change log

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2023-02-23

### Added

- Added `selinux::SecurityContext::previous_of_process()` method.

### Changed

- The prototype of `selinux::policy::load()` changed, promising not to change its input.
  This mirrors a change to `security_load_policy()` introduced by `libselinux` version `3.5`.

  > ⚠️ **This is a breaking change**.

- Updated dependencies: `serial_test`.

## [0.3.3] - 2023-01-05

### Changed

- `selinux::call_back::tests::log()` performed wrong manipulation of function pointers.
  The situation now is a little better for some ABIs, but this will have to be fixed for good once
  Rust allows defining variadic functions.
  This was a bug in unit tests, not in the crate implementation.

  Thank you, [*Ralf Jung*](https://github.com/RalfJung).

- Updated dependencies: `once_cell`, `serial_test`, `socketpair`.
- Updated copyright years.

## [0.3.2] - 2022-11-26

### Changed

- Return value of `selinux_restorecon_get_skipped_errors()` on 32-bits architectures requires
  lossless casting to `u64`.

  Thank you, [*plugwash*](https://github.com/plugwash).

## [0.3.1] - 2022-11-14

### Changed

- Updated dependencies: `selinux-sys`, `once_cell`, `socketpair`.

## [0.3.0] - 2022-09-18

### Changed

- The prototype of `selinux::ContextRestore::restore_context_of_file_system_entry()` changed,
  in order to add support for the new features introduced by `libselinux` version `3.4`.

  > ⚠️ **This is a breaking change**.

  Calling the new prototype with `threads_count` set to `1` reproduces the old behavior.

- Switched to Rust's 2021 edition.
- Updated dependencies: `simplelog`, `once_cell`, `serial_test`, `socketpair`.

## [0.2.7] - 2022-04-09

### Changed

- Test coverage generation now uses the *stable* tool chain.

## [0.2.6] - 2022-03-27

### Changed

- Updated dependencies: `simplelog`, `once_cell`, `tempfile`, `serial_test`, `socketpair`.
- Updated copyright years.

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

  Thank you, [*Matt Rice*](https://github.com/ratmice).

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

- Added `selinux::SecurityContext::to_c_string()` method.

## [0.2.0] - 2021-08-09

### Added

- Added new versions of `set_type()`, `set_range()`, `set_role()` and `set_user()`
  in `selinux::OpaqueSecurityContext` where the new value is a `CStr`.

### Changed

- Renamed multiple methods in `selinux::OpaqueSecurityContext`:
  - `set_type()` to `set_type_str()`.
  - `set_range()` to `set_range_str()`.
  - `set_role()` to `set_role_str()`.
  - `set_user()` to `set_user_str()`.

  > ⚠️ **This is a breaking change**.

## [0.1.3] - 2021-08-02

### Changed

- Stopped using `std::slice::strip_prefix()`, in order to reduce the minimum
  supported Rust version for this crate.

## [0.1.2] - 2021-07-28

### Added

- Implemented `Send` for `selinux::utils::CAllocatedBlock`.

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
