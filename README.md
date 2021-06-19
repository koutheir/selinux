[![crates.io](https://img.shields.io/crates/v/selinux.svg)](https://crates.io/crates/selinux)
[![docs.rs](https://docs.rs/selinux/badge.svg)](https://docs.rs/selinux)
[![license](https://img.shields.io/github/license/koutheir/selinux?color=black)](https://raw.githubusercontent.com/koutheir/selinux/master/LICENSE.txt)

# 🛡️ Safe Rust bindings for `libselinux`

SELinux is a flexible Mandatory Access Control for Linux.

This crate supports `libselinux` from version `2.8` to `3.2`.
Later versions might still be compatible.
This crate exposes neither *deprecated* nor *undocumented* SELinux API functions
and types.

⚠️ This crate is Linux-specific. Building it for non-Linux platforms, or for
the Linux kernel, results in an empty crate.

This documentation is too brief to cover SELinux.
Please refer to the [official SELinux documentation], the manual pages of
the [`libselinux`] native library, and the [`selinux-sys`] crate for a more
complete picture on how to use this crate.

## Cargo features

### ⚓ Backward compatibility

This crate requires `libselinux` version `2.8`, at least.
However, this crate provides some functions that are based on `libselinux`
functions implemented in later versions.
When such newer functions are needed, this crate attempts to load them
dynamically at runtime.
If such functions are implemented by `libselinux`, then the called crate
functions run as expected.
If the needed functions are not implemented by `libselinux`, then an error is
returned indicating that the called crate function is unsupported.

## Versioning

This project adheres to [Semantic Versioning].
The `CHANGELOG.md` file details notable changes over time.

[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

[official SELinux documentation]: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/using_selinux/index
[`libselinux`]: https://man7.org/linux/man-pages/man8/selinux.8.html
[`selinux-sys`]: https://docs.rs/selinux-sys/
