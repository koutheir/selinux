[![crates.io](https://img.shields.io/crates/v/selinux.svg)](https://crates.io/crates/selinux)
[![docs.rs](https://docs.rs/selinux/badge.svg)](https://docs.rs/selinux)
[![license](https://img.shields.io/github/license/koutheir/selinux?color=black)](https://raw.githubusercontent.com/koutheir/selinux/master/LICENSE.txt)

# 🛡️ Safe Rust bindings for `libselinux`

SELinux is a flexible Mandatory Access Control for Linux.

This crate supports `libselinux` from version `2.8` to `3.6`.
Later versions might still be compatible.
This crate exposes neither *deprecated* nor *undocumented* SELinux API functions
and types.

⚠️ This crate is Linux-specific. Building it for non-Linux platforms, or for
the Linux kernel, results in an empty crate.

This documentation is too brief to cover SELinux.
Please refer to the [official SELinux documentation], the manual pages of
the [`libselinux`] native library, and the [`selinux-sys`] crate for a more
complete picture on how to use this crate.

If you cannot find a feature you are looking for by its name, but you know
which `libselinux` APIs relate to it, then try searching the documentation
by that API name.

## ⚓ Backward compatibility

This crate requires `libselinux` version `2.8`, at least.
However, this crate provides some functions that are based on `libselinux`
functions implemented in later versions.
When such newer functions are needed, this crate attempts to load them
dynamically at runtime.
If such functions are implemented by `libselinux`, then the called crate
functions run as expected.
If the needed functions are not implemented by `libselinux`, then an error is
returned indicating that the called crate function is unsupported.

## 🔢 Versioning

This project adheres to [Semantic Versioning].
The `CHANGELOG.md` file details notable changes over time.

## 🛠️ Development

> This section is only relevant for developers contributing to this crate,
> and not for users of this crate.

💡 If you're developing this crate and feel important information is missing
in this section, then please create an issue or a pull request to fix that.

### Build system

This crate uses only `cargo` as a build system. Usual commands are used to
perform most operations, *e.g.*, `build`, `test`, `fmt`.

> Code is read many times more that written, so this crate's code is always
> formatted using `cargo fmt`.

Operations requiring special handling are crafted as cargo [xtask] targets.
The full list of these special operations can be determined by running:
```shell
$ cargo xtask
```
Each special operation can be executed by running:
```shell
$ cargo xtask <operation> [parameters...]
```
For example, to generate coverage information, run:
```shell
$ cargo xtask coverage
```

### Testing

This crate can only be tested on a Linux distribution that has SELinux
supported and enabled at multiple levels:
- The Linux kernel must support SELinux, and have it enabled.
- The file system must be correctly configured.
- The user space must have access to SELinux, usually via `libselinux`.

[Red Hat Enterprise Linux]-like distributions (*e.g.*, [Fedora], [CentOS],
[RockyLinux]) are suitable for testing this crate, either on hardware or inside
virtual machines, but not in containers.

Given that coverage information requires running tests, that information
can only be successfully obtained on a system with SELinux enabled.

### Behavior

This crate uses the `libselinux` API as documented in the manual pages.
It tries to avoid assumptions about implementation details as far as possible,
even when performance might be improved with such knowledge.

The structures and enumerations defined by this crate assume that their user
might, at some point, decide to call *raw* `libselinux` APIs (possible using
the `selinux-sys` crate) for features not yet provided by this crate, or for
some other reasons. That is the reason why methods such as `as_ptr()` are
implemented by these structures, exposing the raw values that `libselinux`
APIs recognize.

### Change log

The [change log] is useful to get a picture of what is going on with the
crate in the recent past.

[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[official SELinux documentation]: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/using_selinux/index
[`libselinux`]: https://man7.org/linux/man-pages/man8/selinux.8.html
[`selinux-sys`]: https://docs.rs/selinux-sys/
[xtask]: https://github.com/matklad/cargo-xtask
[Red Hat Enterprise Linux]: https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux
[Fedora]: https://getfedora.org/
[CentOS]: https://www.centos.org/
[RockyLinux]: https://rockylinux.org/
[change log]: https://github.com/koutheir/selinux/blob/master/CHANGELOG.md
