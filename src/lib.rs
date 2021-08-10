#![cfg(all(target_os = "linux", not(target_env = "kernel")))]
#![doc(html_root_url = "https://docs.rs/selinux/0.2.1")]
#![allow(clippy::upper_case_acronyms)]

/*!
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

## Versioning

This project adheres to [Semantic Versioning].
The `CHANGELOG.md` file details notable changes over time.

[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

[official SELinux documentation]: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/using_selinux/index
[`libselinux`]: https://man7.org/linux/man-pages/man8/selinux.8.html
[`selinux-sys`]: https://docs.rs/selinux-sys/
*/

//
// https://rust-lang.github.io/api-guidelines/checklist.html
//

// Activate these lints to clean up the code and hopefully detect some issues.
#![warn(missing_docs)]
//#![allow(clippy::missing_inline_in_public_items)]
/*
#![warn(clippy::all, clippy::pedantic, clippy::restriction)]
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::implicit_return,
    clippy::print_stdout,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::too_many_lines,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::else_if_without_else,
    clippy::struct_excessive_bools,
    clippy::shadow_reuse,
    clippy::shadow_unrelated,
    clippy::integer_arithmetic,
    clippy::explicit_deref_methods,
    clippy::needless_pass_by_value,
    clippy::copy_iterator,
    clippy::wildcard_enum_match_arm,
    clippy::filetype_is_file,
    clippy::missing_inline_in_public_items,
    clippy::semicolon_if_nothing_returned,
    clippy::default_numeric_fallback,
)]
*/

use std::borrow::Cow;
use std::collections::{hash_map, HashMap};
use std::convert::TryFrom;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::{cmp, fmt, io, mem, ptr, slice, str};

use selinux_sys::pid_t;

#[macro_use]
extern crate bitflags;

#[cfg(test)]
mod tests;

/// Access Vector Cache.
pub mod avc;
/// SELinux call backs.
pub mod call_back;
/// Restore file(s) default SELinux security contexts.
pub mod context_restore;
/// Errors.
pub mod errors;
/// Labeling files.
pub mod label;
/// SELinux paths.
pub mod path;
/// SELinux policies.
pub mod policy;
/// Utilities.
pub mod utils;

use errors::{Error, Result};
use utils::*;

/// Red, green and blue components of a color.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RGB {
    /// Red component.
    pub red: u8,
    /// Green component.
    pub green: u8,
    /// Blue component.
    pub blue: u8,
}

impl RGB {
    /// Create a new instance.
    pub fn new(red: u8, green: u8, blue: u8) -> Self {
        Self { red, green, blue }
    }
}

/// Background and foreground colors.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct LayerColors {
    /// Background color.
    pub background: RGB,
    /// Foreground color.
    pub foreground: RGB,
}

impl LayerColors {
    /// Create a new instance.
    pub fn new(background: RGB, foreground: RGB) -> Self {
        Self {
            background,
            foreground,
        }
    }
}

/// Colors of a security context.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SecurityContextColors {
    /// Background and foreground colors of SELinux user.
    pub user: LayerColors,
    /// Background and foreground colors of SELinux role.
    pub role: LayerColors,
    /// Background and foreground colors of SELinux type.
    pub the_type: LayerColors,
    /// Background and foreground colors of SELinux range.
    pub range: LayerColors,
}

impl SecurityContextColors {
    /// Create a new instance.
    pub fn new(
        user: LayerColors,
        role: LayerColors,
        the_type: LayerColors,
        range: LayerColors,
    ) -> Self {
        Self {
            user,
            role,
            the_type,
            range,
        }
    }
}

/// SELinux security context.
#[derive(Debug)]
pub struct SecurityContext<'t> {
    context: ptr::NonNull<c_char>,
    size: Option<usize>,
    is_raw: bool,
    context_owned: bool,
    _phantom_data: PhantomData<&'t c_char>,
}

impl<'t> SecurityContext<'t> {
    /// Return `false` if security context translation must be performed.
    #[must_use]
    pub fn is_raw_format(&self) -> bool {
        self.is_raw
    }

    /// Return the managed raw pointer to [`c_char`].
    #[must_use]
    pub fn as_ptr(&self) -> *const c_char {
        self.context.as_ptr()
    }

    /// Return the managed raw pointer to [`c_char`].
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut c_char {
        self.context.as_ptr()
    }

    /// Return the security context's byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.size.map_or_else(
            || unsafe { CStr::from_ptr(self.context.as_ptr()).to_bytes() },
            |size| unsafe { slice::from_raw_parts(self.context.as_ptr().cast(), size) },
        )
    }

    /// Return the string value of this security context.
    ///
    /// If the context is empty, then this returns `Ok(None)`.
    pub fn to_c_string(&self) -> Result<Option<Cow<CStr>>> {
        if let Some(size) = self.size {
            let bytes = unsafe { slice::from_raw_parts(self.context.as_ptr().cast(), size) };
            if bytes.is_empty() {
                Ok(None)
            } else if bytes.last().cloned() == Some(0) {
                if let Ok(result) = CStr::from_bytes_with_nul(bytes) {
                    Ok(Some(Cow::Borrowed(result)))
                } else {
                    let op = "CStr::from_bytes_with_nul()";
                    Err(Error::from_io(op, io::ErrorKind::InvalidData.into()))
                }
            } else if let Ok(result) = CString::new(bytes) {
                Ok(Some(Cow::Owned(result)))
            } else {
                let op = "CString::new()";
                Err(Error::from_io(op, io::ErrorKind::InvalidData.into()))
            }
        } else {
            let result = unsafe { CStr::from_ptr(self.context.as_ptr()) };
            Ok(Some(Cow::Borrowed(result)))
        }
    }

    /// Return the security context identified by `context`.
    ///
    /// ⚠️ The returned instance does **NOT** own the provided context.
    /// When the returned instance get dropped, it will **NOT** deallocate
    /// the provided context.
    pub fn from_c_str(c_context: &'t CStr, raw_format: bool) -> SecurityContext<'t> {
        Self {
            context: c_str_to_non_null_ptr(c_context),
            size: Some(c_context.to_bytes().len()),
            is_raw: raw_format,
            context_owned: false,
            _phantom_data: PhantomData,
        }
    }

    /// Return the security context of the current process.
    ///
    /// See: `getcon()`.
    pub fn current(raw_format: bool) -> Result<Self> {
        let (proc, proc_name): (unsafe extern "C" fn(_) -> _, _) = if raw_format {
            (selinux_sys::getcon_raw, "getcon_raw()")
        } else {
            (selinux_sys::getcon, "getcon()")
        };

        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe { proc(&mut context) };
        Self::from_result(proc_name, r, context, raw_format)
    }

    /// Return the security context of the current process before the last exec.
    ///
    /// See: `getprevcon()`.
    pub fn previous(raw_format: bool) -> Result<Self> {
        let (proc, proc_name): (unsafe extern "C" fn(_) -> _, _) = if raw_format {
            (selinux_sys::getprevcon_raw, "getprevcon_raw()")
        } else {
            (selinux_sys::getprevcon, "getprevcon()")
        };

        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe { proc(&mut context) };
        Self::from_result(proc_name, r, context, raw_format)
    }

    /// Set the current security context of the process to this context.
    ///
    /// See: `setcon()`.
    pub fn set_as_current(&self) -> Result<()> {
        let (proc, proc_name): (unsafe extern "C" fn(_) -> _, _) = if self.is_raw {
            (selinux_sys::setcon_raw, "setcon_raw()")
        } else {
            (selinux_sys::setcon, "setcon()")
        };

        ret_val_to_result(proc_name, unsafe { proc(self.context.as_ptr()) })
    }

    /// Get the context of a kernel initial security identifier specified by name.
    ///
    /// See: `security_get_initial_context()`.
    pub fn of_initial_kernel_context(name: &str, raw_format: bool) -> Result<Self> {
        let (proc, proc_name): (unsafe extern "C" fn(_, _) -> _, _) = if raw_format {
            let proc_name = "security_get_initial_context_raw()";
            (selinux_sys::security_get_initial_context_raw, proc_name)
        } else {
            let proc_name = "security_get_initial_context()";
            (selinux_sys::security_get_initial_context, proc_name)
        };

        let c_name = str_to_c_string(name)?;
        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe { proc(c_name.as_ptr(), &mut context) };
        Self::from_result_with_name(proc_name, r, context, name, raw_format)
    }

    /// Get the default SELinux security context for the specified media type
    /// from the policy.
    ///
    /// See: `matchmediacon()`.
    pub fn of_media_type(name: &str) -> Result<Self> {
        let c_name = str_to_c_string(name)?;
        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe { selinux_sys::matchmediacon(c_name.as_ptr(), &mut context) };
        Self::from_result_with_name("matchmediacon()", r, context, name, false)
    }

    /// Return the process context for the specified process identifier.
    ///
    /// See: `getpidcon()`.
    pub fn of_process(process_id: pid_t, raw_format: bool) -> Result<Self> {
        let (proc, proc_name): (unsafe extern "C" fn(_, _) -> _, _) = if raw_format {
            (selinux_sys::getpidcon_raw, "getpidcon_raw()")
        } else {
            (selinux_sys::getpidcon, "getpidcon()")
        };

        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe { proc(process_id, &mut context) };
        Self::from_result_with_pid(proc_name, r, context, process_id, raw_format)
    }

    /// Perform context translation from the human-readable format (translated)
    /// to the internal system format (raw).
    ///
    /// See: `selinux_trans_to_raw_context()`.
    pub fn to_raw_format(&self) -> Result<Self> {
        if self.is_raw {
            return Err(Error::UnexpectedSecurityContextFormat);
        }

        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe {
            selinux_sys::selinux_trans_to_raw_context(self.context.as_ptr(), &mut context)
        };
        Self::from_result("selinux_trans_to_raw_context()", r, context, true)
    }

    /// Perform context translation from the internal system format (raw) to
    /// the human-readable format (translated).
    ///
    /// See: `selinux_raw_to_trans_context()`.
    pub fn to_translated_format(&self) -> Result<Self> {
        if !self.is_raw {
            return Err(Error::UnexpectedSecurityContextFormat);
        }

        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe {
            selinux_sys::selinux_raw_to_trans_context(self.context.as_ptr(), &mut context)
        };
        Self::from_result("selinux_raw_to_trans_context()", r, context, false)
    }

    /// Ask the user to manually enter a context as a fallback if a list of
    /// authorized contexts could not be obtained.
    ///
    /// See: `manual_user_enter_context()`.
    pub fn of_se_user_with_selected_context(se_user: &str, raw_format: bool) -> Result<Self> {
        let mut context: *mut c_char = ptr::null_mut();
        let c_se_user = str_to_c_string(se_user)?;
        let r = unsafe { selinux_sys::manual_user_enter_context(c_se_user.as_ptr(), &mut context) };
        Self::from_result("manual_user_enter_context()", r, context, raw_format)
    }

    /// Obtain a context, for the specified SELinux user identity, that is
    /// reachable from the specified `reachable_from_context`.
    ///
    /// See: `get_default_context()`, `get_default_context_with_level()`,
    /// `get_default_context_with_role()`, `get_default_context_with_rolelevel()`.
    pub fn default_for_se_user(
        se_user: &str,
        role: Option<&str>,
        level: Option<&str>,
        reachable_from_context: Option<&Self>,
        raw_format: bool,
    ) -> Result<Self> {
        let c_se_user = str_to_c_string(se_user)?;

        let c_role = if let Some(role) = role {
            str_to_c_string(role).map(Some)?
        } else {
            None
        };

        let c_level = if let Some(level) = level {
            str_to_c_string(level).map(Some)?
        } else {
            None
        };

        let reachable_from_context =
            reachable_from_context.map_or(ptr::null_mut(), |c| c.context.as_ptr());

        let mut context: *mut c_char = ptr::null_mut();

        let (r, proc_name) = unsafe {
            match (c_role, c_level) {
                (None, None) => (
                    selinux_sys::get_default_context(
                        c_se_user.as_ptr(),
                        reachable_from_context,
                        &mut context,
                    ),
                    "get_default_context()",
                ),

                (None, Some(c_level)) => (
                    selinux_sys::get_default_context_with_level(
                        c_se_user.as_ptr(),
                        c_level.as_ptr(),
                        reachable_from_context,
                        &mut context,
                    ),
                    "get_default_context_with_level()",
                ),

                (Some(c_role), None) => (
                    selinux_sys::get_default_context_with_role(
                        c_se_user.as_ptr(),
                        c_role.as_ptr(),
                        reachable_from_context,
                        &mut context,
                    ),
                    "get_default_context_with_role()",
                ),

                (Some(c_role), Some(c_level)) => (
                    selinux_sys::get_default_context_with_rolelevel(
                        c_se_user.as_ptr(),
                        c_role.as_ptr(),
                        c_level.as_ptr(),
                        reachable_from_context,
                        &mut context,
                    ),
                    "get_default_context_with_rolelevel()",
                ),
            }
        };

        Self::from_result(proc_name, r, context, raw_format)
    }

    /// Get the context used for executing a new process.
    ///
    /// See: `getexeccon()`.
    pub fn of_next_exec(raw_format: bool) -> Result<Option<Self>> {
        let (proc, proc_name): (unsafe extern "C" fn(_) -> _, _) = if raw_format {
            (selinux_sys::getexeccon_raw, "getexeccon_raw()")
        } else {
            (selinux_sys::getexeccon, "getexeccon()")
        };

        Self::of_new_operations(proc, proc_name, raw_format)
    }

    /// Reset the context, used for the next `execve()` call, to the default
    /// policy behavior.
    ///
    /// See: `setexeccon()`.
    pub fn set_default_context_for_next_exec() -> Result<()> {
        let r = unsafe { selinux_sys::setexeccon(ptr::null()) };
        ret_val_to_result("setexeccon()", r)
    }

    /// Set the context used for the next `execve()` call.
    ///
    /// See: `setexeccon()`.
    pub fn set_for_next_exec(&self) -> Result<()> {
        let (proc, proc_name): (unsafe extern "C" fn(_) -> _, _) = if self.is_raw {
            (selinux_sys::setexeccon_raw, "setexeccon_raw()")
        } else {
            (selinux_sys::setexeccon, "setexeccon()")
        };

        ret_val_to_result(proc_name, unsafe { proc(self.context.as_ptr()) })
    }

    /// Get the context used for creating a new file system object.
    ///
    /// See: `getfscreatecon()`.
    pub fn of_new_file_system_objects(raw_format: bool) -> Result<Option<Self>> {
        let (proc, proc_name): (unsafe extern "C" fn(_) -> _, _) = if raw_format {
            (selinux_sys::getfscreatecon_raw, "getfscreatecon_raw()")
        } else {
            (selinux_sys::getfscreatecon, "getfscreatecon()")
        };

        Self::of_new_operations(proc, proc_name, raw_format)
    }

    /// Reset the context, used for creating a new file system object, to the
    /// default policy behavior.
    ///
    /// See: `setfscreatecon()`.
    pub fn set_default_context_for_new_file_system_objects() -> Result<()> {
        let r = unsafe { selinux_sys::setfscreatecon(ptr::null()) };
        ret_val_to_result("setfscreatecon()", r)
    }

    /// Set the context used for creating a new file system object.
    ///
    /// See: `setfscreatecon()`.
    pub fn set_for_new_file_system_objects(&self, raw_format: bool) -> Result<()> {
        let (proc, proc_name): (unsafe extern "C" fn(_) -> _, _) = if raw_format {
            (selinux_sys::setfscreatecon_raw, "setfscreatecon_raw()")
        } else {
            (selinux_sys::setfscreatecon, "setfscreatecon()")
        };

        ret_val_to_result(proc_name, unsafe { proc(self.context.as_ptr()) })
    }

    /// Get the context used for creating a new kernel key ring.
    ///
    /// See: `getkeycreatecon()`.
    pub fn of_new_kernel_key_rings(raw_format: bool) -> Result<Option<Self>> {
        let (proc, proc_name): (unsafe extern "C" fn(_) -> _, _) = if raw_format {
            (selinux_sys::getkeycreatecon_raw, "getkeycreatecon_raw()")
        } else {
            (selinux_sys::getkeycreatecon, "getkeycreatecon()")
        };

        Self::of_new_operations(proc, proc_name, raw_format)
    }

    /// Set the context, used for creating a new kernel key ring, to the
    /// default policy behavior.
    ///
    /// See: `setkeycreatecon()`.
    pub fn set_default_context_for_new_kernel_key_rings() -> Result<()> {
        let r = unsafe { selinux_sys::setkeycreatecon(ptr::null()) };
        ret_val_to_result("setkeycreatecon()", r)
    }

    /// Set the context used for creating a new kernel key ring.
    ///
    /// See: `setkeycreatecon()`.
    pub fn set_for_new_kernel_key_rings(&self, raw_format: bool) -> Result<()> {
        let (proc, proc_name): (unsafe extern "C" fn(_) -> _, _) = if raw_format {
            (selinux_sys::setkeycreatecon_raw, "setkeycreatecon_raw()")
        } else {
            (selinux_sys::setkeycreatecon, "setkeycreatecon()")
        };

        ret_val_to_result(proc_name, unsafe { proc(self.context.as_ptr()) })
    }

    /// Get the context used for creating a new labeled network socket.
    ///
    /// See: `getsockcreatecon()`.
    pub fn of_new_labeled_sockets(raw_format: bool) -> Result<Option<Self>> {
        let (proc, proc_name): (unsafe extern "C" fn(_) -> _, _) = if raw_format {
            (selinux_sys::getsockcreatecon_raw, "getsockcreatecon_raw()")
        } else {
            (selinux_sys::getsockcreatecon, "getsockcreatecon()")
        };

        Self::of_new_operations(proc, proc_name, raw_format)
    }

    /// Set the context, used for creating a new labeled network sockets, to the
    /// default policy behavior.
    ///
    /// See: `setsockcreatecon()`.
    pub fn set_default_context_for_new_labeled_sockets() -> Result<()> {
        let r = unsafe { selinux_sys::setsockcreatecon(ptr::null()) };
        ret_val_to_result("setsockcreatecon()", r)
    }

    /// Set the context used for creating a new labeled network sockets.
    ///
    /// See: `setsockcreatecon()`.
    pub fn set_for_new_labeled_sockets(&self, raw_format: bool) -> Result<()> {
        let (proc, proc_name): (unsafe extern "C" fn(_) -> _, _) = if raw_format {
            (selinux_sys::setsockcreatecon_raw, "setsockcreatecon_raw()")
        } else {
            (selinux_sys::setsockcreatecon, "setsockcreatecon()")
        };

        ret_val_to_result(proc_name, unsafe { proc(self.context.as_ptr()) })
    }

    /// Get the context associated with the given path in the file system.
    ///
    /// See: `lgetfilecon()`, `getfilecon()`.
    pub fn of_path(
        path: impl AsRef<Path>,
        follow_symbolic_links: bool,
        raw_format: bool,
    ) -> Result<Option<Self>> {
        let (proc, proc_name): (unsafe extern "C" fn(_, _) -> _, _) =
            match (follow_symbolic_links, raw_format) {
                (false, false) => (selinux_sys::lgetfilecon, "lgetfilecon()"),
                (false, true) => (selinux_sys::lgetfilecon_raw, "lgetfilecon_raw()"),
                (true, false) => (selinux_sys::getfilecon, "getfilecon()"),
                (true, true) => (selinux_sys::getfilecon_raw, "getfilecon_raw()"),
            };

        let c_path = os_str_to_c_string(path.as_ref().as_os_str())?;
        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe { proc(c_path.as_ptr(), &mut context) };
        if r == -1 {
            let err = io::Error::last_os_error();
            if let Some(libc::ENODATA) = err.raw_os_error() {
                Ok(None)
            } else {
                Err(Error::from_io_path(proc_name, path.as_ref(), err))
            }
        } else {
            Ok(ptr::NonNull::new(context).map(|context| {
                let size = if r >= 0 { Some(r as c_uint) } else { None };
                Self::from_ptr(context, size, raw_format)
            }))
        }
    }

    /// Set the file context to the system defaults.
    ///
    /// See: `selinux_lsetfilecon_default()`.
    pub fn set_default_for_path(path: impl AsRef<Path>) -> Result<()> {
        let c_path = os_str_to_c_string(path.as_ref().as_os_str())?;
        let r = unsafe { selinux_sys::selinux_lsetfilecon_default(c_path.as_ptr()) };
        ret_val_to_result_with_path("selinux_lsetfilecon_default()", r, path.as_ref())
    }

    /// Set the SELinux security context of a file system object.
    ///
    /// See: `lsetfilecon()`, `setfilecon()`.
    pub fn set_for_path(
        &self,
        path: impl AsRef<Path>,
        follow_symbolic_links: bool,
        raw_format: bool,
    ) -> Result<()> {
        let (proc, proc_name): (unsafe extern "C" fn(_, _) -> _, _) =
            match (follow_symbolic_links, raw_format) {
                (false, false) => (selinux_sys::lsetfilecon, "lsetfilecon()"),
                (false, true) => (selinux_sys::lsetfilecon_raw, "lsetfilecon_raw()"),
                (true, false) => (selinux_sys::setfilecon, "setfilecon()"),
                (true, true) => (selinux_sys::setfilecon_raw, "setfilecon_raw()"),
            };

        let c_path = os_str_to_c_string(path.as_ref().as_os_str())?;
        let r = unsafe { proc(c_path.as_ptr(), self.context.as_ptr()) };
        ret_val_to_result_with_path(proc_name, r, path.as_ref())
    }

    /// Get the SELinux security context of a file system object.
    ///
    /// See: `fgetfilecon()`.
    pub fn of_file<T>(fd: &T, raw_format: bool) -> Result<Option<Self>>
    where
        T: AsRawFd,
    {
        let (proc, proc_name): (unsafe extern "C" fn(_, _) -> _, _) = if raw_format {
            (selinux_sys::fgetfilecon_raw, "fgetfilecon_raw()")
        } else {
            (selinux_sys::fgetfilecon, "fgetfilecon()")
        };

        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe { proc(fd.as_raw_fd(), &mut context) };
        if r == -1 {
            let err = io::Error::last_os_error();
            if let Some(libc::ENODATA) = err.raw_os_error() {
                Ok(None)
            } else {
                Err(Error::from_io(proc_name, err))
            }
        } else {
            Ok(ptr::NonNull::new(context).map(|context| {
                let size = if r >= 0 { Some(r as c_uint) } else { None };
                Self::from_ptr(context, size, raw_format)
            }))
        }
    }

    /// Set the SELinux security context of the file system object identified
    /// by an open file descriptor.
    ///
    /// See: `fsetfilecon()`.
    pub fn set_for_file<T>(&self, fd: &T) -> Result<()>
    where
        T: AsRawFd,
    {
        let (proc, proc_name): (unsafe extern "C" fn(_, _) -> _, _) = if self.is_raw {
            (selinux_sys::fsetfilecon_raw, "fsetfilecon_raw()")
        } else {
            (selinux_sys::fsetfilecon, "fsetfilecon()")
        };

        let r = unsafe { proc(fd.as_raw_fd(), self.context.as_ptr()) };
        ret_val_to_result(proc_name, r)
    }

    /// Set the SELinux security context of the peer socket identified by an
    /// open file descriptor.
    ///
    /// See: `getpeercon()`.
    pub fn of_peer_socket<T>(socket: &T, raw_format: bool) -> Result<Self>
    where
        T: AsRawFd,
    {
        let (proc, proc_name): (unsafe extern "C" fn(_, _) -> _, _) = if raw_format {
            (selinux_sys::getpeercon_raw, "getpeercon_raw()")
        } else {
            (selinux_sys::getpeercon, "getpeercon()")
        };

        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe { proc(socket.as_raw_fd(), &mut context) };
        Self::from_result(proc_name, r, context, raw_format)
    }

    /// Return whether the policy permits this source context to access
    /// `target_context` via `target_class` with the requested access vector.
    ///
    /// See: `security_compute_av_flags()`.
    pub fn query_access_decision(
        &self,
        target_context: &Self,
        target_class: SecurityClass,
        requested_access: selinux_sys::access_vector_t,
    ) -> Result<selinux_sys::av_decision> {
        if self.is_raw != target_context.is_raw {
            return Err(Error::SecurityContextFormatMismatch);
        }

        let (proc, proc_name): (unsafe extern "C" fn(_, _, _, _, _) -> _, _) = if self.is_raw {
            let proc_name = "security_compute_av_flags_raw()";
            (selinux_sys::security_compute_av_flags_raw, proc_name)
        } else {
            let proc_name = "security_compute_av_flags()";
            (selinux_sys::security_compute_av_flags, proc_name)
        };

        let mut result = MaybeUninit::<selinux_sys::av_decision>::uninit();
        let r = unsafe {
            proc(
                self.context.as_ptr(),
                target_context.context.as_ptr(),
                target_class.0,
                requested_access,
                result.as_mut_ptr(),
            )
        };

        if r == -1 {
            Err(Error::last_io_error(proc_name))
        } else {
            Ok(unsafe { result.assume_init() })
        }
    }

    /// Compute a context to use for labeling a new named object in a particular
    /// class based on a SID pair.
    ///
    /// See: `security_compute_create_name()`.
    pub fn of_labeling_decision(
        &self,
        target_context: &Self,
        target_class: SecurityClass,
        object_name: &str,
    ) -> Result<Self> {
        if self.is_raw != target_context.is_raw {
            return Err(Error::SecurityContextFormatMismatch);
        }

        let (proc, proc_name): (unsafe extern "C" fn(_, _, _, _, _) -> _, _) = if self.is_raw {
            let proc_name = "security_compute_create_name_raw()";
            (selinux_sys::security_compute_create_name_raw, proc_name)
        } else {
            let proc_name = "security_compute_create_name()";
            (selinux_sys::security_compute_create_name, proc_name)
        };

        let c_object_name = str_to_c_string(object_name)?;
        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe {
            proc(
                self.context.as_ptr(),
                target_context.context.as_ptr(),
                target_class.0,
                c_object_name.as_ptr(),
                &mut context,
            )
        };

        Self::from_result_with_name(proc_name, r, context, object_name, self.is_raw)
    }

    /// Compute the new context to use when relabeling an object.
    ///
    /// See: `security_compute_relabel()`.
    pub fn of_relabeling_decision(
        &self,
        target_context: &Self,
        target_class: SecurityClass,
    ) -> Result<Self> {
        if self.is_raw != target_context.is_raw {
            return Err(Error::SecurityContextFormatMismatch);
        }

        let (proc, proc_name): (unsafe extern "C" fn(_, _, _, _) -> _, _) = if self.is_raw {
            let proc_name = "security_compute_relabel_raw()";
            (selinux_sys::security_compute_relabel_raw, proc_name)
        } else {
            let proc_name = "security_compute_relabel()";
            (selinux_sys::security_compute_relabel, proc_name)
        };

        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe {
            proc(
                self.context.as_ptr(),
                target_context.context.as_ptr(),
                target_class.0,
                &mut context,
            )
        };

        Self::from_result(proc_name, r, context, self.is_raw)
    }

    /// Compute the context to use when labeling a polyinstantiated
    /// object instance.
    ///
    /// See: `security_compute_member()`.
    pub fn of_polyinstantiation_member_decision(
        &self,
        target_context: &Self,
        target_class: SecurityClass,
    ) -> Result<Self> {
        if self.is_raw != target_context.is_raw {
            return Err(Error::SecurityContextFormatMismatch);
        }

        let (proc, proc_name): (unsafe extern "C" fn(_, _, _, _) -> _, _) = if self.is_raw {
            let proc_name = "security_compute_member_raw()";
            (selinux_sys::security_compute_member_raw, proc_name)
        } else {
            let proc_name = "security_compute_member()";
            (selinux_sys::security_compute_member, proc_name)
        };

        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe {
            proc(
                self.context.as_ptr(),
                target_context.context.as_ptr(),
                target_class.0,
                &mut context,
            )
        };

        Self::from_result(proc_name, r, context, self.is_raw)
    }

    /// Determine if a transition from this context to `new_context` using
    /// `target_context` as the object is valid for object class `target_class`.
    ///
    /// This checks against the `mlsvalidatetrans` and `validatetrans`
    /// constraints in the loaded policy.
    ///
    /// See: `security_validatetrans()`.
    pub fn validate_transition(
        &self,
        target_context: &Self,
        target_class: SecurityClass,
        new_context: &Self,
    ) -> Result<()> {
        if self.is_raw != target_context.is_raw {
            return Err(Error::SecurityContextFormatMismatch);
        }

        let onf = OptionalNativeFunctions::get();
        let (proc, proc_name) = if self.is_raw {
            let proc_name = "security_validatetrans_raw()";
            (onf.security_validatetrans_raw, proc_name)
        } else {
            let proc_name = "security_validatetrans()";
            (onf.security_validatetrans, proc_name)
        };

        let r = unsafe {
            proc(
                self.context.as_ptr(),
                target_context.context.as_ptr(),
                target_class.0,
                new_context.context.as_ptr(),
            )
        };

        ret_val_to_result(proc_name, r)
    }

    /// Check the validity of an SELinux context.
    ///
    /// See: `security_check_context()`, `is_selinux_enabled()`.
    #[must_use]
    pub fn check(&self) -> Option<bool> {
        let proc: unsafe extern "C" fn(_) -> _ = if self.is_raw {
            selinux_sys::security_check_context_raw
        } else {
            selinux_sys::security_check_context
        };

        if unsafe { proc(self.context.as_ptr()) } == -1 {
            if unsafe { selinux_sys::is_selinux_enabled() } == 0 {
                None
            } else {
                Some(false)
            }
        } else {
            Some(true)
        }
    }

    /// Canonicalize this security context.
    ///
    /// See: `security_canonicalize_context()`.
    pub fn canonicalize(&self) -> Result<Self> {
        let (proc, proc_name): (unsafe extern "C" fn(_, _) -> _, _) = if self.is_raw {
            let proc_name = "security_canonicalize_context_raw()";
            (selinux_sys::security_canonicalize_context_raw, proc_name)
        } else {
            let proc_name = "security_canonicalize_context()";
            (selinux_sys::security_canonicalize_context, proc_name)
        };

        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe { proc(self.context.as_ptr(), &mut context) };
        Self::from_result(proc_name, r, context, self.is_raw)
    }

    /// Check if this context has the access permission for the specified class
    /// on the target context.
    ///
    /// See: `selinux_check_access()`.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn check_access(
        &self,
        target_context: &Self,
        target_class: &str,
        requested_permission: &str,
        audit_data: *mut c_void,
    ) -> Result<bool> {
        let c_target_class = str_to_c_string(target_class)?;
        let c_requested_permission = str_to_c_string(requested_permission)?;

        let r = unsafe {
            selinux_sys::selinux_check_access(
                self.context.as_ptr(),
                target_context.context.as_ptr(),
                c_target_class.as_ptr(),
                c_requested_permission.as_ptr(),
                audit_data,
            )
        };

        Ok(r == 0)
    }

    /// Check whether a SELinux tty security context is defined as
    /// a securetty context.
    ///
    /// See: `selinux_check_securetty_context()`.
    #[must_use]
    pub fn check_securetty_context(&self) -> bool {
        let r = unsafe { selinux_sys::selinux_check_securetty_context(self.context.as_ptr()) };
        r == 0
    }

    /// Check whether SELinux context type is customizable by the administrator.
    ///
    /// See: `is_context_customizable()`.
    pub fn is_customizable(&self) -> Result<bool> {
        let r = unsafe { selinux_sys::is_context_customizable(self.context.as_ptr()) };
        if r == -1 {
            Err(Error::last_io_error("is_context_customizable()"))
        } else {
            Ok(r != 0)
        }
    }

    /// Return the color string for this SELinux security context.
    ///
    /// See: `selinux_raw_context_to_color()`.
    pub fn to_color(&self) -> Result<SecurityContextColors> {
        if !self.is_raw {
            let raw_context = self.to_raw_format()?;
            return raw_context.to_color();
        }

        let mut color_ptr: *mut c_char = ptr::null_mut();
        let r = unsafe {
            selinux_sys::selinux_raw_context_to_color(self.context.as_ptr(), &mut color_ptr)
        };

        if r == -1 {
            Err(Error::last_io_error("selinux_raw_context_to_color()"))
        } else {
            CAllocatedBlock::new(color_ptr).map_or_else(
                || {
                    let err = io::ErrorKind::InvalidData.into();
                    Err(Error::from_io("selinux_raw_context_to_color()", err))
                },
                |c_color| Self::parse_context_color(c_color.as_c_str().to_bytes()),
            )
        }
    }

    /// Compare this SELinux security context with another one, excluding
    /// the `user` component.
    ///
    /// See: `selinux_file_context_cmp()`.
    #[must_use]
    pub fn compare_user_insensitive(&self, other: &Self) -> cmp::Ordering {
        let r = unsafe {
            selinux_sys::selinux_file_context_cmp(self.context.as_ptr(), other.context.as_ptr())
        };

        r.cmp(&0)
    }

    /// Compare the SELinux security context on disk to the default security
    /// context required by the policy file contexts file.
    ///
    /// See: `selinux_file_context_verify()`.
    pub fn verify_file_context(
        path: impl AsRef<Path>,
        mode: Option<FileAccessMode>,
    ) -> Result<bool> {
        let c_path = os_str_to_c_string(path.as_ref().as_os_str())?;
        let mode = mode.map_or(0, FileAccessMode::mode);

        Error::clear_errno();

        match unsafe { selinux_sys::selinux_file_context_verify(c_path.as_ptr(), mode) } {
            -1 => Err(Error::from_io_path(
                "selinux_file_context_verify()",
                path.as_ref(),
                io::Error::last_os_error(),
            )),

            0 => {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    None | Some(0) => Ok(false),

                    _ => Err(Error::from_io_path(
                        "selinux_file_context_verify()",
                        path.as_ref(),
                        err,
                    )),
                }
            }

            _ => Ok(true),
        }
    }

    fn of_new_operations(
        proc: unsafe extern "C" fn(*mut *mut c_char) -> c_int,
        proc_name: &'static str,
        raw_format: bool,
    ) -> Result<Option<Self>> {
        let mut context: *mut c_char = ptr::null_mut();
        if unsafe { proc(&mut context) } == -1 {
            Err(Error::last_io_error(proc_name))
        } else {
            Ok(ptr::NonNull::new(context).map(|c| Self::from_ptr(c, None, raw_format)))
        }
    }

    fn from_ptr(context: ptr::NonNull<c_char>, size: Option<c_uint>, raw_format: bool) -> Self {
        Self {
            context,
            size: size.map(|size| size as usize),
            is_raw: raw_format,
            context_owned: true,
            _phantom_data: PhantomData,
        }
    }

    fn from_result(
        proc_name: &'static str,
        result: c_int,
        context: *mut c_char,
        raw_format: bool,
    ) -> Result<Self> {
        if result == -1 {
            Err(Error::last_io_error(proc_name))
        } else {
            ptr::NonNull::new(context).map_or_else(
                || Err(Error::from_io(proc_name, io::ErrorKind::InvalidData.into())),
                |context| Ok(Self::from_ptr(context, None, raw_format)),
            )
        }
    }

    fn from_result_with_name(
        proc_name: &'static str,
        result: c_int,
        context: *mut c_char,
        name: &str,
        raw_format: bool,
    ) -> Result<Self> {
        if result == -1 {
            Err(Error::last_io_error(proc_name))
        } else {
            ptr::NonNull::new(context).map_or_else(
                || {
                    Err(Error::IO1Name {
                        operation: proc_name,
                        name: name.into(),
                        source: io::ErrorKind::InvalidData.into(),
                    })
                },
                |context| Ok(Self::from_ptr(context, None, raw_format)),
            )
        }
    }

    fn from_result_with_pid(
        proc_name: &'static str,
        result: c_int,
        context: *mut c_char,
        process_id: pid_t,
        raw_format: bool,
    ) -> Result<Self> {
        if result == -1 {
            let err = io::Error::last_os_error();
            Err(Error::from_io_pid(proc_name, process_id, err))
        } else {
            ptr::NonNull::new(context).map_or_else(
                || {
                    let err = io::ErrorKind::InvalidData.into();
                    Err(Error::from_io_pid(proc_name, process_id, err))
                },
                |context| Ok(Self::from_ptr(context, None, raw_format)),
            )
        }
    }

    fn parse_context_color(bytes: &[u8]) -> Result<SecurityContextColors> {
        let colors: Vec<RGB> = bytes
            .split(u8::is_ascii_whitespace)
            .filter(|&bytes| !bytes.is_empty())
            .take(8)
            .flat_map(|bytes| strip_bytes_prefix(bytes, b"#"))
            .filter(|&bytes| !bytes.is_empty())
            .flat_map(|bytes| str::from_utf8(bytes).ok())
            .flat_map(|s| u32::from_str_radix(s, 16).ok())
            .filter(|&n| n <= 0x00ffffff_u32)
            .map(|n| RGB {
                red: (n & 0xff_u32) as u8,
                green: ((n >> 8) & 0xff_u32) as u8,
                blue: ((n >> 16) & 0xff_u32) as u8,
            })
            .collect();

        if colors.len() == 8 {
            Ok(SecurityContextColors {
                user: LayerColors {
                    background: colors[1],
                    foreground: colors[0],
                },
                role: LayerColors {
                    background: colors[3],
                    foreground: colors[2],
                },
                the_type: LayerColors {
                    background: colors[5],
                    foreground: colors[4],
                },
                range: LayerColors {
                    background: colors[7],
                    foreground: colors[6],
                },
            })
        } else {
            Err(Error::from_io_name(
                "selinux_raw_context_to_color()",
                String::from_utf8_lossy(bytes),
                io::ErrorKind::InvalidData.into(),
            ))
        }
    }
}

impl<'t> Drop for SecurityContext<'t> {
    /// See: `freecon()`.
    fn drop(&mut self) {
        let context = self.context.as_ptr();
        self.context = ptr::NonNull::dangling();
        if self.context_owned {
            unsafe { selinux_sys::freecon(context) }
        }
    }
}

/// List of security contexts.
#[derive(Debug)]
pub struct SecurityContextList {
    context_list: ptr::NonNull<*mut c_char>,
    count: usize,
    _phantom_data: PhantomData<c_char>,
}

impl SecurityContextList {
    /// Return the managed raw pointer to [`c_char`].
    #[must_use]
    pub fn as_ptr(&self) -> *const *const c_char {
        self.context_list.as_ptr().cast()
    }

    /// Return the managed raw pointer to [`c_char`].
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut *mut c_char {
        self.context_list.as_ptr()
    }

    /// Number of security contexts present in this list.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if this list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Obtain a list of contexts, for the specified SELinux user identity,
    /// that are reachable from the specified `reachable_from_context`.
    ///
    /// See: `get_ordered_context_list()`, `get_ordered_context_list_with_level()`.
    pub fn of_se_user(
        se_user: &str,
        level: Option<&str>,
        reachable_from_context: Option<&SecurityContext>,
    ) -> Result<Self> {
        let c_se_user = str_to_c_string(se_user)?;

        let c_level = if let Some(level) = level {
            str_to_c_string(level).map(Some)?
        } else {
            None
        };

        let reachable_from_context =
            reachable_from_context.map_or(ptr::null_mut(), |c| c.context.as_ptr());

        let mut context_list: *mut *mut c_char = ptr::null_mut();

        let (r, proc_name) = unsafe {
            if let Some(c_level) = c_level {
                let r = selinux_sys::get_ordered_context_list_with_level(
                    c_se_user.as_ptr(),
                    c_level.as_ptr(),
                    reachable_from_context,
                    &mut context_list,
                );
                (r, "get_ordered_context_list_with_level()")
            } else {
                let r = selinux_sys::get_ordered_context_list(
                    c_se_user.as_ptr(),
                    reachable_from_context,
                    &mut context_list,
                );
                (r, "get_ordered_context_list()")
            }
        };

        if r == -1 {
            Err(Error::last_io_error(proc_name))
        } else {
            ptr::NonNull::new(context_list).map_or_else(
                || Err(Error::from_io(proc_name, io::ErrorKind::InvalidData.into())),
                |context_list| {
                    Ok(Self {
                        context_list,
                        count: r as c_uint as usize,
                        _phantom_data: PhantomData,
                    })
                },
            )
        }
    }

    /// Return the security context at the given index, if the index is valid.
    ///
    /// ⚠️ The returned instance does **NOT** own the context.
    /// When the returned instance get dropped, it will **NOT** deallocate the
    /// provided context.
    /// Deallocation of the context will only happen when the whole list gets
    /// dropped.
    #[must_use]
    pub fn get(&'_ self, index: usize, raw_format: bool) -> Option<SecurityContext<'_>> {
        if index < self.count {
            let context = unsafe { *self.context_list.as_ptr().wrapping_add(index) };
            ptr::NonNull::new(context).map(|context| SecurityContext {
                context,
                size: None,
                is_raw: raw_format,
                context_owned: false,
                _phantom_data: PhantomData,
            })
        } else {
            None
        }
    }

    /// Ask the user via `stdin`/`stdout` as to which context they want from
    /// this list of contexts, and return a new context as selected by the user.
    ///
    /// See: `query_user_context()`.
    pub fn user_selected_context(&self, raw_format: bool) -> Result<SecurityContext> {
        let mut context: *mut c_char = ptr::null_mut();
        let r =
            unsafe { selinux_sys::query_user_context(self.context_list.as_ptr(), &mut context) };
        SecurityContext::from_result("query_user_context()", r, context, raw_format)
    }
}

impl Drop for SecurityContextList {
    /// See: `freeconary()`.
    fn drop(&mut self) {
        let context_list = self.context_list.as_ptr();
        self.context_list = ptr::NonNull::dangling();
        unsafe { selinux_sys::freeconary(context_list) }
    }
}

/// File access mode.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FileAccessMode(selinux_sys::mode_t);

impl FileAccessMode {
    /// Create a new file access mode, if given a non-zero `mode`.
    #[must_use]
    pub fn new(mode: selinux_sys::mode_t) -> Option<Self> {
        if mode == 0 {
            None
        } else {
            Some(Self(mode))
        }
    }

    /// Return the mode value.
    #[must_use]
    pub fn mode(self) -> selinux_sys::mode_t {
        self.0
    }
}

/// SELinux security class.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SecurityClass(selinux_sys::security_class_t);

impl fmt::Display for SecurityClass {
    /// See: `security_class_to_string()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name_ptr = unsafe { selinux_sys::security_class_to_string(self.0) };
        if name_ptr.is_null() {
            write!(f, "<invalid-class>")
        } else {
            let c_name = unsafe { CStr::from_ptr(name_ptr) };
            write!(f, "{}", c_name.to_string_lossy())
        }
    }
}

impl SecurityClass {
    /// Return the security class value.
    #[must_use]
    pub fn value(&self) -> selinux_sys::security_class_t {
        self.0
    }

    /// Create a new security class, if given a non-zero `class`.
    pub fn new(class: selinux_sys::security_class_t) -> Result<Self> {
        if class == 0 {
            let err = io::ErrorKind::NotFound.into();
            Err(Error::from_io("SecurityClass::new()", err))
        } else {
            Ok(Self(class))
        }
    }

    /// Return the security class corresponding to the string name,
    /// if such class exists.
    ///
    /// See: `string_to_security_class()`.
    pub fn from_name(name: &str) -> Result<Self> {
        let c_name = str_to_c_string(name)?;
        let r = unsafe { selinux_sys::string_to_security_class(c_name.as_ptr()) };
        if r == 0 {
            let err = io::ErrorKind::NotFound.into();
            Err(Error::from_io("string_to_security_class()", err))
        } else {
            Ok(Self(r))
        }
    }

    /// Return the name of the `access_vector` of this security class.
    ///
    /// See: `security_av_perm_to_string()`.
    ///
    /// # Safety
    ///
    /// The returned string must not be **modified** or **freed**.
    pub unsafe fn access_vector_bit_name(
        &self,
        access_vector: selinux_sys::access_vector_t,
    ) -> Result<&'static CStr> {
        let name_ptr = selinux_sys::security_av_perm_to_string(self.0, access_vector);
        if name_ptr.is_null() {
            let err = io::ErrorKind::NotFound.into();
            Err(Error::from_io("security_av_perm_to_string()", err))
        } else {
            Ok(CStr::from_ptr(name_ptr))
        }
    }

    /// Return the access vector bit corresponding to the given name and this
    /// security class.
    ///
    /// See: `string_to_av_perm()`.
    pub fn access_vector_bit(&self, name: &str) -> Result<selinux_sys::access_vector_t> {
        let c_name = str_to_c_string(name)?;
        let r = unsafe { selinux_sys::string_to_av_perm(self.0, c_name.as_ptr()) };
        if r == 0 {
            let err = io::ErrorKind::NotFound.into();
            Err(Error::from_io("string_to_av_perm()", err))
        } else {
            Ok(r)
        }
    }

    /// Compute a full access vector string representation using this security
    /// class and `access_vector`, which may have multiple bits set.
    ///
    /// See: `security_av_string()`.
    pub fn full_access_vector_name(
        &self,
        access_vector: selinux_sys::access_vector_t,
    ) -> Result<CAllocatedBlock<c_char>> {
        let mut name_ptr: *mut c_char = ptr::null_mut();
        if unsafe { selinux_sys::security_av_string(self.0, access_vector, &mut name_ptr) } == -1 {
            Err(Error::last_io_error("security_av_string()"))
        } else {
            CAllocatedBlock::new(name_ptr).ok_or_else(|| {
                Error::from_io("security_av_string()", io::ErrorKind::NotFound.into())
            })
        }
    }
}

impl TryFrom<FileAccessMode> for SecurityClass {
    type Error = Error;

    /// See: `mode_to_security_class()`.
    fn try_from(mode: FileAccessMode) -> Result<Self> {
        let r = unsafe { selinux_sys::mode_to_security_class(mode.mode()) };
        if r == 0 {
            let err = io::ErrorKind::NotFound.into();
            Err(Error::from_io("mode_to_security_class()", err))
        } else {
            Ok(Self(r))
        }
    }
}

/// Opaque security context.
#[derive(Debug)]
pub struct OpaqueSecurityContext {
    context: ptr::NonNull<selinux_sys::context_s_t>,
    _phantom_data: PhantomData<selinux_sys::context_s_t>,
}

impl OpaqueSecurityContext {
    /// Return the managed raw pointer to [`selinux_sys::context_s_t`].
    #[must_use]
    pub fn as_ptr(&self) -> *const selinux_sys::context_s_t {
        self.context.as_ptr()
    }

    /// Return the managed raw pointer to [`selinux_sys::context_s_t`].
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut selinux_sys::context_s_t {
        self.context.as_ptr()
    }

    /// Return a new context initialized to a context string.
    ///
    /// See: `context_new()`.
    pub fn new(context: &str) -> Result<Self> {
        let c_context = str_to_c_string(context)?;
        Self::from_c_str(&c_context)
    }

    /// Return a new context initialized to a context string.
    ///
    /// See: `context_new()`.
    pub fn from_c_str(context: &CStr) -> Result<Self> {
        let context = unsafe { selinux_sys::context_new(context.as_ptr()) };
        ptr::NonNull::new(context).map_or_else(
            || Err(Error::last_io_error("context_new()")),
            |context| {
                Ok(Self {
                    context,
                    _phantom_data: PhantomData,
                })
            },
        )
    }

    /// Return the string value of this security context.
    ///
    /// See: `context_str()`.
    pub fn to_c_string(&self) -> Result<CString> {
        let r = unsafe { selinux_sys::context_str(self.context.as_ptr()) };
        if r.is_null() {
            Err(Error::last_io_error("context_str()"))
        } else {
            Ok(unsafe { CStr::from_ptr(r) }.into())
        }
    }

    /// Return the string value of this security context's type.
    ///
    /// See: `context_type_get()`.
    pub fn the_type(&self) -> Result<CString> {
        self.get(selinux_sys::context_type_get, "context_type_get()")
    }

    /// Set the type of this security context.
    ///
    /// See: `context_type_set()`.
    pub fn set_type_str(&self, new_value: &str) -> Result<()> {
        let c_new_value = str_to_c_string(new_value)?;
        self.set(
            selinux_sys::context_type_set,
            "context_type_set()",
            c_new_value.as_ref(),
        )
    }

    /// Set the type of this security context.
    ///
    /// See: `context_type_set()`.
    pub fn set_type(&self, new_value: &CStr) -> Result<()> {
        let proc_name = "context_type_set()";
        self.set(selinux_sys::context_type_set, proc_name, new_value)
    }

    /// Return the string value of this security context's range.
    ///
    /// See: `context_range_get()`.
    pub fn range(&self) -> Result<CString> {
        self.get(selinux_sys::context_range_get, "context_range_get()")
    }

    /// Set the range of this security context.
    ///
    /// See: `context_range_set()`.
    pub fn set_range_str(&self, new_value: &str) -> Result<()> {
        let c_new_value = str_to_c_string(new_value)?;
        self.set(
            selinux_sys::context_range_set,
            "context_range_set()",
            c_new_value.as_ref(),
        )
    }

    /// Set the range of this security context.
    ///
    /// See: `context_range_set()`.
    pub fn set_range(&self, new_value: &CStr) -> Result<()> {
        let proc_name = "context_range_set()";
        self.set(selinux_sys::context_range_set, proc_name, new_value)
    }

    /// Return the string value of this security context's role.
    ///
    /// See: `context_role_get()`.
    pub fn role(&self) -> Result<CString> {
        self.get(selinux_sys::context_role_get, "context_role_get()")
    }

    /// Set the role of this security context.
    ///
    /// See: `context_role_set()`.
    pub fn set_role_str(&self, new_value: &str) -> Result<()> {
        let c_new_value = str_to_c_string(new_value)?;
        self.set(
            selinux_sys::context_role_set,
            "context_role_set()",
            c_new_value.as_ref(),
        )
    }

    /// Set the role of this security context.
    ///
    /// See: `context_role_set()`.
    pub fn set_role(&self, new_value: &CStr) -> Result<()> {
        let proc_name = "context_role_set()";
        self.set(selinux_sys::context_role_set, proc_name, new_value)
    }

    /// Return the string value of this security context's user.
    ///
    /// See: `context_user_get()`.
    pub fn user(&self) -> Result<CString> {
        self.get(selinux_sys::context_user_get, "context_user_get()")
    }

    /// Set the user of this security context.
    ///
    /// See: `context_user_set()`.
    pub fn set_user_str(&self, new_value: &str) -> Result<()> {
        let c_new_value = str_to_c_string(new_value)?;
        self.set(
            selinux_sys::context_user_set,
            "context_user_set()",
            c_new_value.as_ref(),
        )
    }

    /// Set the user of this security context.
    ///
    /// See: `context_user_set()`.
    pub fn set_user(&self, new_value: &CStr) -> Result<()> {
        let proc_name = "context_user_set()";
        self.set(selinux_sys::context_user_set, proc_name, new_value)
    }

    fn get(
        &self,
        proc: unsafe extern "C" fn(selinux_sys::context_t) -> *const c_char,
        proc_name: &'static str,
    ) -> Result<CString> {
        let r = unsafe { proc(self.context.as_ptr()) };
        if r.is_null() {
            Err(Error::last_io_error(proc_name))
        } else {
            Ok(unsafe { CStr::from_ptr(r) }.into())
        }
    }

    fn set(
        &self,
        proc: unsafe extern "C" fn(selinux_sys::context_t, *const c_char) -> c_int,
        proc_name: &'static str,
        new_value: &CStr,
    ) -> Result<()> {
        if unsafe { proc(self.context.as_ptr(), new_value.as_ptr()) } == 0 {
            Ok(())
        } else {
            Err(Error::last_io_error(proc_name))
        }
    }
}

impl Drop for OpaqueSecurityContext {
    /// See: `context_free()`.
    fn drop(&mut self) {
        let context = self.context.as_ptr();
        self.context = ptr::NonNull::dangling();
        unsafe { selinux_sys::context_free(context) };
    }
}

impl fmt::Display for OpaqueSecurityContext {
    /// See: `context_str()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ptr = unsafe { selinux_sys::context_str(self.context.as_ptr()) };
        let s = if ptr.is_null() {
            Cow::Borrowed("<null>")
        } else {
            unsafe { CStr::from_ptr(ptr) }.to_string_lossy()
        };
        write!(f, "{}", s)
    }
}

/// Support of SELinux in the running kernel.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum KernelSupport {
    /// SELinux is unsupported.
    Unsupported,
    /// SELinux is supported.
    SELinux,
    /// SELinux is supported, with Multi Level Security.
    SELinuxMLS,
}

/// SELinux enforcing mode.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SELinuxMode {
    /// SELinux is not enforcing.
    NotRunning,
    /// SELinux is permissive.
    Permissive,
    /// SELinux is enforcing.
    Enforcing,
}

/// SELinux handling of undefined object classes and permissions.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum UndefinedHandling {
    /// Undefined object classes and permissions are allowed.
    Allowed,
    /// Undefined object classes and permissions are deined at run time.
    DeniedAtRunTime,
    /// Undefined object classes and permissions are rejected at policy load time.
    RejectedAtLoadTime,
}

/// Protection checked by SELinux on `mmap()` and `mprotect()` calls.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ProtectionCheckingMode {
    /// Actual protection that will be applied by the kernel
    /// (including the effects of `READ_IMPLIES_EXEC`).
    CheckingActualProtection,
    /// Protection requested by the application.
    CheckingRequestedProtection,
}

/// Determine the support of SELinux in the running kernel.
///
/// See: `is_selinux_enabled()`, `is_selinux_mls_enabled()`.
#[must_use]
pub fn kernel_support() -> KernelSupport {
    if unsafe { selinux_sys::is_selinux_mls_enabled() } != 0 {
        KernelSupport::SELinuxMLS
    } else if unsafe { selinux_sys::is_selinux_enabled() } != 0 {
        KernelSupport::SELinux
    } else {
        KernelSupport::Unsupported
    }
}

/// Determine how the system was set up to run SELinux.
///
/// See: `selinux_getenforcemode()`.
pub fn boot_mode() -> Result<SELinuxMode> {
    let mut enforce = -1;
    if unsafe { selinux_sys::selinux_getenforcemode(&mut enforce) } == -1 {
        Err(Error::last_io_error("selinux_getenforcemode()"))
    } else {
        match enforce {
            -1 => Ok(SELinuxMode::NotRunning),
            0 => Ok(SELinuxMode::Permissive),
            _ => Ok(SELinuxMode::Enforcing),
        }
    }
}

/// Determine the current SELinux enforcing mode.
///
/// See: `security_getenforce()`.
#[must_use]
pub fn current_mode() -> SELinuxMode {
    match unsafe { selinux_sys::security_getenforce() } {
        -1 => SELinuxMode::NotRunning,
        0 => SELinuxMode::Permissive,
        _ => SELinuxMode::Enforcing,
    }
}

/// Set the current SELinux enforcing mode.
///
/// See: `security_disable()`, `security_setenforce()`.
pub fn set_current_mode(new_mode: SELinuxMode) -> Result<()> {
    let (r, proc_name) = match new_mode {
        SELinuxMode::NotRunning => {
            let r = unsafe { selinux_sys::security_disable() };
            (r, "security_disable()")
        }

        SELinuxMode::Permissive => {
            let r = unsafe { selinux_sys::security_setenforce(0) };
            (r, "security_setenforce()")
        }

        SELinuxMode::Enforcing => {
            let r = unsafe { selinux_sys::security_setenforce(1) };
            (r, "security_setenforce()")
        }
    };

    ret_val_to_result(proc_name, r)
}

/// Return the current SELinux handling of undefined object classes
/// and permissions.
///
/// See: `security_reject_unknown()`, `security_deny_unknown()`.
pub fn undefined_handling() -> Result<UndefinedHandling> {
    let mut reject_unknown = unsafe { (OptionalNativeFunctions::get().security_reject_unknown)() };
    if reject_unknown == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) {
            reject_unknown = 0;
        } else {
            return Err(Error::from_io("security_reject_unknown()", err));
        }
    }

    if reject_unknown == 0 {
        match unsafe { selinux_sys::security_deny_unknown() } {
            -1 => Err(Error::last_io_error("security_deny_unknown()")),

            0 => Ok(UndefinedHandling::Allowed),

            _ => Ok(UndefinedHandling::DeniedAtRunTime),
        }
    } else {
        Ok(UndefinedHandling::RejectedAtLoadTime)
    }
}

/// Determine the protection currently checked by SELinux on `mmap()` and
/// `mprotect()` calls.
///
/// See: `security_get_checkreqprot()`.
pub fn protection_checking_mode() -> Result<ProtectionCheckingMode> {
    match unsafe { selinux_sys::security_get_checkreqprot() } {
        -1 => Err(Error::last_io_error("security_get_checkreqprot()")),

        0 => Ok(ProtectionCheckingMode::CheckingActualProtection),

        _ => Ok(ProtectionCheckingMode::CheckingRequestedProtection),
    }
}

fn dynamic_mapping_into_native_form<'m, 'k, 'o, K, V, O>(
    mapping: &'m [(K, V)],
    c_string_storage: &mut HashMap<&'k str, CString>,
) -> Result<Vec<selinux_sys::security_class_mapping>>
where
    'm: 'k,
    'o: 'k,
    K: AsRef<str> + 'k,
    V: AsRef<[O]>,
    O: AsRef<str> + 'o,
{
    let mut c_map = Vec::with_capacity(mapping.len() + 1);

    for (name, permissions) in mapping {
        let mut element: selinux_sys::security_class_mapping = unsafe { mem::zeroed() };

        if permissions.as_ref().len() >= element.perms.len() {
            let err = io::ErrorKind::InvalidInput.into();
            return Err(Error::from_io("SELinux::set_dynamic_mapping()", err));
        }

        element.name = match c_string_storage.entry(name.as_ref()) {
            hash_map::Entry::Vacant(e) => {
                let c_name = str_to_c_string(name.as_ref())?;
                e.insert(c_name).as_ptr()
            }

            hash_map::Entry::Occupied(e) => e.get().as_ptr(),
        };

        for (index, permission) in permissions.as_ref().iter().enumerate() {
            element.perms[index] = match c_string_storage.entry(permission.as_ref()) {
                hash_map::Entry::Vacant(e) => {
                    let c_permission = str_to_c_string(permission.as_ref())?;
                    e.insert(c_permission).as_ptr()
                }

                hash_map::Entry::Occupied(e) => e.get().as_ptr(),
            };
        }

        c_map.push(element);
    }
    c_map.push(unsafe { mem::zeroed() }); // End of the array.
    Ok(c_map)
}

/// Establishes a mapping from a user-provided ordering of object classes
/// and permissions to the numbers actually used by the loaded system policy.
///
/// See: `selinux_set_mapping()`.
pub fn set_dynamic_mapping<K, V, O>(mapping: &[(K, V)]) -> Result<()>
where
    K: AsRef<str>,
    V: AsRef<[O]>,
    O: AsRef<str>,
{
    // The `selinux_set_mapping()` parameter holds pointers to null-terminated strings.
    //
    // We transform the input `mapping` into an array of `security_class_mapping`
    // by transforming `&str` instances into CString instances and storing
    // them into `c_string_storage`. Pointers to these `CString`s are then stored
    // into the `security_class_mapping` structures.
    let mut c_string_storage = HashMap::<&str, CString>::with_capacity(mapping.len() * 3);
    let mut c_map = dynamic_mapping_into_native_form(mapping, &mut c_string_storage)?;

    let r = unsafe { selinux_sys::selinux_set_mapping(c_map.as_mut_ptr()) };
    ret_val_to_result("selinux_set_mapping()", r)
}

/// Flush the SELinux class cache, e.g., upon a policy reload.
///
/// See: `selinux_flush_class_cache()`.
pub fn flush_class_cache() -> Result<()> {
    Error::clear_errno();
    unsafe { (OptionalNativeFunctions::get().selinux_flush_class_cache)() }

    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        None | Some(0) => Ok(()),
        _ => Err(Error::from_io("selinux_flush_class_cache()", err)),
    }
}

/// Get the SELinux user name and level for a given Linux user name.
///
/// See: `getseuser()`, `getseuserbyname()`.
pub fn se_user_and_level(
    user_name: &str,
    service: Option<&str>,
) -> Result<(CAllocatedBlock<c_char>, CAllocatedBlock<c_char>)> {
    let c_user_name = str_to_c_string(user_name)?;
    let c_service = if let Some(service) = service {
        Some(str_to_c_string(service)?)
    } else {
        None
    };

    let mut se_user_ptr: *mut c_char = ptr::null_mut();
    let mut level_ptr: *mut c_char = ptr::null_mut();

    let (r, proc_name) = if let Some(c_service) = c_service {
        let r = unsafe {
            selinux_sys::getseuser(
                c_user_name.as_ptr(),
                c_service.as_ptr(),
                &mut se_user_ptr,
                &mut level_ptr,
            )
        };

        (r, "getseuser()")
    } else {
        let r = unsafe {
            selinux_sys::getseuserbyname(c_user_name.as_ptr(), &mut se_user_ptr, &mut level_ptr)
        };

        (r, "getseuserbyname()")
    };

    if r == -1 {
        Err(Error::last_io_error(proc_name))
    } else if se_user_ptr.is_null() || level_ptr.is_null() {
        Err(Error::from_io(proc_name, io::ErrorKind::InvalidData.into()))
    } else {
        let se_user = CAllocatedBlock::new(se_user_ptr)
            .ok_or_else(|| Error::from_io(proc_name, io::ErrorKind::InvalidInput.into()))?;

        let level = CAllocatedBlock::new(level_ptr)
            .ok_or_else(|| Error::from_io(proc_name, io::ErrorKind::InvalidInput.into()))?;

        Ok((se_user, level))
    }
}

/// Force a reset of the loaded configuration.
///
/// See: `selinux_reset_config()`.
pub fn reset_config() {
    unsafe { selinux_sys::selinux_reset_config() }
}

/// Get the default type (domain) for role, and set type to refer to it.
///
/// See: `get_default_type()`.
pub fn default_type_for_role(role: &str) -> Result<CAllocatedBlock<c_char>> {
    let mut c_type: *mut c_char = ptr::null_mut();
    let c_role = str_to_c_string(role)?;
    if unsafe { selinux_sys::get_default_type(c_role.as_ptr(), &mut c_type) } == -1 {
        Err(Error::last_io_error("get_default_type()"))
    } else {
        CAllocatedBlock::new(c_type)
            .ok_or_else(|| Error::from_io("get_default_type()", io::ErrorKind::InvalidData.into()))
    }
}
