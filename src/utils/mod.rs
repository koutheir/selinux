#[cfg(test)]
mod tests;

use std::ffi::{CStr, CString, OsStr};
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::{io, mem, ptr};

use once_cell::sync::OnceCell;

use crate::errors::{Error, Result};

pub(crate) fn str_to_c_string(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_r| Error::IO1Name {
        operation: "CString::new",
        name: s.into(),
        source: io::ErrorKind::InvalidInput.into(),
    })
}

#[cfg(unix)]
pub(crate) fn os_str_to_c_string(s: &OsStr) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;

    CString::new(s.as_bytes()).map_err(|_r| Error::PathIsInvalid(PathBuf::from(s)))
}

pub(crate) fn c_str_ptr_to_str<'a>(s: *const c_char) -> Result<&'a str> {
    if s.is_null() {
        let err = io::ErrorKind::InvalidInput.into();
        Err(Error::from_io("utils::c_str_ptr_to_string()", err))
    } else {
        unsafe { CStr::from_ptr(s) }.to_str().map_err(Into::into)
    }
}

#[cfg(unix)]
pub(crate) fn c_str_ptr_to_path<'a>(path_ptr: *const c_char) -> &'a Path {
    use std::os::unix::ffi::OsStrExt;

    let c_path = unsafe { CStr::from_ptr(path_ptr) };
    Path::new(OsStr::from_bytes(c_path.to_bytes()))
}

pub(crate) fn c_str_to_non_null_ptr(s: &CStr) -> ptr::NonNull<c_char> {
    unsafe { ptr::NonNull::new_unchecked(s.as_ptr() as *mut c_char) }
}

pub(crate) fn get_static_path(
    proc: unsafe extern "C" fn() -> *const c_char,
    proc_name: &'static str,
) -> Result<&'static Path> {
    let path_ptr = unsafe { proc() };
    if path_ptr.is_null() {
        Err(Error::from_io(proc_name, io::ErrorKind::InvalidData.into()))
    } else {
        Ok(c_str_ptr_to_path(path_ptr))
    }
}

pub(crate) fn ret_val_to_result(proc_name: &'static str, result: c_int) -> Result<()> {
    if result == -1 {
        Err(Error::last_io_error(proc_name))
    } else {
        Ok(())
    }
}

pub(crate) fn ret_val_to_result_with_path(
    proc_name: &'static str,
    result: c_int,
    path: &Path,
) -> Result<()> {
    if result == -1 {
        let err = io::Error::last_os_error();
        Err(Error::from_io_path(proc_name, path, err))
    } else {
        Ok(())
    }
}

/// An owned block of memory, allocated with [`libc::malloc`].
#[derive(Debug)]
pub struct CAllocatedBlock<T> {
    pub(crate) pointer: ptr::NonNull<T>,
    _phantom_data: PhantomData<T>,
}

impl<T> CAllocatedBlock<T> {
    pub(crate) fn new(pointer: *mut T) -> Option<Self> {
        ptr::NonNull::new(pointer).map(|pointer| Self {
            pointer,
            _phantom_data: PhantomData,
        })
    }

    /// Return the managed raw pointer.
    #[must_use]
    pub fn as_ptr(&self) -> *const T {
        self.pointer.as_ptr()
    }

    /// Return the managed raw pointer.
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.pointer.as_ptr()
    }
}

impl CAllocatedBlock<c_char> {
    /// Return the managed null-terminated C string.
    #[must_use]
    pub fn as_c_str(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.pointer.as_ptr()) }
    }
}

impl<T> Drop for CAllocatedBlock<T> {
    fn drop(&mut self) {
        let pointer = self.pointer.as_ptr();
        self.pointer = ptr::NonNull::dangling();
        unsafe { libc::free(pointer.cast()) };
    }
}

/// Holds addresses of optionally-implemented functions by libselinux.
#[derive(Debug)]
pub(crate) struct OptionalNativeFunctions {
    /// Since version 2.9
    pub(crate) security_reject_unknown: unsafe extern "C" fn() -> c_int,

    /// Since version 3.0
    pub(crate) selabel_get_digests_all_partial_matches: unsafe extern "C" fn(
        rec: *mut selinux_sys::selabel_handle,
        key: *const c_char,
        calculated_digest: *mut *mut u8,
        xattr_digest: *mut *mut u8,
        digest_len: *mut usize,
    ) -> bool,

    /// Since version 3.0
    pub(crate) selabel_hash_all_partial_matches: unsafe extern "C" fn(
        rec: *mut selinux_sys::selabel_handle,
        key: *const c_char,
        digest: *mut u8,
    ) -> bool,

    /// Since version 3.0
    pub(crate) security_validatetrans: unsafe extern "C" fn(
        scon: *const c_char,
        tcon: *const c_char,
        tclass: selinux_sys::security_class_t,
        newcon: *const c_char,
    ) -> c_int,

    /// Since version 3.0
    pub(crate) security_validatetrans_raw: unsafe extern "C" fn(
        scon: *const c_char,
        tcon: *const c_char,
        tclass: selinux_sys::security_class_t,
        newcon: *const c_char,
    ) -> c_int,

    /// Since version 3.1
    pub(crate) selinux_flush_class_cache: unsafe extern "C" fn(),
}

/// Addresses of optionally-implemented functions by libselinux.
pub(crate) static OPT_NATIVE_FN: OnceCell<OptionalNativeFunctions> = OnceCell::new();

impl Default for OptionalNativeFunctions {
    fn default() -> Self {
        Self {
            security_reject_unknown: Self::not_impl_security_reject_unknown,
            selabel_get_digests_all_partial_matches:
                Self::not_impl_selabel_get_digests_all_partial_matches,
            selabel_hash_all_partial_matches: Self::not_impl_selabel_hash_all_partial_matches,
            security_validatetrans: Self::not_impl_security_validatetrans,
            security_validatetrans_raw: Self::not_impl_security_validatetrans,
            selinux_flush_class_cache: Self::not_impl_selinux_flush_class_cache,
        }
    }
}

impl OptionalNativeFunctions {
    pub(crate) fn get() -> &'static Self {
        OPT_NATIVE_FN.get_or_init(Self::initialize)
    }

    fn initialize() -> Self {
        let mut r = Self::default();
        let lib_handle = Self::get_libselinux_handle();
        if !lib_handle.is_null() {
            r.load_functions_addresses(lib_handle)
        }
        Error::clear_errno();
        r
    }

    fn get_libselinux_handle() -> *mut c_void {
        // Ensure libselinux is loaded.
        unsafe { selinux_sys::is_selinux_enabled() };

        // Get a handle to the already-loaded libselinux.
        let flags = libc::RTLD_NOW | libc::RTLD_GLOBAL | libc::RTLD_NOLOAD | libc::RTLD_NODELETE;
        for &lib_name in &[
            "libselinux.so.1\0",
            "libselinux.so\0",
            "libselinux\0",
            "selinux\0",
        ] {
            let lib_handle = unsafe { libc::dlopen(lib_name.as_ptr().cast(), flags) };
            if !lib_handle.is_null() {
                return lib_handle;
            }
        }
        ptr::null_mut()
    }

    fn load_functions_addresses(&mut self, lib_handle: *mut c_void) {
        let f = unsafe { libc::dlsym(lib_handle, "security_reject_unknown\0".as_ptr().cast()) };
        if !f.is_null() {
            self.security_reject_unknown = unsafe { mem::transmute(f) };
        }

        let c_name = "selabel_get_digests_all_partial_matches\0";
        let f = unsafe { libc::dlsym(lib_handle, c_name.as_ptr().cast()) };
        if !f.is_null() {
            self.selabel_get_digests_all_partial_matches = unsafe { mem::transmute(f) };
        }

        let c_name = "selabel_hash_all_partial_matches\0";
        let f = unsafe { libc::dlsym(lib_handle, c_name.as_ptr().cast()) };
        if !f.is_null() {
            self.selabel_hash_all_partial_matches = unsafe { mem::transmute(f) };
        }

        let f = unsafe { libc::dlsym(lib_handle, "security_validatetrans\0".as_ptr().cast()) };
        if !f.is_null() {
            self.security_validatetrans = unsafe { mem::transmute(f) };
        }

        let f = unsafe { libc::dlsym(lib_handle, "security_validatetrans_raw\0".as_ptr().cast()) };
        if !f.is_null() {
            self.security_validatetrans_raw = unsafe { mem::transmute(f) };
        }

        let f = unsafe { libc::dlsym(lib_handle, "selinux_flush_class_cache\0".as_ptr().cast()) };
        if !f.is_null() {
            self.selinux_flush_class_cache = unsafe { mem::transmute(f) };
        }
    }

    unsafe extern "C" fn not_impl_security_reject_unknown() -> c_int {
        Error::set_errno(libc::ENOSYS);
        -1
    }

    unsafe extern "C" fn not_impl_selabel_get_digests_all_partial_matches(
        _rec: *mut selinux_sys::selabel_handle,
        _key: *const c_char,
        _calculated_digest: *mut *mut u8,
        _xattr_digest: *mut *mut u8,
        _digest_len: *mut usize,
    ) -> bool {
        Error::set_errno(libc::ENOSYS);
        false
    }

    unsafe extern "C" fn not_impl_selabel_hash_all_partial_matches(
        _rec: *mut selinux_sys::selabel_handle,
        _key: *const c_char,
        _digest: *mut u8,
    ) -> bool {
        Error::set_errno(libc::ENOSYS);
        false
    }

    unsafe extern "C" fn not_impl_security_validatetrans(
        _scon: *const c_char,
        _tcon: *const c_char,
        _tclass: selinux_sys::security_class_t,
        _newcon: *const c_char,
    ) -> c_int {
        Error::set_errno(libc::ENOSYS);
        -1
    }

    unsafe extern "C" fn not_impl_selinux_flush_class_cache() {
        Error::set_errno(libc::ENOSYS);
    }
}
