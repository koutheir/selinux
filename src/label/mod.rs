#[cfg(test)]
mod tests;

use std::ffi::{CStr, CString};
use std::hash::Hash;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;
use std::{cmp, io, iter, ptr, slice};

use crate::errors::{Error, Result};
use crate::utils::*;
use crate::{FileAccessMode, SecurityContext};

/// Security contexts back-ends.
pub mod back_end;

use crate::label::back_end::BackEnd;

/// Labeling handle used for look up operations.
#[derive(Debug)]
pub struct Labeler<T: BackEnd> {
    pointer: ptr::NonNull<selinux_sys::selabel_handle>,
    _phantom_data1: PhantomData<selinux_sys::selabel_handle>,
    _phantom_data2: PhantomData<T>,
    is_raw: bool,
}

impl<T: BackEnd> Labeler<T> {
    /// Return `false` if security context translation must be performed.
    #[must_use]
    pub fn is_raw_format(&self) -> bool {
        self.is_raw
    }

    /// Return the managed raw pointer to [`selinux_sys::selabel_handle`].
    #[must_use]
    pub fn as_ptr(&self) -> *const selinux_sys::selabel_handle {
        self.pointer.as_ptr()
    }

    /// Return the managed raw pointer to [`selinux_sys::selabel_handle`].
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut selinux_sys::selabel_handle {
        self.pointer.as_ptr()
    }

    /// Initialize a labeling handle to be used for lookup operations.
    ///
    /// See: `selabel_open()`.
    #[doc(alias("selabel_open"))]
    pub fn new(options: &[(c_int, *const c_void)], raw_format: bool) -> Result<Self> {
        use std::convert::TryInto;

        let options: Vec<selinux_sys::selinux_opt> = options
            .iter()
            .map(|&(type_, value)| selinux_sys::selinux_opt {
                type_,
                value: value.cast(),
            })
            .collect();

        let count = options.len().try_into()?;
        let options_ptr = if count == 0 {
            ptr::null()
        } else {
            options.as_ptr()
        };

        let pointer = unsafe { selinux_sys::selabel_open(T::BACK_END, options_ptr, count) };
        ptr::NonNull::new(pointer)
            .map(|pointer| Self {
                pointer,
                _phantom_data1: PhantomData,
                _phantom_data2: PhantomData,
                is_raw: raw_format,
            })
            .ok_or_else(|| Error::last_io_error("selabel_open()"))
    }

    /// Obtain SELinux security context from a string label.
    ///
    /// See: `selabel_lookup()`.
    #[doc(alias("selabel_lookup"))]
    pub fn look_up(&self, key: &CStr, key_type: c_int) -> Result<SecurityContext> {
        let (proc, proc_name): (unsafe extern "C" fn(_, _, _, _) -> _, _) = if self.is_raw {
            (selinux_sys::selabel_lookup_raw, "selabel_lookup_raw()")
        } else {
            (selinux_sys::selabel_lookup, "selabel_lookup()")
        };

        let handle = self.pointer.as_ptr();
        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe { proc(handle, &mut context, key.as_ptr(), key_type) };
        SecurityContext::from_result(proc_name, r, context, self.is_raw)
    }

    /// Return digest of spec files and list of files used.
    ///
    /// See: `selabel_digest()`.
    #[doc(alias("selabel_digest"))]
    pub fn digest(&'_ self) -> Result<Digest<'_>> {
        let mut digest_ptr: *mut u8 = ptr::null_mut();
        let mut digest_size = 0;
        let mut spec_files_ptr: *mut *mut c_char = ptr::null_mut();
        let mut num_spec_files = 0;
        let r = unsafe {
            selinux_sys::selabel_digest(
                self.pointer.as_ptr(),
                &mut digest_ptr,
                &mut digest_size,
                &mut spec_files_ptr,
                &mut num_spec_files,
            )
        };

        if r == -1 {
            Err(Error::last_io_error("selabel_digest()"))
        } else {
            Ok(Digest::new(
                digest_ptr,
                digest_size,
                spec_files_ptr.cast(),
                num_spec_files,
            ))
        }
    }

    /// Print SELinux labeling statistics.
    ///
    /// See: `selabel_stats()`.
    #[doc(alias("selabel_stats"))]
    pub fn log_statistics(&self) {
        unsafe { selinux_sys::selabel_stats(self.pointer.as_ptr()) }
    }
}

impl<T: BackEnd> Drop for Labeler<T> {
    fn drop(&mut self) {
        let pointer = self.pointer.as_ptr();
        self.pointer = ptr::NonNull::dangling();
        unsafe { selinux_sys::selabel_close(pointer) };
    }
}

impl<T: BackEnd> PartialOrd<Labeler<T>> for Labeler<T> {
    /// Compare this instance to another one.
    ///
    /// See: `selabel_cmp()`.
    #[doc(alias("selabel_cmp"))]
    fn partial_cmp(&self, other: &Labeler<T>) -> Option<cmp::Ordering> {
        let r = unsafe { selinux_sys::selabel_cmp(self.pointer.as_ptr(), other.pointer.as_ptr()) };
        match r {
            selinux_sys::selabel_cmp_result::SELABEL_SUBSET => Some(cmp::Ordering::Less),
            selinux_sys::selabel_cmp_result::SELABEL_EQUAL => Some(cmp::Ordering::Equal),
            selinux_sys::selabel_cmp_result::SELABEL_SUPERSET => Some(cmp::Ordering::Greater),
            _ => None,
        }
    }
}

impl<T: BackEnd> PartialEq for Labeler<T> {
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other) == Some(cmp::Ordering::Equal)
    }
}

impl Labeler<back_end::File> {
    /// Return [`Labeler`] with default parameters for `selinux_restorecon()`.
    ///
    /// See: `selinux_restorecon_default_handle()`.
    #[doc(alias("selinux_restorecon_default_handle"))]
    pub fn restorecon_default(raw_format: bool) -> Result<Self> {
        let pointer = unsafe { selinux_sys::selinux_restorecon_default_handle() };
        ptr::NonNull::new(pointer)
            .map(|pointer| Self {
                pointer,
                _phantom_data1: PhantomData,
                _phantom_data2: PhantomData,
                is_raw: raw_format,
            })
            .ok_or_else(|| Error::last_io_error("selinux_restorecon_default_handle()"))
    }

    /// Obtain SELinux security context from a path.
    ///
    /// See: `selabel_lookup()`.
    #[doc(alias("selabel_lookup"))]
    pub fn look_up_by_path(
        &self,
        path: impl AsRef<Path>,
        mode: Option<FileAccessMode>,
    ) -> Result<SecurityContext> {
        let (proc, proc_name): (unsafe extern "C" fn(_, _, _, _) -> _, _) = if self.is_raw {
            (selinux_sys::selabel_lookup_raw, "selabel_lookup_raw()")
        } else {
            (selinux_sys::selabel_lookup, "selabel_lookup()")
        };

        let handle = self.pointer.as_ptr();
        let mut context: *mut c_char = ptr::null_mut();
        let c_path = os_str_to_c_string(path.as_ref().as_os_str())?;
        let mode = mode.map_or(0, FileAccessMode::mode) as c_int;
        let r = unsafe { proc(handle, &mut context, c_path.as_ptr(), mode) };
        SecurityContext::from_result(proc_name, r, context, self.is_raw)
    }

    /// Obtain a best match SELinux security context.
    ///
    /// See: `selabel_lookup_best_match()`.
    #[doc(alias("selabel_lookup_best_match"))]
    pub fn look_up_best_match_by_path(
        &self,
        path: impl AsRef<Path>,
        alias_paths: &[impl AsRef<Path>],
        mode: Option<FileAccessMode>,
    ) -> Result<SecurityContext> {
        let (proc, proc_name): (unsafe extern "C" fn(_, _, _, _, _) -> _, _) = if self.is_raw {
            let proc_name = "selabel_lookup_best_match_raw()";
            (selinux_sys::selabel_lookup_best_match_raw, proc_name)
        } else {
            let proc_name = "selabel_lookup_best_match()";
            (selinux_sys::selabel_lookup_best_match, proc_name)
        };

        let aliases_storage: Vec<CString>;
        let mut aliases: Vec<*const c_char>;

        let aliases_ptr = if alias_paths.is_empty() {
            ptr::null_mut()
        } else {
            aliases_storage = alias_paths
                .iter()
                .map(AsRef::as_ref)
                .map(Path::as_os_str)
                .map(os_str_to_c_string)
                .collect::<Result<Vec<CString>>>()?;

            aliases = aliases_storage
                .iter()
                .map(CString::as_c_str)
                .map(CStr::as_ptr)
                .chain(iter::once(ptr::null()))
                .collect();

            aliases.as_mut_ptr()
        };

        let mut context: *mut c_char = ptr::null_mut();
        let c_path = os_str_to_c_string(path.as_ref().as_os_str())?;
        let r = unsafe {
            proc(
                self.pointer.as_ptr(),
                &mut context,
                c_path.as_ptr(),
                aliases_ptr,
                mode.map_or(0, FileAccessMode::mode) as c_int,
            )
        };
        SecurityContext::from_result(proc_name, r, context, self.is_raw)
    }

    /// Determine whether a direct or partial match is possible on a file path.
    ///
    /// See: `selabel_partial_match()`.
    #[doc(alias("selabel_partial_match"))]
    pub fn partial_match_by_path(&self, path: impl AsRef<Path>) -> Result<bool> {
        let c_path = os_str_to_c_string(path.as_ref().as_os_str())?;
        Ok(unsafe { selinux_sys::selabel_partial_match(self.pointer.as_ptr(), c_path.as_ptr()) })
    }

    /// Retrieve the partial matches digest and the xattr digest that applies
    /// to the supplied path.
    ///
    /// See: `selabel_get_digests_all_partial_matches()`.
    #[doc(alias("selabel_get_digests_all_partial_matches"))]
    pub fn get_digests_all_partial_matches_by_path(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<PartialMatchesDigests> {
        let c_path = os_str_to_c_string(path.as_ref().as_os_str())?;
        let mut calculated_digest_ptr: *mut u8 = ptr::null_mut();
        let mut xattr_digest_ptr: *mut u8 = ptr::null_mut();
        let mut digest_size = 0;
        let r = unsafe {
            (OptionalNativeFunctions::get().selabel_get_digests_all_partial_matches)(
                self.pointer.as_ptr(),
                c_path.as_ptr(),
                &mut calculated_digest_ptr,
                &mut xattr_digest_ptr,
                &mut digest_size,
            )
        };

        let match_result = if r {
            PartialMatchesResult::Match
        } else {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                None | Some(0) => PartialMatchesResult::NoMatchOrMissing,

                _ => {
                    let proc_name = "selabel_get_digests_all_partial_matches()";
                    return Err(Error::from_io_path(proc_name, path.as_ref(), err));
                }
            }
        };

        Ok(PartialMatchesDigests {
            match_result,
            xattr_digest: CAllocatedBlock::new(xattr_digest_ptr),
            calculated_digest: CAllocatedBlock::new(calculated_digest_ptr),
            digest_size,
        })
    }
}

/// Digest of spec files and list of files used.
///
/// ⚠️ This instance does **NOT** own the `digest` or the `spec_files`.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Digest<'l> {
    digest: &'l [u8],
    spec_files: Vec<&'l Path>,
}

impl<'l> Digest<'l> {
    fn new(
        digest: *const u8,
        digest_size: usize,
        spec_files: *const *const c_char,
        num_spec_files: usize,
    ) -> Self {
        let digest = if digest.is_null() || digest_size == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(digest, digest_size) }
        };

        let spec_files = if spec_files.is_null() || num_spec_files == 0 {
            Vec::default()
        } else {
            unsafe { slice::from_raw_parts(spec_files, num_spec_files) }
                .iter()
                .take_while(|&&ptr| !ptr.is_null())
                .map(|&ptr| c_str_ptr_to_path(ptr))
                .collect()
        };

        Self { digest, spec_files }
    }

    /// Digest of spec files.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        self.digest
    }

    /// List of files used.
    #[must_use]
    pub fn spec_files(&self) -> &[&'l Path] {
        &self.spec_files
    }
}

/// Result of a partial match.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub enum PartialMatchesResult {
    /// Digest matches.
    Match,
    /// Either digest does not match, or both digests are missing.
    NoMatchOrMissing,
}

/// Result of [`Labeler::get_digests_all_partial_matches_by_path`].
#[derive(Debug)]
pub struct PartialMatchesDigests {
    match_result: PartialMatchesResult,
    xattr_digest: Option<CAllocatedBlock<u8>>,
    calculated_digest: Option<CAllocatedBlock<u8>>,
    digest_size: usize,
}

impl PartialMatchesDigests {
    /// Return match result.
    #[must_use]
    pub fn match_result(&self) -> PartialMatchesResult {
        self.match_result
    }

    /// Return xattr digest.
    #[must_use]
    pub fn xattr_digest(&self) -> Option<&[u8]> {
        self.xattr_digest
            .as_ref()
            .map(|block| unsafe { slice::from_raw_parts(block.pointer.as_ptr(), self.digest_size) })
    }

    /// Return calculated digest.
    #[must_use]
    pub fn calculated_digest(&self) -> Option<&[u8]> {
        self.calculated_digest
            .as_ref()
            .map(|block| unsafe { slice::from_raw_parts(block.pointer.as_ptr(), self.digest_size) })
    }

    /// Return digest length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.digest_size
    }

    /// Return `true` if digest is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.digest_size == 0
    }
}
