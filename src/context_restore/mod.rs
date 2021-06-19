#[cfg(test)]
mod tests;

use std::ffi::CStr;
use std::marker::PhantomData;
use std::os::raw::c_uint;
use std::path::Path;
use std::{iter, ptr};

use crate::errors::{Error, Result};
use crate::label::Labeler;
use crate::utils::*;

bitflags! {
    /// Flags controlling relabeling operations.
    pub struct RestoreFlags: c_uint {
        /// Force the checking of labels even if the stored SHA1 digest matches
        /// the specfile entries SHA1 digest.
        ///
        /// The specfile entries digest will be written to the `security.sehash`
        /// extended attribute once relabeling has been completed successfully
        /// provided the [`NO_CHANGE`] flag has not been set.
        ///
        /// [`NO_CHANGE`]: Self::NO_CHANGE
        const IGNORE_DIGEST = selinux_sys::SELINUX_RESTORECON_IGNORE_DIGEST as c_uint;

        /// Don't change any file labels (passive check) or update the digest in
        /// the `security.sehash` extended attribute.
        const NO_CHANGE = selinux_sys::SELINUX_RESTORECON_NOCHANGE as c_uint;

        /// If set, reset the files label to match the default spec file context.
        /// If not set only reset the files "type" component of the context
        /// to match the default spec file context.
        const SET_SPEC_FILE_CTX =
            selinux_sys::SELINUX_RESTORECON_SET_SPECFILE_CTX as c_uint;

        /// Change file and directory labels recursively (descend directories)
        /// and if successful write an SHA1 digest of the spec file entries
        /// to an extended attribute.
        const RECURSE = selinux_sys::SELINUX_RESTORECON_RECURSE as c_uint;

        /// Log file label changes.
        ///
        /// Note that if [`VERBOSE`] and [`PROGRESS`] flags are set,
        /// then [`PROGRESS`] will take precedence.
        ///
        /// [`VERBOSE`]: Self::VERBOSE
        /// [`PROGRESS`]:  Self::PROGRESS
        const VERBOSE = selinux_sys::SELINUX_RESTORECON_VERBOSE as c_uint;

        /// Show progress by outputting the number of files in 1k blocks
        /// processed to stdout.
        ///
        /// If the [`MASS_RELABEL`] flag is also set then the approximate
        /// percentage complete will be shown.
        ///
        /// [`MASS_RELABEL`]: Self::MASS_RELABEL
        const PROGRESS = selinux_sys::SELINUX_RESTORECON_PROGRESS as c_uint;

        /// Convert passed-in path name to the canonical path name using
        /// `realpath()`.
        const REAL_PATH = selinux_sys::SELINUX_RESTORECON_REALPATH as c_uint;

        /// Prevent descending into directories that have a different device
        /// number than the path name entry from which the descent began.
        const XDEV = selinux_sys::SELINUX_RESTORECON_XDEV as c_uint;

        /// Attempt to add an association between an inode and a specification.
        /// If there is already an association for the inode and it conflicts
        /// with the specification, then use the last matching specification.
        const ADD_ASSOC = selinux_sys::SELINUX_RESTORECON_ADD_ASSOC as c_uint;

        /// Abort on errors during the file tree walk.
        const ABORT_ON_ERROR = selinux_sys::SELINUX_RESTORECON_ABORT_ON_ERROR as c_uint;

        /// Log any label changes to `syslog()`.
        const SYS_LOG_CHANGES = selinux_sys::SELINUX_RESTORECON_SYSLOG_CHANGES as c_uint;

        /// Log what spec file context matched each file.
        const LOG_MATCHES = selinux_sys::SELINUX_RESTORECON_LOG_MATCHES as c_uint;

        /// Ignore files that do not exist.
        const IGNORE_NO_ENTRY = selinux_sys::SELINUX_RESTORECON_IGNORE_NOENTRY as c_uint;

        /// Do not read `/proc/mounts` to obtain a list of non-seclabel mounts
        /// to be excluded from relabeling checks.
        ///
        /// Setting [`IGNORE_MOUNTS`] is useful where there is a non-seclabel fs
        /// mounted with a seclabel fs mounted on a directory below this.
        ///
        /// [`IGNORE_MOUNTS`]: Self::IGNORE_MOUNTS
        const IGNORE_MOUNTS = selinux_sys::SELINUX_RESTORECON_IGNORE_MOUNTS as c_uint;

        /// Generally set when relabeling the entire OS, that will then show
        /// the approximate percentage complete.
        ///
        /// The [`PROGRESS`] flag must also be set.
        ///
        /// [`PROGRESS`]: Self::PROGRESS
        const MASS_RELABEL = selinux_sys::SELINUX_RESTORECON_MASS_RELABEL as c_uint;

        /// Do not check or update any extended attribute security.sehash entries.
        ///
        /// This flag is supported only by `libselinux` version `3.0` or later.
        const SKIP_DIGEST = 0x08000;

        /// Treat conflicting specifications, such as where two hardlinks for
        /// the same inode have different contexts, as errors.
        ///
        /// This flag is supported only by `libselinux` version `3.1` or later.
        const CONFLICT_ERROR = 0x10000;
    }
}

bitflags! {
    /// Flags of [`ContextRestore::manage_security_sehash_xattr_entries`].
    pub struct XAttrFlags: c_uint {
        /// Recursively descend directories.
        const RECURSE = selinux_sys::SELINUX_RESTORECON_XATTR_RECURSE as c_uint;

        /// Delete non-matching digests from each directory in path name.
        const DELETE_NON_MATCH_DIGESTS = selinux_sys::SELINUX_RESTORECON_XATTR_DELETE_NONMATCH_DIGESTS as c_uint;

        /// Delete all digests from each directory in path name.
        const DELETE_ALL_DIGESTS = selinux_sys::SELINUX_RESTORECON_XATTR_DELETE_ALL_DIGESTS as c_uint;

        /// Don't read `/proc/mounts` to obtain a list of non-seclabel mounts
        /// to be excluded from the search.
        ///
        /// Setting [`IGNORE_MOUNTS`] is useful where there is a non-seclabel fs
        /// mounted with a seclabel fs mounted on a directory below this.
        ///
        /// [`IGNORE_MOUNTS`]: Self::IGNORE_MOUNTS
        const IGNORE_MOUNTS = selinux_sys::SELINUX_RESTORECON_XATTR_IGNORE_MOUNTS as c_uint;
    }
}

/// Restore file(s) default SELinux security contexts.
#[derive(Debug, Default)]
pub struct ContextRestore<'l, T: crate::label::back_end::BackEnd> {
    labeler: Option<&'l mut Labeler<T>>,
}

impl<'l, T> ContextRestore<'l, T>
where
    T: crate::label::back_end::BackEnd,
{
    /// Set a labeling handle for relabeling.
    ///
    /// See: `selinux_restorecon_set_sehandle()`.
    pub fn with_labeler(labeler: &'l mut Labeler<T>) -> Self {
        Self {
            labeler: Some(labeler),
        }
    }

    /// Get the labeling handle to be used for relabeling.
    #[must_use]
    pub fn labeler(&self) -> Option<&&'l mut Labeler<T>> {
        self.labeler.as_ref()
    }

    /// Set an alternate root path for relabeling.
    ///
    /// See: `selinux_restorecon_set_alt_rootpath()`.
    pub fn set_alternative_root_path(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let c_path = os_str_to_c_string(path.as_ref().as_os_str())?;
        let r = unsafe { selinux_sys::selinux_restorecon_set_alt_rootpath(c_path.as_ptr()) };
        ret_val_to_result("selinux_restorecon_set_alt_rootpath()", r)
    }

    /// Add to the list of directories to be excluded from relabeling.
    ///
    /// See: `selinux_restorecon_set_exclude_list()`.
    pub fn add_exclude_list<P>(
        &mut self,
        exclusion_patterns: impl IntoIterator<Item = P>,
    ) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let c_list_storage = exclusion_patterns
            .into_iter()
            .map(|p| os_str_to_c_string(p.as_ref().as_os_str()))
            .collect::<Result<Vec<_>>>()?;

        if !c_list_storage.is_empty() {
            let mut c_ptr_list: Vec<_> = c_list_storage
                .iter()
                .map(AsRef::as_ref)
                .map(CStr::as_ptr)
                .chain(iter::once(ptr::null()))
                .collect();

            unsafe { selinux_sys::selinux_restorecon_set_exclude_list(c_ptr_list.as_mut_ptr()) };
        }
        Ok(())
    }

    /// Restore file(s) default SELinux security contexts.
    ///
    /// See: `selinux_restorecon()`.
    pub fn restore_context_of_file_system_entry(
        self,
        path: impl AsRef<Path>,
        flags: RestoreFlags,
    ) -> Result<()> {
        if let Some(labeler) = self.labeler.map(Labeler::as_mut_ptr) {
            unsafe { selinux_sys::selinux_restorecon_set_sehandle(labeler) };
        }

        let c_path = os_str_to_c_string(path.as_ref().as_os_str())?;
        let r = unsafe { selinux_sys::selinux_restorecon(c_path.as_ptr(), flags.bits()) };
        ret_val_to_result("selinux_restorecon()", r)
    }

    /// Manage default `security.sehash` extended attribute entries added by
    /// `selinux_restorecon()`, `setfiles()` or `restorecon()`.
    ///
    /// See: `selinux_restorecon_xattr()`.
    pub fn manage_security_sehash_xattr_entries(
        dir_path: impl AsRef<Path>,
        flags: XAttrFlags,
    ) -> Result<DirectoryXAttributesIter> {
        let mut xattr_list_ptr: *mut *mut selinux_sys::dir_xattr = ptr::null_mut();
        let c_dir_path = os_str_to_c_string(dir_path.as_ref().as_os_str())?;
        let r = unsafe {
            selinux_sys::selinux_restorecon_xattr(
                c_dir_path.as_ptr(),
                flags.bits(),
                &mut xattr_list_ptr,
            )
        };

        if r == -1 {
            Err(Error::last_io_error("selinux_restorecon_xattr()"))
        } else {
            let xattr_list = ptr::NonNull::new(xattr_list_ptr).map_or(
                ptr::null_mut(),
                |mut xattr_list_ptr| unsafe {
                    let xattr_list = *xattr_list_ptr.as_ref();

                    // Detach the linked list from libselinux, so that we own it from now on.
                    *xattr_list_ptr.as_mut() = ptr::null_mut();

                    xattr_list
                },
            );

            Ok(DirectoryXAttributesIter(xattr_list))
        }
    }
}

/// Status of a [`DirectoryXAttributes`].
#[derive(Debug)]
#[non_exhaustive]
pub enum DirectoryDigestResult {
    /// Match.
    Match {
        /// Matching digest deleted from the directory.
        deleted: bool,
    },
    /// No match.
    NoMatch {
        /// Non-matching digest deleted from the directory.
        deleted: bool,
    },
    /// Error.
    Error,
    /// Unknown status.
    Unknown(c_uint),
}

/// Result of [`ContextRestore::manage_security_sehash_xattr_entries`].
#[derive(Debug)]
pub struct DirectoryXAttributes {
    pointer: ptr::NonNull<selinux_sys::dir_xattr>,
    _phantom_data: PhantomData<selinux_sys::dir_xattr>,
}

impl DirectoryXAttributes {
    /// Return the managed raw pointer to [`selinux_sys::dir_xattr`].
    #[must_use]
    pub fn as_ptr(&self) -> *const selinux_sys::dir_xattr {
        self.pointer.as_ptr()
    }

    /// Return the managed raw pointer to [`selinux_sys::dir_xattr`].
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut selinux_sys::dir_xattr {
        self.pointer.as_ptr()
    }

    /// Directory path.
    #[must_use]
    pub fn directory_path(&self) -> &Path {
        c_str_ptr_to_path(unsafe { self.pointer.as_ref().directory })
    }

    /// A hex encoded string that can be printed.
    pub fn digest(&self) -> Result<&str> {
        c_str_ptr_to_str(unsafe { self.pointer.as_ref().digest })
    }

    /// Status of this entry.
    #[must_use]
    pub fn digest_result(&self) -> DirectoryDigestResult {
        match unsafe { self.pointer.as_ref().result } {
            selinux_sys::digest_result::MATCH => DirectoryDigestResult::Match { deleted: false },

            selinux_sys::digest_result::NOMATCH => {
                DirectoryDigestResult::NoMatch { deleted: false }
            }

            selinux_sys::digest_result::DELETED_MATCH => {
                DirectoryDigestResult::Match { deleted: true }
            }

            selinux_sys::digest_result::DELETED_NOMATCH => {
                DirectoryDigestResult::NoMatch { deleted: true }
            }

            selinux_sys::digest_result::ERROR => DirectoryDigestResult::Error,

            value => DirectoryDigestResult::Unknown(value),
        }
    }
}

impl Drop for DirectoryXAttributes {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.pointer.as_ref().directory.cast());
            libc::free(self.pointer.as_ref().digest.cast());
            libc::free(self.pointer.as_ptr().cast());
        }
    }
}

/// Iterator producing [`DirectoryXAttributes`] elements.
#[derive(Debug)]
pub struct DirectoryXAttributesIter(*mut selinux_sys::dir_xattr);

impl Iterator for DirectoryXAttributesIter {
    type Item = DirectoryXAttributes;

    fn next(&mut self) -> Option<DirectoryXAttributes> {
        ptr::NonNull::new(self.0).map(|pointer| {
            self.0 = unsafe { pointer.as_ref().next };
            DirectoryXAttributes {
                pointer,
                _phantom_data: PhantomData,
            }
        })
    }
}
