#[cfg(test)]
mod tests;

use std::convert::TryFrom;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::sync::Once;
use std::{io, ptr};

use reference_counted_singleton::{RCSRef, RefCountedSingleton};

use crate::errors::{Error, Result};
use crate::utils::{ret_val_to_result, str_to_c_string};
use crate::SecurityContext;

/// Access vector cache.
#[derive(Debug, PartialEq, Eq)]
pub struct AccessVectorCache(Vec<selinux_sys::selinux_opt>);

static AVC_INIT: Once = Once::new();
static mut AVC: MaybeUninit<RefCountedSingleton<AccessVectorCache>> = MaybeUninit::uninit();

fn get_or_init_access_vector_cache() -> &'static RefCountedSingleton<AccessVectorCache> {
    AVC_INIT.call_once(|| unsafe {
        AVC = MaybeUninit::new(RefCountedSingleton::default());
    });

    unsafe {
        AVC.as_ptr()
            .as_ref()
            .expect("Static must have a valid address")
    }
}

impl AccessVectorCache {
    /// Initialize the user space access vector cache.
    ///
    /// The `options` parameter produces zero or more `(type, value)` tuples, where:
    /// - `type` is one of `selinux_sys::AVC_OPT_*` values,
    ///    e.g., [`selinux_sys::AVC_OPT_SETENFORCE`].
    /// - `value` is a pointer whose semantics are specific to `type`.
    ///
    /// Attempting to initialize the access vector cache while it is still
    /// initialized succeeds only if the subsequent initialization uses the same
    /// set of options as the previous, still in scope, one.
    ///
    /// See: `avc_open()`.
    #[doc(alias = "avc_open")]
    pub fn initialize(options: &[(c_int, *const c_void)]) -> Result<RCSRef<Self>> {
        let mut options: Vec<selinux_sys::selinux_opt> = options
            .iter()
            .map(|&(type_, value)| selinux_sys::selinux_opt {
                type_,
                value: value.cast(),
            })
            .collect();
        options.sort_unstable();
        options.dedup();

        let count = c_uint::try_from(options.len())?;
        let options_ptr = if count == 0 {
            ptr::null_mut()
        } else {
            options.as_mut_ptr()
        };

        let mut newly_initialized = false;
        let avc = get_or_init_access_vector_cache();

        let result = avc.get_or_init(|| {
            if unsafe { selinux_sys::avc_open(options_ptr, count) } == -1_i32 {
                Err(Error::last_io_error("avc_open()"))
            } else {
                newly_initialized = true;
                Ok(AccessVectorCache(options.clone())) // First initialization succeeded.
            }
        });

        match result {
            Ok(value) => {
                if newly_initialized || value.0 == options {
                    // Either:
                    // 1. First initialization succeeded, or
                    // 2. Initializing, while still initialized, using the same
                    //    set of options.
                    Ok(value)
                } else {
                    // Initializing, while still initialized, with a different
                    // set of options, is an error.
                    let err = io::ErrorKind::AlreadyExists.into();
                    Err(Error::from_io("AccessVectorCache::initialize()", err))
                }
            }

            Err(None) => Err(Error::LockPoisoned {
                operation: "RefCountedSingleton::get_or_init()",
            }),

            Err(Some(err)) => Err(err),
        }
    }

    /// Flush the user space access vector cache, causing it to forget any
    /// cached access decisions.
    ///
    /// See: `avc_reset()`.
    #[doc(alias = "avc_reset")]
    pub fn reset(&self) -> Result<()> {
        ret_val_to_result("avc_reset()", unsafe { selinux_sys::avc_reset() })
    }

    /// Attempt to free unused memory within the user space access vector
    /// cache, but do not flush any cached access decisions.
    ///
    /// See: `avc_cleanup()`.
    #[doc(alias = "avc_cleanup")]
    pub fn clean_up(&self) {
        unsafe { selinux_sys::avc_cleanup() }
    }

    /// Return a security identifier for the kernel initial security identifier
    /// specified by `security_identifier_name`.
    ///
    /// See: `avc_get_initial_sid()`.
    #[doc(alias = "avc_get_initial_sid")]
    pub fn kernel_initial_security_id<'context>(
        &'context self,
        security_id_name: &str,
        raw_format: bool,
    ) -> Result<SecurityID<'context>> {
        let c_name = str_to_c_string(security_id_name)?;
        let mut security_id: *mut selinux_sys::security_id = ptr::null_mut();
        if unsafe { selinux_sys::avc_get_initial_sid(c_name.as_ptr(), &mut security_id) } == -1_i32
        {
            Err(Error::last_io_error("avc_get_initial_sid()"))
        } else {
            Ok(SecurityID {
                security_id,
                is_raw: raw_format,
                _phantom_data: PhantomData,
            })
        }
    }

    /// Return a security context for the given security identifier.
    ///
    /// See: `avc_sid_to_context()`.
    #[doc(alias = "avc_sid_to_context")]
    pub fn security_context_from_security_id<'context>(
        &'context self,
        mut security_id: SecurityID,
    ) -> Result<SecurityContext<'context>> {
        let is_raw = security_id.is_raw_format();
        let (proc, proc_name): (unsafe extern "C" fn(_, _) -> _, _) = if is_raw {
            let proc_name = "avc_sid_to_context_raw()";
            (selinux_sys::avc_sid_to_context_raw, proc_name)
        } else {
            let proc_name = "avc_sid_to_context()";
            (selinux_sys::avc_sid_to_context, proc_name)
        };

        let mut context: *mut c_char = ptr::null_mut();
        let r = unsafe { proc(security_id.as_mut_ptr(), &mut context) };
        SecurityContext::from_result(proc_name, r, context, is_raw)
    }

    /// Return a security identifier for the given security context.
    ///
    /// See: `avc_context_to_sid()`.
    #[doc(alias = "avc_context_to_sid")]
    pub fn security_id_from_security_context<'context>(
        &'context self,
        context: SecurityContext,
    ) -> Result<SecurityID<'context>> {
        let is_raw = context.is_raw_format();
        let (proc, proc_name): (unsafe extern "C" fn(_, _) -> _, _) = if is_raw {
            let proc_name = "avc_context_to_sid_raw()";
            (selinux_sys::avc_context_to_sid_raw, proc_name)
        } else {
            let proc_name = "avc_context_to_sid()";
            (selinux_sys::avc_context_to_sid, proc_name)
        };

        let mut security_id: *mut selinux_sys::security_id = ptr::null_mut();
        if unsafe { proc(context.as_ptr(), &mut security_id) } == -1_i32 {
            Err(Error::last_io_error(proc_name))
        } else {
            Ok(SecurityID {
                security_id,
                is_raw,
                _phantom_data: PhantomData,
            })
        }
    }
}

impl Drop for AccessVectorCache {
    fn drop(&mut self) {
        unsafe { selinux_sys::avc_destroy() };
    }
}

/// SELinux security identifier.
#[derive(Debug)]
pub struct SecurityID<'id> {
    security_id: *mut selinux_sys::security_id,
    is_raw: bool,
    _phantom_data: PhantomData<&'id selinux_sys::security_id>,
}

impl<'id> SecurityID<'id> {
    /// Return `true` if the security identifier is unspecified.
    #[must_use]
    pub fn is_unspecified(&self) -> bool {
        self.security_id.is_null()
    }

    /// Return `false` if security context translation must be performed.
    #[must_use]
    pub fn is_raw_format(&self) -> bool {
        self.is_raw
    }

    /// Return the managed raw pointer to [`selinux_sys::security_id`].
    #[must_use]
    pub fn as_ptr(&self) -> *const selinux_sys::security_id {
        self.security_id.cast()
    }

    /// Return the managed raw pointer to [`selinux_sys::security_id`].
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut selinux_sys::security_id {
        self.security_id
    }
}

impl<'id> Default for SecurityID<'id> {
    /// Return an unspecified security identifier.
    fn default() -> Self {
        Self {
            security_id: ptr::null_mut(),
            is_raw: false,
            _phantom_data: PhantomData,
        }
    }
}
