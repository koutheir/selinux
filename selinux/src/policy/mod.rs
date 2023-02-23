#[cfg(test)]
mod tests;

use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::path::Path;
use std::{io, ptr};

use crate::errors::{Error, Result};
use crate::utils::*;

/// Load a new SELinux policy.
///
/// See: `security_load_policy()`.
#[doc(alias = "security_load_policy")]
pub fn load(policy_bytes: &[u8]) -> Result<()> {
    // security_load_policy() declares "data" as a constant pointer starting from libselinux
    // version 3.5.
    // Previous supported versions have the same security_load_policy() implementation, but declare
    // "data" as a mutable pointer, even though it is never modified.
    let data = policy_bytes.as_ptr() as *mut c_void;
    let r = unsafe { selinux_sys::security_load_policy(data.cast(), policy_bytes.len()) };
    ret_val_to_result("security_load_policy()", r)
}

/// Make a policy image and load it.
///
/// See: `selinux_mkload_policy()`.
#[doc(alias = "selinux_mkload_policy")]
pub fn make_and_load() -> Result<()> {
    let r = unsafe { selinux_sys::selinux_mkload_policy(0) };
    ret_val_to_result("selinux_mkload_policy()", r)
}

/// Perform the initial policy load.
///
/// See: `selinux_init_load_policy()`.
#[doc(alias = "selinux_init_load_policy")]
pub fn load_initial() -> Result<c_int> {
    let mut enforce: c_int = 0;
    if unsafe { selinux_sys::selinux_init_load_policy(&mut enforce) } == -1_i32 {
        Err(Error::last_io_error("selinux_init_load_policy()"))
    } else {
        Ok(enforce)
    }
}

/// Get the type of SELinux policy running on the system.
///
/// See: `selinux_getpolicytype()`.
#[doc(alias = "selinux_getpolicytype")]
pub fn policy_type() -> Result<CAllocatedBlock<c_char>> {
    let mut name_ptr: *mut c_char = ptr::null_mut();
    if unsafe { selinux_sys::selinux_getpolicytype(&mut name_ptr) } == -1_i32 {
        Err(Error::last_io_error("selinux_getpolicytype()"))
    } else {
        CAllocatedBlock::new(name_ptr).ok_or_else(|| {
            Error::from_io("selinux_getpolicytype()", io::ErrorKind::InvalidData.into())
        })
    }
}

/// Get the version of the SELinux policy.
///
/// See: `security_policyvers()`.
#[doc(alias = "security_policyvers")]
pub fn version_number() -> Result<c_uint> {
    let r: c_int = unsafe { selinux_sys::security_policyvers() };
    if r == -1_i32 {
        Err(Error::last_io_error("security_policyvers()"))
    } else {
        Ok(r as c_uint)
    }
}

/// Return the path of the SELinux policy files for this machine.
///
/// See: `selinux_policy_root()`.
#[doc(alias = "selinux_policy_root")]
pub fn root_path() -> Result<&'static Path> {
    get_static_path(selinux_sys::selinux_policy_root, "selinux_policy_root()")
}

/// Set an alternate SELinux root path for the SELinux policy files for this machine.
///
/// See: `selinux_set_policy_root()`.
#[doc(alias = "selinux_set_policy_root")]
pub fn set_root_path(path: impl AsRef<Path>) -> Result<()> {
    let c_path = os_str_to_c_string(path.as_ref().as_os_str())?;
    let r = unsafe { selinux_sys::selinux_set_policy_root(c_path.as_ptr()) };
    ret_val_to_result_with_path("selinux_set_policy_root()", r, path.as_ref())
}

/// Return the currently loaded policy file from the kernel.
///
/// See: `selinux_current_policy_path()`.
#[doc(alias = "selinux_current_policy_path")]
pub fn current_policy_path() -> Result<&'static Path> {
    let proc_name = "selinux_current_policy_path()";
    get_static_path(selinux_sys::selinux_current_policy_path, proc_name)
}

/// Return the binary policy file loaded into kernel.
///
/// See: `selinux_binary_policy_path()`.
#[doc(alias = "selinux_binary_policy_path")]
pub fn binary_policy_path() -> Result<&'static Path> {
    let proc_name = "selinux_binary_policy_path()";
    get_static_path(selinux_sys::selinux_binary_policy_path, proc_name)
}
