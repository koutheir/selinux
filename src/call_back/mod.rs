#[cfg(test)]
mod tests;

use std::os::raw::{c_char, c_int, c_void};

/// Call back for SELinux operations.
pub trait CallBack {
    /// Prototype of call back function.
    type CallBackType;

    /// Get the current call back function, if one has been set.
    ///
    /// See: `selinux_get_callback()`.
    #[doc(alias="selinux_get_callback")]
    fn get_call_back() -> Option<Self::CallBackType>;

    /// Set or clear the call back function.
    ///
    /// See: `selinux_set_callback()`.
    #[doc(alias="selinux_set_callback")]
    fn set_call_back(call_back: Option<Self::CallBackType>);
}

/// Call back used for logging.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Log;

impl CallBack for Log {
    type CallBackType = unsafe extern "C" fn(c_int, *const c_char, ...) -> c_int;

    fn get_call_back() -> Option<Self::CallBackType> {
        unsafe { selinux_sys::selinux_get_callback(selinux_sys::SELINUX_CB_LOG).func_log }
    }

    fn set_call_back(func_log: Option<Self::CallBackType>) {
        use selinux_sys::{selinux_callback, selinux_set_callback, SELINUX_CB_LOG};
        unsafe { selinux_set_callback(SELINUX_CB_LOG, selinux_callback { func_log }) }
    }
}

/// Call back used for supplemental auditing in AVC messages.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Audit;

impl CallBack for Audit {
    type CallBackType = unsafe extern "C" fn(
        *mut c_void,
        selinux_sys::security_class_t,
        *mut c_char,
        usize,
    ) -> c_int;

    fn get_call_back() -> Option<Self::CallBackType> {
        unsafe { selinux_sys::selinux_get_callback(selinux_sys::SELINUX_CB_AUDIT).func_audit }
    }

    fn set_call_back(func_audit: Option<Self::CallBackType>) {
        use selinux_sys::{selinux_callback, selinux_set_callback, SELINUX_CB_AUDIT};
        unsafe { selinux_set_callback(SELINUX_CB_AUDIT, selinux_callback { func_audit }) }
    }
}

/// Call back used for context validation.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ContextValidation;

impl CallBack for ContextValidation {
    type CallBackType = unsafe extern "C" fn(*mut *mut c_char) -> c_int;

    fn get_call_back() -> Option<Self::CallBackType> {
        unsafe { selinux_sys::selinux_get_callback(selinux_sys::SELINUX_CB_VALIDATE).func_validate }
    }

    fn set_call_back(func_validate: Option<Self::CallBackType>) {
        use selinux_sys::{selinux_callback, selinux_set_callback, SELINUX_CB_VALIDATE};
        unsafe { selinux_set_callback(SELINUX_CB_VALIDATE, selinux_callback { func_validate }) }
    }
}

/// Call back invoked when the system enforcing state changes.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct EnforcingChange;

impl CallBack for EnforcingChange {
    type CallBackType = unsafe extern "C" fn(c_int) -> c_int;

    fn get_call_back() -> Option<Self::CallBackType> {
        use selinux_sys::{selinux_get_callback, SELINUX_CB_SETENFORCE};
        unsafe { selinux_get_callback(SELINUX_CB_SETENFORCE).func_setenforce }
    }

    fn set_call_back(func_setenforce: Option<Self::CallBackType>) {
        use selinux_sys::{selinux_callback, selinux_set_callback, SELINUX_CB_SETENFORCE};
        unsafe { selinux_set_callback(SELINUX_CB_SETENFORCE, selinux_callback { func_setenforce }) }
    }
}

/// Call back invoked when the system security policy is reloaded.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct SecurityPolicyReload;

impl CallBack for SecurityPolicyReload {
    type CallBackType = unsafe extern "C" fn(c_int) -> c_int;

    fn get_call_back() -> Option<Self::CallBackType> {
        use selinux_sys::{selinux_get_callback, SELINUX_CB_POLICYLOAD};
        unsafe { selinux_get_callback(SELINUX_CB_POLICYLOAD).func_policyload }
    }

    fn set_call_back(func_policyload: Option<Self::CallBackType>) {
        use selinux_sys::{selinux_callback, selinux_set_callback, SELINUX_CB_POLICYLOAD};
        unsafe { selinux_set_callback(SELINUX_CB_POLICYLOAD, selinux_callback { func_policyload }) }
    }
}

/// Log type argument indicating the type of message.
pub mod log_type {
    use std::os::raw::c_int;

    /// AVC log entry.
    pub use selinux_sys::SELINUX_AVC as AVC;

    /// Error log entry.
    pub use selinux_sys::SELINUX_ERROR as ERROR;

    /// Informational log entry.
    pub use selinux_sys::SELINUX_INFO as INFO;

    /// Policy loaded.
    pub static POLICY_LOAD: c_int = 4;

    /// SELinux enforcing mode changed.
    pub static SET_ENFORCE: c_int = 5;

    /// Warning log entry.
    pub use selinux_sys::SELINUX_WARNING as WARNING;
}
