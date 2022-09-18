#![cfg(all(test, target_os = "linux", not(target_env = "kernel")))]

use std::fmt;
use std::os::raw::{c_char, c_int, c_void};

fn template<T>(call_back: <T as super::CallBack>::CallBackType)
where
    T: super::CallBack + Default + fmt::Debug,
    <T as super::CallBack>::CallBackType: fmt::Debug + Eq + Copy + Sized,
{
    let _ignored = format!("{:?}", T::default());

    let old_call_back = T::get_call_back();

    T::set_call_back(None);
    assert!(T::get_call_back().is_none());

    let call_back: Option<<T as super::CallBack>::CallBackType> = Some(call_back);
    assert_ne!(old_call_back, call_back);

    T::set_call_back(call_back);
    assert_eq!(T::get_call_back(), call_back);

    T::set_call_back(old_call_back);
    assert_eq!(T::get_call_back(), old_call_back);
}

#[test]
fn log() {
    // For now, stable Rust does not allow defining variadic functions.
    template::<super::Log>(unsafe { *(libc::abort as *const _) });
}

#[test]
fn audit() {
    template::<super::Audit>(audit_call_back);
}

#[test]
fn context_validation() {
    template::<super::ContextValidation>(context_validation_call_back);
}

#[test]
fn enforcing_change() {
    template::<super::EnforcingChange>(enforcing_change_call_back);
}

#[test]
fn security_policy_reload() {
    template::<super::SecurityPolicyReload>(security_policy_reload_call_back);
}

// Dummy call back functions, of the correct prototypes.

unsafe extern "C" fn audit_call_back(
    _audit_data: *mut c_void,
    _security_class: selinux_sys::security_class_t,
    _message_buffer: *mut c_char,
    _message_buffer_size: usize,
) -> c_int {
    0_i32
}

unsafe extern "C" fn context_validation_call_back(_context_ptr: *mut *mut c_char) -> c_int {
    0_i32
}

unsafe extern "C" fn enforcing_change_call_back(_enforcing: c_int) -> c_int {
    0_i32
}

unsafe extern "C" fn security_policy_reload_call_back(_seqno: c_int) -> c_int {
    0_i32
}
