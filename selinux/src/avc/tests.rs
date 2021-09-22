#![cfg(all(test, target_os = "linux", not(target_env = "kernel")))]

use std::{io, ptr};

use assert_matches::assert_matches;
use serial_test::serial;

#[test]
fn security_id_default() {
    let mut sid = super::SecurityID::default();
    assert!(sid.is_unspecified());
    assert!(!sid.is_raw_format());
    assert!(sid.as_ptr().is_null());
    assert!(sid.as_mut_ptr().is_null());

    let _ignored = format!("{:?}", &sid);
}

#[serial]
#[test]
fn access_vector_cache_initialize() {
    match super::AccessVectorCache::initialize(&[]) {
        Ok(avc) => {
            let _ignored = format!("{:?}", avc);
        }

        Err(err) => {
            assert_matches!(err, crate::errors::Error::IO { .. });
            if let crate::errors::Error::IO { source, .. } = err {
                assert_eq!(source.kind(), io::ErrorKind::NotFound);
            }
        }
    }

    let options = &[(selinux_sys::AVC_OPT_SETENFORCE, ptr::null())];

    match super::AccessVectorCache::initialize(options) {
        Ok(avc) => {
            let _ignored = format!("{:?}", avc);
        }

        Err(err) => {
            assert_matches!(err, crate::errors::Error::IO { .. });
            if let crate::errors::Error::IO { source, .. } = err {
                assert_eq!(source.kind(), io::ErrorKind::NotFound);
            }
        }
    }

    if let Ok(avc0) = super::AccessVectorCache::initialize(options) {
        if let Ok(avc1) = super::AccessVectorCache::initialize(options) {
            if let Ok(avc2) = super::AccessVectorCache::initialize(&[(
                selinux_sys::AVC_OPT_SETENFORCE,
                ptr::null(),
            )]) {
                assert_eq!(avc0, avc1);
                assert_eq!(avc0, avc2);

                super::AccessVectorCache::initialize(&[]).unwrap_err();
            }
        }
    }
}

#[serial]
#[test]
fn access_vector_cache_reset() {
    let options = &[(selinux_sys::AVC_OPT_SETENFORCE, ptr::null())];
    let avc = super::AccessVectorCache::initialize(options).unwrap();
    avc.reset().unwrap();
}

#[serial]
#[test]
fn access_vector_cache_clean_up() {
    let options = &[(selinux_sys::AVC_OPT_SETENFORCE, ptr::null())];
    let avc = super::AccessVectorCache::initialize(options).unwrap();
    avc.clean_up();
}

#[serial]
#[test]
fn access_vector_cache_kernel_initial_security_id() {
    let options = &[(selinux_sys::AVC_OPT_SETENFORCE, ptr::null())];
    let avc = super::AccessVectorCache::initialize(options).unwrap();
    match avc.kernel_initial_security_id("unlabeled", false) {
        Ok(mut sid) => {
            assert_eq!(sid.as_ptr(), sid.as_mut_ptr());
            assert!(!sid.is_raw_format());
            assert!(!sid.is_unspecified());

            let mut context = avc.security_context_from_security_id(sid).unwrap();
            assert!(!context.is_raw_format());
            assert_eq!(context.as_ptr(), context.as_mut_ptr());
            assert!(!context.as_bytes().is_empty());

            let _ignored = avc.security_id_from_security_context(context).unwrap();
        }

        Err(err) => {
            assert_matches!(err, crate::errors::Error::IO { .. });
            if let crate::errors::Error::IO { source, .. } = err {
                assert_eq!(source.kind(), io::ErrorKind::NotFound);
            }
        }
    }

    match avc.kernel_initial_security_id("unlabeled", true) {
        Ok(mut sid) => {
            assert_eq!(sid.as_ptr(), sid.as_mut_ptr());
            assert!(sid.is_raw_format());
            assert!(!sid.is_unspecified());

            let mut context = avc.security_context_from_security_id(sid).unwrap();
            assert!(context.is_raw_format());
            assert_eq!(context.as_ptr(), context.as_mut_ptr());
            assert!(!context.as_bytes().is_empty());

            let _ignored = avc.security_id_from_security_context(context).unwrap();
        }

        Err(err) => {
            assert_matches!(err, crate::errors::Error::IO { .. });
            if let crate::errors::Error::IO { source, .. } = err {
                assert_eq!(source.kind(), io::ErrorKind::NotFound);
            }
        }
    }
}
