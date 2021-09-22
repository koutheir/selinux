#![cfg(all(test, target_os = "linux", not(target_env = "kernel")))]

use core::slice;
use std::ffi::{CStr, CString, OsStr};
use std::io::Write;
use std::os::raw::{c_char, c_void};
use std::path::Path;
use std::{io, mem, ptr};

use assert_matches::assert_matches;

#[test]
fn str_to_c_string() {
    assert_eq!(
        super::str_to_c_string("").unwrap(),
        CString::new("").unwrap()
    );

    assert_eq!(
        super::str_to_c_string("xyz").unwrap(),
        CString::new("xyz").unwrap()
    );

    super::str_to_c_string("abc\0xyz").unwrap_err();
}

#[test]
fn os_str_to_c_string() {
    assert_eq!(
        super::os_str_to_c_string(OsStr::new("")).unwrap(),
        CString::new("").unwrap()
    );

    assert_eq!(
        super::os_str_to_c_string(OsStr::new("xyz")).unwrap(),
        CString::new("xyz").unwrap()
    );

    super::os_str_to_c_string(OsStr::new("abc\0xyz")).unwrap_err();
}

#[test]
fn c_str_ptr_to_str() {
    super::c_str_ptr_to_str(ptr::null()).unwrap_err();

    assert_eq!(super::c_str_ptr_to_str("\0".as_ptr().cast()).unwrap(), "");

    assert_eq!(
        super::c_str_ptr_to_str("xyz\0".as_ptr().cast()).unwrap(),
        "xyz"
    );
}

#[test]
fn c_str_ptr_to_path() {
    assert_eq!(
        super::c_str_ptr_to_path("\0".as_ptr().cast()),
        Path::new("")
    );

    assert_eq!(
        super::c_str_ptr_to_path("xyz\0".as_ptr().cast()),
        Path::new("xyz")
    );
}

#[test]
fn ret_val_to_result() {
    super::ret_val_to_result("xyz", 0).unwrap();
    super::ret_val_to_result("xyz", 1).unwrap();

    crate::errors::Error::set_errno(1);
    let err = super::ret_val_to_result("xyz", -1).unwrap_err();
    assert_matches!(err, crate::errors::Error::IO { .. });
    if let crate::errors::Error::IO { source, .. } = err {
        assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
    }
}

#[test]
fn ret_val_to_result_with_path() {
    let test_path = Path::new("/abc");

    super::ret_val_to_result_with_path("xyz", 0, test_path).unwrap();
    super::ret_val_to_result_with_path("xyz", 1, test_path).unwrap();

    crate::errors::Error::set_errno(1);
    let err = super::ret_val_to_result_with_path("xyz", -1, test_path).unwrap_err();
    crate::errors::Error::clear_errno();

    assert_matches!(err, crate::errors::Error::IO1Path { .. });
    if let crate::errors::Error::IO1Path { source, path, .. } = err {
        assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(path, test_path);
    }
}

#[test]
fn c_allocated_block() {
    assert!(super::CAllocatedBlock::<c_void>::new(ptr::null_mut()).is_none());

    let block_ptr: *mut u64 = unsafe { libc::calloc(16, mem::size_of::<u64>()) }.cast();
    let block = super::CAllocatedBlock::new(block_ptr).unwrap();
    assert_eq!(block.as_ptr(), block_ptr);

    let block_ptr: *mut c_char = unsafe { libc::calloc(8, 1) }.cast();
    {
        let mut block_slice: &mut [u8] = unsafe { slice::from_raw_parts_mut(block_ptr.cast(), 8) };
        write!(block_slice, "xyz\0").unwrap();
    }
    let mut block = super::CAllocatedBlock::new(block_ptr).unwrap();
    assert_eq!(block.as_ptr(), block_ptr);
    assert_eq!(block.as_mut_ptr(), block_ptr);
    assert_eq!(
        block.as_c_str(),
        CStr::from_bytes_with_nul("xyz\0".as_bytes()).unwrap()
    );
    let _ignored = format!("{:?}", &block);
}

unsafe extern "C" fn null_ptr() -> *const c_char {
    ptr::null()
}

#[test]
fn get_static_path() {
    super::get_static_path(null_ptr, "null_ptr()").unwrap_err();
}
