#![cfg(all(test, target_os = "linux", not(target_env = "kernel")))]

use std::collections::HashSet;
use std::ffi::CStr;
use std::os::raw::c_void;
use std::path::Path;
use std::ptr;

use assert_matches::assert_matches;

#[test]
fn labeler_new_file() {
    let mut labeler1 = super::Labeler::<super::back_end::File>::new(&[], false).unwrap();
    assert_eq!(labeler1.as_ptr(), labeler1.as_mut_ptr());
    assert!(!labeler1.is_raw_format());

    let _ignored = format!("{:?}", &labeler1);

    let labeler2 = super::Labeler::<super::back_end::File>::new(&[], false).unwrap();
    assert_eq!(labeler1, labeler2);
}

#[test]
fn labeler_log_statistics() {
    let labeler = super::Labeler::<super::back_end::File>::new(&[], false).unwrap();
    labeler.log_statistics();
}

#[test]
fn labeler_digest() {
    let options = &[(selinux_sys::SELABEL_OPT_DIGEST, 1 as *const c_void)];
    let labeler = super::Labeler::<super::back_end::File>::new(options, false).unwrap();

    let digest = labeler.digest().unwrap();
    assert!(!digest.digest().is_empty());
    assert!(!digest.spec_files().is_empty());
}

#[test]
fn labeler_restorecon_default() {
    let _labeler = super::Labeler::restorecon_default(false).unwrap();
}

#[test]
fn labeler_look_up() {
    for &raw_format in &[false, true] {
        let labeler = super::Labeler::<super::back_end::File>::new(&[], raw_format).unwrap();
        let path = unsafe { CStr::from_ptr("/lib\0".as_ptr().cast()) };
        let _context = labeler.look_up(path, 0).unwrap();
    }
}

#[test]
fn labeler_look_up_by_path() {
    for &raw_format in &[false, true] {
        let labeler = super::Labeler::<super::back_end::File>::new(&[], raw_format).unwrap();
        let _context = labeler.look_up_by_path("/lib", None).unwrap();
    }
}

#[test]
fn labeler_look_up_best_match_by_path() {
    for &raw_format in &[false, true] {
        for &alias_paths in &[&[] as &[&str], &["/usr/lib"]] {
            let labeler = super::Labeler::<super::back_end::File>::new(&[], raw_format).unwrap();
            let _context = labeler
                .look_up_best_match_by_path("/lib", alias_paths, None)
                .unwrap();
        }
    }
}

#[test]
fn labeler_partial_match_by_path() {
    let labeler = super::Labeler::<super::back_end::File>::new(&[], false).unwrap();
    let _is_match = labeler.partial_match_by_path("/lib").unwrap();
}

#[test]
fn labeler_get_digests_all_partial_matches_by_path() {
    let labeler = super::Labeler::<super::back_end::File>::new(&[], false).unwrap();

    if let Err(r) = labeler.get_digests_all_partial_matches_by_path("/tmp") {
        let r = r.io_source().unwrap().raw_os_error();
        assert_matches!(r, Some(libc::ENOSYS | libc::ENOENT));
    }
}

#[test]
fn digest() {
    let sf_two_nulls = &[ptr::null(), ptr::null()];

    for &(dg_ptr, dg_len, sf_ptr, sf_len) in &[
        (ptr::null(), 0, ptr::null(), 0),
        (b"".as_ptr(), 0, ptr::null(), 0),
        (b"xyz".as_ptr(), 0, ptr::null(), 0),
        (ptr::null(), 3, ptr::null(), 0),
        (ptr::null(), 0, ptr::null(), 3),
        (ptr::null(), 0, &[].as_ptr(), 0),
        (ptr::null(), 0, sf_two_nulls.as_ptr(), sf_two_nulls.len()),
    ] {
        let digest = super::Digest::new(dg_ptr, dg_len, sf_ptr, sf_len);
        assert!(digest.digest().is_empty());
        assert!(digest.spec_files().is_empty());
    }

    let digest = super::Digest::new(b"xyz".as_ptr(), 3, ptr::null_mut(), 0);
    assert_eq!(digest.digest(), b"xyz");
    assert!(digest.spec_files().is_empty());

    let spec_files = &["abc\0".as_ptr().cast(), ptr::null(), "A\0".as_ptr().cast()];
    let digest = super::Digest::new(ptr::null_mut(), 0, spec_files.as_ptr(), spec_files.len());
    assert!(digest.digest().is_empty());
    assert_eq!(digest.spec_files().len(), 1);
    assert_eq!(digest.spec_files()[0], Path::new("abc"));

    let spec_files = &[
        "abc\0".as_ptr().cast(),
        "abcdef\0".as_ptr().cast(),
        "A\0".as_ptr().cast(),
    ];
    let digest = super::Digest::new(ptr::null_mut(), 0, spec_files.as_ptr(), spec_files.len());
    assert!(digest.digest().is_empty());
    assert_eq!(digest.spec_files().len(), 3);
    assert_eq!(digest.spec_files()[0], Path::new("abc"));
    assert_eq!(digest.spec_files()[1], Path::new("abcdef"));
    assert_eq!(digest.spec_files()[2], Path::new("A"));

    let spec_files = &[
        "abc\0".as_ptr().cast(),
        "abcdef\0".as_ptr().cast(),
        "A\0".as_ptr().cast(),
    ];
    let digest = super::Digest::new(b"xyz".as_ptr(), 3, spec_files.as_ptr(), spec_files.len());
    assert_eq!(digest.digest(), b"xyz");
    assert_eq!(digest.spec_files().len(), 3);
    assert_eq!(digest.spec_files()[0], Path::new("abc"));
    assert_eq!(digest.spec_files()[1], Path::new("abcdef"));
    assert_eq!(digest.spec_files()[2], Path::new("A"));

    let _ignored = format!("{:?}", &digest);
    let digest_clone = digest.clone();
    assert_eq!(digest, digest_clone);
    assert!(digest >= digest_clone);
    assert!(digest <= digest_clone);
    let mut ht = HashSet::new();
    ht.insert(digest_clone);
}

#[test]
fn partial_matches_digests() {
    let pmd = super::PartialMatchesDigests {
        match_result: super::PartialMatchesResult::NoMatchOrMissing,
        xattr_digest: None,
        calculated_digest: None,
        digest_size: 0,
    };
    assert_eq!(
        pmd.match_result(),
        super::PartialMatchesResult::NoMatchOrMissing
    );
    assert!(pmd.is_empty());
    assert_eq!(pmd.len(), 0);
    assert_eq!(pmd.xattr_digest(), None);
    assert_eq!(pmd.calculated_digest(), None);

    let pmd = super::PartialMatchesDigests {
        match_result: super::PartialMatchesResult::Match,
        xattr_digest: None,
        calculated_digest: None,
        digest_size: 10,
    };
    assert_eq!(pmd.match_result(), super::PartialMatchesResult::Match);
    assert!(!pmd.is_empty());
    assert_eq!(pmd.len(), 10);
    assert_eq!(pmd.xattr_digest(), None);
    assert_eq!(pmd.calculated_digest(), None);

    let xattr_digest: *mut u8 = unsafe { libc::malloc(3) }.cast();
    unsafe { ptr::copy_nonoverlapping("abc".as_ptr(), xattr_digest, 3) };

    let pmd = super::PartialMatchesDigests {
        match_result: super::PartialMatchesResult::Match,
        xattr_digest: crate::utils::CAllocatedBlock::new(xattr_digest),
        calculated_digest: None,
        digest_size: 3,
    };
    assert_eq!(pmd.match_result(), super::PartialMatchesResult::Match);
    assert!(!pmd.is_empty());
    assert_eq!(pmd.len(), 3);
    assert_eq!(pmd.xattr_digest(), Some(b"abc" as &[u8]));
    assert_eq!(pmd.calculated_digest(), None);

    let xattr_digest: *mut u8 = unsafe { libc::malloc(3) }.cast();
    unsafe { ptr::copy_nonoverlapping("abc".as_ptr(), xattr_digest, 3) };

    let calculated_digest: *mut u8 = unsafe { libc::malloc(3) }.cast();
    unsafe { ptr::copy_nonoverlapping("xyz".as_ptr(), calculated_digest, 3) };

    let pmd = super::PartialMatchesDigests {
        match_result: super::PartialMatchesResult::Match,
        xattr_digest: crate::utils::CAllocatedBlock::new(xattr_digest),
        calculated_digest: crate::utils::CAllocatedBlock::new(calculated_digest),
        digest_size: 3,
    };
    assert_eq!(pmd.match_result(), super::PartialMatchesResult::Match);
    assert!(!pmd.is_empty());
    assert_eq!(pmd.len(), 3);
    assert_eq!(pmd.xattr_digest(), Some(b"abc" as &[u8]));
    assert_eq!(pmd.calculated_digest(), Some(b"xyz" as &[u8]));

    let _ignored = format!("{:?}", &pmd);
}
