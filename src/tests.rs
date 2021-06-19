#![cfg(all(test, target_os = "linux", not(target_env = "kernel")))]

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::ffi::CStr;
use std::io::Write;
use std::os::raw::{c_char, c_int};
use std::path::Path;
use std::{fs, io, process, ptr};

use assert_matches::assert_matches;

use crate::utils::*;

#[test]
fn security_context_from_c_str() {
    let ptr: *const c_char = "xyz\0".as_ptr().cast();
    let s = unsafe { CStr::from_ptr(ptr) };
    let mut context = super::SecurityContext::from_c_str(s, false);
    assert_eq!(context.as_ptr(), ptr);
    assert_eq!(context.as_mut_ptr(), ptr as *mut c_char);
    assert_eq!(context.as_bytes().len(), 3);
    assert!(!context.is_raw_format());

    let _ignored = format!("{:?}", &context);
}

#[test]
fn security_context_from_result() {
    super::SecurityContext::from_result("xyz", 0, ptr::null_mut(), false).unwrap_err();

    crate::errors::Error::set_errno(1);
    super::SecurityContext::from_result("xyz", -1, 0x1000 as *mut c_char, false).unwrap_err();
    crate::errors::Error::clear_errno();
}

#[test]
fn security_context_from_result_with_name() {
    super::SecurityContext::from_result_with_name("xyz", 0, ptr::null_mut(), "abc", false)
        .unwrap_err();

    crate::errors::Error::set_errno(1);
    super::SecurityContext::from_result_with_name("xyz", -1, 0x1000 as *mut c_char, "abc", false)
        .unwrap_err();
    crate::errors::Error::clear_errno();
}

#[test]
fn security_context_from_result_with_pid() {
    super::SecurityContext::from_result_with_pid("xyz", 0, ptr::null_mut(), 1, false).unwrap_err();

    crate::errors::Error::set_errno(1);
    super::SecurityContext::from_result_with_pid("xyz", -1, 0x1000 as *mut c_char, 1, false)
        .unwrap_err();
    crate::errors::Error::clear_errno();
}

#[test]
fn security_context_parse_context_color() {
    use super::{LayerColors, SecurityContext, SecurityContextColors, RGB};

    for &bytes in &[
        b"" as &[u8],
        b" ",
        b"                 ",
        b"s",
        b"s t",
        b"s t u",
        b"s t u v",
        b"s t u v w",
        b"s t u v w x",
        b"s t u v w x y",
        b"s t u v w x y z",
        b"# # # # # # # #",
        b"#s #t #u #v #w #x #y #z",
        b"#0",
        b"#0 #0",
        b"#0 #0 #0",
        b"#0 #0 #0 #0",
        b"#0 #0 #0 #0 #0",
        b"#0 #0 #0 #0 #0 #0",
        b"#0 #0 #0 #0 #0 #0 #0",
        b"#-1 #0 #0 #0 #0 #0 #0 #0",
        b"#100000000 #0 #0 #0 #0 #0 #0 #0",
        b"#1000000 #0 #0 #0 #0 #0 #0 #0",
    ] {
        SecurityContext::parse_context_color(bytes).unwrap_err();
    }

    let bytes = b"#11 #22   #aa     #bb    #cc #dd #ee #ff";
    let colors = SecurityContext::parse_context_color(bytes).unwrap();
    let expected_colors = SecurityContextColors::new(
        LayerColors::new(RGB::new(0x22, 0, 0), RGB::new(0x11, 0, 0)),
        LayerColors::new(RGB::new(0xbb, 0, 0), RGB::new(0xaa, 0, 0)),
        LayerColors::new(RGB::new(0xdd, 0, 0), RGB::new(0xcc, 0, 0)),
        LayerColors::new(RGB::new(0xff, 0, 0), RGB::new(0xee, 0, 0)),
    );
    assert_eq!(colors, expected_colors);
}

#[test]
fn security_context_color() {
    use super::{LayerColors, SecurityContextColors, RGB};

    let scc = SecurityContextColors::new(
        LayerColors::new(RGB::new(0x22, 0, 0), RGB::new(0x11, 0, 0)),
        LayerColors::new(RGB::new(0xbb, 0, 0), RGB::new(0xaa, 0, 0)),
        LayerColors::new(RGB::new(0xdd, 0, 0), RGB::new(0xcc, 0, 0)),
        LayerColors::new(RGB::new(0xff, 0, 0), RGB::new(0xee, 0, 0)),
    );

    let scc_clone = super::SecurityContextColors::clone(&scc);
    assert_eq!(scc, scc_clone);
    assert!(!(scc < scc_clone));
    assert!(!(scc > scc_clone));
    assert_ne!(scc, super::SecurityContextColors::default());
    let _ignored = format!("{:?}", &scc);
    let mut ht = HashSet::new();
    ht.insert(scc_clone);
}

#[test]
fn security_context_current() {
    let mut context = super::SecurityContext::current(false).unwrap();
    assert!(!context.as_ptr().is_null());
    assert!(!context.as_mut_ptr().is_null());
    assert!(!context.as_bytes().is_empty());

    if let Err(err) = context.is_customizable() {
        assert_matches!(err, crate::errors::Error::IO { .. });
        if let crate::errors::Error::IO { source, .. } = err {
            let errno = source.raw_os_error().unwrap();
            assert!(errno == libc::EINVAL || errno == libc::ENOTDIR);
        }
    }

    let r = context.check();
    assert!(r.is_none() || r == Some(true));

    let _canon_context = context.canonicalize().unwrap();

    let _securetty = context.check_securetty_context();

    //let _color = context.to_color().unwrap();

    context.to_translated_format().unwrap_err();

    let raw_context = context.to_raw_format().unwrap();
    raw_context.to_raw_format().unwrap_err();

    let _canon_raw_context = raw_context.canonicalize().unwrap();

    let r = raw_context.check();
    assert!(r.is_none() || r == Some(true));

    let _context = raw_context.to_translated_format().unwrap();

    let _raw_context = super::SecurityContext::current(true).unwrap();

    let _cmp = context.compare_user_insensitive(&raw_context);
}

#[test]
fn security_context_previous() {
    let _context = super::SecurityContext::previous(false).unwrap();
    let _context = super::SecurityContext::previous(true).unwrap();
}

#[test]
fn security_context_set_as_current() {
    for &raw_format in &[false, true] {
        let context = super::SecurityContext::current(raw_format).unwrap();
        context.set_as_current().unwrap();
    }
}

#[test]
fn security_context_of_next_exec() {
    let _context = super::SecurityContext::of_next_exec(false).unwrap();
    let _context = super::SecurityContext::of_next_exec(true).unwrap();
}

#[test]
fn security_context_set_default_context_for_next_exec() {
    super::SecurityContext::set_default_context_for_next_exec().unwrap();
}

#[test]
fn security_context_set_for_next_exec() {
    for &raw_format in &[false, true] {
        let old_context = super::SecurityContext::of_next_exec(raw_format).unwrap();

        let context = super::SecurityContext::current(raw_format).unwrap();
        context.set_for_next_exec().unwrap();

        if let Some(context) = old_context {
            context.set_for_next_exec().unwrap();
        } else {
            super::SecurityContext::set_default_context_for_next_exec().unwrap();
        }
    }
}

#[test]
fn security_context_of_new_file_system_objects() {
    let _context = super::SecurityContext::of_new_file_system_objects(false).unwrap();
    let _context = super::SecurityContext::of_new_file_system_objects(true).unwrap();
}

#[test]
fn security_context_set_default_context_for_new_file_system_objects() {
    super::SecurityContext::set_default_context_for_new_file_system_objects().unwrap();
}

#[test]
fn security_context_set_for_new_file_system_objects() {
    for &raw_format in &[false, true] {
        let old_context = super::SecurityContext::of_new_file_system_objects(raw_format).unwrap();

        let context = super::SecurityContext::current(raw_format).unwrap();
        context.set_for_new_file_system_objects(raw_format).unwrap();

        if let Some(context) = old_context {
            context.set_for_new_file_system_objects(raw_format).unwrap();
        } else {
            super::SecurityContext::set_default_context_for_new_file_system_objects().unwrap();
        }
    }
}

#[test]
fn security_context_of_new_kernel_key_rings() {
    let _context = super::SecurityContext::of_new_kernel_key_rings(false).unwrap();
    let _context = super::SecurityContext::of_new_kernel_key_rings(true).unwrap();
}

#[test]
fn security_context_set_default_context_for_new_kernel_key_rings() {
    super::SecurityContext::set_default_context_for_new_kernel_key_rings().unwrap();
}

#[test]
fn security_context_set_for_new_kernel_key_rings() {
    for &raw_format in &[false, true] {
        let old_context = super::SecurityContext::of_new_kernel_key_rings(raw_format).unwrap();

        let context = super::SecurityContext::current(raw_format).unwrap();
        context.set_for_new_kernel_key_rings(raw_format).unwrap();

        if let Some(context) = old_context {
            context.set_for_new_kernel_key_rings(raw_format).unwrap();
        } else {
            super::SecurityContext::set_default_context_for_new_kernel_key_rings().unwrap();
        }
    }
}

#[test]
fn security_context_of_new_labeled_sockets() {
    let _context = super::SecurityContext::of_new_labeled_sockets(false).unwrap();
    let _context = super::SecurityContext::of_new_labeled_sockets(true).unwrap();
}

#[test]
fn security_context_set_default_context_for_new_labeled_sockets() {
    super::SecurityContext::set_default_context_for_new_labeled_sockets().unwrap();
}

#[test]
fn security_context_set_for_new_labeled_sockets() {
    for &raw_format in &[false, true] {
        let old_context = super::SecurityContext::of_new_labeled_sockets(raw_format).unwrap();

        let context = super::SecurityContext::current(raw_format).unwrap();
        context.set_for_new_labeled_sockets(raw_format).unwrap();

        if let Some(context) = old_context {
            context.set_for_new_labeled_sockets(raw_format).unwrap();
        } else {
            super::SecurityContext::set_default_context_for_new_labeled_sockets().unwrap();
        }
    }
}

#[test]
fn security_context_of_initial_kernel_context() {
    for &raw_format in &[false, true] {
        let _context =
            super::SecurityContext::of_initial_kernel_context("unlabeled", raw_format).unwrap();
    }
}

#[test]
fn security_context_of_process() {
    let pid = process::id() as c_int;
    for &raw_format in &[false, true] {
        let _context = super::SecurityContext::of_process(pid, raw_format).unwrap();
    }
}

#[test]
fn security_context_of_se_user_with_selected_context() {
    //let _context =
    //    super::SecurityContext::of_se_user_with_selected_context("unconfined_u", false).unwrap();
}

#[test]
fn security_context_default_for_se_user() {
    let _context =
        super::SecurityContext::default_for_se_user("unconfined_u", None, None, None, false)
            .unwrap();

    let _context = super::SecurityContext::default_for_se_user(
        "unconfined_u",
        Some("unconfined_r"),
        None,
        None,
        false,
    )
    .unwrap();

    let _context =
        super::SecurityContext::default_for_se_user("unconfined_u", None, Some("low"), None, false)
            .unwrap();

    let _context = super::SecurityContext::default_for_se_user(
        "unconfined_u",
        Some("unconfined_r"),
        Some("low"),
        None,
        false,
    )
    .unwrap();

    let context = super::SecurityContext::current(false).unwrap();
    let _context = super::SecurityContext::default_for_se_user(
        "unconfined_u",
        None,
        None,
        Some(&context),
        false,
    )
    .unwrap();
}

#[test]
fn security_context_of_media_type() {
    super::SecurityContext::of_media_type("invalid").unwrap_err();
    //let _context = super::SecurityContext::of_media_type("unlabeled").unwrap();
}

#[test]
fn security_context_of_labeling_decision() {
    let context = super::SecurityContext::current(false).unwrap();
    let raw_context = super::SecurityContext::current(true).unwrap();
    let target_class = super::SecurityClass::from_name("process").unwrap();
    context
        .of_labeling_decision(&raw_context, target_class, "process")
        .unwrap_err();
    let _new_context = context
        .of_labeling_decision(&context, target_class, "process")
        .unwrap();
    let _new_context = raw_context
        .of_labeling_decision(&raw_context, target_class, "process")
        .unwrap();
}

#[test]
fn security_context_of_relabeling_decision() {
    let context = super::SecurityContext::current(false).unwrap();
    let raw_context = super::SecurityContext::current(true).unwrap();
    let target_class = super::SecurityClass::from_name("process").unwrap();
    context
        .of_relabeling_decision(&raw_context, target_class)
        .unwrap_err();
    let _new_context = context
        .of_relabeling_decision(&context, target_class)
        .unwrap();
    let _new_context = raw_context
        .of_relabeling_decision(&raw_context, target_class)
        .unwrap();
}

#[test]
fn security_context_of_polyinstantiation_member_decision() {
    let context = super::SecurityContext::current(false).unwrap();
    let raw_context = super::SecurityContext::current(true).unwrap();
    let target_class = super::SecurityClass::from_name("process").unwrap();
    context
        .of_polyinstantiation_member_decision(&raw_context, target_class)
        .unwrap_err();
    let _new_context = context
        .of_polyinstantiation_member_decision(&context, target_class)
        .unwrap();
    let _new_context = raw_context
        .of_polyinstantiation_member_decision(&raw_context, target_class)
        .unwrap();
}

#[test]
fn security_context_validate_transition() {
    let context = super::SecurityContext::current(false).unwrap();
    let raw_context = super::SecurityContext::current(true).unwrap();
    let target_class = super::SecurityClass::from_name("process").unwrap();
    context
        .validate_transition(&raw_context, target_class, &raw_context)
        .unwrap_err();

    if let Err(r) = context.validate_transition(&context, target_class, &context) {
        assert_eq!(r.io_source().unwrap().kind(), io::ErrorKind::Unsupported);
    }

    if let Err(r) = raw_context.validate_transition(&raw_context, target_class, &raw_context) {
        assert_eq!(r.io_source().unwrap().kind(), io::ErrorKind::Unsupported);
    }
}

#[test]
fn security_context_query_access_decision() {
    let context = super::SecurityContext::current(false).unwrap();
    let raw_context = super::SecurityContext::current(true).unwrap();
    let target_class = super::SecurityClass::from_name("process").unwrap();
    context
        .query_access_decision(&raw_context, target_class, 0)
        .unwrap_err();
    let _new_context = context
        .query_access_decision(&context, target_class, 0)
        .unwrap();
    let _new_context = raw_context
        .query_access_decision(&raw_context, target_class, 0)
        .unwrap();
}

#[test]
fn security_context_check_access() {
    let context = super::SecurityContext::current(false).unwrap();
    let raw_context = super::SecurityContext::current(true).unwrap();
    let _new_context = context
        .check_access(&context, "process", "read", ptr::null_mut())
        .unwrap();
    let _new_context = raw_context
        .check_access(&raw_context, "process", "read", ptr::null_mut())
        .unwrap();
}

#[test]
fn security_context_of_path() {
    for &raw_format in &[false, true] {
        for &follow_symbolic_links in &[false, true] {
            for &path in &["/", "/etc/fstab"] {
                let r = super::SecurityContext::of_path(path, follow_symbolic_links, raw_format);
                let _context = r.unwrap();
            }
        }
    }

    let _context = super::SecurityContext::of_path("/non-existent", false, false).unwrap_err();
}

#[test]
fn security_context_set_default_for_path() {
    super::SecurityContext::set_default_for_path("non-existent").unwrap_err();

    /*
    let file = tempfile::NamedTempFile::new().unwrap();
    super::SecurityContext::set_default_for_path(file.path()).unwrap();
    */
}

#[test]
fn security_context_set_for_path() {
    use std::os::unix::fs::symlink;

    let context = super::SecurityContext::current(false).unwrap();
    context
        .set_for_path(Path::new("/non-existent"), false, false)
        .unwrap_err();

    let context =
        unsafe { CStr::from_ptr("unconfined_u:object_r:user_tmp_t:s0\0".as_ptr().cast()) };
    let context = super::SecurityContext::from_c_str(context, false);

    let dir = tempfile::TempDir::new().unwrap();
    let a = dir.path().join("a.txt");
    let la = dir.path().join("la.txt");
    fs::write(&a, "empty file").unwrap();
    symlink(&a, &la).unwrap();

    for &raw_format in &[false, true] {
        for &follow_symbolic_links in &[false, true] {
            context
                .set_for_path(la.as_path(), follow_symbolic_links, raw_format)
                .unwrap();
        }
    }

    super::SecurityContext::verify_file_context("/non-existent", None).unwrap_err();

    /*
    super::SecurityContext::verify_file_context(
        &la,
        super::FileAccessMode::new(libc::S_IFREG | libc::S_IRUSR),
    )
    .unwrap();
    */
}

#[test]
fn security_context_of_file() {
    let mut file = tempfile::tempfile().unwrap();
    writeln!(file, "empty file").unwrap();
    let optional_context = super::SecurityContext::of_file(&file, false).unwrap();
    let optional_raw_context = super::SecurityContext::of_file(&file, true).unwrap();

    if let Some(context) = optional_context {
        context.set_for_file(&file).unwrap();
    }

    if let Some(raw_context) = optional_raw_context {
        raw_context.set_for_file(&file).unwrap();
    }
}

#[test]
fn security_context_of_peer_socket() {
    let (s1, s2) = socketpair::socketpair_stream().unwrap();

    let _context = super::SecurityContext::of_peer_socket(&s1, false).unwrap();
    let _raw_context = super::SecurityContext::of_peer_socket(&s2, true).unwrap();
}

#[test]
fn rgb() {
    let rgb = super::RGB::new(0x22, 0, 0);
    let rgb_clone = super::RGB::clone(&rgb);
    assert_eq!(rgb, rgb_clone);
    assert!(!(rgb < rgb_clone));
    assert!(!(rgb > rgb_clone));
    assert_ne!(rgb, super::RGB::default());
    let _ignored = format!("{:?}", &rgb);
    let mut ht = HashSet::new();
    ht.insert(rgb_clone);
}

#[test]
fn layer_colors() {
    let lc = super::LayerColors::new(super::RGB::new(0x22, 0, 0), super::RGB::new(0x11, 0, 0));
    let lc_clone = super::LayerColors::clone(&lc);
    assert_eq!(lc, lc_clone);
    assert!(!(lc < lc_clone));
    assert!(!(lc > lc_clone));
    assert_ne!(lc, super::LayerColors::default());
    let _ignored = format!("{:?}", &lc);
    let mut ht = HashSet::new();
    ht.insert(lc_clone);
}

#[test]
fn file_access_mode() {
    assert!(super::FileAccessMode::new(0).is_none());

    let m = super::FileAccessMode::new(42);
    assert_eq!(m, Some(super::FileAccessMode(42)));
    assert_eq!(m.unwrap().mode(), 42);

    let _ignored = format!("{:?}", &m);
}

#[test]
fn security_class_new() {
    super::SecurityClass::new(0).unwrap_err();

    let sc = super::SecurityClass::new(1).unwrap();
    assert_eq!(sc.value(), 1);

    let _ignored = format!("{:?}", &sc);
    let _ignored = format!("{}", &sc);

    let _sc = super::SecurityClass::from_name("invalid").unwrap_err();

    let _sc = super::SecurityClass::try_from(
        super::FileAccessMode::new(libc::S_IFREG | libc::S_IRUSR).unwrap(),
    )
    .unwrap();

    super::SecurityClass::try_from(super::FileAccessMode::new(1).unwrap()).unwrap_err();

    let sc = super::SecurityClass::from_name("process").unwrap();
    let _ignored = format!("{:?}", &sc);
    let _ignored = format!("{}", &sc);

    unsafe { sc.access_vector_bit_name(0) }.unwrap_err();
    let _name = unsafe { sc.access_vector_bit_name(1) }.unwrap();

    let _name = sc.full_access_vector_name(0).unwrap();
    let _name = sc.full_access_vector_name(1).unwrap();
    sc.full_access_vector_name(u32::MAX).unwrap_err();

    sc.access_vector_bit("invalid").unwrap_err();

    let _av = sc.access_vector_bit("signal").unwrap();
}

#[test]
fn opaque_security_context() {
    for &context in &[
        "",
        "user1",
        "user1:role1",
        "user1:role1:type1:range1:other1:other2:other3",
    ] {
        super::OpaqueSecurityContext::new(context).unwrap_err();
    }

    for &context in &[
        "user1:role1:type1",
        "user1:role1:type1:range1",
        "user1:role1:type1:range1:other1",
        "user1:role1:type1:range1:other1:other2",
    ] {
        let mut osc = super::OpaqueSecurityContext::new(context).unwrap();

        assert!(!osc.as_ptr().is_null());
        assert!(!osc.as_mut_ptr().is_null());

        let s = osc.to_c_string().unwrap();
        assert!(!s.as_bytes().is_empty());
        assert_eq!(s.to_string_lossy(), format!("{}", &osc));

        assert_eq!(osc.user().unwrap().to_str().ok(), Some("user1"));
        assert_eq!(osc.role().unwrap().to_str().ok(), Some("role1"));
        assert_eq!(osc.the_type().unwrap().to_str().ok(), Some("type1"));

        let expected_range = context.splitn(4, |c| c == ':').nth(3);
        if let Ok(range) = osc.range() {
            assert_eq!(range.to_str().ok(), expected_range);
        } else {
            assert!(expected_range.is_none());
        }

        osc.set_user("user2").unwrap();

        assert_eq!(osc.user().unwrap().to_str().ok(), Some("user2"));
        assert_eq!(osc.role().unwrap().to_str().ok(), Some("role1"));
        assert_eq!(osc.the_type().unwrap().to_str().ok(), Some("type1"));
        if let Ok(range) = osc.range() {
            assert_eq!(range.to_str().ok(), expected_range);
        } else {
            assert!(expected_range.is_none());
        }

        osc.set_role("role2").unwrap();

        assert_eq!(osc.user().unwrap().to_str().ok(), Some("user2"));
        assert_eq!(osc.role().unwrap().to_str().ok(), Some("role2"));
        assert_eq!(osc.the_type().unwrap().to_str().ok(), Some("type1"));
        if let Ok(range) = osc.range() {
            assert_eq!(range.to_str().ok(), expected_range);
        } else {
            assert!(expected_range.is_none());
        }

        osc.set_type("type2").unwrap();

        assert_eq!(osc.user().unwrap().to_str().ok(), Some("user2"));
        assert_eq!(osc.role().unwrap().to_str().ok(), Some("role2"));
        assert_eq!(osc.the_type().unwrap().to_str().ok(), Some("type2"));
        if let Ok(range) = osc.range() {
            assert_eq!(range.to_str().ok(), expected_range);
        } else {
            assert!(expected_range.is_none());
        }

        osc.set_range("range2").unwrap();

        assert_eq!(osc.user().unwrap().to_str().ok(), Some("user2"));
        assert_eq!(osc.role().unwrap().to_str().ok(), Some("role2"));
        assert_eq!(osc.the_type().unwrap().to_str().ok(), Some("type2"));
        assert_eq!(osc.range().unwrap().to_str().ok(), Some("range2"));

        let _ignored = format!("{:?}", &osc);
    }
}

#[test]
fn kernel_support() {
    let r = super::kernel_support();
    let _ignored = format!("{:?}", r);
}

#[test]
fn boot_mode() {
    if let Err(err) = super::boot_mode() {
        assert_matches!(err, crate::errors::Error::IO { .. });
        if let crate::errors::Error::IO { source, .. } = err {
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
        }

        assert!(fs::symlink_metadata("/etc/selinux/config").is_err());
    }
}

#[test]
fn current_mode() {
    let r = super::current_mode();
    let _ignored = format!("{:?}", r);
}

#[test]
fn undefined_handling() {
    if let Err(err) = super::undefined_handling() {
        assert_matches!(err, crate::errors::Error::IO { .. });
        if let crate::errors::Error::IO { source, .. } = err {
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
        }
    }
}

#[test]
fn protection_checking_mode() {
    if let Err(err) = super::protection_checking_mode() {
        assert_matches!(err, crate::errors::Error::IO { .. });
        if let crate::errors::Error::IO { source, .. } = err {
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
        }
    }
}

#[test]
fn dynamic_mapping_into_native_form() {
    let mut c_string_storage = HashMap::default();

    let empty: &[(&str, &[&str]); 0] = &[];
    let c_map = super::dynamic_mapping_into_native_form(empty, &mut c_string_storage).unwrap();
    assert_eq!(c_map.len(), 1 + empty.len());
    assert!(c_map[0].name.is_null());

    let mapping: &[(&str, &[&str]); 1] = &[("", &[])];
    let c_map = super::dynamic_mapping_into_native_form(mapping, &mut c_string_storage).unwrap();
    assert_eq!(c_map.len(), 1 + mapping.len());
    assert!(c_str_ptr_to_str(c_map[0].name).unwrap().is_empty());
    assert!(c_map[0].perms[0].is_null());
    assert!(c_map[1].name.is_null());

    let mapping: &[(&str, &[&str]); 1] = &[("", &["", ""])];
    let c_map = super::dynamic_mapping_into_native_form(mapping, &mut c_string_storage).unwrap();
    assert_eq!(c_map.len(), 1 + mapping.len());
    assert!(c_str_ptr_to_str(c_map[0].name).unwrap().is_empty());
    assert!(c_str_ptr_to_str(c_map[0].perms[0]).unwrap().is_empty());
    assert!(c_str_ptr_to_str(c_map[0].perms[1]).unwrap().is_empty());
    assert!(c_map[0].perms[2].is_null());
    assert!(c_map[1].name.is_null());

    let mapping: &[(&str, &[&str]); 1] = &[("socket", &["bind"])];
    let c_map = super::dynamic_mapping_into_native_form(mapping, &mut c_string_storage).unwrap();
    assert_eq!(c_map.len(), 1 + mapping.len());
    assert_eq!(c_str_ptr_to_str(c_map[0].name).unwrap(), "socket");
    assert_eq!(c_str_ptr_to_str(c_map[0].perms[0]).unwrap(), "bind");
    assert!(c_map[0].perms[1].is_null());
    assert!(c_map[1].name.is_null());

    let mapping: &[(&str, &[&str]); 2] = &[
        ("socket", &["bind"]),
        ("file", &["create", "unlink", "read", "write"]),
    ];
    let c_map = super::dynamic_mapping_into_native_form(mapping, &mut c_string_storage).unwrap();
    assert_eq!(c_map.len(), 1 + mapping.len());
    assert_eq!(c_str_ptr_to_str(c_map[0].name).unwrap(), "socket");
    assert_eq!(c_str_ptr_to_str(c_map[0].perms[0]).unwrap(), "bind");
    assert!(c_map[0].perms[1].is_null());
    assert_eq!(c_str_ptr_to_str(c_map[1].name).unwrap(), "file");
    assert_eq!(c_str_ptr_to_str(c_map[1].perms[0]).unwrap(), "create");
    assert_eq!(c_str_ptr_to_str(c_map[1].perms[1]).unwrap(), "unlink");
    assert_eq!(c_str_ptr_to_str(c_map[1].perms[2]).unwrap(), "read");
    assert_eq!(c_str_ptr_to_str(c_map[1].perms[3]).unwrap(), "write");
    assert!(c_map[1].perms[4].is_null());
    assert!(c_map[2].name.is_null());
}

#[test]
fn security_context_list_of_se_user() {
    let mut se_list = super::SecurityContextList::of_se_user("unconfined_u", None, None).unwrap();
    assert_eq!(se_list.as_ptr(), se_list.as_mut_ptr().cast());
    assert!(!se_list.is_empty());
    assert_ne!(se_list.len(), 0);

    assert!(se_list.get(usize::MAX, false).is_none());
    let _context = se_list.get(0, false).unwrap();

    let _ignored = format!("{:?}", &se_list);

    super::SecurityContextList::of_se_user("invalid", None, None).unwrap_err();

    let _se_list =
        super::SecurityContextList::of_se_user("unconfined_u", Some("low"), None).unwrap();

    let context = super::SecurityContext::current(false).unwrap();
    let _se_list =
        super::SecurityContextList::of_se_user("unconfined_u", None, Some(&context)).unwrap();
}

#[test]
fn set_current_mode() {
    super::set_current_mode(super::SELinuxMode::NotRunning).unwrap_err();
    super::set_current_mode(super::SELinuxMode::Permissive).unwrap_err();
    super::set_current_mode(super::SELinuxMode::Enforcing).unwrap_err();
}

#[test]
fn se_user_and_level() {
    let (se_user, level) = super::se_user_and_level("root", None).unwrap();
    assert!(!se_user.as_c_str().to_bytes().is_empty());
    assert!(!level.as_c_str().to_bytes().is_empty());

    let (_se_user, _level) = super::se_user_and_level("root", Some("file")).unwrap();
}

#[test]
fn reset_config() {
    super::reset_config();
}

#[test]
fn default_type_for_role() {
    //let _type = super::default_type_for_role("unconfined_r").unwrap();
}

#[test]
fn set_dynamic_mapping() {
    let _type = super::set_dynamic_mapping(&[] as &[(&str, &[&str])]).unwrap();
    let _type = super::set_dynamic_mapping(&[("file", &["read", "write"] as &[&str])]).unwrap();
}
