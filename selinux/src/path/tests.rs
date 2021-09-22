#![cfg(all(test, target_os = "linux", not(target_env = "kernel")))]

#[test]
fn selinux() {
    let path = super::selinux().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn default_type_path() {
    let path = super::default_type_path().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn fail_safe_context() {
    let path = super::fail_safe_context().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn removable_context() {
    let path = super::removable_context().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn default_context() {
    let path = super::default_context().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn user_contexts() {
    let path = super::user_contexts().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn file_context() {
    let path = super::file_context().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn file_context_homedir() {
    let path = super::file_context_homedir().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn file_context_local() {
    let path = super::file_context_local().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn file_context_subs() {
    let path = super::file_context_subs().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn file_context_subs_dist() {
    let path = super::file_context_subs_dist().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn home_dir_context() {
    let path = super::home_dir_context().unwrap();
    assert!(!path.as_os_str().is_empty());
    //assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn media_context() {
    let path = super::media_context().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn virtual_domain_context() {
    let path = super::virtual_domain_context().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn virtual_image_context() {
    let path = super::virtual_image_context().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn lxc_contexts() {
    let path = super::lxc_contexts().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn x_context() {
    let path = super::x_context().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn sepgsql_context() {
    let path = super::sepgsql_context().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn openrc_contexts() {
    let path = super::openrc_contexts().unwrap();
    assert!(!path.as_os_str().is_empty());
    //assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn openssh_contexts() {
    let path = super::openssh_contexts().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn snapperd_contexts() {
    let path = super::snapperd_contexts().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn systemd_contexts() {
    let path = super::systemd_contexts().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn contexts() {
    let path = super::contexts().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn securetty_types() {
    let path = super::securetty_types().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn booleans_subs() {
    let path = super::booleans_subs().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn customizable_types() {
    let path = super::customizable_types().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn users_conf() {
    let path = super::users_conf().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn translations() {
    let path = super::translations().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn colors() {
    let path = super::colors().unwrap();
    assert!(!path.as_os_str().is_empty());
    //assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn netfilter_context() {
    let path = super::netfilter_context().unwrap();
    assert!(!path.as_os_str().is_empty());
    //assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}
