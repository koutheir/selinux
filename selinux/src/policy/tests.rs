#![cfg(all(test, target_os = "linux", not(target_env = "kernel")))]

#[test]
fn version_number() {
    match super::version_number() {
        Ok(version) => assert_ne!(version, 0),
        Err(_err) => assert_eq!(crate::current_mode(), crate::SELinuxMode::NotRunning),
    }
}

#[test]
fn policy_type() {
    match super::policy_type() {
        Ok(name) => assert!(!name.as_c_str().to_bytes().is_empty()),
        Err(_err) => assert_eq!(crate::current_mode(), crate::SELinuxMode::NotRunning),
    }
}

#[test]
fn root_path() {
    let path = super::root_path().unwrap();
    assert!(!path.as_os_str().is_empty());
    assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn current_policy_path() {
    match super::current_policy_path() {
        Ok(path) => {
            assert!(!path.as_os_str().is_empty());
            assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
        }

        Err(_err) => assert!(crate::current_mode() == crate::SELinuxMode::NotRunning),
    }
}

#[test]
fn binary_policy_path() {
    let path = super::binary_policy_path().unwrap();
    assert!(!path.as_os_str().is_empty());
    //assert!(path.exists() || crate::current_mode() == crate::SELinuxMode::NotRunning);
}

#[test]
fn load() {
    let policy_bytes = [];
    super::load(&policy_bytes).unwrap_err();
}

#[test]
fn make_and_load() {
    super::make_and_load().unwrap_err();
}

#[test]
fn load_initial() {
    super::load_initial().unwrap_err();
}

#[test]
fn set_root_path() {
    let path = super::current_policy_path().unwrap();
    super::set_root_path(path).unwrap();
}
