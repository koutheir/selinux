use std::os::raw::c_uint;

/// Security contexts backend.
pub trait BackEnd {
    /// Security contexts backend index.
    const BACK_END: c_uint;
}

/// File contexts backend, described in `selabel_file()`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub struct File;

impl BackEnd for File {
    const BACK_END: c_uint = selinux_sys::SELABEL_CTX_FILE as c_uint;
}

/// Media contexts backend, described in `selabel_media()`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub struct Media;

impl BackEnd for Media {
    const BACK_END: c_uint = selinux_sys::SELABEL_CTX_MEDIA as c_uint;
}

/// X Windows contexts backend, described in `selabel_x()`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub struct X;

impl BackEnd for X {
    const BACK_END: c_uint = selinux_sys::SELABEL_CTX_X as c_uint;
}

/// Database objects contexts backend, described in `selabel_db()`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
pub struct DB;

impl BackEnd for DB {
    const BACK_END: c_uint = selinux_sys::SELABEL_CTX_DB as c_uint;
}
