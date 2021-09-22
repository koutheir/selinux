use std::io;
use std::num::TryFromIntError;
use std::os::raw::c_int;
use std::path::PathBuf;
use std::str::Utf8Error;

use selinux_sys::pid_t;

/// Result of a fallible function.
pub type Result<T> = std::result::Result<T, Error>;

/// Error.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Path is invalid.
    #[error("Path is invalid: '{}'", .0.display())]
    PathIsInvalid(PathBuf),

    /// Input security contexts have different formats.
    #[error("Input security contexts have different formats")]
    SecurityContextFormatMismatch,

    /// Security context has an expected format.
    #[error("Security context has an expected format")]
    UnexpectedSecurityContextFormat,

    /// Lock was poisoned.
    #[error("{operation} failed due to poisoned lock")]
    LockPoisoned {
        /// Operation.
        operation: &'static str,
    },

    /// Input/Output operation failed.
    #[error("{operation} failed")]
    IO {
        /// Cause.
        source: io::Error,
        /// Operation.
        operation: &'static str,
    },

    /// Operation failed on a process.
    #[error("{operation} failed on process with ID '{process_id}'")]
    IO1Process {
        /// Cause.
        source: io::Error,
        /// Operation.
        operation: &'static str,
        /// Process identifier.
        process_id: pid_t,
    },

    /// Operation failed on a named object.
    #[error("{operation} failed with '{name}'")]
    IO1Name {
        /// Cause.
        source: io::Error,
        /// Operation.
        operation: &'static str,
        /// Name.
        name: String,
    },

    /// Operation failed on a file system object.
    #[error("{operation} failed on path '{path}'")]
    IO1Path {
        /// Cause.
        source: io::Error,
        /// Operation.
        operation: &'static str,
        /// Path.
        path: PathBuf,
    },

    /// Data is not encoded as UTF-8.
    #[error(transparent)]
    NotUTF8(#[from] Utf8Error),

    /// Integer is out of valid range.
    #[error(transparent)]
    IntegerOutOfRange(#[from] TryFromIntError),
}

impl Error {
    pub(crate) fn from_io(operation: &'static str, source: io::Error) -> Self {
        Error::IO { source, operation }
    }

    pub(crate) fn last_io_error(operation: &'static str) -> Self {
        Error::IO {
            source: io::Error::last_os_error(),
            operation,
        }
    }

    pub(crate) fn from_io_pid(
        operation: &'static str,
        process_id: pid_t,
        source: io::Error,
    ) -> Self {
        Error::IO1Process {
            source,
            operation,
            process_id,
        }
    }

    pub(crate) fn from_io_path(
        operation: &'static str,
        path: impl Into<PathBuf>,
        source: io::Error,
    ) -> Self {
        Error::IO1Path {
            source,
            operation,
            path: path.into(),
        }
    }

    pub(crate) fn from_io_name(
        operation: &'static str,
        name: impl Into<String>,
        source: io::Error,
    ) -> Self {
        Error::IO1Name {
            source,
            operation,
            name: name.into(),
        }
    }

    pub(crate) fn set_errno(errno: c_int) {
        unsafe {
            *libc::__errno_location() = errno;
        }
    }

    pub(crate) fn clear_errno() {
        Self::set_errno(0);
    }

    #[allow(dead_code)] // This is used by unit tests.
    pub(crate) fn io_source(&self) -> Option<&io::Error> {
        match self {
            Self::IO { source, .. } => Some(source),
            Self::IO1Process { source, .. } => Some(source),
            Self::IO1Name { source, .. } => Some(source),
            Self::IO1Path { source, .. } => Some(source),
            _ => None,
        }
    }
}
