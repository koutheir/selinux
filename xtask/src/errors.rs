use std::io;
use std::path::PathBuf;
use std::str::Utf8Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("'{name}' command failed")]
    CommandFailed { name: &'static str },

    #[error(transparent)]
    NotUTF8(#[from] Utf8Error),

    #[error("{operation} failed")]
    IO {
        source: io::Error,
        operation: &'static str,
    },

    #[error("{operation} failed on '{path}'")]
    IO1Path {
        source: io::Error,
        operation: &'static str,
        path: PathBuf,
    },
}

impl Error {
    pub(crate) fn from_io(operation: &'static str, source: io::Error) -> Self {
        Error::IO { source, operation }
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
}
