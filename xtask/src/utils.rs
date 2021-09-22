use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::{fs, io, process};

use log::{debug, info};

use crate::Config;

pub(crate) fn run_cmd(mut cmd: process::Command, name: &str) -> io::Result<()> {
    debug!("Running: {:?}", &cmd);

    if cmd.status()?.success() {
        Ok(())
    } else {
        let err = io::Error::new(io::ErrorKind::Other, format!("'{}' command failed", name));
        Err(err)
    }
}

pub(crate) fn list_files(dir: &Path, extension: &str) -> io::Result<Vec<PathBuf>> {
    let mut result = Vec::with_capacity(16);
    for r_entry in fs::read_dir(dir)? {
        let entry = r_entry?;
        let file_type = entry.file_type()?;
        let file_name = PathBuf::from(entry.file_name());
        if file_type.is_file() && file_name.extension() == Some(OsStr::new(extension)) {
            result.push(entry.path());
        }
    }
    Ok(result)
}

pub(crate) fn find_executable_file(dir: &Path, file_name: &str) -> io::Result<PathBuf> {
    // TODO(KAT): Try to ensure the found file is executable.
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .find(|e| e.file_type().is_file() && e.file_name() == file_name)
        .map(walkdir::DirEntry::into_path)
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
}

#[cfg(unix)]
pub(crate) fn pathbuf_from_vec(bytes: Vec<u8>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    PathBuf::from(OsString::from_vec(bytes))
}

fn cargo_version(toolchain: &str) -> io::Result<()> {
    let mut cmd = process::Command::new("cargo");
    cmd.stdout(process::Stdio::null())
        .args(&[&format!("+{}", toolchain), "--version"]);
    run_cmd(cmd, "cargo")
}

pub(crate) fn cargo_command(config: &Config, toolchain: &str, args: &[&str]) -> io::Result<()> {
    info!("cargo '{}'...", args.join("' '"));

    let cargo = if toolchain.is_empty() {
        env!("CARGO")
    } else {
        let mut result = cargo_version(toolchain);
        if result.is_err() {
            info!("Installing toolchain '{}'...", toolchain);
            rustup(config, &["install", toolchain])?;

            result = cargo_version(toolchain);
        }
        result?;

        "cargo"
    };

    let mut cmd = process::Command::new(cargo);
    cmd.current_dir(&config.workspace_dir)
        .env("RUST_BACKTRACE", "1");

    if !toolchain.is_empty() {
        cmd.arg(&format!("+{}", toolchain));
    }

    cmd.args(args).args(&config.target_args);
    run_cmd(cmd, "cargo")
}

pub(crate) fn rustup(_config: &Config, args: &[&str]) -> io::Result<()> {
    let mut cmd = process::Command::new("rustup");
    cmd.args(args);
    run_cmd(cmd, "rustup")
}
