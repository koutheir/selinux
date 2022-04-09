use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::{env, io};

use log::info;

mod coverage;
mod errors;
mod utils;

use crate::coverage::coverage;
use crate::errors::{Error, Result};

fn main() -> Result<()> {
    let mut args = env::args_os();
    let target = args.nth(1);
    if let Some(target) = target.as_deref().and_then(OsStr::to_str) {
        let verbose = target != "clippy";
        init_logging(verbose)?;

        let config = Config::new(args.collect())?;
        run_target(&config, target)?;
        info!("Done.");
        Ok(())
    } else {
        usage()
    }
}

/// Initialize logging based on the logging level specified on the command line.
pub(crate) fn init_logging(verbose: bool) -> Result<()> {
    use simplelog::{
        ColorChoice, ConfigBuilder, LevelFilter, SimpleLogger, TermLogger, TerminalMode,
    };

    let level_filter = if verbose {
        LevelFilter::Trace
    } else {
        LevelFilter::Warn
    };

    let config = ConfigBuilder::new()
        .set_time_level(LevelFilter::Trace)
        .set_max_level(LevelFilter::Error)
        .set_target_level(LevelFilter::Error)
        .set_location_level(LevelFilter::Trace)
        .set_time_to_local(false)
        .build();

    // The build server does not have a terminal, use a logger to STDERR as fallback.
    TermLogger::init(
        level_filter,
        config.clone(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .or_else(move |_err| SimpleLogger::init(level_filter, config))
    .map_err(|_| {
        let err = io::ErrorKind::AlreadyExists.into();
        Error::from_io("simplelog::loggers::simplelog::SimpleLogger::init", err)
    })
}

struct Config {
    target_args: Vec<OsString>,
    workspace_dir: &'static Path,
    coverage_dir: PathBuf,
    coverage_profdata: PathBuf,
}

impl Config {
    fn new(target_args: Vec<OsString>) -> Result<Self> {
        let workspace_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or_else(|| {
                let err = io::ErrorKind::NotFound.into();
                Error::from_io_path("std::path::Path::parent", env!("CARGO_MANIFEST_DIR"), err)
            })?;

        let target_dir = workspace_dir.join("target");
        let coverage_dir = target_dir.join("coverage");
        let coverage_profdata = coverage_dir.join("coverage.profdata");

        Ok(Self {
            target_args,
            workspace_dir,
            coverage_dir,
            coverage_profdata,
        })
    }
}

fn usage() -> Result<()> {
    eprintln!("Please specify a target name, from one of the following targets:");
    eprintln!("    coverage.");
    eprintln!("You can also specify parameters after targets.");
    Ok(())
}

fn run_target(config: &Config, target: &str) -> Result<()> {
    match target {
        "coverage" => coverage(config),

        _ => usage(),
    }
}
