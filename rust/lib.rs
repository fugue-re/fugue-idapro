//! Fugue importer glue for IDA Pro.
//!
//! Example use:
//! ```rust,ignore
//! use fugue::db::DatabaseImporter;
//! use fugue::ir::LanguageDB;
//!
//! let ldb = LanguageDB::from_directory_with("path/to/processors", true)?;
//! let mut dbi = DatabaseImporter::new("/bin/ls");
//!
//! dbi.register_backend(IDA::new()?);
//!
//! let db = dbi.import(&ldb)?;
//! ```

use std::env;
use std::path::{Path, PathBuf};
use std::process;

use fugue_db::Error as ExportError;
use fugue_db::backend::{Backend, Imported};

use tempfile::tempdir;
use which::{which, which_in};
use url::Url;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IDA Pro is not available as a backend")]
    NotAvailable,
    #[error("invalid path to IDA Pro: {0}")]
    InvalidPath(which::Error),
    #[error("error launching IDA Pro: {0}")]
    Launch(std::io::Error),
    #[error("IDA Pro reported I/O error")]
    InputOutput,
    #[error("IDA Pro reported error on import")]
    Import,
    #[error("IDA Pro reported unsupported file type")]
    Unsupported,
    #[error("IDA Pro reported error when attempting to rebase")]
    Rebase,
    #[error("IDA Pro encountered a generic failure")]
    Failure,
    #[error("could not create temporary directory to store exported database: {0}")]
    TempDirectory(#[source] std::io::Error),
    #[error("`{0}` is not a supported URL scheme")]
    UnsupportedScheme(String),
}

impl From<Error> for ExportError {
    fn from(e: Error) -> Self {
        ExportError::importer_error("ida-pro", e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IDA {
    ida_path: Option<PathBuf>,
    fdb_path: Option<PathBuf>,
    overwrite: bool,
    wine: bool,
}

impl Default for IDA {
    fn default() -> Self {
        Self {
            ida_path: None,
            fdb_path: None,
            overwrite: false,
            wine: false,
        }
    }
}

impl IDA {
    fn find_ida<F: Fn(&str) -> Result<PathBuf, Error>>(f: F) -> Result<(PathBuf, bool), Error> {
        if let Ok(local) = f("idat64").or_else(|_| f("ida64")) {
            Ok((local, false))
        } else {
            f("idat64.exe").or_else(|_| f("ida64.exe")).map(|path| (path, true))
        }
    }

    pub fn new() -> Result<Self, Error> {
        if let Ok(root_dir) = env::var("IDA_INSTALL_DIR") {
            if let Ok(v) = Self::from_path(root_dir) {
                return Ok(v);
            }
        }

        if let Ok((ida_path, wine)) = Self::find_ida(|p| which(p).map_err(Error::InvalidPath)) {
            Ok(Self { ida_path: Some(ida_path), wine, ..Default::default() })
        } else {
            Err(Error::NotAvailable)
        }
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let root_dir = path.as_ref();
        let (ida_path, wine) =
            Self::find_ida(|p| which_in(p, Some(root_dir), ".").map_err(Error::InvalidPath))?;

        Ok(Self { ida_path: Some(ida_path), wine, ..Default::default() })
    }

    pub fn export_path<P: AsRef<Path>>(mut self, path: P, overwrite: bool) -> Self {
        self.fdb_path = Some(path.as_ref().to_owned());
        self.overwrite = overwrite;
        self
    }
}

impl Backend for IDA {
    type Error = Error;

    fn name(&self) -> &'static str {
        "fugue-idapro"
    }

    fn is_available(&self) -> bool {
        self.ida_path.is_some()
    }

    fn is_preferred_for(&self, path: &Url) -> Option<bool> {
        if path.scheme() != "file" {
            return None
        }

        if let Ok(path) = path.to_file_path() {
            path.extension()
                .map(|ext| Some(ext == "i64" || ext == "idb"))
                .unwrap_or(Some(false))
        } else {
            None
        }
    }

    fn import(&self, program: &Url) -> Result<Imported, Self::Error> {
        if program.scheme() != "file" {
            return Err(Error::UnsupportedScheme(program.scheme().to_owned()))
        }

        let program = program.to_file_path()
            .map_err(|_| Error::UnsupportedScheme(program.scheme().to_owned()))?;

        let ida_path = self.ida_path.as_ref().ok_or_else(|| Error::NotAvailable)?;

        let load_existing = program.exists()
            && program
                .extension()
                .map(|e| e == "i64" || e == "idb")
                .unwrap_or(false);

        let force_32bit =
            load_existing && program.extension().map(|e| e == "idb").unwrap_or(false);

        let mut cmd = if !self.wine {
            if force_32bit {
                process::Command::new(format!(
                    "{}",
                    ida_path.with_file_name("idat").display()
                ))
            } else {
                process::Command::new(format!("{}", ida_path.display()))
            }
        } else {
            let mut process = process::Command::new("wine");
            if force_32bit {
                process.arg(format!(
                    "{}",
                    ida_path.with_file_name("idat.exe").display()
                ));
            } else {
                process.arg(format!("{}", ida_path.display()));
            }
            process
        };

        cmd.arg("-A");

        let mut tmp = tempdir()
            .map_err(Error::TempDirectory)?
            .into_path();

        let output = if let Some(ref fdb_path) = self.fdb_path {
            fdb_path.to_owned()
        } else {
            tmp.join("fugue-temp-export.fdb")
        };

        let opts = vec![
            format!("-OFugueOutput:{}", output.display()),
            format!("-OFugueForceOverwrite:{}", self.overwrite),
        ];

        /*
        if let Some(rebase) = rebase {
            if rebase_relative > 0 {
                opts.push(format!("-OFugueRebase:+{:#x}", rebase));
            } else if rebase_relative < 0 {
                opts.push(format!("-OFugueRebase:-{:#x}", rebase));
            } else {
                opts.push(format!("-OFugueRebase:{:#x}", rebase));
            }
        }
        */

        if load_existing {
            cmd.args(&opts);
            cmd.arg(&format!("{}", program.display()));
        } else {
            tmp.push("fugue-import-tmp.ida");
            cmd.arg(&format!("-o{}", tmp.display()));
            cmd.args(&opts);
            cmd.arg(&format!("{}", program.display()));
        }

        match cmd
            .output()
            .map_err(Error::Launch)
            .map(|output| output.status.code())?
        {
            Some(100) => Ok(Imported::File(output)),
            Some(101) => Err(Error::InputOutput)?,
            Some(102) => Err(Error::Import)?,
            Some(103) => Err(Error::Unsupported)?,
            Some(104) => Err(Error::Rebase)?,
            _ => Err(Error::Failure)?,
        }
    }
}
