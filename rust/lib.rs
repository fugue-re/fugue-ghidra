use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use fugue_db::backend::{Backend, Imported};
use fugue_db::Error as ExportError;

use tempfile::tempdir;
use thiserror::Error;
use url::Url;
use which::{which, which_in};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Ghidra is not available as a backend")]
    NotAvailable,
    #[error("invalid path to Ghidra: {0}")]
    InvalidPath(#[from] which::Error),
    #[error("invalid input path: {0}")]
    InvalidInputPath(PathBuf),
    #[error("error launching Ghidra exporter: {0}")]
    Launch(#[from] std::io::Error),
    #[error("Ghidra reported I/O error")]
    InputOutput,
    #[error("Ghidra reported error on import")]
    Import,
    #[error("Ghidra reported unsupported file type")]
    Unsupported,
    #[error("Ghidra encountered a generic failure")]
    Failure,
    #[error("could not fix ownership on project file: {0}")]
    Ownership(#[source] std::io::Error),
    #[error("could not create temporary directory for export: {0}")]
    TempDirectory(#[source] std::io::Error),
    #[error("`{0}` is not a supported URL scheme")]
    UnsupportedScheme(String),
}

impl From<Error> for ExportError {
    fn from(e: Error) -> Self {
        Self::importer_error("ghidra", e)
    }
}

#[derive(Debug)]
pub struct GhidraProject {
    project_root: PathBuf,
    project_name: OsString,
    project_path: PathBuf,
    project_file: PathBuf,
    previous_prp: Vec<u8>,
}

macro_rules! PRP_TEMPLATE {
    () => {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
    <BASIC_INFO>
        <STATE NAME="OWNER" TYPE="string" VALUE="{}" />
    </BASIC_INFO>
</FILE_INFO>"#
    };
}

impl GhidraProject {
    fn toggle_ownership(&mut self, restore: bool) -> Result<(), Error> {
        let prp_path = self.project_path.join("project.prp");
        if !prp_path.exists() {
            return Ok(());
        }

        let old_prp = {
            let mut prp = File::open(&prp_path).map_err(Error::Ownership)?;
            let mut buf = Vec::new();
            prp.read_to_end(&mut buf).map_err(Error::Ownership)?;
            buf
        };

        let mut prp = File::create(&prp_path).map_err(Error::Ownership)?;

        if restore {
            prp.write_all(&self.previous_prp)
        } else {
            self.previous_prp = old_prp;
            write!(prp, PRP_TEMPLATE!(), whoami::username())
        }
        .map_err(Error::Ownership)?;

        Ok(())
    }

    pub fn modify_ownership(&mut self) -> Result<(), Error> {
        self.toggle_ownership(false)
    }

    pub fn restore_ownership(&mut self) -> Result<(), Error> {
        self.toggle_ownership(true)
    }

    pub fn resolve<P: AsRef<Path>>(path: P) -> Option<Self> {
        let path = path.as_ref();

        // there needs to be a project file
        if path.exists() {
            return None;
        }

        let mut parent = path.parent();
        while let Some(project_path) = parent {
            let rep_path = project_path.with_extension("rep");
            // first path that exists
            if rep_path.exists() {
                if project_path.exists() && rep_path != project_path {
                    if !project_path
                        .extension()
                        .map(|ext| ext == "gpr")
                        .unwrap_or(false)
                    {
                        // this can't be a real project
                        return None;
                    }
                }

                if project_path.extension().is_some() {
                    if !project_path
                        .extension()
                        .map(|ext| ext == "gpr" || ext == "rep")
                        .unwrap_or(false)
                    {
                        // this can't be a real project
                        return None;
                    }
                }

                let prp_path = rep_path.join("project.prp");
                if !prp_path.exists() {
                    // this can't be a real project if prp does not exist
                    return None;
                }

                // Sanity checks passed
                return Some(GhidraProject {
                    project_root: rep_path.parent()?.to_owned(),
                    project_name: rep_path.file_stem()?.to_owned(),
                    project_path: rep_path,
                    project_file: path.strip_prefix(project_path).ok()?.to_owned(),
                    previous_prp: Vec::default(),
                });
            }

            if project_path.exists() {
                return None;
            }
            parent = project_path.parent();
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ghidra {
    path: Option<PathBuf>,
    fdb_path: Option<PathBuf>,
    overwrite: bool,
    fix_ownership: bool,
}

impl Default for Ghidra {
    fn default() -> Self {
        Self {
            path: None,
            fdb_path: None,
            overwrite: false,
            fix_ownership: false,
        }
    }
}

impl Ghidra {
    fn find_ghidra<F: Fn(&str) -> Result<PathBuf, Error>>(f: F) -> Result<PathBuf, Error> {
        if cfg!(target_os = "windows") {
            f("ghidraRun.bat")
        } else {
            f("ghidraRun")
        }
    }

    fn find_headless<F: Fn(&str) -> Result<PathBuf, Error>>(f: F) -> Result<PathBuf, Error> {
        if cfg!(target_os = "windows") {
            f("analyzeHeadless.bat")
        } else {
            f("analyzeHeadless")
        }
    }

    pub fn new() -> Result<Self, ExportError> {
        let root = if let Ok(root_dir) = env::var("GHIDRA_INSTALL_DIR") {
            PathBuf::from(root_dir).join("support")
        } else {
            let base = Self::find_ghidra(|p| which(p).map_err(Error::InvalidPath))
                .map_err(ExportError::from)?;
            base.parent().unwrap().join("support")
        };

        let path =
            Self::find_headless(|p| which_in(p, Some(&root), ".").map_err(Error::InvalidPath))
                .map_err(ExportError::from)?;

        Ok(Self {
            path: Some(path),
            ..Default::default()
        })
    }

    pub fn export_path<P: AsRef<Path>>(mut self, path: P, overwrite: bool) -> Self {
        self.fdb_path = Some(path.as_ref().to_owned());
        self.overwrite = overwrite;
        self
    }

    pub fn force_ownership(mut self, force: bool) -> Self {
        self.fix_ownership = force;
        self
    }
}

impl Backend for Ghidra {
    type Error = Error;

    fn name(&self) -> &'static str {
        "fugue-ghidra"
    }

    fn is_available(&self) -> bool {
        self.path.is_some()
    }

    fn is_preferred_for(&self, path: &Url) -> Option<bool> {
        if path.scheme() != "file" {
            return None;
        }

        if let Ok(path) = path.to_file_path() {
            Some(GhidraProject::resolve(&path).is_some())
        } else {
            None
        }
    }

    fn import(&self, program: &Url) -> Result<Imported, Error> {
        if program.scheme() != "file" {
            return Err(Error::UnsupportedScheme(program.scheme().to_owned()));
        }

        let path = program
            .to_file_path()
            .map_err(|_| Error::UnsupportedScheme(program.scheme().to_owned()))?;

        let headless = self.path.as_ref().ok_or_else(|| Error::NotAvailable)?;
        let mut process = process::Command::new(headless);

        // Check if the file is a ghidra project
        let mut project = GhidraProject::resolve(&path);

        if let Some(ref project) = project {
            // existing

            let location = project.project_root.clone();
            let project_name = project.project_name.clone();
            let project_file = project.project_file.clone();

            process.arg(location);
            process.arg(project_name);

            process.arg("-process");
            process.arg(project_file);
        } else {
            // Not a ghidra project, so we need to create one
            let tmp = tempdir().map_err(Error::TempDirectory)?.into_path();
            process.arg(tmp);
            process.arg("fugue-temp-project");

            process.arg("-import");
            process.arg(path);

            process.arg("-deleteProject");
        }

        process.arg("-preScript");
        process.arg("FugueAnalysisOptions.java");

        process.arg("-postScript");
        process.arg("FugueExport.java");

        process.arg(format!("FugueForceOverwrite:{}", self.overwrite));

        let output = if let Some(ref fdb_path) = self.fdb_path {
            process.arg(format!("FugueOutput:{}", fdb_path.display()));
            Imported::File(fdb_path.to_owned())
        } else {
            let mut tmp = tempdir().map_err(Error::TempDirectory)?.into_path();
            tmp.push("fugue-temp-export.fdb");
            process.arg(format!("FugueOutput:{}", tmp.display()));
            Imported::File(tmp)
        };

        // Fix ownership of ghidra project
        if self.fix_ownership {
            if let Some(ref mut project) = project {
                project.modify_ownership()?;
            }
        }

        let result = match process
            .output()
            .map_err(Error::Launch)
            .map(|output| output.status.code())
        {
            Ok(Some(100)) => Ok(output),
            Ok(Some(101)) => Err(Error::InputOutput),
            Ok(Some(102)) => Err(Error::Import),
            Ok(Some(103)) => Err(Error::Unsupported),
            Ok(_) => Err(Error::Failure),
            Err(e) => Err(e),
        };

        if self.fix_ownership {
            if let Some(ref mut project) = project {
                project.restore_ownership()?;
            }
        }

        result
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_clean_import() -> Result<(), Box<dyn std::error::Error>> {
        let ghidra = Ghidra::new()?.export_path("/tmp/exported.fdb", true);
        let url = Url::from_file_path(Path::new("./tests/true").canonicalize()?).unwrap();

        let _ = ghidra.import(&url)?;

        Ok(())
    }
}
