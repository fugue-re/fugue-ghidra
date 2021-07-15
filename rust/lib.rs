use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process;

use fugue_db::backend::{Backend, Imported};
use fugue_db::Error as ExportError;

use tempfile::tempdir;
use thiserror::Error;
use which::{which, which_in};
use url::Url;

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
}

impl GhidraProject {
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
                    if !project_path.extension().map(|ext| ext == "gpr").unwrap_or(false) {
                        // this can't be a real project
                        return None;
                    }
                }

                if project_path.extension().is_some() {
                    if !project_path.extension().map(|ext| ext == "gpr" || ext == "rep").unwrap_or(false) {
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
                });
            }

            if project_path.exists() {
                return None;
            }
            parent = project_path.parent();
        }
        None
    }

    pub fn parts(&self) -> (&Path, &Path) {
        (&self.project_path, &self.project_file)
    }

    /*
    pub fn project(&self) -> Project {
        Project::new(
            Local::new(&self.project_root, self.project_name.to_string_lossy()),
            Process::file(&self.project_file),
        )
    }
    */
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ghidra {
    path: Option<PathBuf>,
    fdb_path: Option<PathBuf>,
    overwrite: bool,
}

impl Default for Ghidra {
    fn default() -> Self {
        Self {
            path: None,
            fdb_path: None,
            overwrite: false,
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

        let path = Self::find_headless(|p| {
            which_in(p, Some(&root), ".").map_err(Error::InvalidPath)
        })
        .map_err(ExportError::from)?;

        Ok(Self { path: Some(path), fdb_path: None, overwrite: false })
    }

    pub fn export_path<P: AsRef<Path>>(mut self, path: P, overwrite: bool) -> Self {
        self.fdb_path = Some(path.as_ref().to_owned());
        self.overwrite = overwrite;
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
            return None
        }

        if let Ok(path) = path.to_file_path() {
            Some(GhidraProject::resolve(&path).is_some())
        } else {
            None
        }
    }

    fn import(&self, program: &Url) -> Result<Imported, Error> {
        if program.scheme() != "file" {
            return Err(Error::UnsupportedScheme(program.scheme().to_owned()))
        }

        let path = program.to_file_path()
            .map_err(|_| Error::UnsupportedScheme(program.scheme().to_owned()))?;

        let headless = self.path.as_ref().ok_or_else(|| Error::NotAvailable)?;
        let mut process = process::Command::new(headless);

        if let Some(project) = GhidraProject::resolve(&path) {
            // existing
            let location = project.project_root.parent()
                .map(|p| p.to_owned())
                .ok_or_else(|| Error::InvalidInputPath(project.project_root.clone()))?;
            let mut project_name = PathBuf::from(project.project_root.file_stem()
                .ok_or_else(|| Error::InvalidInputPath(project.project_root.clone()))?);

            if let Some(parent) = project.project_file.parent() {
                project_name.push(parent);
            }

            let project_file = project.project_file.file_name()
                .ok_or_else(|| Error::InvalidInputPath(project.project_root.clone()))?;

            process.arg(location);
            process.arg(project_name);

            process.arg("-process");
            process.arg(project_file);
        } else {
            let tmp = tempdir()
                .map_err(Error::TempDirectory)?
                .into_path();
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
            let mut tmp = tempdir()
                .map_err(Error::TempDirectory)?
                .into_path();
            tmp.push("fugue-temp-export.fdb");
            process.arg(format!("FugueOutput:{}", tmp.display()));
            Imported::File(tmp)
        };

        println!("{:?}", process);

        match process
            .output()
            .map_err(Error::Launch)
            .map(|output| output.status.code())?
        {
            Some(100) => Ok(output),
            Some(101) => Err(Error::InputOutput),
            Some(102) => Err(Error::Import),
            Some(103) => Err(Error::Unsupported),
            _ => Err(Error::Failure),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_clean_import() -> Result<(), ExportError> {
        let ghidra = Ghidra::new()?;
        let url = Url::parse("file:///usr/bin/ls").unwrap();

        ghidra.import(&url)?;

        Ok(())
    }
}
