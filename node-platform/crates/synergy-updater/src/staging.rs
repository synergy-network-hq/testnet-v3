use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use crate::VerifiedRelease;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedArtifact {
    pub release_id: String,
    pub path: PathBuf,
}

#[derive(Debug)]
pub enum StagingError {
    InvalidRoot,
    AlreadyExists,
    Io(std::io::Error),
}

impl From<std::io::Error> for StagingError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn stage_artifact(
    root: &Path,
    release: &VerifiedRelease,
    artifact: &[u8],
) -> Result<StagedArtifact, StagingError> {
    if !root.is_absolute()
        || root
            .symlink_metadata()
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
    {
        return Err(StagingError::InvalidRoot);
    }
    fs::create_dir_all(root)?;
    let name = release.signed.release.release_id.replace(
        |character: char| {
            !character.is_ascii_alphanumeric() && character != '-' && character != '_'
        },
        "_",
    );
    let directory = root.join(name);
    fs::create_dir(&directory).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            StagingError::AlreadyExists
        } else {
            StagingError::Io(error)
        }
    })?;
    let path = directory.join("artifact.bin");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    file.write_all(artifact)?;
    file.sync_all()?;
    sync_directory(&directory)?;
    sync_directory(root)?;
    Ok(StagedArtifact {
        release_id: release.signed.release.release_id.clone(),
        path,
    })
}

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    OpenOptions::new().read(true).open(path)?.sync_all()
}
