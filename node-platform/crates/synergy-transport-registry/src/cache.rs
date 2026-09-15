use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{SignedTransportSnapshot, SnapshotError, MAX_SNAPSHOT_BYTES};

#[derive(Debug, Clone)]
pub struct TransportSnapshotCache {
    path: PathBuf,
}

impl TransportSnapshotCache {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, SnapshotError> {
        let path = path.as_ref();
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(SnapshotError::InvalidDocument(
                "snapshot cache path must be an absolute file path".into(),
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    pub fn load(&self) -> Result<Option<SignedTransportSnapshot>, SnapshotError> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error("open snapshot cache", error)),
        };
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_SNAPSHOT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("read snapshot cache", error))?;
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(SnapshotError::InvalidDocument(
                "cached snapshot exceeds size limit".into(),
            ));
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| SnapshotError::InvalidDocument(error.to_string()))
    }

    pub fn store(&self, snapshot: &SignedTransportSnapshot) -> Result<(), SnapshotError> {
        let bytes = serde_json::to_vec(snapshot)
            .map_err(|error| SnapshotError::InvalidDocument(error.to_string()))?;
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(SnapshotError::InvalidDocument(
                "snapshot exceeds size limit".into(),
            ));
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| SnapshotError::InvalidDocument("snapshot cache has no parent".into()))?;
        fs::create_dir_all(parent).map_err(|error| io_error("create cache directory", error))?;
        let temporary = self.path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| io_error("open temporary snapshot cache", error))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| io_error("write snapshot cache", error))?;
        fs::rename(&temporary, &self.path)
            .map_err(|error| io_error("install snapshot cache", error))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error("sync snapshot cache directory", error))
    }
}

fn io_error(operation: &str, error: std::io::Error) -> SnapshotError {
    SnapshotError::InvalidDocument(format!("{operation}: {error}"))
}
