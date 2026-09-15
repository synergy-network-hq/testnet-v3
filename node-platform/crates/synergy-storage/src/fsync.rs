use std::{fs, path::Path};

use crate::StorageError;

#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> Result<(), StorageError> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| StorageError::Io(error.to_string()))
}

#[cfg(not(unix))]
pub(crate) fn sync_directory(_: &Path) -> Result<(), StorageError> {
    Ok(())
}
