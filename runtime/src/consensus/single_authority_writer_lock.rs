//! Exclusive single-writer lock for single-authority durable state.
//!
//! Two writable handles to the same finality log or signing journal would
//! break the sign-once and one-block-per-height guarantees, so writable open
//! must be exclusive. Read-only inspection never takes the writer role.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

/// RAII writer claim. Keep the lock file in place when releasing the lock so
/// every upgraded process locks the same inode.
#[derive(Debug)]
pub struct SingleAuthorityWriterLock {
    path: PathBuf,
    _file: File,
}

impl SingleAuthorityWriterLock {
    pub fn acquire(path: &Path) -> Result<Self, String> {
        let lock_path = path.with_extension("writer.lock");
        if let Some(parent) = lock_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|error| format!("Create single-authority lock directory: {error}"))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| format!("Open writer lock {}: {error}", lock_path.display()))?;
        file.try_lock().map_err(|error| {
            format!(
                "single-authority writable state {} is already open for writing or cannot be locked: {error}",
                path.display()
            )
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            _file: file,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
