use std::path::{Path, PathBuf};

use crate::StorageError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskObservation {
    pub available_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskGuard {
    minimum_free_bytes: u64,
}

impl DiskGuard {
    pub fn new(minimum_free_bytes: u64) -> Result<Self, StorageError> {
        if minimum_free_bytes == 0 {
            return Err(StorageError::InvalidDiskThreshold);
        }
        Ok(Self { minimum_free_bytes })
    }

    pub fn observe(&self, path: impl AsRef<Path>) -> Result<DiskObservation, StorageError> {
        observe_available_bytes(path.as_ref())
    }

    pub fn check_path(&self, path: impl AsRef<Path>) -> Result<DiskObservation, StorageError> {
        let observation = self.observe(path)?;
        self.check(observation)?;
        Ok(observation)
    }

    pub fn check(&self, observation: DiskObservation) -> Result<(), StorageError> {
        if observation.available_bytes < self.minimum_free_bytes {
            return Err(StorageError::DiskPressure {
                available: observation.available_bytes,
                required: self.minimum_free_bytes,
            });
        }
        Ok(())
    }
}

#[cfg(unix)]
fn observe_available_bytes(path: &Path) -> Result<DiskObservation, StorageError> {
    use std::{ffi::CString, mem::MaybeUninit, os::unix::ffi::OsStrExt};

    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| StorageError::InvalidPath)?;
    let mut statistics = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is a NUL-terminated CString and `statistics` points to
    // writable storage for one `statvfs` value.
    let result = unsafe { libc::statvfs(path.as_ptr(), statistics.as_mut_ptr()) };
    if result != 0 {
        return Err(StorageError::Io(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    // SAFETY: a successful `statvfs` call initialized the output structure.
    let statistics = unsafe { statistics.assume_init() };
    let available_bytes = (statistics.f_bavail as u64)
        .checked_mul(statistics.f_frsize as u64)
        .ok_or_else(|| StorageError::Io("filesystem free-space value overflowed".into()))?;
    Ok(DiskObservation { available_bytes })
}

#[cfg(not(unix))]
fn observe_available_bytes(path: &Path) -> Result<DiskObservation, StorageError> {
    let _: PathBuf = path.to_path_buf();
    Err(StorageError::Io(
        "filesystem free-space observation is unavailable on this platform".into(),
    ))
}
