use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::key_provider::{ProviderError, ProviderKeyReference};

pub struct FilesystemKeyReference {
    path: PathBuf,
    key_id: String,
}

impl FilesystemKeyReference {
    pub fn new(path: impl AsRef<Path>, key_id: impl Into<String>) -> Result<Self, ProviderError> {
        let path = path.as_ref();
        let key_id = key_id.into();
        if !path.is_absolute() || key_id.trim().is_empty() {
            return Err(ProviderError::InvalidReference);
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| ProviderError::Unavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            return Err(ProviderError::InvalidMaterial);
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ProviderError::PermissionDenied);
        }
        Ok(Self {
            path: path.to_path_buf(),
            key_id,
        })
    }

    pub fn provider_reference(&self) -> ProviderKeyReference {
        ProviderKeyReference {
            provider: format!("aegis-filesystem:{}", self.path.display()),
            key_id: self.key_id.clone(),
        }
    }
}
