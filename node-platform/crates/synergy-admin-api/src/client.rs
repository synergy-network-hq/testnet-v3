use std::path::{Path, PathBuf};

use crate::{AdminError, AdminRequest, AdminResponse};

#[derive(Debug, Clone)]
pub struct LocalAdminClient {
    socket_path: PathBuf,
}

impl LocalAdminClient {
    pub fn new(socket_path: impl AsRef<Path>) -> Result<Self, AdminError> {
        let socket_path = socket_path.as_ref();
        if !socket_path.is_absolute() {
            return Err(AdminError::invalid_request(
                "local Admin API socket path must be absolute",
            ));
        }
        Ok(Self {
            socket_path: socket_path.to_path_buf(),
        })
    }

    #[cfg(unix)]
    pub fn request(&self, request: &AdminRequest) -> Result<AdminResponse, AdminError> {
        crate::local::request(&self.socket_path, request)
    }
}
