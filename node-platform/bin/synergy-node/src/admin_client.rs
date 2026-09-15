use std::path::Path;

use synergy_admin_api::{AdminError, AdminRequest, AdminResponse};

#[cfg(unix)]
pub fn request(socket_path: &Path, request: &AdminRequest) -> Result<AdminResponse, AdminError> {
    synergy_admin_api::local::request(socket_path, request)
}

#[cfg(not(unix))]
pub fn request(_: &Path, _: &AdminRequest) -> Result<AdminResponse, AdminError> {
    Err(AdminError::unavailable(
        "the local Synergy Admin API requires a Unix-domain socket",
    ))
}
