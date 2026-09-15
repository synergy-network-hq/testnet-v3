use std::path::PathBuf;

use super::absolute_path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    pub configuration_path: PathBuf,
    pub signed_manifest_path: PathBuf,
}

pub fn request(
    configuration_path: &str,
    signed_manifest_path: &str,
) -> Result<JoinRequest, String> {
    let configuration_path = absolute_path(configuration_path, "configuration path")?;
    let signed_manifest_path = absolute_path(signed_manifest_path, "signed manifest path")?;
    if configuration_path == signed_manifest_path {
        return Err("configuration and signed manifest paths must be distinct".into());
    }
    Ok(JoinRequest {
        configuration_path,
        signed_manifest_path,
    })
}
