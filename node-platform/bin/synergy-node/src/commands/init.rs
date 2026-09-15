use std::path::PathBuf;

use super::{absolute_path, nonempty};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitializationRequest {
    pub node_name: String,
    pub role: String,
    pub configuration_path: PathBuf,
    pub data_directory: PathBuf,
}

pub fn request(
    node_name: &str,
    role: &str,
    configuration_path: &str,
    data_directory: &str,
) -> Result<InitializationRequest, String> {
    let configuration_path = absolute_path(configuration_path, "configuration path")?;
    let data_directory = absolute_path(data_directory, "data directory")?;
    if configuration_path == data_directory || configuration_path.starts_with(&data_directory) {
        return Err("configuration path and data directory must be distinct".into());
    }
    Ok(InitializationRequest {
        node_name: nonempty(node_name, "node name", 128)?,
        role: nonempty(role, "role", 64)?,
        configuration_path,
        data_directory,
    })
}
