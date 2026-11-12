use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const DEFAULT_MAXIMUM_UPDATE_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpdateChannel {
    #[default]
    Stable,
    Candidate,
    Development,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpdateMode {
    #[default]
    NotifyOnly,
    StageOnly,
    InstallWhenHealthy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateConfiguration {
    pub enabled: bool,
    pub channel: UpdateChannel,
    pub mode: UpdateMode,
    pub catalog_path: Option<PathBuf>,
    pub release_signer_key_id: Option<String>,
    pub release_signer_public_key_path: Option<PathBuf>,
    pub staging_directory: Option<PathBuf>,
    pub installed_sequence: u64,
    pub minimum_free_bytes: u64,
    pub maximum_artifact_bytes: u64,
    pub allow_rollback: bool,
}

impl Default for UpdateConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            channel: UpdateChannel::Stable,
            mode: UpdateMode::NotifyOnly,
            catalog_path: None,
            release_signer_key_id: None,
            release_signer_public_key_path: None,
            staging_directory: None,
            installed_sequence: 0,
            minimum_free_bytes: 2 * 1024 * 1024 * 1024,
            maximum_artifact_bytes: DEFAULT_MAXIMUM_UPDATE_ARTIFACT_BYTES,
            allow_rollback: true,
        }
    }
}
