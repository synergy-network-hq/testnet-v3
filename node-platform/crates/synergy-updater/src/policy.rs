use serde::{Deserialize, Serialize};

use crate::ReleaseChannel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateMode {
    NotifyOnly,
    StageOnly,
    InstallWhenHealthy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticUpdatePolicy {
    pub channel: ReleaseChannel,
    pub mode: UpdateMode,
    pub minimum_free_bytes: u64,
    pub maximum_artifact_bytes: u64,
    pub allow_rollback: bool,
}

impl AutomaticUpdatePolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.minimum_free_bytes == 0
            || self.maximum_artifact_bytes == 0
            || self.maximum_artifact_bytes > crate::MAXIMUM_ARTIFACT_BYTES
        {
            return Err("invalid update policy limits");
        }
        Ok(())
    }
}
