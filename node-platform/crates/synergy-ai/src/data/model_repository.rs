use crate::valid;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelArtifact {
    pub model_id: String,
    pub version: String,
    pub artifact_root: String,
    pub parameter_count: u64,
}
impl ModelArtifact {
    pub fn validate(&self) -> Result<(), String> {
        if !valid(&self.model_id)
            || !valid(&self.version)
            || !valid(&self.artifact_root)
            || self.parameter_count == 0
        {
            return Err("invalid model artifact".into());
        }
        Ok(())
    }
}
