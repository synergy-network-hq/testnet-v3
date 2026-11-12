use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseBinding {
    pub release: String,
    pub artifact_hash: String,
    pub minimum_database_version: u32,
}
impl ReleaseBinding {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.release.trim().is_empty() && crate::hash::hex64(&self.artifact_hash) {
            Ok(())
        } else {
            Err("invalid release binding")
        }
    }
}
