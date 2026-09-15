use crate::valid;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetProvenance {
    pub dataset_id: String,
    pub content_root: String,
    pub source_roots: Vec<String>,
    pub license_id: String,
}
impl DatasetProvenance {
    pub fn validate(&self) -> Result<(), String> {
        if !valid(&self.dataset_id)
            || !valid(&self.content_root)
            || !valid(&self.license_id)
            || self.source_roots.is_empty()
        {
            return Err("invalid dataset provenance".into());
        }
        Ok(())
    }
}
