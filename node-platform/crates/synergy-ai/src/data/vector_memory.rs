use crate::valid;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorRecord {
    pub record_id: String,
    pub namespace: String,
    pub vector_root: String,
    pub dimensions: u32,
}
impl VectorRecord {
    pub fn validate(&self) -> Result<(), String> {
        if !valid(&self.record_id)
            || !valid(&self.namespace)
            || !valid(&self.vector_root)
            || self.dimensions == 0
        {
            return Err("invalid vector record".into());
        }
        Ok(())
    }
}
