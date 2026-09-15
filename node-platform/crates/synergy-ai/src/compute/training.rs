use crate::valid;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingRequest {
    pub model_id: String,
    pub dataset_root: String,
    pub epochs: u32,
    pub maximum_steps: u64,
}
impl TrainingRequest {
    pub fn validate(&self) -> Result<(), String> {
        if !valid(&self.model_id)
            || !valid(&self.dataset_root)
            || self.epochs == 0
            || self.maximum_steps == 0
        {
            return Err("invalid training request".into());
        }
        Ok(())
    }
}
