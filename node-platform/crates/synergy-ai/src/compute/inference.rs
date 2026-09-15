use crate::valid;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceRequest {
    pub model_id: String,
    pub input_root: String,
    pub maximum_output_tokens: u32,
}
impl InferenceRequest {
    pub fn validate(&self) -> Result<(), String> {
        if !valid(&self.model_id) || !valid(&self.input_root) || self.maximum_output_tokens == 0 {
            return Err("invalid inference request".into());
        }
        Ok(())
    }
}
