use crate::valid;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndependenceEvidence {
    pub evaluator_id: String,
    pub provider_id: String,
    pub disclosure_root: String,
}
impl IndependenceEvidence {
    pub fn validate(&self) -> Result<(), String> {
        if !valid(&self.evaluator_id)
            || !valid(&self.provider_id)
            || !valid(&self.disclosure_root)
            || self.evaluator_id == self.provider_id
        {
            return Err("assurance is not independent".into());
        }
        Ok(())
    }
}
