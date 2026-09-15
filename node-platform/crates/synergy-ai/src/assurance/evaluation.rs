use crate::valid;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationReport {
    pub job_id: String,
    pub evaluator_id: String,
    pub evidence_root: String,
    pub score_millionths: u32,
}
impl EvaluationReport {
    pub fn validate(&self) -> Result<(), String> {
        if !valid(&self.job_id)
            || !valid(&self.evaluator_id)
            || !valid(&self.evidence_root)
            || self.score_millionths > 1_000_000
        {
            return Err("invalid evaluation".into());
        }
        Ok(())
    }
}
