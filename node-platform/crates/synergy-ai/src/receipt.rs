use crate::valid;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcome {
    Completed,
    Failed,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiReceipt {
    pub job_id: String,
    pub provider_id: String,
    pub outcome: ReceiptOutcome,
    pub output_root: Option<String>,
    pub usage_root: String,
    pub attestation: Vec<u8>,
}
impl AiReceipt {
    pub fn validate(&self) -> Result<(), String> {
        if !valid(&self.job_id)
            || !valid(&self.provider_id)
            || !valid(&self.usage_root)
            || self.attestation.is_empty()
            || self.attestation.len() > 65536
            || (self.outcome == ReceiptOutcome::Completed
                && self.output_root.as_ref().is_none_or(|v| !valid(v)))
        {
            return Err("invalid AI receipt".into());
        }
        Ok(())
    }
}
