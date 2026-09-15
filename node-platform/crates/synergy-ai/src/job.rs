use crate::{valid, AiCapability};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRequest {
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub gpu_memory_bytes: u64,
    pub maximum_runtime_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiJob {
    pub job_id: String,
    pub submitter: String,
    pub capability: AiCapability,
    pub input_roots: Vec<String>,
    pub resources: ResourceRequest,
    pub policy_id: String,
}
impl AiJob {
    pub fn validate(&self) -> Result<(), String> {
        if !valid(&self.job_id)
            || !valid(&self.submitter)
            || !valid(&self.policy_id)
            || self.input_roots.is_empty()
            || self.input_roots.len() > 256
            || self.input_roots.iter().any(|v| !valid(v))
            || self.resources.cpu_millis == 0
            || self.resources.memory_bytes == 0
            || self.resources.maximum_runtime_ms == 0
        {
            return Err("invalid bounded AI job".into());
        }
        Ok(())
    }
}
