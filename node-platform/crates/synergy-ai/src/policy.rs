use crate::{valid, AiCapability, AiJob};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiPolicy {
    pub policy_id: String,
    pub allowed: BTreeSet<AiCapability>,
    pub max_cpu_millis: u64,
    pub max_memory_bytes: u64,
    pub max_gpu_memory_bytes: u64,
    pub max_runtime_ms: u64,
    pub require_assurance: bool,
}
impl AiPolicy {
    pub fn authorize(&self, j: &AiJob) -> Result<(), String> {
        j.validate()?;
        if !valid(&self.policy_id)
            || j.policy_id != self.policy_id
            || !self.allowed.contains(&j.capability)
            || j.resources.cpu_millis > self.max_cpu_millis
            || j.resources.memory_bytes > self.max_memory_bytes
            || j.resources.gpu_memory_bytes > self.max_gpu_memory_bytes
            || j.resources.maximum_runtime_ms > self.max_runtime_ms
        {
            return Err("AI policy refused job".into());
        }
        Ok(())
    }
}
