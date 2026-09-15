use crate::valid;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRequest {
    pub objective_root: String,
    pub allowed_tools: BTreeSet<String>,
    pub maximum_steps: u32,
}
impl AgentRequest {
    pub fn validate(&self) -> Result<(), String> {
        if !valid(&self.objective_root)
            || self.allowed_tools.is_empty()
            || self.maximum_steps == 0
            || self.allowed_tools.iter().any(|v| !valid(v))
        {
            return Err("invalid bounded agent request".into());
        }
        Ok(())
    }
}
