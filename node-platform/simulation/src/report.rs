use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationReport {
    pub name: String,
    pub passed: bool,
    pub finalized_height: u64,
    pub faults_injected: u64,
    pub notes: Vec<String>,
}
impl SimulationReport {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            Err("simulation report requires a name".into())
        } else {
            Ok(())
        }
    }
}
