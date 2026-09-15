use crate::valid;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedRound {
    pub round_id: String,
    pub model_root: String,
    pub participants: Vec<String>,
    pub minimum_updates: usize,
}
impl FederatedRound {
    pub fn validate(&self) -> Result<(), String> {
        if !valid(&self.round_id)
            || !valid(&self.model_root)
            || self.participants.is_empty()
            || self.minimum_updates == 0
            || self.minimum_updates > self.participants.len()
        {
            return Err("invalid federated round".into());
        }
        Ok(())
    }
}
