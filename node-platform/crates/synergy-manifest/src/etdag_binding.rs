use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtdagBinding {
    pub parameters_hash: String,
    pub fee_schedule_hash: String,
    pub ingress_registry_hash: String,
    pub activation_height: u64,
}
impl EtdagBinding {
    pub fn validate(&self) -> Result<(), &'static str> {
        if [
            self.parameters_hash.as_str(),
            self.fee_schedule_hash.as_str(),
            self.ingress_registry_hash.as_str(),
        ]
        .into_iter()
        .all(crate::hash::hex64)
            && self.activation_height > 0
        {
            Ok(())
        } else {
            Err("invalid ETDAG binding")
        }
    }
}
