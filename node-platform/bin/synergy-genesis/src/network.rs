use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisNetwork {
    pub chain_id: u64,
    pub network_id: String,
    pub protocol_version: String,
    pub activation_unix: u64,
}

impl GenesisNetwork {
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id != 1266
            || self.network_id.trim().is_empty()
            || self.protocol_version.trim().is_empty()
            || self.activation_unix == 0
        {
            return Err("invalid Chain 1266 genesis network binding".into());
        }
        Ok(())
    }
}
