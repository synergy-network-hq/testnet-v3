use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::etdag::GenesisEtdag;
use crate::network::GenesisNetwork;
use crate::validator_set::{self, GenesisValidator};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedGenesis {
    pub format_version: u32,
    pub network: GenesisNetwork,
    pub validators: Vec<GenesisValidator>,
    pub etdag: GenesisEtdag,
    pub initial_state_root: String,
    pub authority_trust_key_id: String,
}

impl UnsignedGenesis {
    pub fn validate(&self) -> Result<(), String> {
        if self.format_version != 1
            || self.initial_state_root.trim().is_empty()
            || self.authority_trust_key_id.trim().is_empty()
        {
            return Err("invalid unsigned genesis header".into());
        }
        self.network.validate()?;
        validator_set::validate(&self.validators)?;
        self.etdag.validate()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| format!("encode genesis: {error}"))
    }

    pub fn genesis_hash(&self) -> Result<String, String> {
        let bytes = self.canonical_bytes()?;
        let mut hasher = Sha3_256::new();
        hasher.update(b"SYNERGY_CHAIN1266_GENESIS_V1");
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }
}
