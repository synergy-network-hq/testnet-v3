use serde::{Deserialize, Serialize};
use synergy_etdag::{EtdagDigest, EtdagParameters};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisEtdag {
    pub parameters: EtdagParameters,
    pub cryptographic_profile_root: String,
    pub ingress_kem_registry_root: EtdagDigest,
}

impl GenesisEtdag {
    pub fn validate(&self) -> Result<(), String> {
        self.parameters
            .validate()
            .map_err(|error| format!("{error:?}"))?;
        self.ingress_kem_registry_root
            .validate()
            .map_err(|error| format!("{error:?}"))?;
        if self.cryptographic_profile_root.trim().is_empty() {
            return Err("ETDAG cryptographic profile root is empty".into());
        }
        Ok(())
    }
}
