use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError, EtdagParameters, IngressKemKeyRegistry, ETDAG_PROFILE_ID};

use super::EtdagFeeSchedule;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedEtdagManifest {
    pub manifest_version: u32,
    pub network_id: String,
    pub chain_id: u64,
    pub profile_id: String,
    pub activation_height: u64,
    pub parameters: EtdagParameters,
    pub fee_schedule: EtdagFeeSchedule,
    pub ingress_keys: IngressKemKeyRegistry,
}

impl GovernedEtdagManifest {
    pub fn validate(&self) -> Result<(), EtdagError> {
        if self.manifest_version != 1
            || self.network_id.trim().is_empty()
            || self.chain_id == 0
            || self.profile_id != ETDAG_PROFILE_ID
            || self.activation_height == 0
        {
            return Err(EtdagError::Governance("invalid ETDAG manifest".into()));
        }
        self.parameters.validate()?;
        self.fee_schedule.validate()?;
        crate::crypto::validate_key_schedule(&self.ingress_keys)
    }

    pub fn root(&self) -> Result<EtdagDigest, EtdagError> {
        self.validate()?;
        EtdagDigest::from_canonical("SYNERGY_ETDAG_GOVERNANCE_MANIFEST_V1", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEtdagManifest {
    pub manifest: GovernedEtdagManifest,
    pub authority_id: String,
    pub key_id: String,
    pub signature: Vec<u8>,
}
