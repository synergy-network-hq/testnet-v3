use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError, EtdagParameters, IngressKemKeyRegistry};

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
            || self.profile_id != self.parameters.profile_id
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

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> GovernedEtdagManifest {
        serde_json::from_value(serde_json::json!({
            "manifest_version":1,"network_id":"isolated","chain_id":1266,
            "profile_id":crate::ETDAG_PROFILE_ID,"activation_height":1,
            "parameters":EtdagParameters::default(),
            "fee_schedule":{"schedule_version":1,"classes":[{"class_id":0,"gas_units":1,"ciphertext_bytes":512,"minimum_fee":0}]},
            "ingress_keys":{"context_root":"a".repeat(128),"records":[{"key_id":"k","validator_id":"v","public_key":{"algorithm":"ML-KEM-1024","public_key":[1]},"activation_height":1,"retirement_height":null}]}
        })).unwrap()
    }

    #[test]
    fn manifest_requires_matching_supported_parameter_profile() {
        let mut value = manifest();
        assert!(value.validate().is_ok());
        value.parameters.profile_id = crate::ETDAG_EXPERIMENTAL_PROFILE_ID.into();
        value.parameters.target_height_offset = 6;
        assert!(value.validate().is_err());
        value.profile_id = value.parameters.profile_id.clone();
        assert!(value.validate().is_ok());
        value.parameters.target_height_offset = 5;
        assert!(value.validate().is_err());
        value.profile_id = "unknown".into();
        value.parameters.profile_id = "unknown".into();
        assert!(value.validate().is_err());
    }
}
