use serde::{Deserialize, Serialize};

use super::target_height::validate_protected_target_height_with_offset;
use crate::{EtdagDigest, EtdagError, EtdagParameters, MIN_TARGET_HEIGHT_OFFSET};

fn legacy_offset() -> u64 {
    MIN_TARGET_HEIGHT_OFFSET
}
fn is_legacy_offset(value: &u64) -> bool {
    *value == MIN_TARGET_HEIGHT_OFFSET
}

/// Compact admission context retained for the existing ingress foundation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetAdmissionContext {
    #[serde(default = "legacy_offset", skip_serializing_if = "is_legacy_offset")]
    pub target_height_offset: u64,
    pub source_finalized_height: u64,
    pub target_height: u64,
    pub active_validator_set_root: String,
    pub validator_consensus_key_root: String,
    pub frozen_voting_weight_root: String,
    pub assigned_cluster_validator_count: u64,
    pub assigned_cluster_total_voting_weight: u64,
}

impl TargetAdmissionContext {
    pub fn validate_with_parameters(&self, parameters: &EtdagParameters) -> Result<(), EtdagError> {
        parameters.validate_target_height(self.source_finalized_height, self.target_height)?;
        if self.target_height_offset != parameters.target_height_offset {
            return Err(EtdagError::ContextMismatch);
        }
        self.validate()
    }

    pub fn validate(&self) -> Result<(), EtdagError> {
        validate_protected_target_height_with_offset(
            self.source_finalized_height,
            self.target_height,
            self.target_height_offset,
        )?;
        if self.active_validator_set_root.is_empty()
            || self.validator_consensus_key_root.is_empty()
            || self.frozen_voting_weight_root.is_empty()
            || self.assigned_cluster_validator_count == 0
            || self.assigned_cluster_total_voting_weight == 0
        {
            return Err(EtdagError::ContextMismatch);
        }
        Ok(())
    }
}

/// Full immutable protected-admission authority migrated from the PoSy/ETDAG
/// protocol shape. It freezes only finalized facts; it never grants authority
/// from a route, VPN membership, or an operator-selected process role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetAdmissionContextV3 {
    pub context_version: u32,
    pub chain_id: u64,
    pub network_id: String,
    pub protocol_version: String,
    pub epoch: u64,
    pub target_height: u64,
    #[serde(default = "legacy_offset", skip_serializing_if = "is_legacy_offset")]
    pub target_height_offset: u64,
    pub source_finalized_height: u64,
    pub source_finality_context_root: String,
    pub active_validator_set_root: String,
    pub validator_consensus_key_root: String,
    pub frozen_voting_weight_root: String,
    pub cluster_schedule_version: String,
    pub finalized_epoch_seed_root: String,
    pub assigned_height_schedule_root: String,
    pub cluster_map_root: String,
    pub assigned_cluster_id: u64,
    pub assigned_cluster_membership_root: String,
    pub assigned_cluster_validator_count: u64,
    pub assigned_cluster_total_voting_weight: u64,
    pub consensus_parameter_root: String,
    pub cryptographic_profile_root: String,
    pub ingress_kem_registry_root: EtdagDigest,
}

impl TargetAdmissionContextV3 {
    pub fn validate_with_parameters(&self, parameters: &EtdagParameters) -> Result<(), EtdagError> {
        parameters.validate_target_height(self.source_finalized_height, self.target_height)?;
        if self.target_height_offset != parameters.target_height_offset {
            return Err(EtdagError::ContextMismatch);
        }
        self.validate()
    }

    pub fn validate(&self) -> Result<(), EtdagError> {
        validate_protected_target_height_with_offset(
            self.source_finalized_height,
            self.target_height,
            self.target_height_offset,
        )?;
        let roots = [
            &self.source_finality_context_root,
            &self.active_validator_set_root,
            &self.validator_consensus_key_root,
            &self.frozen_voting_weight_root,
            &self.finalized_epoch_seed_root,
            &self.assigned_height_schedule_root,
            &self.cluster_map_root,
            &self.assigned_cluster_membership_root,
            &self.consensus_parameter_root,
            &self.cryptographic_profile_root,
        ];
        if self.context_version != 1
            || self.chain_id == 0
            || self.protocol_version.trim().is_empty()
            || self.network_id.trim().is_empty()
            || self.assigned_cluster_validator_count == 0
            || self.assigned_cluster_total_voting_weight == 0
            || roots.iter().any(|root| root.trim().is_empty())
        {
            return Err(EtdagError::ContextMismatch);
        }
        self.ingress_kem_registry_root.validate()
    }

    pub fn root(&self) -> Result<EtdagDigest, EtdagError> {
        self.validate()?;
        EtdagDigest::from_canonical("SYNERGY_ETDAG_TARGET_ADMISSION_CONTEXT_V1", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ETDAG_EXPERIMENTAL_PROFILE_ID;

    const LEGACY_COMPACT: &str = r#"{"source_finalized_height":10,"target_height":15,"active_validator_set_root":"set","validator_consensus_key_root":"keys","frozen_voting_weight_root":"weight","assigned_cluster_validator_count":5,"assigned_cluster_total_voting_weight":10}"#;

    fn legacy_full_bytes() -> String {
        format!(
            r#"{{"context_version":1,"chain_id":1266,"network_id":"legacy","protocol_version":"v3","epoch":1,"target_height":5,"source_finalized_height":0,"source_finality_context_root":"r","active_validator_set_root":"r","validator_consensus_key_root":"r","frozen_voting_weight_root":"r","cluster_schedule_version":"1","finalized_epoch_seed_root":"r","assigned_height_schedule_root":"r","cluster_map_root":"r","assigned_cluster_id":0,"assigned_cluster_membership_root":"r","assigned_cluster_validator_count":5,"assigned_cluster_total_voting_weight":5,"consensus_parameter_root":"r","cryptographic_profile_root":"r","ingress_kem_registry_root":"{}"}}"#,
            "a".repeat(128)
        )
    }

    #[test]
    fn legacy_context_bytes_and_full_root_are_unchanged() {
        let compact: TargetAdmissionContext = serde_json::from_str(LEGACY_COMPACT).unwrap();
        assert_eq!(compact.target_height_offset, 5);
        assert_eq!(serde_json::to_string(&compact).unwrap(), LEGACY_COMPACT);
        let bytes = legacy_full_bytes();
        let full: TargetAdmissionContextV3 = serde_json::from_str(&bytes).unwrap();
        assert_eq!(full.target_height_offset, 5);
        assert_eq!(serde_json::to_string(&full).unwrap(), bytes);
        assert_eq!(
            full.root().unwrap(),
            EtdagDigest::from_domain_bytes(
                "SYNERGY_ETDAG_TARGET_ADMISSION_CONTEXT_V1",
                bytes.as_bytes()
            )
        );
    }

    #[test]
    fn explicit_context_offset_is_bound_and_must_match_signed_parameters() {
        let mut compact: TargetAdmissionContext = serde_json::from_str(LEGACY_COMPACT).unwrap();
        let mut full: TargetAdmissionContextV3 =
            serde_json::from_str(&legacy_full_bytes()).unwrap();
        for offset in 6..=16 {
            let parameters = EtdagParameters {
                profile_id: ETDAG_EXPERIMENTAL_PROFILE_ID.into(),
                target_height_offset: offset,
                ..Default::default()
            };
            compact.target_height_offset = offset;
            compact.target_height = compact.source_finalized_height + offset;
            full.target_height_offset = offset;
            full.target_height = offset;
            assert!(compact.validate_with_parameters(&parameters).is_ok());
            assert!(full.validate_with_parameters(&parameters).is_ok());
            assert!(compact
                .validate_with_parameters(&EtdagParameters::default())
                .is_err());
            assert!(full
                .validate_with_parameters(&EtdagParameters::default())
                .is_err());
            assert!(serde_json::to_string(&full)
                .unwrap()
                .contains("target_height_offset"));
            let mut changed = full.clone();
            changed.target_height_offset = if offset == 16 { 15 } else { offset + 1 };
            changed.target_height = 3;
            full.target_height = 3;
            assert_ne!(full.root().unwrap(), changed.root().unwrap());
        }
        for offset in [0, 4, 17, u64::MAX] {
            compact.target_height_offset = offset;
            full.target_height_offset = offset;
            assert!(compact.validate().is_err());
            assert!(full.validate().is_err());
        }
    }
}
