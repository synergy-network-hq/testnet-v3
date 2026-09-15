use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError, MIN_TARGET_HEIGHT_OFFSET};

/// Compact admission context retained for the existing ingress foundation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetAdmissionContext {
    pub source_finalized_height: u64,
    pub target_height: u64,
    pub active_validator_set_root: String,
    pub validator_consensus_key_root: String,
    pub frozen_voting_weight_root: String,
    pub assigned_cluster_validator_count: u64,
    pub assigned_cluster_total_voting_weight: u64,
}

impl TargetAdmissionContext {
    pub fn validate(&self) -> Result<(), EtdagError> {
        if self.target_height
            != self
                .source_finalized_height
                .checked_add(MIN_TARGET_HEIGHT_OFFSET)
                .ok_or(EtdagError::InvalidTargetOffset)?
            || self.active_validator_set_root.is_empty()
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
    pub fn validate(&self) -> Result<(), EtdagError> {
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
            || self.chain_id != 1266
            || self.protocol_version.trim().is_empty()
            || self.network_id.trim().is_empty()
            || self.target_height
                != self
                    .source_finalized_height
                    .checked_add(MIN_TARGET_HEIGHT_OFFSET)
                    .ok_or(EtdagError::InvalidTargetOffset)?
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
