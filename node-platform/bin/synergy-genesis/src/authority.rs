//! Canonical runtime authority artifacts shared by Genesis and node consumers.
use serde::{Deserialize, Serialize};
use synergy_aegis::SignatureAlgorithm;
use synergy_posy::{
    FrozenValidatorRegistry, SimplifiedEpochContext, SimplifiedFinalityParent, ValidatorRecord,
};

pub const AUTHORITY_SIGNING_DOMAIN: &str = "SYNERGY-POSY-AUTHORITY-BINDING-V1";
pub use synergy_posy::SimplifiedFinalityParent as AuthorityParent;

impl AuthorityPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(self).map_err(|e| format!("encode authority: {e}"))?;
        if bytes.len() > 1024 * 1024 - AUTHORITY_SIGNING_DOMAIN.len() {
            return Err("authority transcript exceeds its bound".into());
        }
        let mut transcript = AUTHORITY_SIGNING_DOMAIN.as_bytes().to_vec();
        transcript.extend_from_slice(&bytes);
        Ok(transcript)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 || self.chain_id == 0 || self.network_id.is_empty() {
            return Err("authority payload is incompatible or malformed".into());
        }
        for validator in &self.validators {
            validator.record.validate().map_err(|e| e.to_string())?;
            if validator.algorithm != SignatureAlgorithm::MlDsa65 || validator.public_key.is_empty()
            {
                return Err("authority validator lacks ML-DSA-65 verification material".into());
            }
        }
        let registry = FrozenValidatorRegistry::new(
            self.epoch,
            self.validators.iter().map(|v| v.record.clone()).collect(),
        )
        .map_err(|e| e.to_string())?;
        let epoch = SimplifiedEpochContext::from_frozen_registry(
            self.chain_id,
            self.network_id.clone(),
            self.epoch,
            self.epoch_start_height,
            self.epoch_end_height,
            self.finalized_epoch_seed_root.clone(),
            self.consensus_parameter_root.clone(),
            &registry,
        )
        .map_err(|e| e.to_string())?;
        self.anchor_parent
            .validate_for_child_height(self.epoch_start_height)
            .map_err(|e| e.to_string())?;
        if let Some(protected) = &self.protected {
            protected.validate(&registry, &epoch)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityValidator {
    pub record: ValidatorRecord,
    pub algorithm: SignatureAlgorithm,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPayload {
    pub version: u32,
    pub chain_id: u64,
    pub network_id: String,
    pub epoch: u64,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub finalized_epoch_seed_root: String,
    pub consensus_parameter_root: String,
    pub validators: Vec<AuthorityValidator>,
    pub anchor_parent: SimplifiedFinalityParent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<ProtectedEpochPolicy>,
}

/// Operator-approved protected cutoff relationship carried in signed authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedCutoffRelationship {
    /// Proposal H binds the H+2 event context; VC(H) closes admission,
    /// proposal H+1 binds its batch, and VC(H+1) authorizes reveal.
    VcEventContextV1,
    /// Explicit versioned asynchronous profile: PoSy commits ordering groups;
    /// a subsequent group closes before prior plaintext may be revealed.
    /// Authorization anchors are immutable snapshots, not inclusion deadlines.
    ProcessingGroupsV1,
}

/// Complete protected policy is inside the pinned-trust-root signature.
/// Mutable node configuration cannot supply any of these authority inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedEpochPolicy {
    pub version: u32,
    /// Required signed activation marker. No legacy/default interpretation is permitted.
    pub cutoff_relationship: ProtectedCutoffRelationship,
    /// Canonical block time schedule from the governed protected material contract.
    pub epoch_start_timestamp_ms: u64,
    pub target_block_time_ms: u64,
    pub parameters: synergy_etdag::EtdagParameters,
    pub initial_world_state: synergy_state::WorldState,
    pub cryptographic_profile_root: String,
    pub ingress_kem_registry: synergy_etdag::crypto::IngressKemKeyRegistry,
    pub cluster_schedule_version: String,
    pub assigned_height_schedule_root: String,
    pub cluster_map_root: String,
    pub assigned_cluster_id: u64,
    pub assigned_cluster_membership_root: String,
}

impl ProtectedEpochPolicy {
    /// Derives the exact consensus time; height is confined to this signed epoch.
    pub fn timestamp_for_height_ms(
        &self,
        epoch_start_height: u64,
        epoch_end_height: u64,
        height: u64,
    ) -> Result<u64, String> {
        if self.epoch_start_timestamp_ms == 0
            || self.target_block_time_ms == 0
            || epoch_start_height == 0
            || epoch_end_height < epoch_start_height
            || height < epoch_start_height
            || height > epoch_end_height
        {
            return Err("invalid governed epoch timestamp schedule or height".into());
        }
        self.target_block_time_ms
            .checked_mul(height - epoch_start_height)
            .and_then(|delta| self.epoch_start_timestamp_ms.checked_add(delta))
            .ok_or_else(|| "governed epoch timestamp overflow".into())
    }

    pub fn commitment(&self) -> Result<String, String> {
        let domain = match self.cutoff_relationship {
            ProtectedCutoffRelationship::VcEventContextV1 => "SYNERGY_FRESH_PROTECTED_POLICY_V1",
            ProtectedCutoffRelationship::ProcessingGroupsV1 => "SYNERGY_ASYNC_PROCESSING_POLICY_V1",
        };
        synergy_posy::canonical_hash(domain, self).map_err(|error| error.to_string())
    }

    pub fn validate(
        &self,
        registry: &FrozenValidatorRegistry,
        epoch: &SimplifiedEpochContext,
    ) -> Result<(), String> {
        self.timestamp_for_height_ms(
            epoch.epoch_start_height,
            epoch.epoch_end_height,
            epoch.epoch_end_height,
        )?;
        self.parameters
            .validate()
            .map_err(|e| format!("protected parameters: {e:?}"))?;
        self.ingress_kem_registry
            .validate_protected_profile()
            .map_err(|e| format!("ingress KEM registry: {e:?}"))?;
        if !matches!(
            (self.version, self.cutoff_relationship),
            (1, ProtectedCutoffRelationship::VcEventContextV1)
                | (2, ProtectedCutoffRelationship::ProcessingGroupsV1)
        ) || self.commitment()? != epoch.consensus_parameter_root
            || self.assigned_cluster_id != 0
            || self.assigned_cluster_membership_root != epoch.active_validator_set_root
            || self.cluster_schedule_version.trim().is_empty()
            || [
                &self.cryptographic_profile_root,
                &self.assigned_height_schedule_root,
                &self.cluster_map_root,
            ]
            .iter()
            .any(|root| !synergy_posy::is_hash(root))
        {
            return Err(
                "protected policy is not bound to the frozen single-cluster authority".into(),
            );
        }
        let active: std::collections::BTreeSet<_> =
            registry.active().map(|v| v.validator_id.as_str()).collect();
        let kem: std::collections::BTreeSet<_> = self
            .ingress_kem_registry
            .records
            .iter()
            .map(|record| record.validator_id.as_str())
            .collect();
        if active != kem {
            return Err("ingress KEM registry differs from frozen validators".into());
        }
        validate_ingress_epoch_coverage(
            &self.ingress_kem_registry,
            epoch.epoch_start_height.max(3),
            epoch.epoch_end_height,
        )?;
        synergy_state::state_root(&self.initial_world_state)
            .map_err(|e| format!("initial state: {e:?}"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorityBinding {
    pub payload: AuthorityPayload,
    pub signer_key_id: String,
    pub signature: Vec<u8>,
}

fn validate_ingress_epoch_coverage(
    registry: &synergy_etdag::IngressKemKeyRegistry,
    start: u64,
    end: u64,
) -> Result<(), String> {
    let mut by_validator = std::collections::BTreeMap::<&str, Vec<_>>::new();
    for record in &registry.records {
        by_validator
            .entry(&record.validator_id)
            .or_default()
            .push(record);
    }
    for records in by_validator.values_mut() {
        records.sort_by_key(|record| record.activation_height);
        let mut next = start;
        let mut covered = false;
        for record in records {
            if record
                .retirement_height
                .is_some_and(|height| height <= next)
            {
                continue;
            }
            if record.activation_height > next {
                break;
            }
            match record.retirement_height {
                None => {
                    covered = true;
                    break;
                }
                Some(height) if height > end => {
                    covered = true;
                    break;
                }
                Some(height) => next = height,
            }
        }
        if !covered {
            return Err(
                "ingress KEM schedule leaves a protected epoch height without an active key".into(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod protected_key_schedule_tests {
    use super::*;
    use synergy_etdag::{
        EtdagDigest, IngressKemKeyRecord, IngressKemKeyRegistry, IngressKemPublicKey,
    };
    #[test]
    fn protected_cutoff_relationship_requires_explicit_supported_signed_marker() {
        assert_eq!(
            serde_json::to_string(&ProtectedCutoffRelationship::VcEventContextV1).unwrap(),
            "\"vc_event_context_v1\""
        );
        assert_eq!(
            serde_json::to_string(&ProtectedCutoffRelationship::ProcessingGroupsV1).unwrap(),
            "\"processing_groups_v1\""
        );
        assert!(
            serde_json::from_str::<ProtectedCutoffRelationship>("\"certified_frontier_v0\"")
                .is_err()
        );
        assert!(serde_json::from_str::<ProtectedCutoffRelationship>("null").is_err());
        let policy = ProtectedEpochPolicy {
            version: 1,
            cutoff_relationship: ProtectedCutoffRelationship::VcEventContextV1,
            epoch_start_timestamp_ms: 1_000_000,
            target_block_time_ms: 1_000,
            parameters: synergy_etdag::EtdagParameters::default(),
            initial_world_state: synergy_state::WorldState::default(),
            cryptographic_profile_root: "a".repeat(64),
            ingress_kem_registry: IngressKemKeyRegistry {
                context_root: EtdagDigest::from_domain_bytes("test", b"registry"),
                records: vec![],
            },
            cluster_schedule_version: "test".into(),
            assigned_height_schedule_root: "b".repeat(64),
            cluster_map_root: "c".repeat(64),
            assigned_cluster_id: 0,
            assigned_cluster_membership_root: "d".repeat(64),
        };
        assert_eq!(
            policy.timestamp_for_height_ms(1, 100, 1).unwrap(),
            1_000_000
        );
        assert_eq!(
            policy.timestamp_for_height_ms(1, 100, 3).unwrap(),
            1_002_000
        );
        assert!(policy.timestamp_for_height_ms(1, 100, 0).is_err());
        assert!(policy.timestamp_for_height_ms(1, 100, 101).is_err());
        assert!(policy.timestamp_for_height_ms(0, 100, 1).is_err());
        let mut invalid_time = policy.clone();
        invalid_time.target_block_time_ms = 0;
        assert!(invalid_time.timestamp_for_height_ms(1, 100, 1).is_err());
        invalid_time.target_block_time_ms = u64::MAX;
        assert!(invalid_time.timestamp_for_height_ms(1, 100, 3).is_err());
        invalid_time.target_block_time_ms = 1;
        invalid_time.epoch_start_timestamp_ms = u64::MAX;
        assert!(invalid_time.timestamp_for_height_ms(1, 100, 2).is_err());
        let mut encoded = serde_json::to_value(&policy).unwrap();
        let mut processing = policy.clone();
        processing.version = 2;
        processing.cutoff_relationship = ProtectedCutoffRelationship::ProcessingGroupsV1;
        assert_ne!(
            processing.commitment().unwrap(),
            policy.commitment().unwrap()
        );
        assert_ne!(
            processing.commitment().unwrap(),
            synergy_posy::canonical_hash("SYNERGY_FRESH_PROTECTED_POLICY_V1", &processing).unwrap()
        );
        for field in ["epoch_start_timestamp_ms", "target_block_time_ms"] {
            let mut absent = encoded.clone();
            absent.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<ProtectedEpochPolicy>(absent).is_err());
        }
        assert!(serde_json::from_value::<ProtectedEpochPolicy>(encoded.clone()).is_ok());
        encoded
            .as_object_mut()
            .unwrap()
            .remove("cutoff_relationship");
        assert!(serde_json::from_value::<ProtectedEpochPolicy>(encoded.clone()).is_err());
        encoded["cutoff_relationship"] = serde_json::json!("certified_frontier_v0");
        assert!(serde_json::from_value::<ProtectedEpochPolicy>(encoded).is_err());
    }
    #[test]
    fn signed_policy_rejects_delayed_activation_rotation_gaps_and_early_retirement() {
        let record = |activation, retirement| IngressKemKeyRecord {
            key_id: format!("key-{activation}"),
            validator_id: "validator".into(),
            public_key: IngressKemPublicKey {
                algorithm: "ML-KEM-1024".into(),
                public_key: vec![],
            },
            activation_height: activation,
            retirement_height: retirement,
        };
        let check = |records| {
            validate_ingress_epoch_coverage(
                &IngressKemKeyRegistry {
                    context_root: EtdagDigest::from_domain_bytes("test", b"registry"),
                    records,
                },
                3,
                100,
            )
        };
        assert!(check(vec![record(100, None)]).is_err());
        assert!(check(vec![record(1, Some(50)), record(51, None)]).is_err());
        assert!(check(vec![record(1, Some(100))]).is_err());
        assert!(check(vec![record(1, Some(50)), record(50, Some(101))]).is_ok());
        assert!(check(vec![record(1, None)]).is_ok());
    }
}
