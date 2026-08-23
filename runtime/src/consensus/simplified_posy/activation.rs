//! Fail-closed activation binding for the simplified PoSy v3 profile.
//!
//! A node configuration, environment variable, wall clock, or operator flag
//! is never an activation authority. The only initial activation input is a
//! schema-v1 record embedded in the canonical Genesis `consensus` object. The
//! Genesis hash therefore commits to the exact finalized schema-v4 manifest
//! and initial frozen validator set. This block-zero chain derives its epoch
//! seed from that immutable binding; it never imports legacy-chain finality.

use super::{SimplifiedEpochContext, VerifiedSimplifiedEpochTransition};
use crate::consensus_parameters::ConsensusParameterRoot;
use crate::posy_simplified_parameters::{
    SimplifiedConsensusParameterManifest, POSY_SIMPLIFIED_FRESH_GENESIS_BOUNDARY,
    POSY_SIMPLIFIED_PARAMETER_FINALIZED_STATUS,
};
use crate::synergy_types::{
    Epoch, Hash, Height, ValidatorSet, SYNERGY_TESTNET_V3_CHAIN_ID, TESTNET_V3_CANONICAL_NETWORK_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const POSY_SIMPLIFIED_ACTIVATION_BINDING_SCHEMA_VERSION: u32 = 1;
pub const POSY_SIMPLIFIED_ACTIVATION_BINDING_STATUS: &str = "FINALIZED_AND_GENESIS_BOUND";
pub const POSY_SIMPLIFIED_ACTIVATION_JSON_POINTER: &str = "/consensus/posy_v3_activation";

/// Immutable launch-time authorization for the first simplified PoSy epoch.
///
/// The validator set is public consensus material only. Private validator
/// keys are never carried by this record and remain under the existing Aegis
/// custody and durable signer-journal boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenesisBoundSimplifiedActivation {
    pub binding_schema_version: u32,
    pub binding_status: String,
    pub governance_decision_id: String,
    pub parameter_root_sha3_512: String,
    pub activation_epoch: u64,
    pub activation_height: u64,
    pub manifest: SimplifiedConsensusParameterManifest,
    pub frozen_validator_set: ValidatorSet,
}

impl GenesisBoundSimplifiedActivation {
    fn starts_fresh_genesis(&self) -> bool {
        self.manifest.activation_boundary == POSY_SIMPLIFIED_FRESH_GENESIS_BOUNDARY
    }

    /// Validates every immutable authority without consulting process-local
    /// configuration, health observations, time, or environment variables.
    pub fn validate(&self) -> Result<(), String> {
        if self.binding_schema_version != POSY_SIMPLIFIED_ACTIVATION_BINDING_SCHEMA_VERSION
            || self.binding_status != POSY_SIMPLIFIED_ACTIVATION_BINDING_STATUS
        {
            return Err("simplified activation binding schema or status is invalid".to_string());
        }
        self.manifest.require_activatable()?;
        if self.manifest.status != POSY_SIMPLIFIED_PARAMETER_FINALIZED_STATUS {
            return Err("simplified activation manifest is not FINALIZED".to_string());
        }
        let approval = self
            .manifest
            .governance_approval_id
            .as_deref()
            .ok_or_else(|| "simplified activation has no governance approval".to_string())?;
        if approval.trim().is_empty() || self.governance_decision_id != approval {
            return Err(
                "simplified activation Decision ID does not match governance approval".to_string(),
            );
        }
        let manifest_root = self.manifest.root()?;
        let declared_root = ConsensusParameterRoot::from_hex(&self.parameter_root_sha3_512)?;
        if declared_root.is_zero() || declared_root != manifest_root {
            return Err("simplified activation parameter root mismatch".to_string());
        }
        if self.manifest.activation_epoch != Some(self.activation_epoch)
            || self.manifest.activation_height != Some(self.activation_height)
        {
            return Err(
                "simplified activation coordinates do not match the finalized manifest".to_string(),
            );
        }
        if !self.starts_fresh_genesis() || self.activation_epoch != 0 || self.activation_height != 1
        {
            return Err(
                "simplified activation must be the fresh-genesis block-one authority".to_string(),
            );
        }
        if self.frozen_validator_set != self.frozen_validator_set.canonicalized() {
            return Err(
                "simplified activation validator set is not in canonical validator-id order"
                    .to_string(),
            );
        }
        if self.frozen_validator_set.epoch != Epoch(self.activation_epoch) {
            return Err(
                "simplified activation validator-set epoch does not match the boundary".to_string(),
            );
        }
        self.frozen_validator_set
            .validate_unique_validator_and_key_ids()?;
        let declared_initial_count = usize::try_from(self.manifest.active_validator_count)
            .map_err(|_| "simplified initial validator count exceeds usize".to_string())?;
        if self.frozen_validator_set.validators.len() != declared_initial_count {
            return Err(format!(
                "simplified activation froze {} validators but its initial manifest declares {}",
                self.frozen_validator_set.validators.len(),
                declared_initial_count
            ));
        }
        let epoch_end = self.epoch_end_height()?;
        // Derivation rechecks the dynamic epoch topology, one cluster,
        // ML-DSA-65 key shape, nonzero weights, and leave-one-out weighted
        // liveness. Later finalized epoch transitions may freeze a larger set.
        SimplifiedEpochContext::derive(
            Epoch(self.activation_epoch),
            Height(self.activation_height),
            epoch_end,
            Hash::from_domain_bytes(
                "SYNERGY_POSY_SIMPLIFIED_ACTIVATION_VALIDATION_SEED_V1",
                b"shape-validation-only",
            ),
            manifest_root,
            &self.frozen_validator_set,
        )?;
        Ok(())
    }

    pub fn epoch_end_height(&self) -> Result<Height, String> {
        self.activation_height
            .checked_add(
                self.manifest
                    .epoch_length_blocks
                    .checked_sub(1)
                    .ok_or_else(|| "simplified activation epoch length is zero".to_string())?,
            )
            .map(Height)
            .ok_or_else(|| "simplified activation epoch end height overflows".to_string())
    }

    /// Derives block one's epoch context for a separate Testnet-v3 chain.
    /// The seed commits to the complete finalized activation record (including
    /// public membership and parameter root) under a domain distinct from the
    /// legacy v2-boundary transition. There is no old-chain data dependency.
    pub fn derive_fresh_genesis_epoch_context(&self) -> Result<SimplifiedEpochContext, String> {
        self.validate()?;
        if !self.starts_fresh_genesis() {
            return Err(
                "only a fresh-genesis activation can derive a genesis epoch context".into(),
            );
        }
        let canonical_binding = serde_json::to_vec(self)
            .map_err(|error| format!("serialize fresh simplified activation seed: {error}"))?;
        let seed = Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_FRESH_GENESIS_EPOCH_SEED_V1",
            &canonical_binding,
        );
        SimplifiedEpochContext::derive(
            Epoch(0),
            Height(1),
            self.epoch_end_height()?,
            seed,
            self.manifest.root()?,
            &self.frozen_validator_set,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusProfileAtHeight {
    /// The fresh Genesis has selected the frozen initial simplified epoch.
    PosySimplifiedV3 {
        epoch_context: SimplifiedEpochContext,
        validator_set: ValidatorSet,
    },
}

/// Reads the optional activation authority from an already integrity-checked
/// canonical Genesis JSON value. A present but partial record is an error;
/// it is never interpreted as "not configured".
pub fn load_genesis_bound_simplified_activation(
    canonical_genesis: &Value,
) -> Result<Option<GenesisBoundSimplifiedActivation>, String> {
    let Some(raw) = canonical_genesis.pointer(POSY_SIMPLIFIED_ACTIVATION_JSON_POINTER) else {
        return Ok(None);
    };
    if canonical_genesis
        .pointer("/network/chain_id")
        .and_then(Value::as_u64)
        != Some(SYNERGY_TESTNET_V3_CHAIN_ID)
        || canonical_genesis
            .pointer("/network/network_slug")
            .and_then(Value::as_str)
            != Some(TESTNET_V3_CANONICAL_NETWORK_ID)
    {
        return Err(
            "simplified activation binding is not attached to the canonical Testnet-v3 Genesis identity"
                .to_string(),
        );
    }
    let hash_inputs = canonical_genesis
        .pointer("/canonicalization/genesis_hash_inputs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "simplified activation Genesis has no canonical hash-input declaration".to_string()
        })?;
    if !hash_inputs
        .iter()
        .any(|entry| entry.as_str() == Some("consensus"))
    {
        return Err(
            "simplified activation is not covered by the canonical Genesis hash".to_string(),
        );
    }
    let binding: GenesisBoundSimplifiedActivation = serde_json::from_value(raw.clone())
        .map_err(|error| format!("parse Genesis-bound simplified activation: {error}"))?;
    binding.validate()?;
    if canonical_genesis
        .pointer("/network/consensus_version")
        .and_then(Value::as_str)
        != Some(super::POSY_SIMPLIFIED_PROTOCOL_VERSION)
    {
        return Err(
            "fresh simplified activation does not match the canonical Genesis consensus version"
                .to_string(),
        );
    }
    Ok(Some(binding))
}

/// Chooses the only consensus profile from canonical fresh-Genesis authority.
/// Missing or malformed authority is a startup error, never a legacy fallback.
pub fn select_consensus_profile_at_height(
    next_height: Height,
    activation: Option<&GenesisBoundSimplifiedActivation>,
) -> Result<ConsensusProfileAtHeight, String> {
    let activation = activation.ok_or_else(|| {
        "fresh Testnet-v3 Genesis is missing its simplified PoSy activation".to_string()
    })?;
    activation.validate()?;
    if next_height.0 == 0 {
        return Err("simplified consensus cannot select a block-zero execution height".into());
    }
    let epoch_context = activation.derive_fresh_genesis_epoch_context()?;
    if !epoch_context.contains_height(next_height) {
        return Err(
            "simplified fresh-genesis restart is beyond its frozen epoch; a verified v3 epoch-transition context is required"
                .to_string(),
        );
    }
    Ok(ConsensusProfileAtHeight::PosySimplifiedV3 {
        epoch_context,
        validator_set: activation.frozen_validator_set.clone(),
    })
}

/// Selects a later v3 epoch only from a previously verified transition
/// capability. This is deliberately separate from the one-time fresh-Genesis
/// selector: passing a validator set, height, or process flag alone can never
/// authorize onboarding.
pub fn select_consensus_profile_from_verified_v3_transition(
    next_height: Height,
    transition: &VerifiedSimplifiedEpochTransition,
) -> Result<ConsensusProfileAtHeight, String> {
    let epoch_context = transition.next_epoch_context();
    if !epoch_context.contains_height(next_height) {
        return Err(
            "verified v3 transition does not authorize the requested consensus height".to_string(),
        );
    }
    epoch_context.validate_against(transition.next_validator_set())?;
    Ok(ConsensusProfileAtHeight::PosySimplifiedV3 {
        epoch_context: epoch_context.clone(),
        validator_set: transition.next_validator_set().clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::simplified_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION;
    use crate::posy_simplified_parameters::{
        SimplifiedPerformanceTargets, POSY_SIMPLIFIED_FRESH_GENESIS_BOUNDARY,
        POSY_SIMPLIFIED_PARAMETER_FINALIZED_STATUS,
    };
    use crate::synergy_types::{
        AegisPqKeyId, AegisPqPublicKey, ChainId, ClusterId, NetworkId, UmaId, ValidatorId,
        ValidatorRecord, ValidatorStatus, TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM,
        TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES,
    };
    use serde_json::json;

    fn validator_set() -> ValidatorSet {
        ValidatorSet {
            epoch: Epoch(0),
            validators: (0..5)
                .map(|index| {
                    let key = AegisPqPublicKey {
                        key_id: AegisPqKeyId(format!("key-{index}")),
                        algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                        key_bytes: vec![index as u8 + 1; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES],
                    };
                    ValidatorRecord {
                        validator_id: ValidatorId(format!("validator-{index}")),
                        validator_uma_id: UmaId(format!("uma:validator-{index}")),
                        consensus_public_key: key.clone(),
                        peer_public_key: key.clone(),
                        operator_public_key: key,
                        voting_weight: 1,
                        status: ValidatorStatus::Active,
                        cluster_id: ClusterId(0),
                        activation_epoch: Epoch(0),
                    }
                })
                .collect(),
        }
    }

    fn manifest() -> SimplifiedConsensusParameterManifest {
        SimplifiedConsensusParameterManifest {
            schema_version: 4,
            release_id: "testnet-v3".to_string(),
            status: POSY_SIMPLIFIED_PARAMETER_FINALIZED_STATUS.to_string(),
            governance_approval_id: Some("TV3-POSY-V3-UNIT-TEST".to_string()),
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::fresh_posy_testnet_v3(),
            protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
            activation_boundary: POSY_SIMPLIFIED_FRESH_GENESIS_BOUNDARY.to_string(),
            activation_epoch: Some(0),
            activation_height: Some(1),
            epoch_length_blocks: 1_000,
            active_validator_count: 5,
            consensus_cluster_count: 1,
            healthy_path: vec!["PROPOSAL".into(), "VOTE".into(), "QC".into()],
            ordinary_vote_phases: 1,
            normal_qc_types: 1,
            exceptional_certificate: "TC".to_string(),
            chained_qc_commit_depth: 3,
            leader_schedule_domain: "PoSy/LeaderSchedule/v3".to_string(),
            leader_schedule_rank_bits: 512,
            leader_schedule_weighted: false,
            leader_lease_blocks: 10,
            takeover_rule: "sequential_strict_dual_quorum_tc_for_current_lease".to_string(),
            count_quorum_rule: "3*signed_count>2*active_validator_count".to_string(),
            required_distinct_signers: 4,
            weight_quorum_rule: "3*signed_weight>2*total_frozen_weight".to_string(),
            consensus_signature_algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
            allow_quorum_reduction: false,
            allow_local_leader_election: false,
            require_single_validator_failure_liveness: true,
            signer_journal_required: true,
            safety_halt_on_conflicting_valid_qcs: true,
            etdag_finality_separation_required: true,
            protected_execution_binding_required: true,
            initial_etdag_activation:
                crate::posy_simplified_parameters::POSY_SIMPLIFIED_ETDAG_GOVERNED_GENESIS_BINDING_REQUIRED
                    .to_string(),
            target_block_time_ms: 2_000,
            proposal_timeout_ms: 1_500,
            vote_timeout_ms: 1_500,
            max_round_timeout_ms: 10_000,
            performance_targets: SimplifiedPerformanceTargets {
                proposal_latency_ms: 450,
                qc_formation_latency_ms: 1_850,
                chained_finality_latency_ms: 6_000,
                tc_recovery_latency_ms: 3_000,
                finality_p95_ms: 7_500,
                finality_p99_ms: 9_000,
            },
        }
    }

    fn activation() -> GenesisBoundSimplifiedActivation {
        let manifest = manifest();
        GenesisBoundSimplifiedActivation {
            binding_schema_version: POSY_SIMPLIFIED_ACTIVATION_BINDING_SCHEMA_VERSION,
            binding_status: POSY_SIMPLIFIED_ACTIVATION_BINDING_STATUS.to_string(),
            governance_decision_id: manifest.governance_approval_id.clone().unwrap(),
            parameter_root_sha3_512: manifest.root().unwrap().to_hex(),
            activation_epoch: 0,
            activation_height: 1,
            manifest,
            frozen_validator_set: validator_set(),
        }
    }

    fn genesis_with(binding: Value) -> Value {
        json!({
            "network": {
                "chain_id": SYNERGY_TESTNET_V3_CHAIN_ID,
                "network_slug": TESTNET_V3_CANONICAL_NETWORK_ID,
                "consensus_version": POSY_SIMPLIFIED_PROTOCOL_VERSION
            },
            "canonicalization": {"genesis_hash_inputs": ["network", "consensus"]},
            "consensus": {"posy_v3_activation": binding}
        })
    }

    #[test]
    fn fresh_genesis_selects_frozen_v3_context_at_block_one() {
        let activation = activation();
        let selected = select_consensus_profile_at_height(Height(1), Some(&activation)).unwrap();
        let ConsensusProfileAtHeight::PosySimplifiedV3 {
            epoch_context,
            validator_set,
        } = selected
        else {
            panic!("fresh Genesis must select simplified v3");
        };
        assert_eq!(epoch_context.epoch, Epoch(0));
        assert_eq!(epoch_context.epoch_start_height, Height(1));
        assert_eq!(epoch_context.epoch_end_height, Height(1_000));
        assert_eq!(epoch_context.v2_boundary_anchor, None);
        assert_eq!(validator_set.validators.len(), 5);
        assert_eq!(
            epoch_context,
            activation.derive_fresh_genesis_epoch_context().unwrap()
        );
    }

    #[test]
    fn proposed_partial_or_mismatched_bindings_fail_closed() {
        let mut proposed = activation();
        proposed.manifest.status = "PROPOSED_NOT_ACTIVATED".to_string();
        proposed.manifest.governance_approval_id = None;
        proposed.manifest.activation_epoch = None;
        proposed.manifest.activation_height = None;
        assert!(select_consensus_profile_at_height(Height(1), Some(&proposed)).is_err());

        let mut wrong_root = activation();
        wrong_root.parameter_root_sha3_512 = "00".repeat(64);
        assert!(wrong_root.validate().is_err());

        let mut unsafe_weight = activation();
        unsafe_weight.frozen_validator_set.validators[0].voting_weight = 4;
        unsafe_weight.frozen_validator_set.validators[1].voting_weight = 2;
        unsafe_weight.frozen_validator_set.validators[2].voting_weight = 2;
        unsafe_weight.frozen_validator_set.validators[3].voting_weight = 2;
        unsafe_weight.frozen_validator_set.validators[4].voting_weight = 2;
        assert!(unsafe_weight.validate().is_err());
    }

    #[test]
    fn missing_activation_never_falls_back() {
        let error = select_consensus_profile_at_height(Height(1), None).unwrap_err();
        assert!(error.contains("missing its simplified PoSy activation"));
    }

    #[test]
    fn genesis_loader_rejects_partial_or_unhashed_bindings() {
        let binding = serde_json::to_value(activation()).unwrap();
        let loaded = load_genesis_bound_simplified_activation(&genesis_with(binding.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(loaded.activation_height, 1);

        let mut partial = binding;
        partial
            .as_object_mut()
            .unwrap()
            .remove("governance_decision_id");
        assert!(load_genesis_bound_simplified_activation(&genesis_with(partial)).is_err());

        let mut unhashed = genesis_with(serde_json::to_value(activation()).unwrap());
        unhashed["canonicalization"]["genesis_hash_inputs"] = json!(["network"]);
        assert!(load_genesis_bound_simplified_activation(&unhashed).is_err());
    }

    #[test]
    fn environment_or_wall_clock_cannot_change_selection() {
        let activation = activation();
        std::env::set_var("SYNERGY_POSY_V3_FORCE_ACTIVATE", "true");
        std::env::set_var("SYNERGY_POSY_V3_ACTIVATION_HEIGHT", "1");
        let selected = select_consensus_profile_at_height(Height(1), Some(&activation)).unwrap();
        std::env::remove_var("SYNERGY_POSY_V3_FORCE_ACTIVATE");
        std::env::remove_var("SYNERGY_POSY_V3_ACTIVATION_HEIGHT");
        assert!(matches!(
            selected,
            ConsensusProfileAtHeight::PosySimplifiedV3 { .. }
        ));
    }
}
