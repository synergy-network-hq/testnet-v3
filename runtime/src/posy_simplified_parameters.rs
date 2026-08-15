use crate::consensus::simplified_posy::{
    POSY_SIMPLIFIED_LEADER_LEASE_BLOCKS, POSY_SIMPLIFIED_LEADER_SCHEDULE_DOMAIN,
    POSY_SIMPLIFIED_INITIAL_VALIDATOR_COUNT, POSY_SIMPLIFIED_PROTOCOL_VERSION,
};
use crate::consensus_parameters::{ConsensusParameterRoot, MAX_CONSENSUS_PARAMETER_MANIFEST_BYTES};
use crate::synergy_types::{
    ChainId, NetworkId, SYNERGY_TESTNET_V3_CHAIN_ID, SYNERGY_TESTNET_V3_NETWORK_ID,
    TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const POSY_SIMPLIFIED_PARAMETER_SCHEMA_VERSION: u32 = 4;
pub const POSY_SIMPLIFIED_PARAMETER_PROPOSAL_STATUS: &str = "PROPOSED_NOT_ACTIVATED";
pub const POSY_SIMPLIFIED_PARAMETER_FINALIZED_STATUS: &str = "FINALIZED";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedPerformanceTargets {
    pub proposal_latency_ms: u64,
    pub qc_formation_latency_ms: u64,
    pub chained_finality_latency_ms: u64,
    pub tc_recovery_latency_ms: u64,
    pub finality_p95_ms: u64,
    pub finality_p99_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedConsensusParameterManifest {
    pub schema_version: u32,
    pub release_id: String,
    pub status: String,
    pub governance_approval_id: Option<String>,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub activation_boundary: String,
    pub activation_epoch: Option<u64>,
    pub activation_height: Option<u64>,
    pub epoch_length_blocks: u64,
    /// Validator count frozen for the proposed first v3 activation epoch.
    /// Later epoch contexts derive membership and quorum from their finalized
    /// transition; this field is not a protocol-wide validator-count limit.
    pub active_validator_count: u64,
    pub consensus_cluster_count: u64,
    pub healthy_path: Vec<String>,
    pub ordinary_vote_phases: u64,
    pub normal_qc_types: u64,
    pub exceptional_certificate: String,
    pub chained_qc_commit_depth: u64,
    pub leader_schedule_domain: String,
    pub leader_schedule_rank_bits: u64,
    pub leader_schedule_weighted: bool,
    pub leader_lease_blocks: u64,
    pub takeover_rule: String,
    pub count_quorum_rule: String,
    pub required_distinct_signers: u64,
    pub weight_quorum_rule: String,
    pub consensus_signature_algorithm: String,
    pub allow_quorum_reduction: bool,
    pub allow_local_leader_election: bool,
    pub require_single_validator_failure_liveness: bool,
    pub signer_journal_required: bool,
    pub safety_halt_on_conflicting_valid_qcs: bool,
    pub etdag_finality_separation_required: bool,
    pub protected_execution_binding_required: bool,
    pub initial_etdag_activation: String,
    pub proposal_timeout_ms: u64,
    pub vote_timeout_ms: u64,
    pub max_round_timeout_ms: u64,
    pub performance_targets: SimplifiedPerformanceTargets,
}

impl SimplifiedConsensusParameterManifest {
    pub fn validate_proposal(&self) -> Result<(), String> {
        if self.schema_version != POSY_SIMPLIFIED_PARAMETER_SCHEMA_VERSION
            || self.release_id != "testnet-v3"
            || self.chain_id.0 != SYNERGY_TESTNET_V3_CHAIN_ID
            || self.network_id.0 != SYNERGY_TESTNET_V3_NETWORK_ID
            || self.protocol_version != POSY_SIMPLIFIED_PROTOCOL_VERSION
            || self.activation_boundary != "declared_epoch_boundary_only"
        {
            return Err(
                "simplified manifest identity or activation boundary is invalid".to_string(),
            );
        }
        match self.status.as_str() {
            POSY_SIMPLIFIED_PARAMETER_PROPOSAL_STATUS => {
                if self.governance_approval_id.is_some()
                    || self.activation_epoch.is_some()
                    || self.activation_height.is_some()
                {
                    return Err(
                        "an unactivated proposal cannot declare approval or activation coordinates"
                            .to_string(),
                    );
                }
            }
            POSY_SIMPLIFIED_PARAMETER_FINALIZED_STATUS => {
                self.require_activation_fields()?;
            }
            other => return Err(format!("unsupported simplified manifest status {other}")),
        }
        if self.epoch_length_blocks == 0
            || self.active_validator_count != POSY_SIMPLIFIED_INITIAL_VALIDATOR_COUNT as u64
            || self.consensus_cluster_count != 1
            || self.healthy_path != ["PROPOSAL", "VOTE", "QC"]
            || self.ordinary_vote_phases != 1
            || self.normal_qc_types != 1
            || self.exceptional_certificate != "TC"
            || self.chained_qc_commit_depth != 3
            || self.leader_schedule_domain != POSY_SIMPLIFIED_LEADER_SCHEDULE_DOMAIN
            || self.leader_schedule_rank_bits != 512
            || self.leader_schedule_weighted
            || self.leader_lease_blocks != POSY_SIMPLIFIED_LEADER_LEASE_BLOCKS
            || self.takeover_rule != "sequential_strict_dual_quorum_tc_for_current_lease"
        {
            return Err(
                "simplified consensus-path, leader, lease, or finality profile mismatch"
                    .to_string(),
            );
        }
        if self.count_quorum_rule != "3*signed_count>2*active_validator_count"
            || self.required_distinct_signers != 4
            || self.weight_quorum_rule != "3*signed_weight>2*total_frozen_weight"
            || self.consensus_signature_algorithm != TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM
            || self.allow_quorum_reduction
            || self.allow_local_leader_election
            || !self.require_single_validator_failure_liveness
            || !self.signer_journal_required
            || !self.safety_halt_on_conflicting_valid_qcs
        {
            return Err(
                "simplified quorum, cryptography, or fail-closed profile mismatch".to_string(),
            );
        }
        if !self.etdag_finality_separation_required
            || !self.protected_execution_binding_required
            || self.initial_etdag_activation != "preserve_current_finalized_manifest_state"
        {
            return Err("simplified manifest weakens the PoSy v2.2 ETDAG boundary".to_string());
        }
        for (name, value) in [
            ("proposal_timeout_ms", self.proposal_timeout_ms),
            ("vote_timeout_ms", self.vote_timeout_ms),
            ("max_round_timeout_ms", self.max_round_timeout_ms),
            (
                "proposal_latency_ms",
                self.performance_targets.proposal_latency_ms,
            ),
            (
                "qc_formation_latency_ms",
                self.performance_targets.qc_formation_latency_ms,
            ),
            (
                "chained_finality_latency_ms",
                self.performance_targets.chained_finality_latency_ms,
            ),
            (
                "tc_recovery_latency_ms",
                self.performance_targets.tc_recovery_latency_ms,
            ),
            ("finality_p95_ms", self.performance_targets.finality_p95_ms),
            ("finality_p99_ms", self.performance_targets.finality_p99_ms),
        ] {
            if value == 0 {
                return Err(format!("simplified parameter {name} must be nonzero"));
            }
        }
        if self.performance_targets.finality_p95_ms > self.performance_targets.finality_p99_ms {
            return Err("simplified finality p95 target exceeds p99".to_string());
        }
        Ok(())
    }

    pub fn require_activatable(&self) -> Result<(), String> {
        self.validate_proposal()?;
        if self.status != POSY_SIMPLIFIED_PARAMETER_FINALIZED_STATUS {
            return Err(
                "POSY_SIMPLIFIED_PROFILE_NOT_ACTIVATED: manifest remains a proposal".to_string(),
            );
        }
        self.require_activation_fields()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate_proposal()?;
        serde_json::to_vec(self)
            .map_err(|error| format!("serialize simplified parameter manifest: {error}"))
    }

    pub fn root(&self) -> Result<ConsensusParameterRoot, String> {
        Ok(ConsensusParameterRoot::from_canonical_manifest_bytes(
            &self.canonical_bytes()?,
        ))
    }

    fn require_activation_fields(&self) -> Result<(), String> {
        if self
            .governance_approval_id
            .as_ref()
            .is_none_or(|approval| approval.trim().is_empty())
            || self.activation_epoch.is_none_or(|epoch| epoch == 0)
            || self.activation_height.is_none_or(|height| height == 0)
        {
            return Err(
                "finalized simplified manifest requires approval ID, activation epoch, and activation height"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedSimplifiedConsensusParameters {
    pub manifest: SimplifiedConsensusParameterManifest,
    pub canonical_bytes: Vec<u8>,
    pub root: ConsensusParameterRoot,
}

pub fn load_simplified_consensus_parameter_proposal(
    path: &Path,
) -> Result<LoadedSimplifiedConsensusParameters, String> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "read simplified parameter manifest {}: {error}",
            path.display()
        )
    })?;
    load_simplified_consensus_parameter_proposal_bytes(&bytes)
}

pub fn load_simplified_consensus_parameter_proposal_bytes(
    bytes: &[u8],
) -> Result<LoadedSimplifiedConsensusParameters, String> {
    if bytes.is_empty() || bytes.len() > MAX_CONSENSUS_PARAMETER_MANIFEST_BYTES {
        return Err("simplified parameter manifest size is invalid".to_string());
    }
    let manifest: SimplifiedConsensusParameterManifest = serde_json::from_slice(bytes)
        .map_err(|error| format!("parse simplified parameter manifest: {error}"))?;
    let canonical_bytes = manifest.canonical_bytes()?;
    if bytes != canonical_bytes {
        return Err(
            "simplified parameter manifest is not canonical; whitespace, field reordering, and trailing bytes are prohibited"
                .to_string(),
        );
    }
    let root = manifest.root()?;
    Ok(LoadedSimplifiedConsensusParameters {
        manifest,
        canonical_bytes,
        root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal() -> SimplifiedConsensusParameterManifest {
        SimplifiedConsensusParameterManifest {
            schema_version: 4,
            release_id: "testnet-v3".to_string(),
            status: POSY_SIMPLIFIED_PARAMETER_PROPOSAL_STATUS.to_string(),
            governance_approval_id: None,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: "posy/3.0".to_string(),
            activation_boundary: "declared_epoch_boundary_only".to_string(),
            activation_epoch: None,
            activation_height: None,
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
            consensus_signature_algorithm: "mldsa65".to_string(),
            allow_quorum_reduction: false,
            allow_local_leader_election: false,
            require_single_validator_failure_liveness: true,
            signer_journal_required: true,
            safety_halt_on_conflicting_valid_qcs: true,
            etdag_finality_separation_required: true,
            protected_execution_binding_required: true,
            initial_etdag_activation: "preserve_current_finalized_manifest_state".to_string(),
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

    #[test]
    fn proposal_is_canonical_but_cannot_activate() {
        let manifest = proposal();
        let bytes = manifest.canonical_bytes().unwrap();
        let loaded = load_simplified_consensus_parameter_proposal_bytes(&bytes).unwrap();
        assert_eq!(loaded.manifest, manifest);
        assert!(loaded
            .manifest
            .require_activatable()
            .unwrap_err()
            .contains("NOT_ACTIVATED"));
    }

    #[test]
    fn checked_in_proposal_has_the_reviewed_root_and_remains_inactive() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../launch/TESTNET_V3_POSY_SIMPLIFIED_PARAMETER_PROPOSAL.json");
        let loaded = load_simplified_consensus_parameter_proposal(&path).unwrap();
        assert_eq!(
            loaded.root.to_hex(),
            "2c8be6837fa49c160887cc1fcf2b741eadd72172bdeed27c9645c08ebe88be5fb562ca82e89af7cbe821157aba6d0e20a7727f0ff9e191a14dff5744fd4de101"
        );
        assert!(loaded.manifest.require_activatable().is_err());
    }

    #[test]
    fn noncanonical_or_weakened_proposals_fail_closed() {
        let manifest = proposal();
        let mut bytes = manifest.canonical_bytes().unwrap();
        bytes.push(b'\n');
        assert!(load_simplified_consensus_parameter_proposal_bytes(&bytes).is_err());
        let mut weakened = manifest;
        weakened.allow_quorum_reduction = true;
        assert!(weakened.validate_proposal().is_err());
    }
}
