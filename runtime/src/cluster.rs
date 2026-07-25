use crate::address::{generate_validator_cluster_address, is_valid_cluster_address};
use crate::consensus::dual_quorum::required_cluster_quorum;
use crate::validator::{
    canonical_validator_cluster_address, canonical_validator_cluster_plan_for_epoch_with_seed,
    target_validator_cluster_count, CanonicalValidatorClusterRotation, Validator, ValidatorStatus,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;

pub const BPS_DENOMINATOR: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterConfig {
    pub minimum_cluster_size: usize,
    pub target_cluster_size: usize,
    pub maximum_cluster_size: usize,
    pub minimum_clusters_for_parallel_consensus: usize,
    pub parallel_consensus_min_validators: usize,
    pub routine_rotation_bps: u64,
    pub risk_rotation_bps: u64,
    pub emergency_rotation_bps: u64,
    pub full_rotation_interval_epochs: u64,
    pub anti_affinity_enabled: bool,
    pub co_cluster_history_window_epochs: u64,
    pub max_pair_repetition_within_window: u64,
    pub repeated_pairing_penalty_bps: u64,
    pub allow_mid_epoch_emergency_rotation: bool,
    pub preserve_cluster_address_on_full_rotation: bool,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            minimum_cluster_size: 5,
            target_cluster_size: 7,
            maximum_cluster_size: 10,
            minimum_clusters_for_parallel_consensus: 2,
            parallel_consensus_min_validators: 10,
            routine_rotation_bps: 2_500,
            risk_rotation_bps: 5_000,
            emergency_rotation_bps: 10_000,
            full_rotation_interval_epochs: 10,
            anti_affinity_enabled: true,
            co_cluster_history_window_epochs: 12,
            max_pair_repetition_within_window: 3,
            repeated_pairing_penalty_bps: 2_000,
            allow_mid_epoch_emergency_rotation: true,
            preserve_cluster_address_on_full_rotation: true,
        }
    }
}

impl ClusterConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.minimum_cluster_size == 0 {
            return Err("minimum_cluster_size must be > 0".to_string());
        }
        if self.target_cluster_size < self.minimum_cluster_size {
            return Err("target_cluster_size must be >= minimum_cluster_size".to_string());
        }
        if self.maximum_cluster_size < self.target_cluster_size {
            return Err("maximum_cluster_size must be >= target_cluster_size".to_string());
        }
        for (name, value) in [
            ("routine_rotation_bps", self.routine_rotation_bps),
            ("risk_rotation_bps", self.risk_rotation_bps),
            ("emergency_rotation_bps", self.emergency_rotation_bps),
            (
                "repeated_pairing_penalty_bps",
                self.repeated_pairing_penalty_bps,
            ),
        ] {
            if value > BPS_DENOMINATOR {
                return Err(format!("{name} must be <= 10000 bps"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClusterStatus {
    Active,
    Degraded,
    Quarantined,
    Retired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RotationMode {
    RoutineRotation,
    RiskRotation,
    EmergencyRotation,
    FullPlannedReshuffle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RotationSeverity {
    Normal,
    Elevated,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cluster {
    pub cluster_address: String,
    pub cluster_index: u64,
    pub created_epoch: u64,
    pub created_block_height: u64,
    pub status: ClusterStatus,
    pub current_epoch: u64,
    pub current_validator_ids: Vec<String>,
    pub previous_validator_ids: Vec<String>,
    pub target_cluster_size: usize,
    pub min_cluster_size: usize,
    pub max_cluster_size: usize,
    pub current_quorum_threshold: usize,
    pub current_fault_tolerance_f: usize,
    pub total_rewards_earned_nwei: u128,
    pub total_rewards_settled_nwei: u128,
    pub total_blocks_proposed: u64,
    pub total_blocks_finalized: u64,
    pub total_missed_rounds: u64,
    pub total_slashing_events: u64,
    pub total_emergency_rotations: u64,
    pub last_rotation_epoch: Option<u64>,
    pub last_full_rotation_epoch: Option<u64>,
}

impl Cluster {
    pub fn new(
        network_id: &str,
        genesis_hash: &str,
        cluster_index: u64,
        created_epoch: u64,
        created_block_height: u64,
        config: &ClusterConfig,
    ) -> Self {
        let cluster_address =
            derive_synergy_cluster_address(network_id, genesis_hash, cluster_index, created_epoch);
        Self {
            cluster_address,
            cluster_index,
            created_epoch,
            created_block_height,
            status: ClusterStatus::Active,
            current_epoch: created_epoch,
            current_validator_ids: Vec::new(),
            previous_validator_ids: Vec::new(),
            target_cluster_size: config.target_cluster_size,
            min_cluster_size: config.minimum_cluster_size,
            max_cluster_size: config.maximum_cluster_size,
            current_quorum_threshold: 0,
            current_fault_tolerance_f: 0,
            total_rewards_earned_nwei: 0,
            total_rewards_settled_nwei: 0,
            total_blocks_proposed: 0,
            total_blocks_finalized: 0,
            total_missed_rounds: 0,
            total_slashing_events: 0,
            total_emergency_rotations: 0,
            last_rotation_epoch: None,
            last_full_rotation_epoch: None,
        }
    }

    pub fn apply_assignment(&mut self, epoch_id: u64, validator_ids: Vec<String>) {
        self.previous_validator_ids = std::mem::take(&mut self.current_validator_ids);
        self.current_validator_ids = validator_ids;
        self.current_epoch = epoch_id;
        self.current_fault_tolerance_f = fault_tolerance_f(self.current_validator_ids.len());
        self.current_quorum_threshold = quorum_threshold(self.current_validator_ids.len());
        self.last_rotation_epoch = Some(epoch_id);
    }
}

pub fn derive_synergy_cluster_address(
    network_id: &str,
    genesis_hash: &str,
    cluster_index: u64,
    created_epoch: u64,
) -> String {
    let seed = format!("{network_id}:{genesis_hash}:{cluster_index}:{created_epoch}");
    generate_validator_cluster_address(&seed)
}

pub fn fault_tolerance_f(cluster_size: usize) -> usize {
    cluster_size.saturating_sub(1) / 3
}

pub fn quorum_threshold(cluster_size: usize) -> usize {
    required_cluster_quorum(cluster_size)
}

pub fn cluster_count_for_active_validators(
    active_validator_count: usize,
    _config: &ClusterConfig,
) -> usize {
    target_validator_cluster_count(active_validator_count)
}

pub fn balanced_cluster_sizes(active_validator_count: usize, config: &ClusterConfig) -> Vec<usize> {
    let cluster_count = cluster_count_for_active_validators(active_validator_count, config);
    if cluster_count == 0 {
        return Vec::new();
    }
    let base = active_validator_count / cluster_count;
    let extra = active_validator_count % cluster_count;
    (0..cluster_count)
        .map(|index| base + usize::from(index < extra))
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorAssignmentInput {
    pub validator_id: String,
    pub stake_nwei: u128,
    pub synergy_score_bps: u64,
    pub jailed: bool,
    pub slashed: bool,
    pub infrastructure_domain: Option<String>,
    pub geographic_region: Option<String>,
    pub previous_cluster_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterAssignmentSet {
    pub epoch_id: u64,
    pub assignment_hash: String,
    pub cluster_assignments: Vec<ClusterAssignment>,
    pub randomness_source: String,
    pub generated_block_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterAssignment {
    pub epoch_id: u64,
    pub cluster_address: String,
    pub validator_ids: Vec<String>,
    pub quorum_threshold: usize,
    pub fault_tolerance_f: usize,
    pub rotation_mode: RotationMode,
    pub assignment_reason: String,
}

pub fn compute_cluster_assignments(
    epoch_id: u64,
    active_validators: &[ValidatorAssignmentInput],
    _network_id: &str,
    _genesis_hash: &str,
    randomness_source: &str,
    generated_block_height: u64,
    config: &ClusterConfig,
) -> Result<ClusterAssignmentSet, String> {
    config.validate()?;
    let validators = active_validators
        .iter()
        .filter(|validator| !validator.jailed && !validator.slashed)
        .cloned()
        .collect::<Vec<_>>();
    let unique_ids = validators
        .iter()
        .map(|validator| validator.validator_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    if unique_ids.len() != validators.len() {
        return Err(
            "active validator assignment input contains duplicate validator IDs".to_string(),
        );
    }

    let previous_cluster_ids = validators
        .iter()
        .filter_map(|validator| validator.previous_cluster_address.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(index, address)| (address, index as u64))
        .collect::<HashMap<_, _>>();
    let runtime_validators = validators
        .iter()
        .map(|input| {
            let mut validator = Validator::new(
                input.validator_id.clone(),
                input.validator_id.clone(),
                input.validator_id.clone(),
                u64::try_from(input.stake_nwei).unwrap_or(u64::MAX),
            );
            validator.status = ValidatorStatus::Active;
            validator.finalized_synergy_score_bps = input.synergy_score_bps.min(BPS_DENOMINATOR);
            validator.synergy_score = validator.finalized_synergy_score_bps as f64 / 100.0;
            validator.cluster_id = input
                .previous_cluster_address
                .as_ref()
                .and_then(|address| previous_cluster_ids.get(address).copied());
            if validator.cluster_id.is_some() {
                validator.cluster_assignment_epoch = Some(epoch_id.saturating_sub(1));
            }
            validator
        })
        .collect::<Vec<_>>();
    let plan = canonical_validator_cluster_plan_for_epoch_with_seed(
        &runtime_validators,
        epoch_id,
        randomness_source,
    );
    let rotation_mode = match plan.rotation {
        CanonicalValidatorClusterRotation::LowScoreEpoch
        | CanonicalValidatorClusterRotation::None => RotationMode::RoutineRotation,
        CanonicalValidatorClusterRotation::CapacityExpansion
        | CanonicalValidatorClusterRotation::FullEpoch
        | CanonicalValidatorClusterRotation::StateRepair => RotationMode::FullPlannedReshuffle,
    };
    let assignment_reason = match plan.rotation {
        CanonicalValidatorClusterRotation::None => "stable_epoch_assignment",
        CanonicalValidatorClusterRotation::CapacityExpansion => "capacity_expansion",
        CanonicalValidatorClusterRotation::LowScoreEpoch => "low_score_epoch_rotation",
        CanonicalValidatorClusterRotation::FullEpoch => "ten_epoch_full_reshuffle",
        CanonicalValidatorClusterRotation::StateRepair => "assignment_state_repair",
    };
    let mut assignments = Vec::with_capacity(plan.clusters.len());
    for (_cluster_index, members) in plan.clusters {
        let cluster_address =
            canonical_validator_cluster_address(assignments.len() as u64, &members);
        let validator_ids = members
            .iter()
            .map(|validator| validator.address.clone())
            .collect::<Vec<_>>();
        assignments.push(ClusterAssignment {
            epoch_id,
            cluster_address,
            quorum_threshold: quorum_threshold(validator_ids.len()),
            fault_tolerance_f: fault_tolerance_f(validator_ids.len()),
            validator_ids,
            rotation_mode: rotation_mode.clone(),
            assignment_reason: assignment_reason.to_string(),
        });
    }

    let assignment_hash = hash_assignment_set(epoch_id, randomness_source, &assignments);
    Ok(ClusterAssignmentSet {
        epoch_id,
        assignment_hash,
        cluster_assignments: assignments,
        randomness_source: randomness_source.to_string(),
        generated_block_height,
    })
}

fn hash_assignment_set(
    epoch_id: u64,
    randomness_source: &str,
    assignments: &[ClusterAssignment],
) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(epoch_id.to_le_bytes());
    hasher.update(randomness_source.as_bytes());
    for assignment in assignments {
        hasher.update(assignment.cluster_address.as_bytes());
        for validator_id in &assignment.validator_ids {
            hasher.update(validator_id.as_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CoClusterHistory {
    pub validator_a: String,
    pub validator_b: String,
    pub epochs_together_count: u64,
    pub last_epoch_together: u64,
    pub rolling_window_count: u64,
}

pub fn update_co_cluster_history(
    history: &mut HashMap<(String, String), CoClusterHistory>,
    epoch_id: u64,
    assignments: &[ClusterAssignment],
    window_epochs: u64,
) {
    for assignment in assignments {
        for i in 0..assignment.validator_ids.len() {
            for j in i + 1..assignment.validator_ids.len() {
                let mut pair = [
                    assignment.validator_ids[i].clone(),
                    assignment.validator_ids[j].clone(),
                ];
                pair.sort();
                let key = (pair[0].clone(), pair[1].clone());
                let entry = history.entry(key).or_insert_with(|| CoClusterHistory {
                    validator_a: pair[0].clone(),
                    validator_b: pair[1].clone(),
                    ..CoClusterHistory::default()
                });
                entry.epochs_together_count = entry.epochs_together_count.saturating_add(1);
                entry.rolling_window_count =
                    if epoch_id.saturating_sub(entry.last_epoch_together) <= window_epochs {
                        entry.rolling_window_count.saturating_add(1)
                    } else {
                        1
                    };
                entry.last_epoch_together = epoch_id;
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationTriggerMetrics {
    pub validator_jailed: bool,
    pub validator_slashed: bool,
    pub double_signing_evidence: bool,
    pub invalid_block_proposal: bool,
    pub missed_quorum_event: bool,
    pub cluster_lost_quorum: bool,
    pub finality_degradation_bps: u64,
    pub repeated_latency_anomaly: bool,
    pub correlated_downtime: bool,
    pub cartel_risk_score_bps: u64,
    pub excessive_repeated_pairings: bool,
    pub cluster_performance_score_bps: u64,
    pub suspected_malicious_validators: usize,
    pub fault_tolerance_f: usize,
    pub consensus_safety_alarm: bool,
}

impl Default for RotationTriggerMetrics {
    fn default() -> Self {
        Self {
            validator_jailed: false,
            validator_slashed: false,
            double_signing_evidence: false,
            invalid_block_proposal: false,
            missed_quorum_event: false,
            cluster_lost_quorum: false,
            finality_degradation_bps: 0,
            repeated_latency_anomaly: false,
            correlated_downtime: false,
            cartel_risk_score_bps: 0,
            excessive_repeated_pairings: false,
            cluster_performance_score_bps: 10_000,
            suspected_malicious_validators: 0,
            fault_tolerance_f: 0,
            consensus_safety_alarm: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationDecision {
    pub rotation_mode: RotationMode,
    pub affected_cluster_address: String,
    pub reason: String,
    pub severity: RotationSeverity,
    pub execute_at_epoch: u64,
    pub execute_at_block_height_optional: Option<u64>,
    pub requires_mid_epoch_segmentation: bool,
}

pub fn evaluate_cluster_rotation_triggers(
    epoch_id: u64,
    cluster_address: &str,
    metrics: &RotationTriggerMetrics,
    config: &ClusterConfig,
) -> RotationDecision {
    let emergency = metrics.cluster_lost_quorum
        || metrics.double_signing_evidence
        || metrics.consensus_safety_alarm
        || metrics.suspected_malicious_validators > metrics.fault_tolerance_f
        || (metrics.correlated_downtime && metrics.cluster_performance_score_bps < 8_000);

    if emergency {
        return RotationDecision {
            rotation_mode: RotationMode::EmergencyRotation,
            affected_cluster_address: cluster_address.to_string(),
            reason: "safety_or_liveness_emergency".to_string(),
            severity: RotationSeverity::Critical,
            execute_at_epoch: epoch_id,
            execute_at_block_height_optional: None,
            requires_mid_epoch_segmentation: config.allow_mid_epoch_emergency_rotation,
        };
    }

    let risk = metrics.validator_jailed
        || metrics.validator_slashed
        || metrics.invalid_block_proposal
        || metrics.missed_quorum_event
        || metrics.repeated_latency_anomaly
        || metrics.excessive_repeated_pairings
        || metrics.cartel_risk_score_bps >= 7_500
        || metrics.cluster_performance_score_bps < 9_000;
    if risk {
        return RotationDecision {
            rotation_mode: RotationMode::RiskRotation,
            affected_cluster_address: cluster_address.to_string(),
            reason: "risk_trigger_detected".to_string(),
            severity: RotationSeverity::Elevated,
            execute_at_epoch: epoch_id + 1,
            execute_at_block_height_optional: None,
            requires_mid_epoch_segmentation: false,
        };
    }

    RotationDecision {
        rotation_mode: RotationMode::RoutineRotation,
        affected_cluster_address: cluster_address.to_string(),
        reason: "normal_epoch_boundary".to_string(),
        severity: RotationSeverity::Normal,
        execute_at_epoch: epoch_id + 1,
        execute_at_block_height_optional: None,
        requires_mid_epoch_segmentation: false,
    }
}

pub fn rotation_count(cluster_size: usize, rotation_bps: u64) -> usize {
    if cluster_size == 0 || rotation_bps == 0 {
        return 0;
    }
    let count = ((cluster_size as u128) * (rotation_bps as u128)) / (BPS_DENOMINATOR as u128);
    usize::try_from(count)
        .unwrap_or(cluster_size)
        .clamp(1, cluster_size)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochClusterAssignmentSnapshot {
    pub epoch_id: u64,
    pub cluster_address: String,
    pub validator_ids: Vec<String>,
    pub quorum_threshold: usize,
    pub fault_tolerance_f: usize,
    pub assignment_hash: String,
    pub rotation_mode: RotationMode,
    pub created_block_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochParticipationSnapshot {
    pub epoch_id: u64,
    pub cluster_address: String,
    pub validator_id: String,
    pub validator_reward_address: String,
    pub validator_stake_at_epoch_start: u128,
    pub validator_synergy_score_at_epoch_start: u64,
    pub participation_score_bps: u64,
    pub proposal_score_bps: u64,
    pub validation_score_bps: u64,
    pub uptime_score_bps: u64,
    pub cluster_performance_score_bps: u64,
    pub pending_reward_nwei: u128,
    pub accountability_epoch: u64,
    pub unlock_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochParticipationSegment {
    pub epoch_id: u64,
    pub segment_id: String,
    pub cluster_address: String,
    pub validator_id: String,
    pub start_block_height: u64,
    pub end_block_height: u64,
    pub participation_score_bps: u64,
    pub cluster_performance_score_bps: u64,
    pub segment_reward_nwei: u128,
    pub segment_reason: String,
}

pub fn segmented_pending_reward(segments: &[EpochParticipationSegment]) -> Result<u128, String> {
    segments
        .iter()
        .try_fold(0u128, |acc, segment| {
            acc.checked_add(segment.segment_reward_nwei)
        })
        .ok_or_else(|| "segmented reward overflow".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterStatusResponse {
    pub cluster_address: String,
    pub status: ClusterStatus,
    pub current_epoch: u64,
    pub current_validator_ids: Vec<String>,
    pub previous_validator_ids: Vec<String>,
    pub current_quorum_threshold: usize,
    pub current_fault_tolerance_f: usize,
    pub current_rotation_mode: RotationMode,
    pub last_rotation_epoch: Option<u64>,
    pub last_full_rotation_epoch: Option<u64>,
    pub total_rewards_earned_nwei: u128,
    pub total_rewards_settled_nwei: u128,
    pub recent_performance_score_bps: u64,
    pub recent_finality_success_rate_bps: u64,
    pub recent_missed_rounds: u64,
    pub recent_slashing_events: u64,
    pub cartel_risk_score_bps: Option<u64>,
    pub co_cluster_repetition_summary: Option<BTreeMap<String, u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorClusterHistoryResponse {
    pub validator_id: String,
    pub current_cluster_address: Option<String>,
    pub prior_cluster_assignments: Vec<EpochClusterAssignmentSnapshot>,
    pub epochs_by_cluster: BTreeMap<String, Vec<u64>>,
    pub pending_rewards_by_original_cluster: BTreeMap<String, u128>,
    pub participation_segments: Vec<EpochParticipationSegment>,
    pub reliability_streak: u64,
    pub current_bonus_tier: u64,
    pub next_bonus_tier: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClusterAuditEvent {
    ClusterCreated {
        cluster_address: String,
        cluster_index: u64,
        created_epoch: u64,
        created_block_height: u64,
    },
    ClusterRetired {
        cluster_address: String,
        retired_epoch: u64,
        retired_block_height: u64,
        reason: String,
    },
    ClusterAssignmentComputed {
        epoch_id: u64,
        assignment_hash: String,
        cluster_count: usize,
        randomness_source: String,
    },
    ClusterRotationExecuted {
        epoch_id: u64,
        cluster_address: String,
        rotation_mode: RotationMode,
        rotation_bps: u64,
        removed_validator_ids: Vec<String>,
        added_validator_ids: Vec<String>,
        reason: String,
    },
    ClusterEmergencyRotationExecuted {
        epoch_id: u64,
        cluster_address: String,
        block_height: u64,
        reason: String,
        segment_required: bool,
    },
    EpochClusterAssignmentSnapshotCreated {
        epoch_id: u64,
        cluster_address: String,
        validator_count: usize,
        quorum_threshold: usize,
        fault_tolerance_f: usize,
        assignment_hash: String,
    },
    EpochParticipationSegmentCreated(EpochParticipationSegment),
    CoClusterHistoryUpdated {
        epoch_id: u64,
        validator_a: String,
        validator_b: String,
        rolling_window_count: u64,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterLedger {
    pub clusters: HashMap<String, Cluster>,
    pub assignment_snapshots: HashMap<u64, Vec<EpochClusterAssignmentSnapshot>>,
    pub participation_snapshots: Vec<EpochParticipationSnapshot>,
    pub participation_segments: Vec<EpochParticipationSegment>,
    pub co_cluster_history: HashMap<(String, String), CoClusterHistory>,
    pub audit_events: Vec<ClusterAuditEvent>,
}

lazy_static! {
    pub static ref CLUSTER_LEDGER: Arc<Mutex<ClusterLedger>> =
        Arc::new(Mutex::new(ClusterLedger::default()));
}

impl ClusterLedger {
    pub fn ensure_cluster(
        &mut self,
        network_id: &str,
        genesis_hash: &str,
        cluster_index: u64,
        epoch_id: u64,
        block_height: u64,
        config: &ClusterConfig,
    ) -> String {
        let address = derive_synergy_cluster_address(network_id, genesis_hash, cluster_index, 0);
        self.clusters.entry(address.clone()).or_insert_with(|| {
            let cluster = Cluster::new(
                network_id,
                genesis_hash,
                cluster_index,
                epoch_id,
                block_height,
                config,
            );
            self.audit_events.push(ClusterAuditEvent::ClusterCreated {
                cluster_address: cluster.cluster_address.clone(),
                cluster_index,
                created_epoch: epoch_id,
                created_block_height: block_height,
            });
            cluster
        });
        address
    }

    pub fn apply_assignment_set(
        &mut self,
        assignment_set: ClusterAssignmentSet,
        config: &ClusterConfig,
    ) -> Result<(), String> {
        let mut snapshots = Vec::new();
        for assignment in assignment_set.cluster_assignments {
            if !is_valid_cluster_address(&assignment.cluster_address) {
                return Err(format!(
                    "invalid cluster address {}",
                    assignment.cluster_address
                ));
            }
            let cluster = self
                .clusters
                .entry(assignment.cluster_address.clone())
                .or_insert_with(|| Cluster {
                    cluster_address: assignment.cluster_address.clone(),
                    cluster_index: 0,
                    created_epoch: assignment.epoch_id,
                    created_block_height: assignment_set.generated_block_height,
                    status: ClusterStatus::Active,
                    current_epoch: assignment.epoch_id,
                    current_validator_ids: Vec::new(),
                    previous_validator_ids: Vec::new(),
                    target_cluster_size: config.target_cluster_size,
                    min_cluster_size: config.minimum_cluster_size,
                    max_cluster_size: config.maximum_cluster_size,
                    current_quorum_threshold: 0,
                    current_fault_tolerance_f: 0,
                    total_rewards_earned_nwei: 0,
                    total_rewards_settled_nwei: 0,
                    total_blocks_proposed: 0,
                    total_blocks_finalized: 0,
                    total_missed_rounds: 0,
                    total_slashing_events: 0,
                    total_emergency_rotations: 0,
                    last_rotation_epoch: None,
                    last_full_rotation_epoch: None,
                });
            cluster.apply_assignment(assignment.epoch_id, assignment.validator_ids.clone());
            if matches!(assignment.rotation_mode, RotationMode::FullPlannedReshuffle) {
                cluster.last_full_rotation_epoch = Some(assignment.epoch_id);
            }
            snapshots.push(EpochClusterAssignmentSnapshot {
                epoch_id: assignment.epoch_id,
                cluster_address: assignment.cluster_address.clone(),
                validator_ids: assignment.validator_ids.clone(),
                quorum_threshold: assignment.quorum_threshold,
                fault_tolerance_f: assignment.fault_tolerance_f,
                assignment_hash: assignment_set.assignment_hash.clone(),
                rotation_mode: assignment.rotation_mode.clone(),
                created_block_height: assignment_set.generated_block_height,
            });
            self.audit_events
                .push(ClusterAuditEvent::EpochClusterAssignmentSnapshotCreated {
                    epoch_id: assignment.epoch_id,
                    cluster_address: assignment.cluster_address,
                    validator_count: assignment.validator_ids.len(),
                    quorum_threshold: assignment.quorum_threshold,
                    fault_tolerance_f: assignment.fault_tolerance_f,
                    assignment_hash: assignment_set.assignment_hash.clone(),
                });
        }
        update_co_cluster_history(
            &mut self.co_cluster_history,
            assignment_set.epoch_id,
            &snapshots
                .iter()
                .map(|snapshot| ClusterAssignment {
                    epoch_id: snapshot.epoch_id,
                    cluster_address: snapshot.cluster_address.clone(),
                    validator_ids: snapshot.validator_ids.clone(),
                    quorum_threshold: snapshot.quorum_threshold,
                    fault_tolerance_f: snapshot.fault_tolerance_f,
                    rotation_mode: snapshot.rotation_mode.clone(),
                    assignment_reason: "snapshot".to_string(),
                })
                .collect::<Vec<_>>(),
            config.co_cluster_history_window_epochs,
        );
        self.assignment_snapshots
            .insert(assignment_set.epoch_id, snapshots);
        Ok(())
    }

    pub fn get_cluster_status(&self, cluster_address: &str) -> Option<ClusterStatusResponse> {
        self.clusters
            .get(cluster_address)
            .map(|cluster| ClusterStatusResponse {
                cluster_address: cluster.cluster_address.clone(),
                status: cluster.status.clone(),
                current_epoch: cluster.current_epoch,
                current_validator_ids: cluster.current_validator_ids.clone(),
                previous_validator_ids: cluster.previous_validator_ids.clone(),
                current_quorum_threshold: cluster.current_quorum_threshold,
                current_fault_tolerance_f: cluster.current_fault_tolerance_f,
                current_rotation_mode: RotationMode::RoutineRotation,
                last_rotation_epoch: cluster.last_rotation_epoch,
                last_full_rotation_epoch: cluster.last_full_rotation_epoch,
                total_rewards_earned_nwei: cluster.total_rewards_earned_nwei,
                total_rewards_settled_nwei: cluster.total_rewards_settled_nwei,
                recent_performance_score_bps: 0,
                recent_finality_success_rate_bps: 0,
                recent_missed_rounds: cluster.total_missed_rounds,
                recent_slashing_events: cluster.total_slashing_events,
                cartel_risk_score_bps: None,
                co_cluster_repetition_summary: None,
            })
    }

    pub fn get_epoch_cluster_assignments(
        &self,
        epoch_id: u64,
    ) -> Vec<EpochClusterAssignmentSnapshot> {
        self.assignment_snapshots
            .get(&epoch_id)
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validators(count: usize) -> Vec<ValidatorAssignmentInput> {
        (0..count)
            .map(|index| ValidatorAssignmentInput {
                validator_id: format!("validator-{index}"),
                stake_nwei: 1_000_000_000,
                synergy_score_bps: 10_000,
                jailed: false,
                slashed: false,
                infrastructure_domain: None,
                geographic_region: None,
                previous_cluster_address: None,
            })
            .collect()
    }

    #[test]
    fn syngrp1_cluster_address_is_exactly_41_characters() {
        let address = derive_synergy_cluster_address("synergy-testnet", "genesis", 0, 0);
        assert_eq!(address.len(), 41);
        assert!(address.starts_with("syngrp1"));
        assert!(is_valid_cluster_address(&address));
    }

    #[test]
    fn invalid_cluster_address_length_or_prefix_is_rejected() {
        assert!(!is_valid_cluster_address("syngrp1short"));
        assert!(!is_valid_cluster_address(
            "synw1yccae2hurf7zr3udzus3200x04jlvgds0wkw"
        ));
    }

    #[test]
    fn cluster_sizing_examples_are_balanced() {
        let config = ClusterConfig::default();
        assert_eq!(balanced_cluster_sizes(5, &config), vec![5]);
        assert_eq!(balanced_cluster_sizes(9, &config), vec![9]);
        assert_eq!(balanced_cluster_sizes(10, &config), vec![5, 5]);
        assert_eq!(balanced_cluster_sizes(18, &config), vec![9, 9]);
        assert_eq!(balanced_cluster_sizes(28, &config), vec![7, 7, 7, 7]);
        assert_eq!(balanced_cluster_sizes(35, &config), vec![7, 7, 7, 7, 7]);
        assert_eq!(
            balanced_cluster_sizes(60, &config),
            vec![8, 8, 8, 8, 7, 7, 7, 7]
        );
        assert_eq!(balanced_cluster_sizes(154, &config), vec![7; 22]);
    }

    #[test]
    fn community_validator_cluster_thresholds_follow_protocol_expansion_rules() {
        let config = ClusterConfig::default();
        let cases = [
            (0, vec![]),
            (1, vec![1]),
            (9, vec![9]),
            (10, vec![5, 5]),
            (20, vec![10, 10]),
            (21, vec![7, 7, 7]),
            (27, vec![9, 9, 9]),
            (28, vec![7, 7, 7, 7]),
            (34, vec![9, 9, 8, 8]),
            (35, vec![7, 7, 7, 7, 7]),
            (42, vec![7, 7, 7, 7, 7, 7]),
            (154, vec![7; 22]),
        ];

        for (validator_count, expected_sizes) in cases {
            assert_eq!(
                balanced_cluster_sizes(validator_count, &config),
                expected_sizes,
                "unexpected balanced cluster sizes for {validator_count} validators"
            );
            assert_eq!(
                cluster_count_for_active_validators(validator_count, &config),
                expected_sizes.len(),
                "unexpected cluster count for {validator_count} validators"
            );
        }

        assert_eq!(quorum_threshold(5), 4, "two 5-node clusters must be 4-of-5");
        assert_eq!(
            quorum_threshold(7),
            5,
            "three or more 7-node clusters must be 5-of-7"
        );
    }

    #[test]
    fn quorum_and_fault_tolerance_are_bft_derived() {
        assert_eq!(fault_tolerance_f(5), 1);
        assert_eq!(quorum_threshold(5), 4);
        assert_eq!(fault_tolerance_f(6), 1);
        assert_eq!(quorum_threshold(6), 5);
        assert_eq!(fault_tolerance_f(7), 2);
        assert_eq!(quorum_threshold(7), 5);
        assert_eq!(fault_tolerance_f(10), 3);
        assert_eq!(quorum_threshold(10), 7);
        assert_eq!(fault_tolerance_f(12), 3);
        assert_eq!(quorum_threshold(12), 9);
        assert_eq!(fault_tolerance_f(13), 4);
        assert_eq!(quorum_threshold(13), 9);
    }

    #[test]
    fn dynamic_cluster_assignments_keep_independent_quorum_per_cluster() {
        let config = ClusterConfig::default();
        let active = validators(13);
        let assignments = compute_cluster_assignments(
            11,
            &active,
            "synergy-testnet",
            "genesis",
            "block-hash",
            500,
            &config,
        )
        .unwrap();

        let cluster_sizes = assignments
            .cluster_assignments
            .iter()
            .map(|assignment| assignment.validator_ids.len())
            .collect::<Vec<_>>();
        assert_eq!(cluster_sizes, vec![7, 6]);
        for assignment in assignments.cluster_assignments {
            assert_eq!(
                assignment.quorum_threshold,
                quorum_threshold(assignment.validator_ids.len())
            );
            assert_eq!(
                assignment.fault_tolerance_f,
                fault_tolerance_f(assignment.validator_ids.len())
            );
        }
    }

    #[test]
    fn dynamic_cluster_assignment_supports_three_clusters() {
        let config = ClusterConfig::default();
        let active = validators(21);
        let assignments = compute_cluster_assignments(
            12,
            &active,
            "synergy-testnet",
            "genesis",
            "block-hash",
            600,
            &config,
        )
        .unwrap();

        assert_eq!(assignments.cluster_assignments.len(), 3);
        assert!(assignments
            .cluster_assignments
            .iter()
            .all(|assignment| assignment.validator_ids.len() == 7
                && assignment.quorum_threshold == 5));
    }

    #[test]
    fn assignments_are_deterministic_for_same_epoch_input() {
        let config = ClusterConfig::default();
        let active = validators(24);
        let a = compute_cluster_assignments(
            7,
            &active,
            "synergy-testnet",
            "genesis",
            "block-hash",
            100,
            &config,
        )
        .unwrap();
        let b = compute_cluster_assignments(
            7,
            &active,
            "synergy-testnet",
            "genesis",
            "block-hash",
            100,
            &config,
        )
        .unwrap();
        assert_eq!(a.assignment_hash, b.assignment_hash);
        assert_eq!(a.cluster_assignments, b.cluster_assignments);
    }

    #[test]
    fn assignments_change_when_randomness_changes() {
        let config = ClusterConfig::default();
        let active = validators(24);
        let a = compute_cluster_assignments(
            7,
            &active,
            "synergy-testnet",
            "genesis",
            "block-a",
            100,
            &config,
        )
        .unwrap();
        let b = compute_cluster_assignments(
            7,
            &active,
            "synergy-testnet",
            "genesis",
            "block-b",
            100,
            &config,
        )
        .unwrap();
        assert_ne!(a.assignment_hash, b.assignment_hash);
    }

    #[test]
    fn routine_rotation_count_defaults_to_25_percent() {
        assert_eq!(
            rotation_count(12, ClusterConfig::default().routine_rotation_bps),
            3
        );
        assert_eq!(
            rotation_count(5, ClusterConfig::default().routine_rotation_bps),
            1
        );
    }

    #[test]
    fn risk_and_emergency_triggers_are_distinct() {
        let config = ClusterConfig::default();
        let risk = RotationTriggerMetrics {
            validator_jailed: true,
            ..RotationTriggerMetrics::default()
        };
        let decision = evaluate_cluster_rotation_triggers(10, "cluster", &risk, &config);
        assert_eq!(decision.rotation_mode, RotationMode::RiskRotation);
        assert_eq!(decision.severity, RotationSeverity::Elevated);

        let emergency = RotationTriggerMetrics {
            cluster_lost_quorum: true,
            ..RotationTriggerMetrics::default()
        };
        let decision = evaluate_cluster_rotation_triggers(10, "cluster", &emergency, &config);
        assert_eq!(decision.rotation_mode, RotationMode::EmergencyRotation);
        assert!(decision.requires_mid_epoch_segmentation);
    }

    #[test]
    fn segmented_rewards_sum_deterministically() {
        let segments = vec![
            EpochParticipationSegment {
                epoch_id: 10,
                segment_id: "10:0".to_string(),
                cluster_address: "cluster-a".to_string(),
                validator_id: "validator-7".to_string(),
                start_block_height: 1,
                end_block_height: 10,
                participation_score_bps: 10_000,
                cluster_performance_score_bps: 10_000,
                segment_reward_nwei: 300,
                segment_reason: "normal".to_string(),
            },
            EpochParticipationSegment {
                epoch_id: 10,
                segment_id: "10:1".to_string(),
                cluster_address: "cluster-b".to_string(),
                validator_id: "validator-7".to_string(),
                start_block_height: 11,
                end_block_height: 20,
                participation_score_bps: 10_000,
                cluster_performance_score_bps: 10_000,
                segment_reward_nwei: 500,
                segment_reason: "emergency_rotation".to_string(),
            },
        ];
        assert_eq!(segmented_pending_reward(&segments).unwrap(), 800);
    }

    #[test]
    fn cluster_address_stays_stable_after_rotation() {
        let config = ClusterConfig::default();
        let mut cluster = Cluster::new("synergy-testnet", "genesis", 0, 0, 1, &config);
        let address = cluster.cluster_address.clone();
        cluster.apply_assignment(1, vec!["a".to_string(), "b".to_string()]);
        cluster.apply_assignment(2, vec!["c".to_string(), "d".to_string()]);
        assert_eq!(cluster.cluster_address, address);
        assert_eq!(
            cluster.previous_validator_ids,
            vec!["a".to_string(), "b".to_string()]
        );
    }
}
