use crate::consensus::validator_scoring_params::{ValidatorScoringConfig, BPS_DENOMINATOR};
use crate::crypto::pqc::PQCManager;
use crate::validator::{Validator, ValidatorManager};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const VERBOSE_SYNERGY_LOGS: bool = false;

macro_rules! synergy_log {
    ($($arg:tt)*) => {
        if VERBOSE_SYNERGY_LOGS {
            println!($($arg)*);
        }
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynergyScoreComponents {
    pub stake_weight: f64,
    pub reputation: f64,
    pub contribution_index: f64,
    pub cartelization_penalty: f64,
    pub normalized_score: f64,
    pub last_updated: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorMetrics {
    pub stake_amount: u64,
    pub blocks_participated: u64,
    pub blocks_eligible: u64,
    pub correct_votes: u64,
    pub total_votes: u64,
    pub successful_proposals: u64,
    pub relay_assists: u64,
    pub average_latency: f64,
    pub slashing_penalty: f64,
    pub last_update_block: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSnapshot {
    pub epoch_number: u64,
    pub total_stake: u64,
    pub active_validator_count: usize,
    pub individual_synergy_scores: HashMap<String, f64>,
    pub merkle_root: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorSynergyScoreProfile {
    pub validator_address: String,
    pub operator_address: Option<String>,
    pub cluster_address: Option<String>,
    pub current_score_bps: u64,
    pub previous_score_bps: u64,
    pub score_version: u64,
    pub last_scored_epoch: u64,
    pub last_clean_epoch: Option<u64>,
    pub status_for_rewards: String,
    pub created_at: u64,
    pub updated_at: u64,
}

impl ValidatorSynergyScoreProfile {
    pub fn initialized(
        validator_address: impl Into<String>,
        operator_address: Option<String>,
        cluster_address: Option<String>,
        epoch: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            validator_address: validator_address.into(),
            operator_address,
            cluster_address,
            current_score_bps: BPS_DENOMINATOR,
            previous_score_bps: BPS_DENOMINATOR,
            score_version: 1,
            last_scored_epoch: epoch,
            last_clean_epoch: None,
            status_for_rewards: "eligible".to_string(),
            created_at: timestamp,
            updated_at: timestamp,
        }
    }

    pub fn existing(
        validator_address: impl Into<String>,
        operator_address: Option<String>,
        cluster_address: Option<String>,
        current_score_bps: u64,
        previous_score_bps: u64,
        score_version: u64,
        last_scored_epoch: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            validator_address: validator_address.into(),
            operator_address,
            cluster_address,
            current_score_bps: clamp_bps(current_score_bps),
            previous_score_bps: clamp_bps(previous_score_bps),
            score_version,
            last_scored_epoch,
            last_clean_epoch: None,
            status_for_rewards: "eligible".to_string(),
            created_at: timestamp,
            updated_at: timestamp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorEpochEvidence {
    pub epoch: u64,
    pub validator_address: String,
    pub expected_consensus_duties: u64,
    pub observed_consensus_votes: u64,
    pub expected_responsiveness_messages: u64,
    pub timely_responsiveness_messages: u64,
    pub assigned_proposals: u64,
    pub successful_proposals: u64,
    pub missed_proposals: u64,
    pub rejected_or_invalid_proposals: u64,
    pub valid_signed_artifacts: u64,
    pub invalid_signed_artifacts: u64,
    pub equivocation_evidence: u64,
    pub state_hash_mismatches: u64,
    pub cluster_expected_contributions: u64,
    pub cluster_observed_contributions: u64,
    pub uptime_observed_checks: u64,
    pub uptime_successful_checks: u64,
    pub config_compliant: Option<bool>,
    pub telemetry_available: Option<bool>,
    pub telemetry_missing_operator_fault: bool,
    pub scoring_data_available: bool,
    pub incident_relief: bool,
    pub reason_codes: Vec<String>,
    pub evidence_refs: Vec<String>,
}

impl ValidatorEpochEvidence {
    pub fn no_history(validator_address: impl Into<String>, epoch: u64) -> Self {
        Self {
            epoch,
            validator_address: validator_address.into(),
            expected_consensus_duties: 0,
            observed_consensus_votes: 0,
            expected_responsiveness_messages: 0,
            timely_responsiveness_messages: 0,
            assigned_proposals: 0,
            successful_proposals: 0,
            missed_proposals: 0,
            rejected_or_invalid_proposals: 0,
            valid_signed_artifacts: 0,
            invalid_signed_artifacts: 0,
            equivocation_evidence: 0,
            state_hash_mismatches: 0,
            cluster_expected_contributions: 0,
            cluster_observed_contributions: 0,
            uptime_observed_checks: 0,
            uptime_successful_checks: 0,
            config_compliant: None,
            telemetry_available: None,
            telemetry_missing_operator_fault: false,
            scoring_data_available: false,
            incident_relief: false,
            reason_codes: vec!["SCORE_INITIALIZED_NO_HISTORY".to_string()],
            evidence_refs: Vec::new(),
        }
    }

    pub fn from_validator(validator: &Validator, epoch: u64) -> Self {
        let expected_consensus_duties = validator
            .total_transactions_validated
            .saturating_add(validator.missed_blocks);
        if expected_consensus_duties == 0
            && validator.total_blocks_produced == 0
            && validator.double_signs == 0
            && validator.equivocation_evidence_count == 0
        {
            return Self::no_history(validator.address.clone(), epoch);
        }

        let valid_signed_artifacts = validator
            .total_transactions_validated
            .saturating_add(validator.total_blocks_produced);
        Self {
            epoch,
            validator_address: validator.address.clone(),
            expected_consensus_duties,
            observed_consensus_votes: validator.total_transactions_validated,
            expected_responsiveness_messages: expected_consensus_duties,
            timely_responsiveness_messages: validator.total_transactions_validated,
            assigned_proposals: validator
                .total_blocks_produced
                .saturating_add(validator.missed_blocks),
            successful_proposals: validator.total_blocks_produced,
            missed_proposals: validator.missed_blocks,
            rejected_or_invalid_proposals: 0,
            valid_signed_artifacts,
            invalid_signed_artifacts: validator.double_signs,
            equivocation_evidence: validator
                .equivocation_evidence_count
                .saturating_add(validator.double_signs),
            state_hash_mismatches: 0,
            cluster_expected_contributions: 0,
            cluster_observed_contributions: 0,
            uptime_observed_checks: expected_consensus_duties,
            uptime_successful_checks: validator.total_transactions_validated,
            config_compliant: Some(true),
            telemetry_available: Some(true),
            telemetry_missing_operator_fault: false,
            scoring_data_available: true,
            incident_relief: false,
            reason_codes: Vec::new(),
            evidence_refs: vec![format!(
                "validator-registry:{}:epoch:{}",
                validator.address, epoch
            )],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorEpochScorecard {
    pub epoch: u64,
    pub validator_address: String,
    pub score_before_bps: u64,
    pub epoch_raw_score_bps: u64,
    pub score_after_bps: u64,
    pub consensus_participation_bps: u64,
    pub proposal_participation_bps: u64,
    pub validation_accuracy_bps: u64,
    pub cluster_contribution_bps: u64,
    pub uptime_bps: u64,
    pub responsiveness_bps: u64,
    pub config_compliance_bps: u64,
    pub telemetry_integrity_bps: u64,
    pub fault_penalty_bps: u64,
    pub reward_score_coefficient_bps: u64,
    pub reason_codes: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub finalized_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorScoreEvent {
    pub event_id: String,
    pub epoch: u64,
    pub block_height: Option<u64>,
    pub artifact_ref: Option<String>,
    pub validator_address: String,
    pub event_type: String,
    pub severity: String,
    pub score_delta_bps: i64,
    pub reason_code: String,
    pub evidence_ref: Option<String>,
    pub emitted_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorScoreComputation {
    pub profile: ValidatorSynergyScoreProfile,
    pub scorecard: ValidatorEpochScorecard,
    pub events: Vec<ValidatorScoreEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultCategory {
    None,
    Minor,
    Major,
    Critical,
    IncidentRelief,
}

pub fn clamp_bps(value: u64) -> u64 {
    value.min(BPS_DENOMINATOR)
}

fn add_reason(reason_codes: &mut Vec<String>, reason: &str) {
    if !reason_codes.iter().any(|existing| existing == reason) {
        reason_codes.push(reason.to_string());
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return BPS_DENOMINATOR;
    }
    let capped_numerator = numerator.min(denominator);
    ((capped_numerator as u128 * BPS_DENOMINATOR as u128) / denominator as u128) as u64
}

fn score_reward_coefficient_from_score(score_bps: u64) -> u64 {
    match clamp_bps(score_bps) {
        9_500..=10_000 => BPS_DENOMINATOR,
        9_000..=9_499 => 9_500,
        8_000..=8_999 => 8_500,
        7_000..=7_999 => 7_000,
        6_000..=6_999 => 5_000,
        5_000..=5_999 => 2_500,
        _ => 0,
    }
}

fn weighted_epoch_raw_score_bps(
    uptime_bps: u64,
    responsiveness_bps: u64,
    consensus_participation_bps: u64,
    validation_accuracy_bps: u64,
    cluster_contribution_bps: u64,
    config_compliance_bps: u64,
    telemetry_integrity_bps: u64,
    config: &ValidatorScoringConfig,
) -> u64 {
    let weighted = (uptime_bps as u128 * config.uptime_weight_bps as u128)
        + (responsiveness_bps as u128 * config.responsiveness_weight_bps as u128)
        + (consensus_participation_bps as u128 * config.consensus_participation_weight_bps as u128)
        + (validation_accuracy_bps as u128 * config.validation_accuracy_weight_bps as u128)
        + (cluster_contribution_bps as u128 * config.cluster_contribution_weight_bps as u128)
        + (config_compliance_bps as u128 * config.config_compliance_weight_bps as u128)
        + (telemetry_integrity_bps as u128 * config.telemetry_integrity_weight_bps as u128);
    (weighted / BPS_DENOMINATOR as u128) as u64
}

fn config_compliance_score(
    evidence: &ValidatorEpochEvidence,
    reason_codes: &mut Vec<String>,
) -> u64 {
    match evidence.config_compliant {
        Some(true) => BPS_DENOMINATOR,
        Some(false) => {
            add_reason(reason_codes, "CONFIG_NONCOMPLIANT");
            0
        }
        None => {
            add_reason(reason_codes, "CONFIG_DATA_UNAVAILABLE");
            BPS_DENOMINATOR
        }
    }
}

fn telemetry_integrity_score(
    evidence: &ValidatorEpochEvidence,
    reason_codes: &mut Vec<String>,
) -> u64 {
    match evidence.telemetry_available {
        Some(true) => BPS_DENOMINATOR,
        Some(false) if evidence.telemetry_missing_operator_fault => {
            add_reason(reason_codes, "VALIDATOR_TELEMETRY_MISSING");
            0
        }
        Some(false) | None => {
            add_reason(reason_codes, "SCORING_DATA_UNAVAILABLE");
            BPS_DENOMINATOR
        }
    }
}

fn classify_fault(
    evidence: &ValidatorEpochEvidence,
    reason_codes: &mut Vec<String>,
) -> FaultCategory {
    if evidence.incident_relief {
        add_reason(reason_codes, "CATEGORY_D_INCIDENT_RELIEF");
        return FaultCategory::IncidentRelief;
    }

    if evidence.equivocation_evidence > 0
        || evidence.invalid_signed_artifacts > 0
        || evidence.state_hash_mismatches > 0
    {
        add_reason(reason_codes, "CATEGORY_A_INTEGRITY_FAULT");
        return FaultCategory::Critical;
    }

    let persistent_misses = evidence.expected_consensus_duties > 0
        && evidence.observed_consensus_votes.saturating_mul(2) < evidence.expected_consensus_duties;
    let serious_downtime = evidence.uptime_observed_checks > 0
        && evidence.uptime_successful_checks.saturating_mul(100)
            < evidence.uptime_observed_checks.saturating_mul(97);
    let config_or_telemetry_failure = evidence.config_compliant == Some(false)
        || (evidence.telemetry_available == Some(false)
            && evidence.telemetry_missing_operator_fault);

    if persistent_misses || serious_downtime || config_or_telemetry_failure {
        add_reason(reason_codes, "CATEGORY_B_OPERATIONAL_FAULT");
        return FaultCategory::Major;
    }

    let brief_downtime = evidence.expected_consensus_duties > evidence.observed_consensus_votes
        || evidence.missed_proposals > 0
        || evidence.rejected_or_invalid_proposals > 0;
    if brief_downtime {
        add_reason(reason_codes, "CATEGORY_C_MINOR_FAULT");
        return FaultCategory::Minor;
    }

    FaultCategory::None
}

pub fn calculate_validator_epoch_score(
    profile: &ValidatorSynergyScoreProfile,
    evidence: &ValidatorEpochEvidence,
    config: &ValidatorScoringConfig,
) -> Result<ValidatorScoreComputation, String> {
    config.validate()?;

    let finalized_at = current_timestamp();
    let mut reason_codes = evidence.reason_codes.clone();
    let score_before_bps = clamp_bps(profile.current_score_bps);

    let scoring_data_available = evidence.scoring_data_available;
    if !scoring_data_available {
        add_reason(&mut reason_codes, "SCORING_DATA_UNAVAILABLE");
    }
    if profile.score_version <= 1 && profile.last_scored_epoch == evidence.epoch {
        add_reason(&mut reason_codes, "SCORE_INITIALIZED_NO_HISTORY");
    }

    let consensus_participation_bps = if scoring_data_available {
        if evidence.expected_consensus_duties == 0 {
            add_reason(&mut reason_codes, "NO_CONSENSUS_DUTY_ASSIGNED");
        }
        ratio_bps(
            evidence.observed_consensus_votes,
            evidence.expected_consensus_duties,
        )
    } else {
        BPS_DENOMINATOR
    };

    let responsiveness_bps = if scoring_data_available {
        if evidence.expected_responsiveness_messages == 0 {
            add_reason(&mut reason_codes, "NO_RESPONSIVENESS_DUTY_ASSIGNED");
        }
        ratio_bps(
            evidence.timely_responsiveness_messages,
            evidence.expected_responsiveness_messages,
        )
    } else {
        BPS_DENOMINATOR
    };

    let proposal_participation_bps = if scoring_data_available {
        if evidence.assigned_proposals == 0 {
            add_reason(&mut reason_codes, "NO_PROPOSAL_DUTY_ASSIGNED");
            BPS_DENOMINATOR
        } else {
            ratio_bps(evidence.successful_proposals, evidence.assigned_proposals)
        }
    } else {
        BPS_DENOMINATOR
    };

    let signed_artifact_count = evidence
        .valid_signed_artifacts
        .saturating_add(evidence.invalid_signed_artifacts)
        .saturating_add(evidence.equivocation_evidence)
        .saturating_add(evidence.state_hash_mismatches);
    let validation_accuracy_bps = if scoring_data_available {
        if signed_artifact_count == 0 {
            add_reason(&mut reason_codes, "NO_SIGNED_ARTIFACTS_OBSERVED");
        }
        ratio_bps(evidence.valid_signed_artifacts, signed_artifact_count)
    } else {
        BPS_DENOMINATOR
    };

    let cluster_contribution_bps = if scoring_data_available {
        if evidence.cluster_expected_contributions == 0 {
            add_reason(&mut reason_codes, "CLUSTER_CONTRIBUTION_NOT_MEASURED");
            BPS_DENOMINATOR
        } else {
            ratio_bps(
                evidence.cluster_observed_contributions,
                evidence.cluster_expected_contributions,
            )
        }
    } else {
        BPS_DENOMINATOR
    };

    let uptime_bps = if scoring_data_available {
        if evidence.uptime_observed_checks == 0 {
            add_reason(&mut reason_codes, "UPTIME_DATA_UNAVAILABLE");
        }
        ratio_bps(
            evidence.uptime_successful_checks,
            evidence.uptime_observed_checks,
        )
    } else {
        BPS_DENOMINATOR
    };

    let config_compliance_bps = if scoring_data_available {
        config_compliance_score(evidence, &mut reason_codes)
    } else {
        BPS_DENOMINATOR
    };
    let telemetry_integrity_bps = if scoring_data_available {
        telemetry_integrity_score(evidence, &mut reason_codes)
    } else {
        BPS_DENOMINATOR
    };

    let epoch_raw_score_bps = clamp_bps(weighted_epoch_raw_score_bps(
        uptime_bps,
        responsiveness_bps,
        consensus_participation_bps,
        validation_accuracy_bps,
        cluster_contribution_bps,
        config_compliance_bps,
        telemetry_integrity_bps,
        config,
    ));

    let score_after_bps = ((score_before_bps as u128 * config.previous_score_weight_bps as u128)
        + (epoch_raw_score_bps as u128 * config.epoch_score_weight_bps as u128))
        / BPS_DENOMINATOR as u128;
    let mut score_after_bps = score_after_bps as u64;

    let fault_category = classify_fault(evidence, &mut reason_codes);
    if matches!(
        fault_category,
        FaultCategory::None | FaultCategory::IncidentRelief
    ) && score_after_bps > score_before_bps
    {
        score_after_bps = score_after_bps.min(
            score_before_bps
                .saturating_add(config.max_clean_recovery_bps)
                .min(BPS_DENOMINATOR),
        );
    }

    let mut fault_penalty_bps = 0;
    let mut reward_score_coefficient_bps;
    match fault_category {
        FaultCategory::Critical => {
            let capped = score_after_bps.min(config.category_a_score_cap_bps);
            fault_penalty_bps = score_after_bps.saturating_sub(capped);
            score_after_bps = capped;
            reward_score_coefficient_bps = 0;
        }
        FaultCategory::Major => {
            let capped = score_after_bps.min(config.category_b_score_cap_bps);
            fault_penalty_bps = score_after_bps.saturating_sub(capped);
            score_after_bps = capped;
            reward_score_coefficient_bps = score_reward_coefficient_from_score(score_after_bps)
                .min(config.category_b_reward_cap_bps);
        }
        FaultCategory::Minor => {
            let before_penalty = score_after_bps;
            score_after_bps = score_after_bps.saturating_sub(config.category_c_penalty_bps);
            fault_penalty_bps = before_penalty.saturating_sub(score_after_bps);
            reward_score_coefficient_bps = score_reward_coefficient_from_score(score_after_bps);
        }
        FaultCategory::IncidentRelief | FaultCategory::None => {
            reward_score_coefficient_bps = score_reward_coefficient_from_score(score_after_bps);
        }
    }

    score_after_bps = clamp_bps(score_after_bps);
    reward_score_coefficient_bps = clamp_bps(reward_score_coefficient_bps);
    let status_for_rewards = if reward_score_coefficient_bps == 0 {
        "withheld"
    } else if reward_score_coefficient_bps < BPS_DENOMINATOR {
        "reduced"
    } else {
        "eligible"
    };

    let scorecard = ValidatorEpochScorecard {
        epoch: evidence.epoch,
        validator_address: evidence.validator_address.clone(),
        score_before_bps,
        epoch_raw_score_bps,
        score_after_bps,
        consensus_participation_bps,
        proposal_participation_bps,
        validation_accuracy_bps,
        cluster_contribution_bps,
        uptime_bps,
        responsiveness_bps,
        config_compliance_bps,
        telemetry_integrity_bps,
        fault_penalty_bps,
        reward_score_coefficient_bps,
        reason_codes: reason_codes.clone(),
        evidence_refs: evidence.evidence_refs.clone(),
        finalized_at,
    };

    let next_profile = ValidatorSynergyScoreProfile {
        validator_address: profile.validator_address.clone(),
        operator_address: profile.operator_address.clone(),
        cluster_address: profile.cluster_address.clone(),
        current_score_bps: score_after_bps,
        previous_score_bps: score_before_bps,
        score_version: profile.score_version.saturating_add(1),
        last_scored_epoch: evidence.epoch,
        last_clean_epoch: if matches!(fault_category, FaultCategory::None) {
            Some(evidence.epoch)
        } else {
            profile.last_clean_epoch
        },
        status_for_rewards: status_for_rewards.to_string(),
        created_at: profile.created_at,
        updated_at: finalized_at,
    };

    let events = reason_codes
        .iter()
        .enumerate()
        .map(|(index, reason_code)| ValidatorScoreEvent {
            event_id: format!(
                "{}:{}:{}",
                evidence.validator_address, evidence.epoch, index
            ),
            epoch: evidence.epoch,
            block_height: None,
            artifact_ref: evidence.evidence_refs.first().cloned(),
            validator_address: evidence.validator_address.clone(),
            event_type: "validator_score_reason".to_string(),
            severity: match reason_code.as_str() {
                "CATEGORY_A_INTEGRITY_FAULT" => "critical",
                "CATEGORY_B_OPERATIONAL_FAULT" => "major",
                "CATEGORY_C_MINOR_FAULT" => "minor",
                "CATEGORY_D_INCIDENT_RELIEF" | "CATEGORY_D_NO_OPERATOR_FAULT" => "relief",
                _ => "info",
            }
            .to_string(),
            score_delta_bps: score_after_bps as i64 - score_before_bps as i64,
            reason_code: reason_code.clone(),
            evidence_ref: evidence.evidence_refs.first().cloned(),
            emitted_at: finalized_at,
        })
        .collect();

    Ok(ValidatorScoreComputation {
        profile: next_profile,
        scorecard,
        events,
    })
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Debug)]
pub struct SynergyScoreCalculator {
    pub validator_manager: Arc<ValidatorManager>,
    pub pqc_manager: Arc<Mutex<PQCManager>>,
    pub stake_cap: f64,
    pub decay_rate: f64,
    pub contribution_coefficients: (f64, f64, f64),
    pub correlation_threshold: f64,
    pub timing_similarity_threshold: f64,
    pub cartel_size_threshold: usize,
    pub epoch_length: u64,
}

impl SynergyScoreCalculator {
    pub fn new(
        validator_manager: Arc<ValidatorManager>,
        pqc_manager: Arc<Mutex<PQCManager>>,
    ) -> Self {
        SynergyScoreCalculator {
            validator_manager,
            pqc_manager,
            stake_cap: 0.05,                            // 5% cap
            decay_rate: 0.0001,                         // per block
            contribution_coefficients: (0.5, 0.3, 0.2), // proposals, relay_assists, network_score
            correlation_threshold: 0.85,
            timing_similarity_threshold: 0.9,
            cartel_size_threshold: 10,
            epoch_length: 1000,
        }
    }

    pub fn calculate_synergy_score(&self, validator: &Validator) -> SynergyScoreComponents {
        synergy_log!(
            "    🔍 [calculate_synergy_score] START for validator: {}",
            validator.address
        );

        synergy_log!("    📏 [calculate_synergy_score] Calculating stake_weight...");
        let stake_weight = self.calculate_stake_weight(validator);
        synergy_log!(
            "    ✅ [calculate_synergy_score] stake_weight: {}",
            stake_weight
        );

        synergy_log!("    📈 [calculate_synergy_score] Calculating reputation...");
        let reputation = self.calculate_reputation(validator);
        synergy_log!(
            "    ✅ [calculate_synergy_score] reputation: {}",
            reputation
        );

        synergy_log!("    🎯 [calculate_synergy_score] Calculating contribution_index...");
        let contribution_index = self.calculate_contribution_index(validator);
        synergy_log!(
            "    ✅ [calculate_synergy_score] contribution_index: {}",
            contribution_index
        );

        synergy_log!("    🚫 [calculate_synergy_score] Calculating cartelization_penalty...");
        let cartelization_penalty = self.calculate_cartelization_penalty(validator);
        synergy_log!(
            "    ✅ [calculate_synergy_score] cartelization_penalty: {}",
            cartelization_penalty
        );

        let raw_score = Self::raw_score_from_components(
            stake_weight,
            reputation,
            contribution_index,
            cartelization_penalty,
        );
        synergy_log!("    🧮 [calculate_synergy_score] raw_score: {}", raw_score);

        let normalized_score = self.normalize_score(raw_score);
        synergy_log!(
            "    ✅ [calculate_synergy_score] normalized_score: {}",
            normalized_score
        );

        SynergyScoreComponents {
            stake_weight,
            reputation,
            contribution_index,
            cartelization_penalty,
            normalized_score,
            last_updated: Self::current_timestamp(),
        }
    }

    fn calculate_stake_weight(&self, validator: &Validator) -> f64 {
        let total_stake = self.get_total_stake();
        let stake_fraction = validator.stake_amount as f64 / total_stake as f64;
        stake_fraction.min(self.stake_cap)
    }

    fn calculate_reputation(&self, validator: &Validator) -> f64 {
        let uptime_factor = self.calculate_uptime_factor(validator);
        let accuracy_factor = self.calculate_accuracy_factor(validator);
        let slashing_penalty = self.calculate_decayed_penalty(validator);

        uptime_factor * accuracy_factor * (1.0 - slashing_penalty)
    }

    fn calculate_uptime_factor(&self, validator: &Validator) -> f64 {
        let blocks_participated = validator.total_blocks_produced;
        let blocks_eligible = validator.total_blocks_produced + validator.missed_blocks;
        if blocks_eligible == 0 {
            1.0
        } else {
            blocks_participated as f64 / blocks_eligible as f64
        }
    }

    fn calculate_accuracy_factor(&self, validator: &Validator) -> f64 {
        let correct_votes = validator.total_transactions_validated;
        let total_votes = correct_votes + validator.missed_blocks;
        if total_votes == 0 {
            1.0
        } else {
            correct_votes as f64 / total_votes as f64
        }
    }

    fn calculate_decayed_penalty(&self, validator: &Validator) -> f64 {
        // Apply exponential decay to the slashing penalty as per Equation 5 in PoSy.txt
        let decayed_penalty = validator.slashing_penalty * (-self.decay_rate).exp();
        decayed_penalty.min(1.0) // Ensure penalty doesn't exceed 1.0
    }

    fn calculate_contribution_index(&self, validator: &Validator) -> f64 {
        let proposals = validator.total_blocks_produced as f64;
        let relay_assists = validator.collaboration_score;
        let network_score = 1.0 / validator.average_block_time.max(0.1);

        let (alpha, beta, gamma) = self.contribution_coefficients;
        alpha * proposals + beta * relay_assists + gamma * network_score
    }

    pub fn calculate_pairwise_synergy(
        &self,
        validator1: &Validator,
        validator2: &Validator,
    ) -> f64 {
        // Calculate pairwise synergy between two validators
        let components1 = self.calculate_synergy_score(validator1);
        let components2 = self.calculate_synergy_score(validator2);

        // Use geometric mean of normalized scores as pairwise synergy
        (components1.normalized_score * components2.normalized_score).sqrt()
    }

    pub fn normalize_scores(&self, scores: &[f64]) -> Vec<f64> {
        // Normalize a set of scores to sum to 1.0
        let total: f64 = scores.iter().sum();
        if total == 0.0 {
            vec![0.0; scores.len()]
        } else {
            scores.iter().map(|&score| score / total).collect()
        }
    }

    pub fn apply_decay_factor(&self, score: f64, blocks_since_last_update: u64) -> f64 {
        // Apply exponential decay to a score based on time since last update
        let decay_factor = (-self.decay_rate * blocks_since_last_update as f64).exp();
        score * decay_factor
    }

    fn calculate_cartelization_penalty(&self, validator: &Validator) -> f64 {
        let correlation_factor = self.detect_cartel_correlation(validator);
        let cartel_size = self.detect_cartel_size(validator);

        if cartel_size >= self.cartel_size_threshold
            && correlation_factor > self.correlation_threshold
        {
            1.0 + correlation_factor * cartel_size as f64 * 0.1
        } else {
            1.0
        }
    }

    fn detect_cartel_correlation(&self, _validator: &Validator) -> f64 {
        // Simplified cartel detection
        // In full implementation, construct_vote_vector and calculate_pairwise_correlations methods would be needed
        // For now, return a baseline value indicating no cartel behavior detected
        0.0
    }

    fn detect_cartel_size(&self, validator: &Validator) -> usize {
        // Simplified cartel detection
        // Full implementation would require historical analysis
        if validator.double_signs > 0 {
            5 // Assume small cartel if double signing detected
        } else {
            1
        }
    }

    fn normalize_score(&self, raw_score: f64) -> f64 {
        let max_raw = self.calculate_max_raw_score();

        if max_raw == 0.0 {
            return raw_score.min(100.0);
        }

        ((raw_score / max_raw) * 100.0).min(100.0)
    }

    fn get_total_stake(&self) -> u64 {
        let validators = self.validator_manager.get_active_validators();
        validators.iter().map(|v| v.stake_amount).sum()
    }

    fn calculate_raw_score(&self, validator: &Validator) -> f64 {
        let stake_weight = self.calculate_stake_weight(validator);
        let reputation = self.calculate_reputation(validator);
        let contribution_index = self.calculate_contribution_index(validator);
        let cartelization_penalty = self.calculate_cartelization_penalty(validator);

        Self::raw_score_from_components(
            stake_weight,
            reputation,
            contribution_index,
            cartelization_penalty,
        )
    }

    fn calculate_raw_scores(&self) -> Vec<f64> {
        self.validator_manager
            .get_all_validators()
            .into_iter()
            .map(|validator| self.calculate_raw_score(&validator))
            .collect()
    }

    fn calculate_max_raw_score(&self) -> f64 {
        self.calculate_raw_scores().into_iter().fold(0.0, f64::max)
    }

    fn raw_score_from_components(
        stake_weight: f64,
        reputation: f64,
        contribution_index: f64,
        cartelization_penalty: f64,
    ) -> f64 {
        if cartelization_penalty == 0.0 {
            0.0
        } else {
            (stake_weight * reputation * contribution_index) / cartelization_penalty
        }
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[derive(Debug, Clone)]
pub struct CartelDetection {
    pub vote_history: HashMap<String, Vec<bool>>, // validator_address -> vote vector
    pub timing_data: HashMap<String, Vec<u64>>,   // validator_address -> timestamps
    pub correlation_matrix: HashMap<(String, String), f64>,
}

impl CartelDetection {
    pub fn new() -> Self {
        CartelDetection {
            vote_history: HashMap::new(),
            timing_data: HashMap::new(),
            correlation_matrix: HashMap::new(),
        }
    }

    pub fn record_vote(&mut self, validator_address: &str, voted: bool, timestamp: u64) {
        self.vote_history
            .entry(validator_address.to_string())
            .or_insert_with(Vec::new)
            .push(voted);

        self.timing_data
            .entry(validator_address.to_string())
            .or_insert_with(Vec::new)
            .push(timestamp);
    }

    pub fn detect_cartels(&mut self) -> HashMap<String, f64> {
        let mut cartel_penalties = HashMap::new();
        let validators: Vec<String> = self.vote_history.keys().cloned().collect();

        // Calculate pairwise correlations
        for i in 0..validators.len() {
            for j in i + 1..validators.len() {
                let v1 = &validators[i];
                let v2 = &validators[j];

                if let (Some(votes1), Some(votes2)) =
                    (self.vote_history.get(v1), self.vote_history.get(v2))
                {
                    let correlation = self.calculate_pearson_correlation(votes1, votes2);
                    self.correlation_matrix
                        .insert((v1.clone(), v2.clone()), correlation);
                }
            }
        }

        // Identify cartels based on correlation and timing
        for validator in &validators {
            let penalty = self.calculate_cartel_penalty(validator);
            if penalty > 1.0 {
                cartel_penalties.insert(validator.clone(), penalty);
            }
        }

        cartel_penalties
    }

    fn calculate_pearson_correlation(&self, votes1: &[bool], votes2: &[bool]) -> f64 {
        let n = votes1.len().min(votes2.len());
        if n == 0 {
            return 0.0;
        }

        let mut sum1 = 0.0;
        let mut sum2 = 0.0;
        let mut sum1_sq = 0.0;
        let mut sum2_sq = 0.0;
        let mut p_sum = 0.0;

        for i in 0..n {
            let x = if votes1[i] { 1.0 } else { 0.0 };
            let y = if votes2[i] { 1.0 } else { 0.0 };

            sum1 += x;
            sum2 += y;
            sum1_sq += x * x;
            sum2_sq += y * y;
            p_sum += x * y;
        }

        let num = p_sum - (sum1 * sum2 / n as f64);
        let den1 = (sum1_sq - (sum1 * sum1 / n as f64)).sqrt();
        let den2 = (sum2_sq - (sum2 * sum2 / n as f64)).sqrt();

        if den1 == 0.0 || den2 == 0.0 {
            0.0
        } else {
            num / (den1 * den2)
        }
    }

    fn calculate_cartel_penalty(&self, validator: &str) -> f64 {
        let mut total_correlation = 0.0;
        let mut cartel_size = 0;

        if let Some(timestamps) = self.timing_data.get(validator) {
            for (other_validator, correlation) in &self.correlation_matrix {
                if other_validator.0 == *validator || other_validator.1 == *validator {
                    let other = if other_validator.0 == *validator {
                        &other_validator.1
                    } else {
                        &other_validator.0
                    };

                    if *correlation > 0.85 {
                        if let Some(other_timestamps) = self.timing_data.get(other) {
                            let timing_similarity =
                                self.calculate_timing_similarity(timestamps, other_timestamps);
                            if timing_similarity > 0.9 {
                                total_correlation += *correlation;
                                cartel_size += 1;
                            }
                        }
                    }
                }
            }
        }

        if cartel_size > 0 {
            let avg_correlation = total_correlation / cartel_size as f64;
            1.0 + avg_correlation * cartel_size as f64 * 0.1
        } else {
            1.0
        }
    }

    fn calculate_timing_similarity(&self, timestamps1: &[u64], timestamps2: &[u64]) -> f64 {
        let n = timestamps1.len().min(timestamps2.len());
        if n == 0 {
            return 0.0;
        }

        let median1 = self.calculate_median(timestamps1);
        let median2 = self.calculate_median(timestamps2);
        let block_time = 5.0; // average block time in seconds

        1.0 - (median1 as f64 - median2 as f64).abs() / block_time
    }

    fn calculate_median(&self, values: &[u64]) -> u64 {
        let mut sorted = values.to_vec();
        sorted.sort();
        let len = sorted.len();
        if len == 0 {
            0
        } else if len % 2 == 0 {
            (sorted[len / 2 - 1] + sorted[len / 2]) / 2
        } else {
            sorted[len / 2]
        }
    }
}

#[cfg(test)]
mod validator_score_tests {
    use super::*;

    fn profile() -> ValidatorSynergyScoreProfile {
        ValidatorSynergyScoreProfile::initialized("synv1validator", None, None, 1, 1)
    }

    fn clean_evidence() -> ValidatorEpochEvidence {
        ValidatorEpochEvidence {
            epoch: 2,
            validator_address: "synv1validator".to_string(),
            expected_consensus_duties: 100,
            observed_consensus_votes: 100,
            expected_responsiveness_messages: 100,
            timely_responsiveness_messages: 100,
            assigned_proposals: 0,
            successful_proposals: 0,
            missed_proposals: 0,
            rejected_or_invalid_proposals: 0,
            valid_signed_artifacts: 100,
            invalid_signed_artifacts: 0,
            equivocation_evidence: 0,
            state_hash_mismatches: 0,
            cluster_expected_contributions: 0,
            cluster_observed_contributions: 0,
            uptime_observed_checks: 100,
            uptime_successful_checks: 100,
            config_compliant: Some(true),
            telemetry_available: Some(true),
            telemetry_missing_operator_fault: false,
            scoring_data_available: true,
            incident_relief: false,
            reason_codes: Vec::new(),
            evidence_refs: vec!["epoch:2".to_string()],
        }
    }

    #[test]
    fn score_clamps_and_no_proposal_duty_is_neutral() {
        assert_eq!(clamp_bps(12_345), BPS_DENOMINATOR);
        let result = calculate_validator_epoch_score(
            &profile(),
            &clean_evidence(),
            &ValidatorScoringConfig::default(),
        )
        .unwrap();
        assert_eq!(result.scorecard.proposal_participation_bps, 10_000);
        assert!(result
            .scorecard
            .reason_codes
            .contains(&"NO_PROPOSAL_DUTY_ASSIGNED".to_string()));
        assert_eq!(result.scorecard.score_after_bps, 10_000);
    }

    #[test]
    fn missed_votes_reduce_consensus_participation_and_score() {
        let mut evidence = clean_evidence();
        evidence.observed_consensus_votes = 75;
        evidence.timely_responsiveness_messages = 75;
        evidence.valid_signed_artifacts = 75;
        let result = calculate_validator_epoch_score(
            &profile(),
            &evidence,
            &ValidatorScoringConfig::default(),
        )
        .unwrap();

        assert_eq!(result.scorecard.consensus_participation_bps, 7_500);
        assert!(result.scorecard.score_after_bps < 10_000);
        assert!(result
            .scorecard
            .reason_codes
            .contains(&"CATEGORY_C_MINOR_FAULT".to_string()));
    }

    #[test]
    fn invalid_artifacts_trigger_category_a_and_zero_reward_coefficient() {
        let mut evidence = clean_evidence();
        evidence.invalid_signed_artifacts = 1;
        evidence.equivocation_evidence = 1;
        let result = calculate_validator_epoch_score(
            &profile(),
            &evidence,
            &ValidatorScoringConfig::default(),
        )
        .unwrap();

        assert!(result.scorecard.score_after_bps <= 2_500);
        assert_eq!(result.scorecard.reward_score_coefficient_bps, 0);
        assert!(result
            .scorecard
            .reason_codes
            .contains(&"CATEGORY_A_INTEGRITY_FAULT".to_string()));
    }

    #[test]
    fn validator_missing_telemetry_penalizes_but_system_missing_data_does_not() {
        let mut operator_fault = clean_evidence();
        operator_fault.telemetry_available = Some(false);
        operator_fault.telemetry_missing_operator_fault = true;
        let penalized = calculate_validator_epoch_score(
            &profile(),
            &operator_fault,
            &ValidatorScoringConfig::default(),
        )
        .unwrap();
        assert_eq!(penalized.scorecard.telemetry_integrity_bps, 0);
        assert!(penalized.scorecard.score_after_bps < 10_000);
        assert!(penalized
            .scorecard
            .reason_codes
            .contains(&"VALIDATOR_TELEMETRY_MISSING".to_string()));

        let mut system_fault = clean_evidence();
        system_fault.scoring_data_available = false;
        system_fault.telemetry_available = None;
        let neutral = calculate_validator_epoch_score(
            &profile(),
            &system_fault,
            &ValidatorScoringConfig::default(),
        )
        .unwrap();
        assert_eq!(neutral.scorecard.telemetry_integrity_bps, 10_000);
        assert_eq!(neutral.scorecard.score_after_bps, 10_000);
    }

    #[test]
    fn rolling_score_recovery_is_capped_per_clean_epoch() {
        let mut recovering = profile();
        recovering.current_score_bps = 7_500;
        let result = calculate_validator_epoch_score(
            &recovering,
            &clean_evidence(),
            &ValidatorScoringConfig::default(),
        )
        .unwrap();
        assert_eq!(result.scorecard.score_after_bps, 8_000);
    }
}
