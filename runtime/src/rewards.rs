use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;

use crate::epoch::{epoch_for_block_height, TESTNET_EPOCH_LENGTH_BLOCKS};

pub const BPS_DENOMINATOR: u64 = 10_000;
pub const DEFAULT_REWARD_EPOCH_LENGTH_BLOCKS: u64 = TESTNET_EPOCH_LENGTH_BLOCKS;

pub fn reward_epoch_for_block_height(block_height: u64, epoch_length: u64) -> u64 {
    epoch_for_block_height(block_height, epoch_length)
}

pub fn default_reward_epoch_for_block_height(block_height: u64) -> u64 {
    reward_epoch_for_block_height(block_height, DEFAULT_REWARD_EPOCH_LENGTH_BLOCKS)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardConfig {
    pub validator_fee_share_bps: u64,
    pub treasury_fee_share_bps: u64,
    pub burn_fee_share_bps: u64,
    pub network_owned_validator_treasury_share_bps: u64,
    pub network_owned_validator_bonus_pool_share_bps: u64,
    pub phase1_consensus_participation_weight_bps: u64,
    pub phase1_block_proposal_weight_bps: u64,
    pub phase1_validation_accuracy_weight_bps: u64,
    pub phase1_cluster_contribution_weight_bps: u64,
    pub phase1_synergy_score_modifier_weight_bps: u64,
    pub phase2_uptime_weight_bps: u64,
    pub phase2_responsiveness_weight_bps: u64,
    pub phase2_no_jail_slash_weight_bps: u64,
    pub phase2_cluster_stability_weight_bps: u64,
    pub phase2_governance_participation_weight_bps: u64,
    pub min_base_fee_nwei: u64,
    pub max_base_fee_change_per_epoch_bps: u64,
    pub target_epoch_utilization_bps: u64,
    pub adjustment_rate_bps: u64,
    pub target_gas_epoch: u64,
    pub congestion_multiplier_bps: u64,
    pub max_congestion_premium_bps: u64,
    pub bonus_tier_10_epoch_bps: u64,
    pub bonus_tier_50_epoch_bps: u64,
    pub bonus_tier_100_epoch_bps: u64,
    pub bonus_tier_250_epoch_bps: u64,
    pub bonus_tier_500_epoch_bps: u64,
    pub max_reliability_bonus_bps: u64,
    pub high_performance_uptime_threshold_bps: u64,
    pub high_performance_consensus_threshold_bps: u64,
    pub cluster_cooperation_threshold_bps: u64,
    pub governance_participation_threshold_bps: u64,
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            validator_fee_share_bps: 7_000,
            treasury_fee_share_bps: 3_000,
            burn_fee_share_bps: 0,
            network_owned_validator_treasury_share_bps: 7_000,
            network_owned_validator_bonus_pool_share_bps: 3_000,
            phase1_consensus_participation_weight_bps: 3_500,
            phase1_block_proposal_weight_bps: 2_000,
            phase1_validation_accuracy_weight_bps: 2_000,
            phase1_cluster_contribution_weight_bps: 1_500,
            phase1_synergy_score_modifier_weight_bps: 1_000,
            phase2_uptime_weight_bps: 3_500,
            phase2_responsiveness_weight_bps: 2_500,
            phase2_no_jail_slash_weight_bps: 2_000,
            phase2_cluster_stability_weight_bps: 1_000,
            phase2_governance_participation_weight_bps: 1_000,
            min_base_fee_nwei: 1,
            max_base_fee_change_per_epoch_bps: 1_250,
            target_epoch_utilization_bps: 6_000,
            adjustment_rate_bps: 1_000,
            target_gas_epoch: 30_000_000,
            congestion_multiplier_bps: 1_000,
            max_congestion_premium_bps: 5_000,
            bonus_tier_10_epoch_bps: 200,
            bonus_tier_50_epoch_bps: 500,
            bonus_tier_100_epoch_bps: 1_000,
            bonus_tier_250_epoch_bps: 1_500,
            bonus_tier_500_epoch_bps: 2_000,
            max_reliability_bonus_bps: 3_000,
            high_performance_uptime_threshold_bps: 9_800,
            high_performance_consensus_threshold_bps: 9_500,
            cluster_cooperation_threshold_bps: 9_500,
            governance_participation_threshold_bps: 8_000,
        }
    }
}

impl RewardConfig {
    pub fn validate(&self) -> Result<(), String> {
        validate_sum(
            "fee shares",
            &[
                self.validator_fee_share_bps,
                self.treasury_fee_share_bps,
                self.burn_fee_share_bps,
            ],
        )?;
        validate_sum(
            "network-owned validator reward shares",
            &[
                self.network_owned_validator_treasury_share_bps,
                self.network_owned_validator_bonus_pool_share_bps,
            ],
        )?;
        validate_sum(
            "phase 1 weights",
            &[
                self.phase1_consensus_participation_weight_bps,
                self.phase1_block_proposal_weight_bps,
                self.phase1_validation_accuracy_weight_bps,
                self.phase1_cluster_contribution_weight_bps,
                self.phase1_synergy_score_modifier_weight_bps,
            ],
        )?;
        validate_sum(
            "phase 2 weights",
            &[
                self.phase2_uptime_weight_bps,
                self.phase2_responsiveness_weight_bps,
                self.phase2_no_jail_slash_weight_bps,
                self.phase2_cluster_stability_weight_bps,
                self.phase2_governance_participation_weight_bps,
            ],
        )?;

        for (name, value) in self.bps_values() {
            if value > BPS_DENOMINATOR {
                return Err(format!("{name} must be <= 10000 bps"));
            }
        }

        if self.min_base_fee_nwei == 0 {
            return Err("min_base_fee_nWei must be >= 1".to_string());
        }
        if self.target_gas_epoch == 0 {
            return Err("target_gas_epoch must be > 0".to_string());
        }

        Ok(())
    }

    fn bps_values(&self) -> [(&'static str, u64); 32] {
        [
            ("validator_fee_share_bps", self.validator_fee_share_bps),
            ("treasury_fee_share_bps", self.treasury_fee_share_bps),
            ("burn_fee_share_bps", self.burn_fee_share_bps),
            (
                "network_owned_validator_treasury_share_bps",
                self.network_owned_validator_treasury_share_bps,
            ),
            (
                "network_owned_validator_bonus_pool_share_bps",
                self.network_owned_validator_bonus_pool_share_bps,
            ),
            (
                "phase1_consensus_participation_weight_bps",
                self.phase1_consensus_participation_weight_bps,
            ),
            (
                "phase1_block_proposal_weight_bps",
                self.phase1_block_proposal_weight_bps,
            ),
            (
                "phase1_validation_accuracy_weight_bps",
                self.phase1_validation_accuracy_weight_bps,
            ),
            (
                "phase1_cluster_contribution_weight_bps",
                self.phase1_cluster_contribution_weight_bps,
            ),
            (
                "phase1_synergy_score_modifier_weight_bps",
                self.phase1_synergy_score_modifier_weight_bps,
            ),
            ("phase2_uptime_weight_bps", self.phase2_uptime_weight_bps),
            (
                "phase2_responsiveness_weight_bps",
                self.phase2_responsiveness_weight_bps,
            ),
            (
                "phase2_no_jail_slash_weight_bps",
                self.phase2_no_jail_slash_weight_bps,
            ),
            (
                "phase2_cluster_stability_weight_bps",
                self.phase2_cluster_stability_weight_bps,
            ),
            (
                "phase2_governance_participation_weight_bps",
                self.phase2_governance_participation_weight_bps,
            ),
            (
                "max_base_fee_change_per_epoch_bps",
                self.max_base_fee_change_per_epoch_bps,
            ),
            (
                "target_epoch_utilization_bps",
                self.target_epoch_utilization_bps,
            ),
            ("adjustment_rate_bps", self.adjustment_rate_bps),
            ("congestion_multiplier_bps", self.congestion_multiplier_bps),
            (
                "max_congestion_premium_bps",
                self.max_congestion_premium_bps,
            ),
            ("bonus_tier_10_epoch_bps", self.bonus_tier_10_epoch_bps),
            ("bonus_tier_50_epoch_bps", self.bonus_tier_50_epoch_bps),
            ("bonus_tier_100_epoch_bps", self.bonus_tier_100_epoch_bps),
            ("bonus_tier_250_epoch_bps", self.bonus_tier_250_epoch_bps),
            ("bonus_tier_500_epoch_bps", self.bonus_tier_500_epoch_bps),
            ("max_reliability_bonus_bps", self.max_reliability_bonus_bps),
            (
                "high_performance_uptime_threshold_bps",
                self.high_performance_uptime_threshold_bps,
            ),
            (
                "high_performance_consensus_threshold_bps",
                self.high_performance_consensus_threshold_bps,
            ),
            (
                "cluster_cooperation_threshold_bps",
                self.cluster_cooperation_threshold_bps,
            ),
            (
                "governance_participation_threshold_bps",
                self.governance_participation_threshold_bps,
            ),
            ("reserved_bps_1", 0),
            ("reserved_bps_2", 0),
        ]
    }
}

fn validate_sum(label: &str, values: &[u64]) -> Result<(), String> {
    let sum = values
        .iter()
        .try_fold(0u64, |acc, value| acc.checked_add(*value))
        .ok_or_else(|| format!("{label} overflow"))?;
    if sum != BPS_DENOMINATOR {
        return Err(format!("{label} must sum to 10000 bps, got {sum}"));
    }
    Ok(())
}

fn weighted_average_bps(components: &[(u64, u64)]) -> Result<u64, String> {
    let weighted_sum = components.iter().try_fold(0u128, |acc, (score, weight)| {
        if *score > BPS_DENOMINATOR || *weight > BPS_DENOMINATOR {
            return None;
        }
        acc.checked_add((*score as u128) * (*weight as u128))
    });

    weighted_sum
        .map(|sum| (sum / (BPS_DENOMINATOR as u128)) as u64)
        .ok_or_else(|| "basis-point weighted average overflow or invalid bps".to_string())
}

fn mul_bps(amount_nwei: u128, bps: u64) -> Result<u128, String> {
    if bps > BPS_DENOMINATOR {
        return Err("bps value exceeds 10000".to_string());
    }
    amount_nwei
        .checked_mul(bps as u128)
        .map(|value| value / (BPS_DENOMINATOR as u128))
        .ok_or_else(|| "basis-point multiplication overflow".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochFeeDistribution {
    pub epoch_id: u64,
    pub total_fees_nwei: u128,
    pub validator_share_nwei: u128,
    pub treasury_share_nwei: u128,
    pub burn_share_nwei: u128,
    pub rounding_dust_nwei: u128,
    pub distribution_block_height: u64,
    pub timestamp: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EpochFeeAccumulatorStatus {
    Open,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeAccumulator {
    pub epoch_id: u64,
    pub total_collected_nwei: u128,
    pub by_tx_type: BTreeMap<String, u128>,
    pub opened_at_height: u64,
    pub closed_at_height: Option<u64>,
    pub status: EpochFeeAccumulatorStatus,
}

impl FeeAccumulator {
    pub fn new(epoch_id: u64, opened_at_height: u64) -> Self {
        Self {
            epoch_id,
            total_collected_nwei: 0,
            by_tx_type: BTreeMap::new(),
            opened_at_height,
            closed_at_height: None,
            status: EpochFeeAccumulatorStatus::Open,
        }
    }

    pub fn record_fee(&mut self, tx_type: impl Into<String>, fee_nwei: u128) -> Result<(), String> {
        if self.status == EpochFeeAccumulatorStatus::Closed {
            return Err("cannot record fee into closed epoch accumulator".to_string());
        }
        self.total_collected_nwei = self
            .total_collected_nwei
            .checked_add(fee_nwei)
            .ok_or_else(|| "fee accumulator total overflow".to_string())?;
        let entry = self.by_tx_type.entry(tx_type.into()).or_insert(0);
        *entry = entry
            .checked_add(fee_nwei)
            .ok_or_else(|| "fee accumulator tx type overflow".to_string())?;
        Ok(())
    }

    pub fn close(&mut self, closed_at_height: u64) {
        self.closed_at_height = Some(closed_at_height);
        self.status = EpochFeeAccumulatorStatus::Closed;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeCollectorDistribution {
    pub epoch_id: u64,
    pub from_address: String,
    pub validator_reward_pool_address: String,
    pub validator_reward_pool_amount_nwei: u128,
    pub treasury_wallet_address: String,
    pub treasury_amount_nwei: u128,
    pub burn_amount_nwei: u128,
    pub dust_nwei: u128,
    pub distribution_state_id: String,
    pub distributed_block_height: u64,
}

pub fn split_epoch_fees(
    epoch_id: u64,
    total_fees_nwei: u128,
    distribution_block_height: u64,
) -> Result<EpochFeeDistribution, String> {
    split_epoch_fees_with_config(
        epoch_id,
        total_fees_nwei,
        distribution_block_height,
        &RewardConfig::default(),
    )
}

pub fn split_epoch_fees_with_config(
    epoch_id: u64,
    total_fees_nwei: u128,
    distribution_block_height: u64,
    config: &RewardConfig,
) -> Result<EpochFeeDistribution, String> {
    config.validate()?;
    let validator_share = mul_bps(total_fees_nwei, config.validator_fee_share_bps)?;
    let burn_share = mul_bps(total_fees_nwei, config.burn_fee_share_bps)?;
    let nominal_treasury = mul_bps(total_fees_nwei, config.treasury_fee_share_bps)?;
    let assigned = validator_share
        .checked_add(burn_share)
        .and_then(|value| value.checked_add(nominal_treasury))
        .ok_or_else(|| "epoch fee shares overflow".to_string())?;
    let dust = total_fees_nwei.saturating_sub(assigned);
    let treasury_share = nominal_treasury
        .checked_add(dust)
        .ok_or_else(|| "treasury dust assignment overflow".to_string())?;

    Ok(EpochFeeDistribution {
        epoch_id,
        total_fees_nwei,
        validator_share_nwei: validator_share,
        treasury_share_nwei: treasury_share,
        burn_share_nwei: burn_share,
        rounding_dust_nwei: dust,
        distribution_block_height,
        timestamp: None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Phase1Metrics {
    pub consensus_participation_score_bps: u64,
    pub block_proposal_score_bps: u64,
    pub validation_accuracy_score_bps: u64,
    pub cluster_contribution_score_bps: u64,
    pub synergy_score_modifier_bps: u64,
}

pub fn calculate_phase1_score_bps(
    metrics: &Phase1Metrics,
    config: &RewardConfig,
) -> Result<u64, String> {
    config.validate()?;
    weighted_average_bps(&[
        (
            metrics.consensus_participation_score_bps,
            config.phase1_consensus_participation_weight_bps,
        ),
        (
            metrics.block_proposal_score_bps,
            config.phase1_block_proposal_weight_bps,
        ),
        (
            metrics.validation_accuracy_score_bps,
            config.phase1_validation_accuracy_weight_bps,
        ),
        (
            metrics.cluster_contribution_score_bps,
            config.phase1_cluster_contribution_weight_bps,
        ),
        (
            metrics.synergy_score_modifier_bps,
            config.phase1_synergy_score_modifier_weight_bps,
        ),
    ])
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PendingRewardStatus {
    Pending,
    Settled,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SettlementStatus {
    Pending,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UnreleasedDestination {
    Burn,
    Treasury,
    TreasuryRecovery,
    BonusPool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorPendingReward {
    pub original_epoch_id: u64,
    pub epoch_id: u64,
    pub original_cluster_address: String,
    pub cluster_id: String,
    pub validator_id: String,
    pub reward_payout_address: String,
    pub pending_reward_nwei: u128,
    pub source_emissions_nwei: u128,
    pub source_fee_rewards_nwei: u128,
    pub source_cluster_bonus_nwei: u128,
    pub phase1_score_bps: u64,
    pub consensus_participation_score_bps: u64,
    pub block_proposal_score_bps: u64,
    pub validation_accuracy_score_bps: u64,
    pub cluster_contribution_score_bps: u64,
    pub synergy_score_modifier_bps: u64,
    pub created_at_epoch: u64,
    pub unlock_epoch: u64,
    pub accountability_epoch: u64,
    pub status: PendingRewardStatus,
    pub segment_ids: Vec<String>,
}

pub fn calculate_pending_reward(
    epoch_id: u64,
    cluster_address: &str,
    validator_id: &str,
    reward_payout_address: &str,
    source_emissions_nwei: u128,
    source_fee_rewards_nwei: u128,
    source_cluster_bonus_nwei: u128,
    metrics: &Phase1Metrics,
    config: &RewardConfig,
) -> Result<ValidatorPendingReward, String> {
    if crate::address::is_network_burn_address(reward_payout_address) {
        return Err("network burn address cannot be a validator reward payout".to_string());
    }
    if crate::address::is_network_burn_address(cluster_address) {
        return Err("network burn address cannot be a cluster reward escrow".to_string());
    }
    let phase1_score_bps = calculate_phase1_score_bps(metrics, config)?;
    let total_source = source_emissions_nwei
        .checked_add(source_fee_rewards_nwei)
        .and_then(|value| value.checked_add(source_cluster_bonus_nwei))
        .ok_or_else(|| "pending reward source overflow".to_string())?;
    let pending_reward_nwei = mul_bps(total_source, phase1_score_bps)?;

    Ok(ValidatorPendingReward {
        original_epoch_id: epoch_id,
        epoch_id,
        original_cluster_address: cluster_address.to_string(),
        cluster_id: cluster_address.to_string(),
        validator_id: validator_id.to_string(),
        reward_payout_address: reward_payout_address.to_string(),
        pending_reward_nwei,
        source_emissions_nwei,
        source_fee_rewards_nwei,
        source_cluster_bonus_nwei,
        phase1_score_bps,
        consensus_participation_score_bps: metrics.consensus_participation_score_bps,
        block_proposal_score_bps: metrics.block_proposal_score_bps,
        validation_accuracy_score_bps: metrics.validation_accuracy_score_bps,
        cluster_contribution_score_bps: metrics.cluster_contribution_score_bps,
        synergy_score_modifier_bps: metrics.synergy_score_modifier_bps,
        created_at_epoch: epoch_id,
        unlock_epoch: epoch_id + 1,
        accountability_epoch: epoch_id + 1,
        status: PendingRewardStatus::Pending,
        segment_ids: Vec::new(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterRewardSettlement {
    pub epoch_id: u64,
    pub cluster_address: String,
    pub cluster_index: u64,
    pub total_cluster_reward_nwei: u128,
    pub total_validator_pending_rewards_nwei: u128,
    pub validator_count: u64,
    pub assignment_hash: String,
    pub rotation_mode: String,
    pub settlement_status: SettlementStatus,
    pub created_block_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorPhase1Input {
    pub cluster_address: String,
    pub validator_id: String,
    pub reward_payout_address: String,
    pub metrics: Phase1Metrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterRewardAllocation {
    pub epoch_id: u64,
    pub cluster_address: String,
    pub cluster_weight_score: u128,
    pub cluster_reward_nwei: u128,
    pub validator_count: u64,
    pub validator_pending_rewards: Vec<ValidatorPendingReward>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterRewardEscrow {
    pub epoch_id: u64,
    pub cluster_id: String,
    pub cluster_escrow_address: String,
    pub funded_amount_nwei: u128,
    pub pending_validator_rewards_nwei: u128,
    pub dust_nwei: u128,
    pub validator_reward_pool_address: String,
    pub funded_block_height: u64,
    pub status: SettlementStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochRewardAllocation {
    pub epoch_id: u64,
    pub pool_amount_nwei: u128,
    pub total_cluster_rewards_nwei: u128,
    pub total_validator_pending_rewards_nwei: u128,
    pub rounding_dust_nwei: u128,
    pub cluster_allocations: Vec<ClusterRewardAllocation>,
}

pub fn allocate_epoch_validator_rewards(
    epoch_id: u64,
    pool_amount_nwei: u128,
    validators: &[ValidatorPhase1Input],
    created_block_height: u64,
    config: &RewardConfig,
) -> Result<EpochRewardAllocation, String> {
    config.validate()?;
    if validators.is_empty() {
        return Err("cannot allocate validator rewards without validators".to_string());
    }

    #[derive(Clone)]
    struct ScoredValidator {
        input: ValidatorPhase1Input,
        phase1_score_bps: u64,
    }

    let mut clusters: BTreeMap<String, Vec<ScoredValidator>> = BTreeMap::new();
    for input in validators {
        if crate::address::is_network_burn_address(&input.reward_payout_address) {
            return Err("network burn address cannot be a validator reward payout".to_string());
        }
        if crate::address::is_network_burn_address(&input.cluster_address) {
            return Err("network burn address cannot be a cluster reward escrow".to_string());
        }
        let phase1_score_bps = calculate_phase1_score_bps(&input.metrics, config)?;
        clusters
            .entry(input.cluster_address.clone())
            .or_default()
            .push(ScoredValidator {
                input: input.clone(),
                phase1_score_bps,
            });
    }
    for cluster_validators in clusters.values_mut() {
        cluster_validators
            .sort_by(|left, right| left.input.validator_id.cmp(&right.input.validator_id));
    }

    let cluster_weights = clusters
        .iter()
        .map(|(cluster, validators)| {
            let weight = validators
                .iter()
                .try_fold(0u128, |acc, validator| {
                    acc.checked_add(validator.phase1_score_bps as u128)
                })
                .ok_or_else(|| "cluster weight overflow".to_string())?;
            Ok((cluster.clone(), weight))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let total_weight = cluster_weights
        .iter()
        .try_fold(0u128, |acc, (_, weight)| acc.checked_add(*weight))
        .ok_or_else(|| "total validator weight overflow".to_string())?;
    if total_weight == 0 {
        return Err("cannot allocate validator rewards with zero total phase1 weight".to_string());
    }

    let mut cluster_allocations = Vec::with_capacity(clusters.len());
    let mut assigned_clusters = 0u128;
    for (cluster_index, (cluster_address, cluster_weight)) in cluster_weights.iter().enumerate() {
        let cluster_reward = if cluster_index + 1 == cluster_weights.len() {
            pool_amount_nwei.saturating_sub(assigned_clusters)
        } else {
            pool_amount_nwei
                .checked_mul(*cluster_weight)
                .ok_or_else(|| "cluster reward allocation overflow".to_string())?
                / total_weight
        };
        assigned_clusters = assigned_clusters
            .checked_add(cluster_reward)
            .ok_or_else(|| "assigned cluster reward overflow".to_string())?;

        let cluster_validators = clusters
            .get(cluster_address)
            .ok_or_else(|| "cluster allocation missing validators".to_string())?;
        let cluster_weight_total = cluster_validators
            .iter()
            .try_fold(0u128, |acc, validator| {
                acc.checked_add(validator.phase1_score_bps as u128)
            })
            .ok_or_else(|| "cluster validator weight overflow".to_string())?;

        let mut pending_rewards = Vec::with_capacity(cluster_validators.len());
        let mut assigned_validators = 0u128;
        for (validator_index, scored) in cluster_validators.iter().enumerate() {
            let pending_reward = if validator_index + 1 == cluster_validators.len() {
                cluster_reward.saturating_sub(assigned_validators)
            } else if cluster_weight_total == 0 {
                0
            } else {
                cluster_reward
                    .checked_mul(scored.phase1_score_bps as u128)
                    .ok_or_else(|| "validator reward allocation overflow".to_string())?
                    / cluster_weight_total
            };
            assigned_validators = assigned_validators
                .checked_add(pending_reward)
                .ok_or_else(|| "assigned validator reward overflow".to_string())?;

            pending_rewards.push(ValidatorPendingReward {
                original_epoch_id: epoch_id,
                epoch_id,
                original_cluster_address: cluster_address.clone(),
                cluster_id: cluster_address.clone(),
                validator_id: scored.input.validator_id.clone(),
                reward_payout_address: scored.input.reward_payout_address.clone(),
                pending_reward_nwei: pending_reward,
                source_emissions_nwei: 0,
                source_fee_rewards_nwei: pending_reward,
                source_cluster_bonus_nwei: 0,
                phase1_score_bps: scored.phase1_score_bps,
                consensus_participation_score_bps: scored
                    .input
                    .metrics
                    .consensus_participation_score_bps,
                block_proposal_score_bps: scored.input.metrics.block_proposal_score_bps,
                validation_accuracy_score_bps: scored.input.metrics.validation_accuracy_score_bps,
                cluster_contribution_score_bps: scored.input.metrics.cluster_contribution_score_bps,
                synergy_score_modifier_bps: scored.input.metrics.synergy_score_modifier_bps,
                created_at_epoch: epoch_id,
                unlock_epoch: epoch_id + 1,
                accountability_epoch: epoch_id + 1,
                status: PendingRewardStatus::Pending,
                segment_ids: vec![format!(
                    "epoch:{epoch_id}:cluster:{cluster_address}:block:{created_block_height}"
                )],
            });
        }

        cluster_allocations.push(ClusterRewardAllocation {
            epoch_id,
            cluster_address: cluster_address.clone(),
            cluster_weight_score: *cluster_weight,
            cluster_reward_nwei: cluster_reward,
            validator_count: pending_rewards.len() as u64,
            validator_pending_rewards: pending_rewards,
        });
    }

    let total_pending = cluster_allocations
        .iter()
        .flat_map(|cluster| &cluster.validator_pending_rewards)
        .try_fold(0u128, |acc, reward| {
            acc.checked_add(reward.pending_reward_nwei)
        })
        .ok_or_else(|| "total pending reward overflow".to_string())?;

    Ok(EpochRewardAllocation {
        epoch_id,
        pool_amount_nwei,
        total_cluster_rewards_nwei: assigned_clusters,
        total_validator_pending_rewards_nwei: total_pending,
        rounding_dust_nwei: pool_amount_nwei.saturating_sub(total_pending),
        cluster_allocations,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidatorPenaltyReason {
    None,
    MinorDowntime,
    MajorDowntime,
    Jailed,
    Slashed,
    DoubleSigning,
    Equivocation,
    InvalidProposal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleasePerformance {
    pub uptime_score_bps: u64,
    pub responsiveness_score_bps: u64,
    pub no_jail_slash_score_bps: u64,
    pub cluster_stability_score_bps: u64,
    pub governance_participation_score_bps: u64,
    pub penalty_reason: ValidatorPenaltyReason,
}

pub fn calculate_release_coefficient(
    performance: &ReleasePerformance,
    config: &RewardConfig,
) -> Result<u64, String> {
    config.validate()?;
    match performance.penalty_reason {
        ValidatorPenaltyReason::Slashed
        | ValidatorPenaltyReason::DoubleSigning
        | ValidatorPenaltyReason::Equivocation
        | ValidatorPenaltyReason::InvalidProposal => return Ok(0),
        _ => {}
    }

    let score = weighted_average_bps(&[
        (
            performance.uptime_score_bps,
            config.phase2_uptime_weight_bps,
        ),
        (
            performance.responsiveness_score_bps,
            config.phase2_responsiveness_weight_bps,
        ),
        (
            performance.no_jail_slash_score_bps,
            config.phase2_no_jail_slash_weight_bps,
        ),
        (
            performance.cluster_stability_score_bps,
            config.phase2_cluster_stability_weight_bps,
        ),
        (
            performance.governance_participation_score_bps,
            config.phase2_governance_participation_weight_bps,
        ),
    ])?;

    let mut coefficient = if score >= 9_995 {
        BPS_DENOMINATOR
    } else if score >= 9_950 {
        9_500
    } else if score >= 9_900 {
        8_500
    } else if score >= 9_800 {
        6_000
    } else if score >= 9_700 {
        2_500
    } else {
        0
    };

    coefficient = match performance.penalty_reason {
        ValidatorPenaltyReason::Jailed => coefficient.min(5_000),
        ValidatorPenaltyReason::MajorDowntime => coefficient.min(6_000),
        ValidatorPenaltyReason::MinorDowntime => coefficient.min(8_500),
        _ => coefficient,
    };

    Ok(coefficient.min(BPS_DENOMINATOR))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorRewardSettlement {
    pub original_epoch_id: u64,
    pub accountability_epoch: u64,
    pub unlock_epoch: u64,
    pub cluster_id: String,
    pub original_cluster_address: String,
    pub validator_id: String,
    pub reward_payout_address: String,
    pub pending_reward_nwei: u128,
    pub release_coefficient_bps: u64,
    pub final_reward_nwei: u128,
    pub unreleased_reward_nwei: u128,
    pub unreleased_destination: UnreleasedDestination,
    pub settled_block_height: u64,
    pub status: SettlementStatus,
}

pub fn settle_pending_reward(
    pending: &mut ValidatorPendingReward,
    release_coefficient_bps: u64,
    settled_block_height: u64,
) -> Result<ValidatorRewardSettlement, String> {
    if pending.status != PendingRewardStatus::Pending {
        return Err("pending reward already settled".to_string());
    }
    let final_reward = mul_bps(pending.pending_reward_nwei, release_coefficient_bps)?;
    let unreleased = pending
        .pending_reward_nwei
        .checked_sub(final_reward)
        .ok_or_else(|| "unreleased reward underflow".to_string())?;
    pending.status = PendingRewardStatus::Settled;

    Ok(ValidatorRewardSettlement {
        original_epoch_id: pending.original_epoch_id,
        accountability_epoch: pending.accountability_epoch,
        unlock_epoch: pending.unlock_epoch,
        cluster_id: pending.cluster_id.clone(),
        original_cluster_address: pending.original_cluster_address.clone(),
        validator_id: pending.validator_id.clone(),
        reward_payout_address: pending.reward_payout_address.clone(),
        pending_reward_nwei: pending.pending_reward_nwei,
        release_coefficient_bps,
        final_reward_nwei: final_reward,
        unreleased_reward_nwei: unreleased,
        unreleased_destination: UnreleasedDestination::TreasuryRecovery,
        settled_block_height,
        status: SettlementStatus::Complete,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkOwnedValidatorRewardRouting {
    pub epoch_id: u64,
    pub validator_id: String,
    pub total_reward_nwei: u128,
    pub treasury_share_nwei: u128,
    pub bonus_pool_share_nwei: u128,
    pub rounding_dust_nwei: u128,
    pub routing_block_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorMetadata {
    pub validator_id: String,
    pub reward_payout_address: String,
    pub is_network_owned_validator: bool,
}

pub fn route_network_owned_validator_reward(
    epoch_id: u64,
    validator: &ValidatorMetadata,
    reward_nwei: u128,
    routing_block_height: u64,
    config: &RewardConfig,
) -> Result<NetworkOwnedValidatorRewardRouting, String> {
    config.validate()?;
    if !validator.is_network_owned_validator {
        return Err("validator is not marked as network-owned validator".to_string());
    }
    let bonus_pool_share = mul_bps(
        reward_nwei,
        config.network_owned_validator_bonus_pool_share_bps,
    )?;
    let nominal_treasury = mul_bps(
        reward_nwei,
        config.network_owned_validator_treasury_share_bps,
    )?;
    let assigned = bonus_pool_share
        .checked_add(nominal_treasury)
        .ok_or_else(|| "genesis reward routing overflow".to_string())?;
    let dust = reward_nwei.saturating_sub(assigned);
    let treasury_share = nominal_treasury
        .checked_add(dust)
        .ok_or_else(|| "genesis treasury dust overflow".to_string())?;

    Ok(NetworkOwnedValidatorRewardRouting {
        epoch_id,
        validator_id: validator.validator_id.clone(),
        total_reward_nwei: reward_nwei,
        treasury_share_nwei: treasury_share,
        bonus_pool_share_nwei: bonus_pool_share,
        rounding_dust_nwei: dust,
        routing_block_height,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ReliabilityBonusPool {
    pub balance_nwei: u128,
    pub total_funded_nwei: u128,
    pub total_distributed_nwei: u128,
}

impl ReliabilityBonusPool {
    pub fn fund(&mut self, amount_nwei: u128) -> Result<(), String> {
        self.balance_nwei = self
            .balance_nwei
            .checked_add(amount_nwei)
            .ok_or_else(|| "bonus pool balance overflow".to_string())?;
        self.total_funded_nwei = self
            .total_funded_nwei
            .checked_add(amount_nwei)
            .ok_or_else(|| "bonus pool funding overflow".to_string())?;
        Ok(())
    }

    pub fn distribute(&mut self, amount_nwei: u128) -> Result<(), String> {
        if amount_nwei > self.balance_nwei {
            return Err("bonus pool cannot distribute more than balance".to_string());
        }
        self.balance_nwei -= amount_nwei;
        self.total_distributed_nwei = self
            .total_distributed_nwei
            .checked_add(amount_nwei)
            .ok_or_else(|| "bonus pool distribution overflow".to_string())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReliabilityEligibility {
    pub uptime_bps: u64,
    pub consensus_participation_bps: u64,
    pub cluster_cooperation_bps: u64,
    pub governance_participation_bps: u64,
    pub penalty_reason: ValidatorPenaltyReason,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorReliabilityState {
    pub validator_id: String,
    pub current_streak_epochs: u64,
    pub highest_streak_epochs: u64,
    pub last_high_performance_epoch: Option<u64>,
    pub current_bonus_tier_bps: u64,
    pub eligible_for_bonus: bool,
    pub last_penalty_reason: ValidatorPenaltyReason,
}

impl ValidatorReliabilityState {
    pub fn new(validator_id: impl Into<String>) -> Self {
        Self {
            validator_id: validator_id.into(),
            current_streak_epochs: 0,
            highest_streak_epochs: 0,
            last_high_performance_epoch: None,
            current_bonus_tier_bps: 0,
            eligible_for_bonus: false,
            last_penalty_reason: ValidatorPenaltyReason::None,
        }
    }
}

pub fn bonus_tier_bps(streak_epochs: u64, config: &RewardConfig) -> u64 {
    let tier = if streak_epochs >= 500 {
        config.bonus_tier_500_epoch_bps
    } else if streak_epochs >= 250 {
        config.bonus_tier_250_epoch_bps
    } else if streak_epochs >= 100 {
        config.bonus_tier_100_epoch_bps
    } else if streak_epochs >= 50 {
        config.bonus_tier_50_epoch_bps
    } else if streak_epochs >= 10 {
        config.bonus_tier_10_epoch_bps
    } else {
        0
    };
    tier.min(config.max_reliability_bonus_bps)
}

pub fn is_bonus_eligible(eligibility: &ReliabilityEligibility, config: &RewardConfig) -> bool {
    eligibility.active
        && eligibility.uptime_bps >= config.high_performance_uptime_threshold_bps
        && eligibility.consensus_participation_bps
            >= config.high_performance_consensus_threshold_bps
        && eligibility.cluster_cooperation_bps >= config.cluster_cooperation_threshold_bps
        && eligibility.governance_participation_bps >= config.governance_participation_threshold_bps
        && matches!(eligibility.penalty_reason, ValidatorPenaltyReason::None)
}

pub fn update_reliability_streak(
    state: &mut ValidatorReliabilityState,
    epoch_id: u64,
    eligibility: &ReliabilityEligibility,
    config: &RewardConfig,
) {
    let eligible = is_bonus_eligible(eligibility, config);
    state.last_penalty_reason = eligibility.penalty_reason.clone();

    if eligible {
        state.current_streak_epochs = state.current_streak_epochs.saturating_add(1);
        state.last_high_performance_epoch = Some(epoch_id);
    } else {
        match eligibility.penalty_reason {
            ValidatorPenaltyReason::MinorDowntime => {
                state.current_streak_epochs = state.current_streak_epochs * 9 / 10;
            }
            ValidatorPenaltyReason::None if !eligibility.active => {}
            _ => {
                state.current_streak_epochs = 0;
            }
        }
    }

    state.highest_streak_epochs = state.highest_streak_epochs.max(state.current_streak_epochs);
    state.current_bonus_tier_bps = bonus_tier_bps(state.current_streak_epochs, config);
    state.eligible_for_bonus = eligible;
}

pub fn calculate_reliability_bonus(
    state: &ValidatorReliabilityState,
    base_reward_nwei: u128,
    pool: &ReliabilityBonusPool,
    config: &RewardConfig,
) -> Result<u128, String> {
    config.validate()?;
    if !state.eligible_for_bonus {
        return Ok(0);
    }
    let bonus = mul_bps(base_reward_nwei, state.current_bonus_tier_bps)?;
    Ok(bonus.min(pool.balance_nwei))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorRewardStatus {
    pub current_epoch_id: u64,
    pub validator_id: String,
    pub validator_status: String,
    pub current_epoch_participation_score_bps: u64,
    pub previous_epoch_pending_reward: Option<ValidatorPendingReward>,
    pub accountability_epoch: Option<u64>,
    pub unlock_epoch: Option<u64>,
    pub estimated_release_coefficient_bps: u64,
    pub projected_final_reward_nwei: u128,
    pub projected_unreleased_amount_nwei: u128,
    pub current_reliability_streak: u64,
    pub highest_reliability_streak: u64,
    pub current_bonus_tier_bps: u64,
    pub next_bonus_tier_bps: u64,
    pub epochs_until_next_bonus_tier: u64,
    pub reliability_bonus_eligibility: bool,
    pub uptime_percentage_bps: u64,
    pub consensus_participation_percentage_bps: u64,
    pub responsiveness_score_bps: u64,
    pub cluster_performance_score_bps: u64,
    pub governance_participation_score_bps: u64,
    pub jailing_status: bool,
    pub slashing_status: bool,
    pub pending_settlements: Vec<ValidatorPendingReward>,
    pub completed_settlements: Vec<ValidatorRewardSettlement>,
    pub network_owned_validator_routing: Vec<NetworkOwnedValidatorRewardRouting>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreasuryRecoveryEntry {
    pub original_epoch_id: u64,
    pub settlement_epoch: u64,
    pub validator_id: String,
    pub cluster_id: String,
    pub amount_nwei: u128,
    pub treasury_recovery_wallet_address: String,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TreasuryRecoveryLedger {
    pub epoch: u64,
    pub total_recovered_nwei: u128,
    pub entries: Vec<TreasuryRecoveryEntry>,
}

impl TreasuryRecoveryLedger {
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            total_recovered_nwei: 0,
            entries: Vec::new(),
        }
    }

    pub fn credit(&mut self, entry: TreasuryRecoveryEntry) -> Result<(), String> {
        self.total_recovered_nwei = self
            .total_recovered_nwei
            .checked_add(entry.amount_nwei)
            .ok_or_else(|| "treasury recovery ledger overflow".to_string())?;
        self.entries.push(entry);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RewardAuditEvent {
    GasFeeCollected {
        epoch_id: u64,
        tx_hash: String,
        fee_nwei: u128,
    },
    EpochFeesClosed {
        accumulator: FeeAccumulator,
        distribution: EpochFeeDistribution,
    },
    EpochFeeDistribution(EpochFeeDistribution),
    FeeCollectorDistributed(FeeCollectorDistribution),
    ClusterRewardSettlement(ClusterRewardSettlement),
    ClusterRewardEscrowed(ClusterRewardEscrow),
    ValidatorPendingRewardCreated(ValidatorPendingReward),
    ValidatorReleaseCoefficientCalculated {
        accountability_epoch: u64,
        validator_id: String,
        release_coefficient_bps: u64,
    },
    ValidatorRewardSettled(ValidatorRewardSettlement),
    TreasuryRecoveryCredited {
        original_epoch_id: u64,
        settlement_epoch: u64,
        validator_id: String,
        cluster_id: String,
        amount_nwei: u128,
        treasury_recovery_wallet_address: String,
        reason_codes: Vec<String>,
    },
    NetworkOwnedValidatorRewardRouted(NetworkOwnedValidatorRewardRouting),
    ReliabilityBonusPoolFunded {
        epoch_id: u64,
        amount_nwei: u128,
    },
    ReliabilityBonusPaid {
        epoch_id: u64,
        validator_id: String,
        amount_nwei: u128,
    },
    ValidatorReliabilityStreakUpdated(ValidatorReliabilityState),
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RewardLedger {
    pub fee_accumulators: HashMap<u64, FeeAccumulator>,
    pub fee_distributions: HashMap<u64, EpochFeeDistribution>,
    pub fee_collector_distributions: HashMap<u64, FeeCollectorDistribution>,
    pub epoch_reward_allocations: HashMap<u64, EpochRewardAllocation>,
    pub cluster_reward_escrows: HashMap<(u64, String), ClusterRewardEscrow>,
    pub cluster_settlements: HashMap<(u64, String), ClusterRewardSettlement>,
    pub pending_rewards: Vec<ValidatorPendingReward>,
    pub reward_settlements: Vec<ValidatorRewardSettlement>,
    pub network_owned_routings: HashMap<(u64, String), NetworkOwnedValidatorRewardRouting>,
    pub reliability_states: HashMap<String, ValidatorReliabilityState>,
    pub bonus_pool: ReliabilityBonusPool,
    pub treasury_recovery_ledger: HashMap<u64, TreasuryRecoveryLedger>,
    pub audit_events: Vec<RewardAuditEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardInvariantViolation {
    pub code: String,
    pub epoch: Option<u64>,
    pub subject: Option<String>,
    pub expected_nwei: Option<u128>,
    pub actual_nwei: Option<u128>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardInvariantReport {
    pub epoch: Option<u64>,
    pub passed: bool,
    pub checked_invariants: Vec<String>,
    pub violations: Vec<RewardInvariantViolation>,
}

impl RewardInvariantReport {
    fn new(epoch: Option<u64>) -> Self {
        Self {
            epoch,
            passed: true,
            checked_invariants: vec![
                "fee_events_match_accumulators".to_string(),
                "fee_distributions_reconcile".to_string(),
                "reward_allocations_reconcile".to_string(),
                "cluster_escrows_reconcile".to_string(),
                "settlements_reconcile".to_string(),
                "treasury_recovery_reconciles".to_string(),
                "single_execution_guards_hold".to_string(),
                "burn_address_is_excluded".to_string(),
                "settlement_audit_events_exist".to_string(),
            ],
            violations: Vec::new(),
        }
    }

    fn fail(
        &mut self,
        code: &str,
        epoch: Option<u64>,
        subject: Option<String>,
        expected_nwei: Option<u128>,
        actual_nwei: Option<u128>,
        message: impl Into<String>,
    ) {
        self.passed = false;
        self.violations.push(RewardInvariantViolation {
            code: code.to_string(),
            epoch,
            subject,
            expected_nwei,
            actual_nwei,
            message: message.into(),
        });
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedRewardLedger {
    #[serde(default)]
    pub fee_accumulators: Vec<FeeAccumulator>,
    #[serde(default)]
    pub fee_distributions: Vec<EpochFeeDistribution>,
    #[serde(default)]
    pub fee_collector_distributions: Vec<FeeCollectorDistribution>,
    #[serde(default)]
    pub epoch_reward_allocations: Vec<EpochRewardAllocation>,
    #[serde(default)]
    pub cluster_reward_escrows: Vec<ClusterRewardEscrow>,
    #[serde(default)]
    pub cluster_settlements: Vec<ClusterRewardSettlement>,
    #[serde(default)]
    pub pending_rewards: Vec<ValidatorPendingReward>,
    #[serde(default)]
    pub reward_settlements: Vec<ValidatorRewardSettlement>,
    #[serde(default)]
    pub network_owned_routings: Vec<NetworkOwnedValidatorRewardRouting>,
    #[serde(default)]
    pub reliability_states: Vec<ValidatorReliabilityState>,
    #[serde(default)]
    pub bonus_pool: ReliabilityBonusPool,
    #[serde(default)]
    pub treasury_recovery_ledger: Vec<TreasuryRecoveryLedger>,
    #[serde(default)]
    pub audit_events: Vec<RewardAuditEvent>,
}

lazy_static! {
    pub static ref REWARD_LEDGER: Arc<Mutex<RewardLedger>> =
        Arc::new(Mutex::new(RewardLedger::default()));
}

#[cfg(test)]
lazy_static! {
    static ref REWARD_LEDGER_TEST_GUARD: Mutex<()> = Mutex::new(());
}

#[cfg(test)]
pub(crate) fn reward_ledger_test_guard() -> std::sync::MutexGuard<'static, ()> {
    REWARD_LEDGER_TEST_GUARD.lock().unwrap()
}

#[cfg(test)]
pub(crate) fn reset_reward_ledger_for_test() {
    *REWARD_LEDGER.lock().unwrap() = RewardLedger::default();
}

impl RewardLedger {
    pub fn to_persisted_state(&self) -> PersistedRewardLedger {
        let mut fee_accumulators: Vec<_> = self.fee_accumulators.values().cloned().collect();
        fee_accumulators.sort_by_key(|entry| entry.epoch_id);

        let mut fee_distributions: Vec<_> = self.fee_distributions.values().cloned().collect();
        fee_distributions.sort_by_key(|entry| entry.epoch_id);

        let mut fee_collector_distributions: Vec<_> =
            self.fee_collector_distributions.values().cloned().collect();
        fee_collector_distributions.sort_by_key(|entry| entry.epoch_id);

        let mut epoch_reward_allocations: Vec<_> =
            self.epoch_reward_allocations.values().cloned().collect();
        epoch_reward_allocations.sort_by_key(|entry| entry.epoch_id);

        let mut cluster_reward_escrows: Vec<_> =
            self.cluster_reward_escrows.values().cloned().collect();
        cluster_reward_escrows.sort_by(|left, right| {
            left.epoch_id.cmp(&right.epoch_id).then_with(|| {
                left.cluster_escrow_address
                    .cmp(&right.cluster_escrow_address)
            })
        });

        let mut cluster_settlements: Vec<_> = self.cluster_settlements.values().cloned().collect();
        cluster_settlements.sort_by(|left, right| {
            left.epoch_id
                .cmp(&right.epoch_id)
                .then_with(|| left.cluster_address.cmp(&right.cluster_address))
        });

        let mut network_owned_routings: Vec<_> =
            self.network_owned_routings.values().cloned().collect();
        network_owned_routings.sort_by(|left, right| {
            left.epoch_id
                .cmp(&right.epoch_id)
                .then_with(|| left.validator_id.cmp(&right.validator_id))
        });

        let mut reliability_states: Vec<_> = self.reliability_states.values().cloned().collect();
        reliability_states.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));

        let mut treasury_recovery_ledger: Vec<_> =
            self.treasury_recovery_ledger.values().cloned().collect();
        treasury_recovery_ledger.sort_by_key(|entry| entry.epoch);

        PersistedRewardLedger {
            fee_accumulators,
            fee_distributions,
            fee_collector_distributions,
            epoch_reward_allocations,
            cluster_reward_escrows,
            cluster_settlements,
            pending_rewards: self.pending_rewards.clone(),
            reward_settlements: self.reward_settlements.clone(),
            network_owned_routings,
            reliability_states,
            bonus_pool: self.bonus_pool.clone(),
            treasury_recovery_ledger,
            audit_events: self.audit_events.clone(),
        }
    }

    pub fn from_persisted_state(state: PersistedRewardLedger) -> Self {
        let mut ledger = Self::default();
        for entry in state.fee_accumulators {
            ledger.fee_accumulators.insert(entry.epoch_id, entry);
        }
        for entry in state.fee_distributions {
            ledger.fee_distributions.insert(entry.epoch_id, entry);
        }
        for entry in state.fee_collector_distributions {
            ledger
                .fee_collector_distributions
                .insert(entry.epoch_id, entry);
        }
        for entry in state.epoch_reward_allocations {
            ledger
                .epoch_reward_allocations
                .insert(entry.epoch_id, entry);
        }
        for entry in state.cluster_reward_escrows {
            ledger.cluster_reward_escrows.insert(
                (entry.epoch_id, entry.cluster_escrow_address.clone()),
                entry,
            );
        }
        for entry in state.cluster_settlements {
            ledger
                .cluster_settlements
                .insert((entry.epoch_id, entry.cluster_address.clone()), entry);
        }
        ledger.pending_rewards = state.pending_rewards;
        ledger.reward_settlements = state.reward_settlements;
        for entry in state.network_owned_routings {
            ledger
                .network_owned_routings
                .insert((entry.epoch_id, entry.validator_id.clone()), entry);
        }
        for entry in state.reliability_states {
            ledger
                .reliability_states
                .insert(entry.validator_id.clone(), entry);
        }
        ledger.bonus_pool = state.bonus_pool;
        for entry in state.treasury_recovery_ledger {
            ledger.treasury_recovery_ledger.insert(entry.epoch, entry);
        }
        ledger.audit_events = state.audit_events;
        ledger
    }

    pub fn check_invariants(&self, epoch: Option<u64>) -> RewardInvariantReport {
        let mut report = RewardInvariantReport::new(epoch);
        self.check_fee_invariants(epoch, &mut report);
        self.check_reward_allocation_invariants(epoch, &mut report);
        self.check_settlement_invariants(epoch, &mut report);
        self.check_treasury_recovery_invariants(epoch, &mut report);
        report
    }

    pub fn get_epoch_audit_events(&self, epoch: Option<u64>) -> Vec<RewardAuditEvent> {
        self.audit_events
            .iter()
            .filter(|event| match event {
                RewardAuditEvent::GasFeeCollected { epoch_id, .. } => {
                    Self::epoch_matches(epoch, *epoch_id)
                }
                RewardAuditEvent::EpochFeesClosed { distribution, .. } => {
                    Self::epoch_matches(epoch, distribution.epoch_id)
                }
                RewardAuditEvent::EpochFeeDistribution(distribution) => {
                    Self::epoch_matches(epoch, distribution.epoch_id)
                }
                RewardAuditEvent::FeeCollectorDistributed(distribution) => {
                    Self::epoch_matches(epoch, distribution.epoch_id)
                }
                RewardAuditEvent::ClusterRewardSettlement(settlement) => {
                    Self::epoch_matches(epoch, settlement.epoch_id)
                }
                RewardAuditEvent::ClusterRewardEscrowed(escrow) => {
                    Self::epoch_matches(epoch, escrow.epoch_id)
                }
                RewardAuditEvent::ValidatorPendingRewardCreated(reward) => {
                    Self::epoch_matches(epoch, reward.original_epoch_id)
                        || Self::epoch_matches(epoch, reward.accountability_epoch)
                }
                RewardAuditEvent::ValidatorReleaseCoefficientCalculated {
                    accountability_epoch,
                    ..
                } => Self::epoch_matches(epoch, *accountability_epoch),
                RewardAuditEvent::ValidatorRewardSettled(settlement) => {
                    Self::settlement_matches(epoch, settlement)
                }
                RewardAuditEvent::TreasuryRecoveryCredited {
                    original_epoch_id,
                    settlement_epoch,
                    ..
                } => {
                    Self::epoch_matches(epoch, *original_epoch_id)
                        || Self::epoch_matches(epoch, *settlement_epoch)
                }
                RewardAuditEvent::NetworkOwnedValidatorRewardRouted(routing) => {
                    Self::epoch_matches(epoch, routing.epoch_id)
                }
                RewardAuditEvent::ReliabilityBonusPoolFunded { epoch_id, .. }
                | RewardAuditEvent::ReliabilityBonusPaid { epoch_id, .. } => {
                    Self::epoch_matches(epoch, *epoch_id)
                }
                RewardAuditEvent::ValidatorReliabilityStreakUpdated(state) => epoch
                    .map(|epoch_id| state.last_high_performance_epoch == Some(epoch_id))
                    .unwrap_or(true),
            })
            .cloned()
            .collect()
    }

    fn check_fee_invariants(&self, epoch: Option<u64>, report: &mut RewardInvariantReport) {
        let mut fee_events_by_epoch: HashMap<u64, u128> = HashMap::new();
        let mut epoch_close_events: HashMap<u64, u64> = HashMap::new();
        let mut collector_distribution_events: HashMap<u64, u64> = HashMap::new();

        for event in &self.audit_events {
            match event {
                RewardAuditEvent::GasFeeCollected {
                    epoch_id, fee_nwei, ..
                } => {
                    if Self::epoch_matches(epoch, *epoch_id) {
                        let total = fee_events_by_epoch.entry(*epoch_id).or_insert(0);
                        *total = total.saturating_add(*fee_nwei);
                    }
                }
                RewardAuditEvent::EpochFeesClosed { distribution, .. } => {
                    if Self::epoch_matches(epoch, distribution.epoch_id) {
                        let count = epoch_close_events.entry(distribution.epoch_id).or_insert(0);
                        *count = count.saturating_add(1);
                    }
                }
                RewardAuditEvent::FeeCollectorDistributed(distribution) => {
                    if Self::epoch_matches(epoch, distribution.epoch_id) {
                        let count = collector_distribution_events
                            .entry(distribution.epoch_id)
                            .or_insert(0);
                        *count = count.saturating_add(1);
                    }
                }
                _ => {}
            }
        }

        for (epoch_id, event_total) in fee_events_by_epoch {
            match self.fee_accumulators.get(&epoch_id) {
                Some(accumulator) if accumulator.total_collected_nwei == event_total => {}
                Some(accumulator) => report.fail(
                    "fee_event_total_mismatch",
                    Some(epoch_id),
                    Some("fee_accumulator".to_string()),
                    Some(event_total),
                    Some(accumulator.total_collected_nwei),
                    "Fee accumulator total does not equal collected fee audit events",
                ),
                None => report.fail(
                    "fee_accumulator_missing",
                    Some(epoch_id),
                    Some("fee_accumulator".to_string()),
                    Some(event_total),
                    None,
                    "Fee audit events exist without an epoch fee accumulator",
                ),
            }
        }

        for accumulator in self
            .fee_accumulators
            .values()
            .filter(|entry| Self::epoch_matches(epoch, entry.epoch_id))
        {
            let by_tx_type_total = accumulator
                .by_tx_type
                .values()
                .fold(0u128, |acc, value| acc.saturating_add(*value));
            if by_tx_type_total != accumulator.total_collected_nwei {
                report.fail(
                    "fee_accumulator_tx_type_total_mismatch",
                    Some(accumulator.epoch_id),
                    Some("fee_accumulator.by_tx_type".to_string()),
                    Some(accumulator.total_collected_nwei),
                    Some(by_tx_type_total),
                    "Fee accumulator tx-type subtotals do not equal total collected fees",
                );
            }
        }

        for distribution in self
            .fee_distributions
            .values()
            .filter(|entry| Self::epoch_matches(epoch, entry.epoch_id))
        {
            let split_total = distribution
                .validator_share_nwei
                .saturating_add(distribution.treasury_share_nwei)
                .saturating_add(distribution.burn_share_nwei);
            if split_total != distribution.total_fees_nwei {
                report.fail(
                    "fee_distribution_split_mismatch",
                    Some(distribution.epoch_id),
                    Some("fee_distribution".to_string()),
                    Some(distribution.total_fees_nwei),
                    Some(split_total),
                    "Fee distribution shares do not sum to total fees",
                );
            }

            match self.fee_accumulators.get(&distribution.epoch_id) {
                Some(accumulator)
                    if accumulator.total_collected_nwei == distribution.total_fees_nwei
                        && accumulator.status == EpochFeeAccumulatorStatus::Closed => {}
                Some(accumulator) => report.fail(
                    "closed_fee_accumulator_mismatch",
                    Some(distribution.epoch_id),
                    Some("fee_accumulator".to_string()),
                    Some(distribution.total_fees_nwei),
                    Some(accumulator.total_collected_nwei),
                    "Closed fee distribution does not match a closed fee accumulator",
                ),
                None => report.fail(
                    "fee_distribution_without_accumulator",
                    Some(distribution.epoch_id),
                    Some("fee_distribution".to_string()),
                    Some(distribution.total_fees_nwei),
                    None,
                    "Fee distribution exists without a fee accumulator",
                ),
            }

            match self.fee_collector_distributions.get(&distribution.epoch_id) {
                Some(collector_distribution)
                    if collector_distribution.validator_reward_pool_amount_nwei
                        == distribution.validator_share_nwei
                        && collector_distribution.treasury_amount_nwei
                            == distribution.treasury_share_nwei
                        && collector_distribution.burn_amount_nwei
                            == distribution.burn_share_nwei
                        && collector_distribution.dust_nwei == distribution.rounding_dust_nwei => {}
                Some(collector_distribution) => report.fail(
                    "fee_collector_distribution_mismatch",
                    Some(distribution.epoch_id),
                    Some("fee_collector_distribution".to_string()),
                    Some(distribution.total_fees_nwei),
                    Some(
                        collector_distribution
                            .validator_reward_pool_amount_nwei
                            .saturating_add(collector_distribution.treasury_amount_nwei)
                            .saturating_add(collector_distribution.burn_amount_nwei),
                    ),
                    "Fee collector distribution does not match closed fee split",
                ),
                None => report.fail(
                    "fee_collector_distribution_missing",
                    Some(distribution.epoch_id),
                    Some("fee_collector_distribution".to_string()),
                    Some(distribution.total_fees_nwei),
                    None,
                    "Closed fee distribution has no fee collector distribution record",
                ),
            }
        }

        for (epoch_id, count) in epoch_close_events {
            if count > 1 {
                report.fail(
                    "duplicate_epoch_fee_close_event",
                    Some(epoch_id),
                    Some("audit_events".to_string()),
                    Some(1),
                    Some(count as u128),
                    "More than one EpochFeesClosed audit event exists for one epoch",
                );
            }
        }

        for (epoch_id, count) in collector_distribution_events {
            if count > 1 {
                report.fail(
                    "duplicate_fee_collector_distribution_event",
                    Some(epoch_id),
                    Some("audit_events".to_string()),
                    Some(1),
                    Some(count as u128),
                    "More than one FeeCollectorDistributed audit event exists for one epoch",
                );
            }
        }
    }

    fn check_reward_allocation_invariants(
        &self,
        epoch: Option<u64>,
        report: &mut RewardInvariantReport,
    ) {
        for allocation in self
            .epoch_reward_allocations
            .values()
            .filter(|entry| Self::epoch_matches(epoch, entry.epoch_id))
        {
            if let Some(distribution) = self.fee_distributions.get(&allocation.epoch_id) {
                if allocation.pool_amount_nwei != distribution.validator_share_nwei {
                    report.fail(
                        "validator_pool_distribution_mismatch",
                        Some(allocation.epoch_id),
                        Some("epoch_reward_allocation".to_string()),
                        Some(distribution.validator_share_nwei),
                        Some(allocation.pool_amount_nwei),
                        "Validator reward pool allocation does not equal epoch validator fee share",
                    );
                }
            }

            let cluster_total = allocation
                .cluster_allocations
                .iter()
                .fold(0u128, |acc, cluster| {
                    acc.saturating_add(cluster.cluster_reward_nwei)
                });
            if cluster_total != allocation.total_cluster_rewards_nwei
                || cluster_total != allocation.pool_amount_nwei
            {
                report.fail(
                    "cluster_allocation_total_mismatch",
                    Some(allocation.epoch_id),
                    Some("cluster_allocations".to_string()),
                    Some(allocation.pool_amount_nwei),
                    Some(cluster_total),
                    "Cluster allocations do not sum to validator reward pool amount",
                );
            }

            let pending_total = allocation
                .cluster_allocations
                .iter()
                .flat_map(|cluster| cluster.validator_pending_rewards.iter())
                .fold(0u128, |acc, reward| {
                    acc.saturating_add(reward.pending_reward_nwei)
                });
            if pending_total != allocation.total_validator_pending_rewards_nwei {
                report.fail(
                    "validator_pending_total_mismatch",
                    Some(allocation.epoch_id),
                    Some("validator_pending_rewards".to_string()),
                    Some(allocation.total_validator_pending_rewards_nwei),
                    Some(pending_total),
                    "Validator pending rewards do not sum to recorded allocation total",
                );
            }
            if allocation.rounding_dust_nwei
                != allocation.pool_amount_nwei.saturating_sub(pending_total)
            {
                report.fail(
                    "allocation_dust_mismatch",
                    Some(allocation.epoch_id),
                    Some("epoch_reward_allocation.rounding_dust_nwei".to_string()),
                    Some(allocation.pool_amount_nwei.saturating_sub(pending_total)),
                    Some(allocation.rounding_dust_nwei),
                    "Allocation dust does not match pool minus pending rewards",
                );
            }

            for cluster in &allocation.cluster_allocations {
                if !cluster.cluster_address.starts_with("syngrp1")
                    || crate::address::is_network_burn_address(&cluster.cluster_address)
                {
                    report.fail(
                        "invalid_cluster_reward_escrow_address",
                        Some(allocation.epoch_id),
                        Some(cluster.cluster_address.clone()),
                        None,
                        None,
                        "Cluster reward escrow is not a valid syngrp1 protocol escrow",
                    );
                }

                let cluster_pending_total = cluster
                    .validator_pending_rewards
                    .iter()
                    .fold(0u128, |acc, reward| {
                        acc.saturating_add(reward.pending_reward_nwei)
                    });
                if cluster_pending_total > cluster.cluster_reward_nwei {
                    report.fail(
                        "cluster_pending_exceeds_reward",
                        Some(allocation.epoch_id),
                        Some(cluster.cluster_address.clone()),
                        Some(cluster.cluster_reward_nwei),
                        Some(cluster_pending_total),
                        "Validator pending rewards exceed cluster reward allocation",
                    );
                }

                match self
                    .cluster_reward_escrows
                    .get(&(allocation.epoch_id, cluster.cluster_address.clone()))
                {
                    Some(escrow)
                        if escrow.funded_amount_nwei == cluster.cluster_reward_nwei
                            && escrow.pending_validator_rewards_nwei == cluster_pending_total
                            && escrow.dust_nwei
                                == escrow
                                    .funded_amount_nwei
                                    .saturating_sub(escrow.pending_validator_rewards_nwei) => {}
                    Some(escrow) => report.fail(
                        "cluster_escrow_mismatch",
                        Some(allocation.epoch_id),
                        Some(cluster.cluster_address.clone()),
                        Some(cluster.cluster_reward_nwei),
                        Some(escrow.funded_amount_nwei),
                        "Cluster escrow does not match cluster reward allocation",
                    ),
                    None => report.fail(
                        "cluster_escrow_missing",
                        Some(allocation.epoch_id),
                        Some(cluster.cluster_address.clone()),
                        Some(cluster.cluster_reward_nwei),
                        None,
                        "Cluster reward allocation has no escrow record",
                    ),
                }
            }
        }

        for escrow in self
            .cluster_reward_escrows
            .values()
            .filter(|entry| Self::epoch_matches(epoch, entry.epoch_id))
        {
            if escrow.funded_amount_nwei
                != escrow
                    .pending_validator_rewards_nwei
                    .saturating_add(escrow.dust_nwei)
            {
                report.fail(
                    "cluster_escrow_dust_mismatch",
                    Some(escrow.epoch_id),
                    Some(escrow.cluster_escrow_address.clone()),
                    Some(escrow.funded_amount_nwei),
                    Some(
                        escrow
                            .pending_validator_rewards_nwei
                            .saturating_add(escrow.dust_nwei),
                    ),
                    "Cluster escrow funded amount does not equal pending rewards plus dust",
                );
            }
            if crate::address::is_network_burn_address(&escrow.cluster_escrow_address) {
                report.fail(
                    "burn_address_used_as_cluster_escrow",
                    Some(escrow.epoch_id),
                    Some(escrow.cluster_escrow_address.clone()),
                    None,
                    None,
                    "Network burn address cannot be a cluster reward escrow",
                );
            }
        }
    }

    fn check_settlement_invariants(&self, epoch: Option<u64>, report: &mut RewardInvariantReport) {
        let mut pending_keys: HashSet<(u64, String, String)> = HashSet::new();
        let mut pending_by_key: HashMap<(u64, String, String), &ValidatorPendingReward> =
            HashMap::new();
        for pending in &self.pending_rewards {
            if !Self::pending_matches(epoch, pending) {
                continue;
            }
            let key = (
                pending.original_epoch_id,
                pending.original_cluster_address.clone(),
                pending.validator_id.clone(),
            );
            if !pending_keys.insert(key.clone()) {
                report.fail(
                    "duplicate_pending_reward",
                    Some(pending.original_epoch_id),
                    Some(pending.validator_id.clone()),
                    None,
                    None,
                    "Duplicate pending validator reward exists for the same epoch and cluster",
                );
            }
            if crate::address::is_network_burn_address(&pending.reward_payout_address) {
                report.fail(
                    "burn_address_used_as_validator_payout",
                    Some(pending.original_epoch_id),
                    Some(pending.validator_id.clone()),
                    None,
                    None,
                    "Network burn address cannot be a validator reward payout",
                );
            }
            pending_by_key.insert(key, pending);
        }

        let settlement_event_keys = self
            .audit_events
            .iter()
            .filter_map(|event| match event {
                RewardAuditEvent::ValidatorRewardSettled(settlement) => Some((
                    settlement.original_epoch_id,
                    settlement.original_cluster_address.clone(),
                    settlement.validator_id.clone(),
                )),
                _ => None,
            })
            .collect::<HashSet<_>>();
        let coefficient_event_keys = self
            .audit_events
            .iter()
            .filter_map(|event| match event {
                RewardAuditEvent::ValidatorReleaseCoefficientCalculated {
                    accountability_epoch,
                    validator_id,
                    ..
                } => Some((*accountability_epoch, validator_id.clone())),
                _ => None,
            })
            .collect::<HashSet<_>>();

        let mut settlement_keys: HashSet<(u64, String, String)> = HashSet::new();
        let mut settled_by_cluster: HashMap<(u64, String), u128> = HashMap::new();
        for settlement in self
            .reward_settlements
            .iter()
            .filter(|entry| Self::settlement_matches(epoch, entry))
        {
            let key = (
                settlement.original_epoch_id,
                settlement.original_cluster_address.clone(),
                settlement.validator_id.clone(),
            );
            if !settlement_keys.insert(key.clone()) {
                report.fail(
                    "duplicate_validator_settlement",
                    Some(settlement.original_epoch_id),
                    Some(settlement.validator_id.clone()),
                    None,
                    None,
                    "Validator reward settlement was recorded more than once",
                );
            }

            let settlement_total = settlement
                .final_reward_nwei
                .saturating_add(settlement.unreleased_reward_nwei);
            if settlement_total != settlement.pending_reward_nwei {
                report.fail(
                    "settlement_total_mismatch",
                    Some(settlement.original_epoch_id),
                    Some(settlement.validator_id.clone()),
                    Some(settlement.pending_reward_nwei),
                    Some(settlement_total),
                    "Released plus unreleased reward does not equal pending reward",
                );
            }
            if settlement.unreleased_reward_nwei > 0
                && settlement.unreleased_destination != UnreleasedDestination::TreasuryRecovery
            {
                report.fail(
                    "unreleased_reward_not_treasury_recovery",
                    Some(settlement.original_epoch_id),
                    Some(settlement.validator_id.clone()),
                    Some(settlement.unreleased_reward_nwei),
                    None,
                    "Unreleased validator reward must go to Treasury Recovery",
                );
            }
            if crate::address::is_network_burn_address(&settlement.reward_payout_address) {
                report.fail(
                    "burn_address_used_as_settlement_payout",
                    Some(settlement.original_epoch_id),
                    Some(settlement.validator_id.clone()),
                    None,
                    None,
                    "Network burn address cannot receive validator settlement payout",
                );
            }

            if let Some(pending) = pending_by_key.get(&key) {
                if pending.pending_reward_nwei != settlement.pending_reward_nwei {
                    report.fail(
                        "settlement_pending_record_mismatch",
                        Some(settlement.original_epoch_id),
                        Some(settlement.validator_id.clone()),
                        Some(pending.pending_reward_nwei),
                        Some(settlement.pending_reward_nwei),
                        "Settlement amount does not match pending reward record",
                    );
                }
            } else {
                report.fail(
                    "settlement_without_pending_reward",
                    Some(settlement.original_epoch_id),
                    Some(settlement.validator_id.clone()),
                    Some(settlement.pending_reward_nwei),
                    None,
                    "Settlement exists without a matching pending reward record",
                );
            }

            if !settlement_event_keys.contains(&key) {
                report.fail(
                    "settlement_audit_event_missing",
                    Some(settlement.original_epoch_id),
                    Some(settlement.validator_id.clone()),
                    None,
                    None,
                    "ValidatorRewardSettled audit event is missing for settlement",
                );
            }
            if !coefficient_event_keys.contains(&(
                settlement.accountability_epoch,
                settlement.validator_id.clone(),
            )) {
                report.fail(
                    "release_coefficient_audit_event_missing",
                    Some(settlement.accountability_epoch),
                    Some(settlement.validator_id.clone()),
                    None,
                    None,
                    "ValidatorReleaseCoefficientCalculated audit event is missing for settlement",
                );
            }

            let cluster_key = (
                settlement.original_epoch_id,
                settlement.original_cluster_address.clone(),
            );
            let cluster_total = settled_by_cluster.entry(cluster_key).or_insert(0);
            *cluster_total = cluster_total.saturating_add(settlement.pending_reward_nwei);
        }

        for ((epoch_id, cluster_address), settled_total) in settled_by_cluster {
            if let Some(escrow) = self
                .cluster_reward_escrows
                .get(&(epoch_id, cluster_address.clone()))
            {
                if settled_total > escrow.funded_amount_nwei {
                    report.fail(
                        "cluster_escrow_overpaid",
                        Some(epoch_id),
                        Some(cluster_address),
                        Some(escrow.funded_amount_nwei),
                        Some(settled_total),
                        "Settlements draw more than the cluster escrow funded amount",
                    );
                }
            }
        }
    }

    fn check_treasury_recovery_invariants(
        &self,
        epoch: Option<u64>,
        report: &mut RewardInvariantReport,
    ) {
        let mut expected_recovery_by_epoch: HashMap<u64, u128> = HashMap::new();
        for settlement in &self.reward_settlements {
            if settlement.unreleased_reward_nwei == 0 {
                continue;
            }
            let total = expected_recovery_by_epoch
                .entry(settlement.accountability_epoch)
                .or_insert(0);
            *total = total.saturating_add(settlement.unreleased_reward_nwei);
        }

        for (recovery_epoch, expected_total) in expected_recovery_by_epoch
            .iter()
            .filter(|(entry_epoch, _)| Self::epoch_matches(epoch, **entry_epoch))
        {
            let actual_total = self
                .treasury_recovery_ledger
                .get(recovery_epoch)
                .map(|ledger| ledger.total_recovered_nwei)
                .unwrap_or(0);
            if actual_total != *expected_total {
                report.fail(
                    "treasury_recovery_total_mismatch",
                    Some(*recovery_epoch),
                    Some("treasury_recovery_ledger".to_string()),
                    Some(*expected_total),
                    Some(actual_total),
                    "Treasury Recovery ledger does not equal unreleased validator rewards",
                );
            }
        }

        for recovery in self
            .treasury_recovery_ledger
            .values()
            .filter(|entry| Self::epoch_matches(epoch, entry.epoch))
        {
            let entry_total = recovery
                .entries
                .iter()
                .fold(0u128, |acc, entry| acc.saturating_add(entry.amount_nwei));
            if entry_total != recovery.total_recovered_nwei {
                report.fail(
                    "treasury_recovery_entry_total_mismatch",
                    Some(recovery.epoch),
                    Some("treasury_recovery_ledger.entries".to_string()),
                    Some(recovery.total_recovered_nwei),
                    Some(entry_total),
                    "Treasury Recovery entries do not sum to ledger total",
                );
            }
            for entry in &recovery.entries {
                if crate::address::is_network_burn_address(&entry.treasury_recovery_wallet_address)
                {
                    report.fail(
                        "treasury_recovery_sent_to_burn_address",
                        Some(recovery.epoch),
                        Some(entry.validator_id.clone()),
                        Some(entry.amount_nwei),
                        None,
                        "Treasury Recovery cannot route unreleased rewards to the burn address",
                    );
                }
            }
        }
    }

    fn epoch_matches(filter: Option<u64>, epoch_id: u64) -> bool {
        filter.map(|epoch| epoch == epoch_id).unwrap_or(true)
    }

    fn pending_matches(filter: Option<u64>, pending: &ValidatorPendingReward) -> bool {
        filter
            .map(|epoch| {
                pending.original_epoch_id == epoch
                    || pending.unlock_epoch == epoch
                    || pending.accountability_epoch == epoch
            })
            .unwrap_or(true)
    }

    fn settlement_matches(filter: Option<u64>, settlement: &ValidatorRewardSettlement) -> bool {
        filter
            .map(|epoch| {
                settlement.original_epoch_id == epoch
                    || settlement.unlock_epoch == epoch
                    || settlement.accountability_epoch == epoch
            })
            .unwrap_or(true)
    }

    pub fn record_fee_charged(
        &mut self,
        epoch_id: u64,
        tx_hash: impl Into<String>,
        tx_type: impl Into<String>,
        fee_nwei: u128,
        block_height: u64,
    ) -> Result<(), String> {
        let accumulator = self
            .fee_accumulators
            .entry(epoch_id)
            .or_insert_with(|| FeeAccumulator::new(epoch_id, block_height));
        accumulator.record_fee(tx_type, fee_nwei)?;
        self.audit_events.push(RewardAuditEvent::GasFeeCollected {
            epoch_id,
            tx_hash: tx_hash.into(),
            fee_nwei,
        });
        Ok(())
    }

    pub fn distribute_epoch_fees(
        &mut self,
        epoch_id: u64,
        total_fees_nwei: u128,
        distribution_block_height: u64,
    ) -> Result<&EpochFeeDistribution, String> {
        if self.fee_distributions.contains_key(&epoch_id) {
            return Ok(self
                .fee_distributions
                .get(&epoch_id)
                .expect("checked existing epoch fee distribution"));
        }
        let distribution = split_epoch_fees(epoch_id, total_fees_nwei, distribution_block_height)?;
        let accumulator = self
            .fee_accumulators
            .entry(epoch_id)
            .or_insert_with(|| FeeAccumulator::new(epoch_id, distribution_block_height));
        if accumulator.total_collected_nwei == 0 {
            accumulator.total_collected_nwei = total_fees_nwei;
        } else if accumulator.total_collected_nwei != total_fees_nwei {
            return Err(format!(
                "epoch fee accumulator total {} does not match distribution total {}",
                accumulator.total_collected_nwei, total_fees_nwei
            ));
        }
        accumulator.close(distribution_block_height);
        self.audit_events.push(RewardAuditEvent::EpochFeesClosed {
            accumulator: accumulator.clone(),
            distribution: distribution.clone(),
        });
        self.audit_events
            .push(RewardAuditEvent::EpochFeeDistribution(distribution.clone()));
        self.fee_distributions.insert(epoch_id, distribution);
        Ok(self.fee_distributions.get(&epoch_id).expect("inserted"))
    }

    pub fn record_fee_collector_distribution(
        &mut self,
        distribution: FeeCollectorDistribution,
    ) -> Result<(), String> {
        if self
            .fee_collector_distributions
            .contains_key(&distribution.epoch_id)
        {
            return Ok(());
        }
        self.audit_events
            .push(RewardAuditEvent::FeeCollectorDistributed(
                distribution.clone(),
            ));
        self.fee_collector_distributions
            .insert(distribution.epoch_id, distribution);
        Ok(())
    }

    pub fn record_epoch_reward_allocation(
        &mut self,
        allocation: EpochRewardAllocation,
        validator_reward_pool_address: &str,
        funded_block_height: u64,
    ) -> Result<(), String> {
        if self
            .epoch_reward_allocations
            .contains_key(&allocation.epoch_id)
        {
            return Ok(());
        }
        for cluster in &allocation.cluster_allocations {
            let key = (allocation.epoch_id, cluster.cluster_address.clone());
            if self.cluster_reward_escrows.contains_key(&key)
                || self.cluster_settlements.contains_key(&key)
            {
                return Err("cluster reward escrow already exists".to_string());
            }
        }

        for (cluster_index, cluster) in allocation.cluster_allocations.iter().enumerate() {
            let key = (allocation.epoch_id, cluster.cluster_address.clone());
            let pending_total = cluster
                .validator_pending_rewards
                .iter()
                .try_fold(0u128, |acc, reward| {
                    acc.checked_add(reward.pending_reward_nwei)
                })
                .ok_or_else(|| "cluster pending reward sum overflow".to_string())?;
            let escrow = ClusterRewardEscrow {
                epoch_id: allocation.epoch_id,
                cluster_id: cluster.cluster_address.clone(),
                cluster_escrow_address: cluster.cluster_address.clone(),
                funded_amount_nwei: cluster.cluster_reward_nwei,
                pending_validator_rewards_nwei: pending_total,
                dust_nwei: cluster.cluster_reward_nwei.saturating_sub(pending_total),
                validator_reward_pool_address: validator_reward_pool_address.to_string(),
                funded_block_height,
                status: SettlementStatus::Pending,
            };
            let settlement = ClusterRewardSettlement {
                epoch_id: allocation.epoch_id,
                cluster_address: cluster.cluster_address.clone(),
                cluster_index: cluster_index as u64,
                total_cluster_reward_nwei: cluster.cluster_reward_nwei,
                total_validator_pending_rewards_nwei: pending_total,
                validator_count: cluster.validator_count,
                assignment_hash: format!(
                    "epoch:{}:cluster:{}:block:{}",
                    allocation.epoch_id, cluster.cluster_address, funded_block_height
                ),
                rotation_mode: "phase1_fee_rewards".to_string(),
                settlement_status: SettlementStatus::Pending,
                created_block_height: funded_block_height,
            };
            self.audit_events
                .push(RewardAuditEvent::ClusterRewardEscrowed(escrow.clone()));
            self.audit_events
                .push(RewardAuditEvent::ClusterRewardSettlement(
                    settlement.clone(),
                ));
            self.cluster_reward_escrows.insert(key.clone(), escrow);
            self.cluster_settlements.insert(key, settlement);
            for reward in &cluster.validator_pending_rewards {
                self.add_pending_reward(reward.clone())?;
            }
        }

        self.epoch_reward_allocations
            .insert(allocation.epoch_id, allocation);
        Ok(())
    }

    pub fn create_cluster_settlement(
        &mut self,
        settlement: ClusterRewardSettlement,
    ) -> Result<(), String> {
        let key = (settlement.epoch_id, settlement.cluster_address.clone());
        if self.cluster_settlements.contains_key(&key) {
            return Err("cluster reward settlement already exists".to_string());
        }
        self.audit_events
            .push(RewardAuditEvent::ClusterRewardSettlement(
                settlement.clone(),
            ));
        self.cluster_settlements.insert(key, settlement);
        Ok(())
    }

    pub fn add_pending_reward(&mut self, reward: ValidatorPendingReward) -> Result<(), String> {
        if self.pending_rewards.iter().any(|existing| {
            existing.original_epoch_id == reward.original_epoch_id
                && existing.original_cluster_address == reward.original_cluster_address
                && existing.validator_id == reward.validator_id
        }) {
            return Err("pending reward already exists".to_string());
        }
        self.audit_events
            .push(RewardAuditEvent::ValidatorPendingRewardCreated(
                reward.clone(),
            ));
        self.pending_rewards.push(reward);
        Ok(())
    }

    pub fn settle_pending_rewards(
        &mut self,
        unlock_epoch: u64,
        release_coefficients: &HashMap<String, u64>,
        settled_block_height: u64,
    ) -> Result<Vec<ValidatorRewardSettlement>, String> {
        let mut settlements = Vec::new();
        for pending in self
            .pending_rewards
            .iter_mut()
            .filter(|reward| reward.unlock_epoch == unlock_epoch)
        {
            if pending.status != PendingRewardStatus::Pending {
                continue;
            }
            let coefficient = release_coefficients
                .get(&pending.validator_id)
                .copied()
                .unwrap_or(0);
            self.audit_events
                .push(RewardAuditEvent::ValidatorReleaseCoefficientCalculated {
                    accountability_epoch: pending.accountability_epoch,
                    validator_id: pending.validator_id.clone(),
                    release_coefficient_bps: coefficient,
                });
            let settlement = settle_pending_reward(pending, coefficient, settled_block_height)?;
            self.audit_events
                .push(RewardAuditEvent::ValidatorRewardSettled(settlement.clone()));
            if settlement.unreleased_reward_nwei > 0 {
                let reason_codes = vec![format!(
                    "release_coefficient_bps:{}",
                    settlement.release_coefficient_bps
                )];
                let recovery_entry = TreasuryRecoveryEntry {
                    original_epoch_id: settlement.original_epoch_id,
                    settlement_epoch: pending.accountability_epoch,
                    validator_id: settlement.validator_id.clone(),
                    cluster_id: settlement.cluster_id.clone(),
                    amount_nwei: settlement.unreleased_reward_nwei,
                    treasury_recovery_wallet_address:
                        crate::token::TREASURY_RECOVERY_WALLET_ADDRESS.to_string(),
                    reason_codes: reason_codes.clone(),
                };
                self.treasury_recovery_ledger
                    .entry(pending.accountability_epoch)
                    .or_insert_with(|| TreasuryRecoveryLedger::new(pending.accountability_epoch))
                    .credit(recovery_entry.clone())?;
                self.audit_events
                    .push(RewardAuditEvent::TreasuryRecoveryCredited {
                        original_epoch_id: recovery_entry.original_epoch_id,
                        settlement_epoch: recovery_entry.settlement_epoch,
                        validator_id: recovery_entry.validator_id,
                        cluster_id: recovery_entry.cluster_id,
                        amount_nwei: recovery_entry.amount_nwei,
                        treasury_recovery_wallet_address: recovery_entry
                            .treasury_recovery_wallet_address,
                        reason_codes: recovery_entry.reason_codes,
                    });
            }
            self.reward_settlements.push(settlement.clone());
            settlements.push(settlement);
        }
        Ok(settlements)
    }

    pub fn record_network_owned_routing(
        &mut self,
        routing: NetworkOwnedValidatorRewardRouting,
    ) -> Result<(), String> {
        let key = (routing.epoch_id, routing.validator_id.clone());
        if self.network_owned_routings.contains_key(&key) {
            return Err("network-owned validator routing already executed".to_string());
        }
        self.bonus_pool.fund(routing.bonus_pool_share_nwei)?;
        self.audit_events
            .push(RewardAuditEvent::ReliabilityBonusPoolFunded {
                epoch_id: routing.epoch_id,
                amount_nwei: routing.bonus_pool_share_nwei,
            });
        self.audit_events
            .push(RewardAuditEvent::NetworkOwnedValidatorRewardRouted(
                routing.clone(),
            ));
        self.network_owned_routings.insert(key, routing);
        Ok(())
    }

    pub fn get_validator_pending_rewards(&self, validator_id: &str) -> Vec<ValidatorPendingReward> {
        self.pending_rewards
            .iter()
            .filter(|reward| reward.validator_id == validator_id)
            .cloned()
            .collect()
    }

    pub fn get_validator_reward_status(
        &self,
        validator_id: &str,
        current_epoch_id: u64,
    ) -> ValidatorRewardStatus {
        let pending: Vec<_> = self
            .pending_rewards
            .iter()
            .filter(|reward| {
                reward.validator_id == validator_id && reward.status == PendingRewardStatus::Pending
            })
            .cloned()
            .collect();
        let completed: Vec<_> = self
            .reward_settlements
            .iter()
            .filter(|settlement| settlement.validator_id == validator_id)
            .cloned()
            .collect();
        let previous_epoch_pending_reward = pending
            .iter()
            .filter(|reward| reward.original_epoch_id + 1 == current_epoch_id)
            .next()
            .cloned();
        let projected = pending.first().cloned();
        let estimated_release = BPS_DENOMINATOR;
        let projected_final = projected
            .as_ref()
            .map(|reward| mul_bps(reward.pending_reward_nwei, estimated_release).unwrap_or(0))
            .unwrap_or(0);
        let projected_unreleased = projected
            .as_ref()
            .map(|reward| reward.pending_reward_nwei.saturating_sub(projected_final))
            .unwrap_or(0);
        let reliability = self
            .reliability_states
            .get(validator_id)
            .cloned()
            .unwrap_or_else(|| ValidatorReliabilityState::new(validator_id));
        let next_tier = next_bonus_tier(reliability.current_streak_epochs);
        let config = RewardConfig::default();
        let network_owned_validator_routing = self
            .network_owned_routings
            .values()
            .filter(|routing| routing.validator_id == validator_id)
            .cloned()
            .collect();

        ValidatorRewardStatus {
            current_epoch_id,
            validator_id: validator_id.to_string(),
            validator_status: "Unknown".to_string(),
            current_epoch_participation_score_bps: 0,
            previous_epoch_pending_reward,
            accountability_epoch: projected.as_ref().map(|reward| reward.accountability_epoch),
            unlock_epoch: projected.as_ref().map(|reward| reward.unlock_epoch),
            estimated_release_coefficient_bps: estimated_release,
            projected_final_reward_nwei: projected_final,
            projected_unreleased_amount_nwei: projected_unreleased,
            current_reliability_streak: reliability.current_streak_epochs,
            highest_reliability_streak: reliability.highest_streak_epochs,
            current_bonus_tier_bps: reliability.current_bonus_tier_bps,
            next_bonus_tier_bps: bonus_tier_bps(next_tier, &config),
            epochs_until_next_bonus_tier: next_tier
                .saturating_sub(reliability.current_streak_epochs),
            reliability_bonus_eligibility: reliability.eligible_for_bonus,
            uptime_percentage_bps: 0,
            consensus_participation_percentage_bps: 0,
            responsiveness_score_bps: 0,
            cluster_performance_score_bps: 0,
            governance_participation_score_bps: 0,
            jailing_status: matches!(
                reliability.last_penalty_reason,
                ValidatorPenaltyReason::Jailed
            ),
            slashing_status: matches!(
                reliability.last_penalty_reason,
                ValidatorPenaltyReason::Slashed
            ),
            pending_settlements: pending,
            completed_settlements: completed,
            network_owned_validator_routing,
        }
    }
}

fn next_bonus_tier(current_streak: u64) -> u64 {
    for tier in [10, 50, 100, 250, 500] {
        if current_streak < tier {
            return tier;
        }
    }
    500
}

pub fn prorate_bonus_claims(
    claims: &[(String, u128)],
    available_nwei: u128,
) -> Result<Vec<(String, u128)>, String> {
    let total_claimed = claims
        .iter()
        .try_fold(0u128, |acc, (_, amount)| acc.checked_add(*amount))
        .ok_or_else(|| "bonus claim total overflow".to_string())?;
    if total_claimed <= available_nwei {
        return Ok(claims.to_vec());
    }
    if total_claimed == 0 {
        return Ok(claims.iter().map(|(id, _)| (id.clone(), 0)).collect());
    }

    let mut paid = 0u128;
    let mut result = Vec::with_capacity(claims.len());
    for (index, (validator_id, claim)) in claims.iter().enumerate() {
        let amount = if index + 1 == claims.len() {
            available_nwei.saturating_sub(paid)
        } else {
            claim
                .checked_mul(available_nwei)
                .ok_or_else(|| "bonus proration overflow".to_string())?
                / total_claimed
        };
        paid = paid
            .checked_add(amount)
            .ok_or_else(|| "bonus paid total overflow".to_string())?;
        result.push((validator_id.clone(), amount));
    }
    Ok(result)
}

pub fn duplicate_guard_key(parts: &[&str]) -> String {
    parts.join(":")
}

pub fn ensure_not_duplicate(seen: &mut HashSet<String>, key: String) -> Result<(), String> {
    if !seen.insert(key) {
        return Err("duplicate reward operation".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reward_epochs_follow_canonical_one_based_block_ranges() {
        assert_eq!(default_reward_epoch_for_block_height(1), 0);
        assert_eq!(default_reward_epoch_for_block_height(1_000), 0);
        assert_eq!(default_reward_epoch_for_block_height(1_001), 1);
        assert_eq!(default_reward_epoch_for_block_height(2_000), 1);
        assert_eq!(default_reward_epoch_for_block_height(2_001), 2);
    }

    fn perfect_phase1() -> Phase1Metrics {
        Phase1Metrics {
            consensus_participation_score_bps: 10_000,
            block_proposal_score_bps: 10_000,
            validation_accuracy_score_bps: 10_000,
            cluster_contribution_score_bps: 10_000,
            synergy_score_modifier_bps: 10_000,
        }
    }

    fn closed_reward_ledger_fixture() -> RewardLedger {
        let mut ledger = RewardLedger::default();
        ledger
            .record_fee_charged(7, "tx-a", "native_snrg_send", 40, 70)
            .unwrap();
        ledger
            .record_fee_charged(7, "tx-b", "native_snrg_send", 60, 71)
            .unwrap();
        let distribution = ledger.distribute_epoch_fees(7, 100, 99).unwrap().clone();
        ledger
            .record_fee_collector_distribution(FeeCollectorDistribution {
                epoch_id: 7,
                from_address: crate::token::FEE_COLLECTOR_ADDRESS.to_string(),
                validator_reward_pool_address: crate::token::VALIDATOR_REWARDS_POOL_ADDRESS
                    .to_string(),
                validator_reward_pool_amount_nwei: distribution.validator_share_nwei,
                treasury_wallet_address: crate::token::DAO_TREASURY_ADDRESS.to_string(),
                treasury_amount_nwei: distribution.treasury_share_nwei,
                burn_amount_nwei: distribution.burn_share_nwei,
                dust_nwei: distribution.rounding_dust_nwei,
                distribution_state_id: "epoch-fees:7".to_string(),
                distributed_block_height: 99,
            })
            .unwrap();

        let validators = vec![ValidatorPhase1Input {
            cluster_address: "syngrp1cluster-a".to_string(),
            validator_id: "validator-a".to_string(),
            reward_payout_address: "synw1validator-a".to_string(),
            metrics: perfect_phase1(),
        }];
        let allocation = allocate_epoch_validator_rewards(
            7,
            distribution.validator_share_nwei,
            &validators,
            100,
            &RewardConfig::default(),
        )
        .unwrap();
        ledger
            .record_epoch_reward_allocation(
                allocation,
                crate::token::VALIDATOR_REWARDS_POOL_ADDRESS,
                100,
            )
            .unwrap();
        ledger
            .settle_pending_rewards(8, &HashMap::from([("validator-a".to_string(), 8_500)]), 200)
            .unwrap();

        ledger
    }

    #[test]
    fn reward_config_validates_required_sums() {
        assert!(RewardConfig::default().validate().is_ok());
        let mut config = RewardConfig::default();
        config.validator_fee_share_bps = 6_499;
        assert!(config.validate().is_err());
    }

    #[test]
    fn epoch_fee_split_is_70_30_with_treasury_dust() {
        let split = split_epoch_fees(7, 101, 55).unwrap();
        assert_eq!(split.validator_share_nwei, 70);
        assert_eq!(split.burn_share_nwei, 0);
        assert_eq!(split.treasury_share_nwei, 31);
        assert_eq!(split.rounding_dust_nwei, 1);
        assert_eq!(
            split.validator_share_nwei + split.treasury_share_nwei + split.burn_share_nwei,
            split.total_fees_nwei
        );
    }

    #[test]
    fn pending_reward_is_delayed_and_tracks_sources() {
        let pending = calculate_pending_reward(
            10,
            "syngrp1cluster",
            "validator-7",
            "synw1payout",
            1_000,
            500,
            250,
            &perfect_phase1(),
            &RewardConfig::default(),
        )
        .unwrap();
        assert_eq!(pending.pending_reward_nwei, 1_750);
        assert_eq!(pending.accountability_epoch, 11);
        assert_eq!(pending.unlock_epoch, 11);
        assert_eq!(pending.status, PendingRewardStatus::Pending);
        assert_eq!(pending.source_fee_rewards_nwei, 500);
    }

    #[test]
    fn better_phase1_score_earns_higher_pending_reward() {
        let mut weaker = perfect_phase1();
        weaker.block_proposal_score_bps = 5_000;
        let strong = calculate_pending_reward(
            1,
            "cluster",
            "a",
            "payout",
            1_000,
            0,
            0,
            &perfect_phase1(),
            &RewardConfig::default(),
        )
        .unwrap();
        let weak = calculate_pending_reward(
            1,
            "cluster",
            "b",
            "payout",
            1_000,
            0,
            0,
            &weaker,
            &RewardConfig::default(),
        )
        .unwrap();
        assert!(strong.pending_reward_nwei > weak.pending_reward_nwei);
    }

    #[test]
    fn release_coefficient_thresholds_and_penalties_are_enforced() {
        let config = RewardConfig::default();
        let perfect = ReleasePerformance {
            uptime_score_bps: 10_000,
            responsiveness_score_bps: 10_000,
            no_jail_slash_score_bps: 10_000,
            cluster_stability_score_bps: 10_000,
            governance_participation_score_bps: 10_000,
            penalty_reason: ValidatorPenaltyReason::None,
        };
        assert_eq!(
            calculate_release_coefficient(&perfect, &config).unwrap(),
            10_000
        );

        let ninety_nine = ReleasePerformance {
            uptime_score_bps: 9_900,
            responsiveness_score_bps: 9_900,
            no_jail_slash_score_bps: 9_900,
            cluster_stability_score_bps: 9_900,
            governance_participation_score_bps: 9_900,
            penalty_reason: ValidatorPenaltyReason::None,
        };
        assert_eq!(
            calculate_release_coefficient(&ninety_nine, &config).unwrap(),
            8_500
        );

        let slashed = ReleasePerformance {
            penalty_reason: ValidatorPenaltyReason::Slashed,
            ..perfect
        };
        assert_eq!(calculate_release_coefficient(&slashed, &config).unwrap(), 0);
    }

    #[test]
    fn final_reward_settlement_recovers_unreleased_amount_and_is_single_use() {
        let mut pending = calculate_pending_reward(
            5,
            "cluster",
            "validator",
            "payout",
            1_000,
            0,
            0,
            &perfect_phase1(),
            &RewardConfig::default(),
        )
        .unwrap();
        let settlement = settle_pending_reward(&mut pending, 9_000, 99).unwrap();
        assert_eq!(settlement.final_reward_nwei, 900);
        assert_eq!(settlement.unreleased_reward_nwei, 100);
        assert_eq!(
            settlement.unreleased_destination,
            UnreleasedDestination::TreasuryRecovery
        );
        assert!(settle_pending_reward(&mut pending, 9_000, 100).is_err());
    }

    #[test]
    fn epoch_reward_allocation_reconciles_clusters_and_pending_rewards() {
        let half_phase1 = Phase1Metrics {
            consensus_participation_score_bps: 5_000,
            block_proposal_score_bps: 5_000,
            validation_accuracy_score_bps: 5_000,
            cluster_contribution_score_bps: 5_000,
            synergy_score_modifier_bps: 5_000,
        };
        let validators = vec![
            ValidatorPhase1Input {
                cluster_address: "syngrp1cluster-a".to_string(),
                validator_id: "validator-1".to_string(),
                reward_payout_address: "synw1validator1".to_string(),
                metrics: perfect_phase1(),
            },
            ValidatorPhase1Input {
                cluster_address: "syngrp1cluster-a".to_string(),
                validator_id: "validator-2".to_string(),
                reward_payout_address: "synw1validator2".to_string(),
                metrics: half_phase1,
            },
            ValidatorPhase1Input {
                cluster_address: "syngrp1cluster-b".to_string(),
                validator_id: "validator-3".to_string(),
                reward_payout_address: "synw1validator3".to_string(),
                metrics: perfect_phase1(),
            },
        ];

        let allocation =
            allocate_epoch_validator_rewards(9, 25_000, &validators, 999, &RewardConfig::default())
                .unwrap();

        assert_eq!(allocation.cluster_allocations.len(), 2);
        assert_eq!(allocation.total_cluster_rewards_nwei, 25_000);
        assert_eq!(allocation.total_validator_pending_rewards_nwei, 25_000);
        assert_eq!(allocation.rounding_dust_nwei, 0);
        assert_eq!(
            allocation.cluster_allocations[0].cluster_reward_nwei,
            15_000
        );
        assert_eq!(
            allocation.cluster_allocations[0].validator_pending_rewards[0].pending_reward_nwei,
            10_000
        );
        assert_eq!(
            allocation.cluster_allocations[0].validator_pending_rewards[1].pending_reward_nwei,
            5_000
        );
        assert_eq!(
            allocation.cluster_allocations[1].cluster_reward_nwei,
            10_000
        );
    }

    #[test]
    fn ledger_sends_unreleased_rewards_to_treasury_recovery() {
        let mut ledger = RewardLedger::default();
        let pending = calculate_pending_reward(
            1,
            "syngrp1cluster",
            "validator",
            "synw1payout",
            1_000,
            0,
            0,
            &perfect_phase1(),
            &RewardConfig::default(),
        )
        .unwrap();
        ledger.add_pending_reward(pending).unwrap();

        let settlements = ledger
            .settle_pending_rewards(2, &HashMap::from([("validator".to_string(), 8_500)]), 77)
            .unwrap();

        assert_eq!(settlements.len(), 1);
        assert_eq!(settlements[0].final_reward_nwei, 850);
        assert_eq!(settlements[0].unreleased_reward_nwei, 150);
        assert_eq!(
            settlements[0].unreleased_destination,
            UnreleasedDestination::TreasuryRecovery
        );
        let recovery = ledger.treasury_recovery_ledger.get(&2).unwrap();
        assert_eq!(recovery.total_recovered_nwei, 150);
        assert_eq!(
            recovery.entries[0].treasury_recovery_wallet_address,
            crate::token::TREASURY_RECOVERY_WALLET_ADDRESS
        );
        assert!(ledger.audit_events.iter().any(|event| matches!(
            event,
            RewardAuditEvent::TreasuryRecoveryCredited {
                amount_nwei: 150,
                ..
            }
        )));
    }

    #[test]
    fn network_owned_validator_rewards_route_70_30() {
        let validator = ValidatorMetadata {
            validator_id: "genesis-1".to_string(),
            reward_payout_address: "synw1payout".to_string(),
            is_network_owned_validator: true,
        };
        let routing =
            route_network_owned_validator_reward(1, &validator, 101, 77, &RewardConfig::default())
                .unwrap();
        assert_eq!(routing.treasury_share_nwei, 71);
        assert_eq!(routing.bonus_pool_share_nwei, 30);
        assert_eq!(routing.rounding_dust_nwei, 1);
    }

    #[test]
    fn normal_validator_cannot_use_network_owned_routing() {
        let validator = ValidatorMetadata {
            validator_id: "normal".to_string(),
            reward_payout_address: "synw1payout".to_string(),
            is_network_owned_validator: false,
        };
        assert!(route_network_owned_validator_reward(
            1,
            &validator,
            100,
            77,
            &RewardConfig::default(),
        )
        .is_err());
    }

    #[test]
    fn bonus_pool_accounting_cannot_overpay() {
        let mut pool = ReliabilityBonusPool::default();
        pool.fund(100).unwrap();
        assert!(pool.distribute(101).is_err());
        pool.distribute(40).unwrap();
        assert_eq!(pool.balance_nwei, 60);
        assert_eq!(pool.total_funded_nwei, 100);
        assert_eq!(pool.total_distributed_nwei, 40);
    }

    #[test]
    fn progressive_bonus_tiers_are_calculated() {
        let config = RewardConfig::default();
        assert_eq!(bonus_tier_bps(10, &config), 200);
        assert_eq!(bonus_tier_bps(50, &config), 500);
        assert_eq!(bonus_tier_bps(100, &config), 1_000);
        assert_eq!(bonus_tier_bps(250, &config), 1_500);
        assert_eq!(bonus_tier_bps(500, &config), 2_000);
    }

    #[test]
    fn reliability_streak_increment_decay_and_reset() {
        let config = RewardConfig::default();
        let mut state = ValidatorReliabilityState::new("validator");
        let eligible = ReliabilityEligibility {
            uptime_bps: 9_900,
            consensus_participation_bps: 9_600,
            cluster_cooperation_bps: 9_700,
            governance_participation_bps: 8_500,
            penalty_reason: ValidatorPenaltyReason::None,
            active: true,
        };
        update_reliability_streak(&mut state, 1, &eligible, &config);
        assert_eq!(state.current_streak_epochs, 1);

        state.current_streak_epochs = 100;
        let minor = ReliabilityEligibility {
            penalty_reason: ValidatorPenaltyReason::MinorDowntime,
            ..eligible.clone()
        };
        update_reliability_streak(&mut state, 2, &minor, &config);
        assert_eq!(state.current_streak_epochs, 90);

        let slashed = ReliabilityEligibility {
            penalty_reason: ValidatorPenaltyReason::Slashed,
            ..eligible
        };
        update_reliability_streak(&mut state, 3, &slashed, &config);
        assert_eq!(state.current_streak_epochs, 0);
    }

    #[test]
    fn ledger_rejects_duplicate_settlements_and_queries_pending_rewards() {
        let mut ledger = RewardLedger::default();
        ledger.distribute_epoch_fees(1, 1_000, 10).unwrap();
        let duplicate = ledger.distribute_epoch_fees(1, 1_000, 11).unwrap();
        assert_eq!(duplicate.distribution_block_height, 10);

        let pending = calculate_pending_reward(
            1,
            "cluster-a",
            "validator-1",
            "payout",
            100,
            0,
            0,
            &perfect_phase1(),
            &RewardConfig::default(),
        )
        .unwrap();
        ledger.add_pending_reward(pending).unwrap();
        assert_eq!(ledger.get_validator_pending_rewards("validator-1").len(), 1);
    }

    #[test]
    fn fee_accumulator_closes_once_and_matches_distribution_total() {
        let mut ledger = RewardLedger::default();
        ledger
            .record_fee_charged(7, "tx-a", "native_snrg_send", 40, 70)
            .unwrap();
        ledger
            .record_fee_charged(7, "tx-b", "native_snrg_send", 60, 71)
            .unwrap();

        let distribution = ledger.distribute_epoch_fees(7, 100, 99).unwrap().clone();
        assert_eq!(distribution.validator_share_nwei, 70);
        let accumulator = ledger.fee_accumulators.get(&7).unwrap();
        assert_eq!(accumulator.total_collected_nwei, 100);
        assert_eq!(accumulator.status, EpochFeeAccumulatorStatus::Closed);
        assert_eq!(
            accumulator.by_tx_type.get("native_snrg_send").copied(),
            Some(100)
        );

        let event_count = ledger.audit_events.len();
        let duplicate = ledger.distribute_epoch_fees(7, 100, 100).unwrap();
        assert_eq!(duplicate.distribution_block_height, 99);
        assert_eq!(ledger.audit_events.len(), event_count);
    }

    #[test]
    fn reward_invariant_report_passes_for_reconciled_epoch_lifecycle() {
        let ledger = closed_reward_ledger_fixture();

        let report = ledger.check_invariants(None);

        assert!(
            report.passed,
            "expected reconciled ledger to pass invariants, got {:?}",
            report.violations
        );
    }

    #[test]
    fn reward_invariant_report_flags_fee_accumulator_mismatch() {
        let mut ledger = closed_reward_ledger_fixture();
        ledger
            .fee_accumulators
            .get_mut(&7)
            .expect("fixture should have epoch accumulator")
            .total_collected_nwei = 99;

        let report = ledger.check_invariants(Some(7));

        assert!(!report.passed);
        assert!(report
            .violations
            .iter()
            .any(|violation| violation.code == "fee_event_total_mismatch"));
    }

    #[test]
    fn epoch_audit_events_are_filtered_by_related_epoch() {
        let mut ledger = RewardLedger::default();
        ledger
            .record_fee_charged(787, "tx-audit-787", "native_snrg_send", 42, 787_001)
            .expect("fee audit event should record");
        ledger
            .record_fee_charged(788, "tx-audit-788", "native_snrg_send", 7, 788_001)
            .expect("other epoch fee audit event should record");

        let audit = ledger.get_epoch_audit_events(Some(787));
        assert_eq!(audit.len(), 1);
        assert!(matches!(
            audit.first(),
            Some(RewardAuditEvent::GasFeeCollected {
                epoch_id: 787,
                fee_nwei: 42,
                ..
            })
        ));

        let all_audit = ledger.get_epoch_audit_events(None);
        assert_eq!(all_audit.len(), 2);
    }

    #[test]
    fn burn_address_cannot_be_validator_payout() {
        let err = calculate_pending_reward(
            1,
            "syngrp1cluster",
            "validator",
            crate::address::NETWORK_BURN_ADDRESS,
            1_000,
            0,
            0,
            &perfect_phase1(),
            &RewardConfig::default(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            "network burn address cannot be a validator reward payout"
        );
    }

    #[test]
    fn bonus_claims_are_prorated_when_pool_is_insufficient() {
        let paid =
            prorate_bonus_claims(&[("a".to_string(), 100), ("b".to_string(), 300)], 200).unwrap();
        assert_eq!(paid, vec![("a".to_string(), 50), ("b".to_string(), 150)]);
    }
}
