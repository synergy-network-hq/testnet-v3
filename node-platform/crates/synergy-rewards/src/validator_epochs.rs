//! NORS-03 validator-pool accounting. Only canonical execution may supply the
//! complete contribution, stake, funding and accountability facts. This module
//! does not verify those facts or set policy. It prepares atomic state diffs;
//! only the finalized execution owner may apply them.
//! Do not route these allocations through the immediate-credit reward ledger.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use synergy_address::{address_kind, is_spendable_user_address, is_valid_address, AddressKind};
use synergy_protocol_types::{Epoch, Height, NodeAddress, NodeClass, ProtocolHash};

mod world;
pub use world::{
    prepare_world_epoch_close, WorldEpochCloseInputs, VALIDATOR_REWARD_EPOCH_STATE_KEY,
};

const BPS: u64 = 10_000;
pub const TESTNET_VALIDATOR_MINIMUM_STAKE_NWEI: u128 = 50_000_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorRewardError {
    InvalidPolicy,
    InvalidEarningEvidence,
    InvalidAccountabilityEvidence,
    UnexpectedEpochOrHeight,
    InvalidLedger,
    InvalidFundingDebits,
    Arithmetic,
}

impl fmt::Display for ValidatorRewardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPolicy => "invalid validator reward policy",
            Self::InvalidEarningEvidence => "invalid validator earning inputs",
            Self::InvalidAccountabilityEvidence => "invalid or incomplete accountability inputs",
            Self::UnexpectedEpochOrHeight => "validator rewards must close once in epoch order",
            Self::InvalidLedger => "invalid validator epoch reward ledger",
            Self::InvalidFundingDebits => "funding debits must match newly locked rewards",
            Self::Arithmetic => "validator reward arithmetic out of range",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ValidatorRewardError {}

type Result<T> = std::result::Result<T, ValidatorRewardError>;

/// Parameters must come from the active authenticated policy. There are no
/// defaults for the pool share, cap, or handling of an unassigned duty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorRewardPolicy {
    pub policy_commitment: ProtocolHash,
    pub treasury_recovery_address: String,
    pub validator_pool_bps: u16,
    #[serde(with = "amount")]
    pub validator_pool_cap_nwei: u128,
    #[serde(with = "amount")]
    pub minimum_stake_nwei: u128,
    pub unassigned_proposal_bps: u16,
}

impl ValidatorRewardPolicy {
    fn validate(&self) -> Result<()> {
        if self.policy_commitment.is_zero()
            || !is_valid_address(&self.treasury_recovery_address)
            || address_kind(&self.treasury_recovery_address) == AddressKind::BurnAddress
            || !valid_bps(self.validator_pool_bps)
            || !valid_bps(self.unassigned_proposal_bps)
            || self.minimum_stake_nwei < TESTNET_VALIDATOR_MINIMUM_STAKE_NWEI
        {
            return Err(ValidatorRewardError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Actual funded amounts for the earning epoch. The executor must debit the
/// approved sources, deduplicate finalized fees, and reserve the locked funds
/// atomically with the ledger update; these fields do not confer mint authority.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochRewardFunding {
    #[serde(with = "amount")]
    pub emissions_nwei: u128,
    #[serde(with = "amount")]
    pub treasury_allocation_nwei: u128,
    #[serde(with = "amount")]
    pub finalized_fee_share_nwei: u128,
    #[serde(with = "amount")]
    pub approved_revenue_share_nwei: u128,
}

impl EpochRewardFunding {
    fn total(self) -> Result<u128> {
        self.emissions_nwei
            .checked_add(self.treasury_allocation_nwei)
            .and_then(|amount| amount.checked_add(self.finalized_fee_share_nwei))
            .and_then(|amount| amount.checked_add(self.approved_revenue_share_nwei))
            .ok_or(ValidatorRewardError::Arithmetic)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalContribution {
    Unassigned,
    Assigned(u16),
}

/// Normalized earning metrics for one registered, authorized validator. The
/// executor must derive these from finalized evidence, including assigned
/// duties, valid cooperation and any disqualification during this epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorEpochContribution {
    pub payout_address: String,
    pub bonded_stake_nwei: u128,
    pub consensus_bps: u16,
    pub proposal: ProposalContribution,
    pub accuracy_bps: u16,
    pub cluster_bps: u16,
    pub synergy_score_bps: u16,
}

impl ValidatorEpochContribution {
    fn score(&self, node: &NodeAddress, policy: &ValidatorRewardPolicy) -> Result<u16> {
        let proposal = match self.proposal {
            ProposalContribution::Unassigned => policy.unassigned_proposal_bps,
            ProposalContribution::Assigned(score) => score,
        };
        let components = [
            (self.consensus_bps, 3_500),
            (proposal, 2_000),
            (self.accuracy_bps, 2_000),
            (self.cluster_bps, 1_500),
            (self.synergy_score_bps, 1_000),
        ];
        if node.class() != NodeClass::ConsensusAndChainIntegrity
            || self.bonded_stake_nwei < policy.minimum_stake_nwei
            || address_kind(&self.payout_address) != AddressKind::Wallet
            || !is_spendable_user_address(&self.payout_address)
            || components.iter().any(|(value, _)| !valid_bps(*value))
        {
            return Err(ValidatorRewardError::InvalidEarningEvidence);
        }
        Ok((components
            .iter()
            .map(|(value, weight)| u64::from(*value) * weight)
            .sum::<u64>()
            / BPS) as u16)
    }
}

/// Caps for non-uptime faults must come from the authorized fault policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountabilityFault {
    None,
    AuthorizedCapBps(u16),
    ValidatorJailedCapBps(u16),
    CategoryA,
}

/// Full-window facts for the *accountability* epoch only. An executor must
/// derive expected units from the entire window, never node-local telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorAccountability {
    pub available_units: u64,
    pub expected_units: u64,
    pub fault: AccountabilityFault,
    #[serde(with = "amount")]
    pub compensation_penalty_nwei: u128,
}

impl ValidatorAccountability {
    fn coefficient(self) -> Result<u16> {
        if self.expected_units == 0 || self.available_units > self.expected_units {
            return Err(ValidatorRewardError::InvalidAccountabilityEvidence);
        }
        let uptime = u128::from(self.available_units) * 100_000 / u128::from(self.expected_units);
        let uptime_bps = match uptime {
            99_950.. => 10_000,
            99_500.. => 9_500,
            99_000.. => 8_500,
            98_000.. => 6_000,
            97_000.. => 2_500,
            _ => 0,
        };
        let cap = match self.fault {
            AccountabilityFault::None => 10_000,
            AccountabilityFault::CategoryA => 0,
            AccountabilityFault::AuthorizedCapBps(cap) if valid_bps(cap) => cap,
            AccountabilityFault::ValidatorJailedCapBps(cap) if cap <= 5_000 => cap,
            _ => return Err(ValidatorRewardError::InvalidAccountabilityEvidence),
        };
        Ok(uptime_bps.min(cap))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingValidatorReward {
    pub payout_address: String,
    pub allocation_score_bps: u16,
    #[serde(with = "amount")]
    pub locked_nwei: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorEpochAllocation {
    pub earning_epoch: Epoch,
    pub accountability_epoch: Epoch,
    pub funding: EpochRewardFunding,
    #[serde(with = "amount")]
    pub validator_pool_nwei: u128,
    #[serde(with = "amount")]
    pub unallocated_pool_nwei: u128,
    pub validators: BTreeMap<NodeAddress, PendingValidatorReward>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorRewardDisposition {
    pub payout_address: String,
    pub accountability: ValidatorAccountability,
    pub release_coefficient_bps: u16,
    #[serde(with = "amount")]
    pub locked_nwei: u128,
    #[serde(with = "amount")]
    pub applied_penalty_nwei: u128,
    #[serde(with = "amount")]
    pub released_nwei: u128,
    #[serde(with = "amount")]
    pub treasury_recovery_nwei: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorEpochSettlement {
    pub earning_epoch: Epoch,
    pub accountability_epoch: Epoch,
    pub treasury_recovery_address: String,
    pub validators: BTreeMap<NodeAddress, ValidatorRewardDisposition>,
}

/// Receipt to commit alongside the updated ledger and its monetary transfers.
/// Keep historical receipts in finalized history; the active ledger retains one
/// earning epoch and the latest receipt, without per-message evidence files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorRewardEpochClose {
    pub policy_commitment: ProtocolHash,
    pub boundary_height: Height,
    pub pending: ValidatorEpochAllocation,
    pub settlement: Option<ValidatorEpochSettlement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorRewardEpochLedger {
    policy: ValidatorRewardPolicy,
    next_epoch: Epoch,
    latest: Option<ValidatorRewardEpochClose>,
}

impl ValidatorRewardEpochLedger {
    /// Initialize only for an explicitly enabled policy in authenticated state.
    pub fn new(policy: ValidatorRewardPolicy, first_epoch: Epoch) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            policy,
            next_epoch: first_epoch,
            latest: None,
        })
    }

    pub fn latest_close(&self) -> Option<&ValidatorRewardEpochClose> {
        self.latest.as_ref()
    }

    /// Compute the candidate ledger for a canonical epoch-close transition.
    /// Does not mutate the old state: publish this candidate only in the same
    /// atomic finalized commit as the escrow movements and settlement receipt.
    pub fn prepare_epoch_close(
        &self,
        closing_epoch: Epoch,
        boundary_height: Height,
        funding: EpochRewardFunding,
        earnings: &BTreeMap<NodeAddress, ValidatorEpochContribution>,
        accountability: &BTreeMap<NodeAddress, ValidatorAccountability>,
    ) -> Result<Self> {
        self.policy.validate()?;
        if closing_epoch != self.next_epoch
            || boundary_height.get() == 0
            || self
                .latest
                .as_ref()
                .is_some_and(|last| boundary_height <= last.boundary_height)
        {
            return Err(ValidatorRewardError::UnexpectedEpochOrHeight);
        }
        let next_epoch = closing_epoch
            .checked_next()
            .map_err(|_| ValidatorRewardError::Arithmetic)?;
        let settlement = match &self.latest {
            Some(last)
                if last.policy_commitment == self.policy.policy_commitment
                    && last.pending.accountability_epoch == closing_epoch
                    && last.pending.earning_epoch.checked_next() == Ok(closing_epoch) =>
            {
                Some(self.settle(&last.pending, accountability)?)
            }
            Some(_) => return Err(ValidatorRewardError::InvalidLedger),
            None if accountability.is_empty() => None,
            None => return Err(ValidatorRewardError::InvalidAccountabilityEvidence),
        };

        let pool = fraction(
            funding.total()?,
            u64::from(self.policy.validator_pool_bps),
            BPS,
        )?
        .min(self.policy.validator_pool_cap_nwei);
        let mut total_score = 0_u64;
        let mut validators = BTreeMap::new();
        for (node, contribution) in earnings {
            let score = contribution.score(node, &self.policy)?;
            total_score = total_score
                .checked_add(u64::from(score))
                .ok_or(ValidatorRewardError::Arithmetic)?;
            validators.insert(
                node.clone(),
                PendingValidatorReward {
                    payout_address: contribution.payout_address.clone(),
                    allocation_score_bps: score,
                    locked_nwei: 0,
                },
            );
        }
        let mut unallocated = pool;
        if total_score != 0 {
            for reward in validators.values_mut() {
                reward.locked_nwei =
                    fraction(pool, u64::from(reward.allocation_score_bps), total_score)?;
                unallocated = unallocated
                    .checked_sub(reward.locked_nwei)
                    .ok_or(ValidatorRewardError::Arithmetic)?;
            }
        }
        // There is no accountability obligation for an allocation of zero.
        validators.retain(|_, reward| reward.locked_nwei != 0);

        Ok(Self {
            policy: self.policy.clone(),
            next_epoch,
            latest: Some(ValidatorRewardEpochClose {
                policy_commitment: self.policy.policy_commitment,
                boundary_height,
                pending: ValidatorEpochAllocation {
                    earning_epoch: closing_epoch,
                    accountability_epoch: next_epoch,
                    funding,
                    validator_pool_nwei: pool,
                    unallocated_pool_nwei: unallocated,
                    validators,
                },
                settlement,
            }),
        })
    }

    fn settle(
        &self,
        pending: &ValidatorEpochAllocation,
        accountability: &BTreeMap<NodeAddress, ValidatorAccountability>,
    ) -> Result<ValidatorEpochSettlement> {
        if !pending.validators.keys().eq(accountability.keys()) {
            return Err(ValidatorRewardError::InvalidAccountabilityEvidence);
        }
        let mut validators = BTreeMap::new();
        let mut remaining = pending
            .validator_pool_nwei
            .checked_sub(pending.unallocated_pool_nwei)
            .ok_or(ValidatorRewardError::InvalidLedger)?;
        for ((node, reward), evidence) in pending.validators.iter().zip(accountability.values()) {
            remaining = remaining
                .checked_sub(reward.locked_nwei)
                .ok_or(ValidatorRewardError::InvalidLedger)?;
            let coefficient = evidence.coefficient()?;
            let gross = fraction(reward.locked_nwei, u64::from(coefficient), BPS)?;
            let applied_penalty = gross.min(evidence.compensation_penalty_nwei);
            let released = gross - applied_penalty;
            validators.insert(
                node.clone(),
                ValidatorRewardDisposition {
                    payout_address: reward.payout_address.clone(),
                    accountability: *evidence,
                    release_coefficient_bps: coefficient,
                    locked_nwei: reward.locked_nwei,
                    applied_penalty_nwei: applied_penalty,
                    released_nwei: released,
                    // Bond slashes are an independent balance transition. Never
                    // debit them again from the pending reward escrow.
                    treasury_recovery_nwei: reward.locked_nwei - released,
                },
            );
        }
        if remaining != 0 {
            return Err(ValidatorRewardError::InvalidLedger);
        }
        Ok(ValidatorEpochSettlement {
            earning_epoch: pending.earning_epoch,
            accountability_epoch: pending.accountability_epoch,
            treasury_recovery_address: self.policy.treasury_recovery_address.clone(),
            validators,
        })
    }
}

fn valid_bps(value: u16) -> bool {
    u64::from(value) <= BPS
}

/// floor(value * factor / denominator) without a potentially overflowing
/// 192-bit intermediate. Both products fit because factor <= denominator
/// and the remainder and factor are at most u64.
fn fraction(value: u128, factor: u64, denominator: u64) -> Result<u128> {
    if denominator == 0 || factor > denominator {
        return Err(ValidatorRewardError::Arithmetic);
    }
    let (factor, denominator) = (u128::from(factor), u128::from(denominator));
    Ok((value / denominator) * factor + (value % denominator) * factor / denominator)
}

/// Canonical decimal strings preserve the full integer in JSON, including
/// when a receipt passes through browser and mobile serializers.
mod amount {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty()
            || text.len() > 39
            || (text.starts_with('0') && text.len() != 1)
            || !text.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(serde::de::Error::custom("invalid nWei decimal string"));
        }
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(seed: u8) -> String {
        if seed == 2 {
            "synw7E5F4552091A69125d5DfCb7b8C2659029395Bdf".to_owned()
        } else {
            synergy_address::derive_standard_account_address(&[seed; 1_793]).unwrap()
        }
    }

    fn node(seed: u8) -> NodeAddress {
        NodeAddress::parse(
            synergy_address::generate_validator_address(&format!("{seed:02x}").repeat(1_793), 1)
                .unwrap(),
        )
        .unwrap()
    }

    fn ledger(cap: u128) -> ValidatorRewardEpochLedger {
        ValidatorRewardEpochLedger::new(
            ValidatorRewardPolicy {
                policy_commitment: ProtocolHash::new([1; 32]),
                treasury_recovery_address: wallet(9),
                validator_pool_bps: 10_000,
                validator_pool_cap_nwei: cap,
                minimum_stake_nwei: TESTNET_VALIDATOR_MINIMUM_STAKE_NWEI,
                unassigned_proposal_bps: 10_000,
            },
            Epoch::new(5),
        )
        .unwrap()
    }

    fn earning(seed: u8, proposal: ProposalContribution) -> ValidatorEpochContribution {
        ValidatorEpochContribution {
            payout_address: wallet(seed),
            bonded_stake_nwei: TESTNET_VALIDATOR_MINIMUM_STAKE_NWEI,
            consensus_bps: 10_000,
            proposal,
            accuracy_bps: 10_000,
            cluster_bps: 10_000,
            synergy_score_bps: 10_000,
        }
    }

    fn funding(nwei: u128) -> EpochRewardFunding {
        EpochRewardFunding {
            treasury_allocation_nwei: nwei,
            ..Default::default()
        }
    }

    fn accountability(available_units: u64) -> ValidatorAccountability {
        ValidatorAccountability {
            available_units,
            expected_units: 100_000,
            fault: AccountabilityFault::None,
            compensation_penalty_nwei: 0,
        }
    }

    #[test]
    fn overlapping_epochs_survive_restart_and_release_only_preceding_earnings() {
        let validator = node(1);
        let first_earnings = BTreeMap::from([(
            validator.clone(),
            earning(2, ProposalContribution::Unassigned),
        )]);
        let second_earnings = BTreeMap::from([(
            validator.clone(),
            earning(3, ProposalContribution::Assigned(10_000)),
        )]);
        let first = ledger(10_000)
            .prepare_epoch_close(
                Epoch::new(5),
                Height::new(50),
                funding(1_000),
                &first_earnings,
                &BTreeMap::new(),
            )
            .unwrap();
        let close = first.latest_close().unwrap();
        assert_eq!(close.pending.earning_epoch, Epoch::new(5));
        assert_eq!(close.pending.accountability_epoch, Epoch::new(6));
        assert_eq!(close.pending.validators[&validator].locked_nwei, 1_000);
        assert!(close.settlement.is_none());
        let restored: ValidatorRewardEpochLedger =
            serde_json::from_slice(&serde_json::to_vec(&first).unwrap()).unwrap();
        let assessment = BTreeMap::from([(validator.clone(), accountability(99_000))]);
        assert_eq!(
            restored.prepare_epoch_close(
                Epoch::new(6),
                Height::new(60),
                funding(2_000),
                &second_earnings,
                &BTreeMap::new()
            ),
            Err(ValidatorRewardError::InvalidAccountabilityEvidence)
        );
        let second = restored
            .prepare_epoch_close(
                Epoch::new(6),
                Height::new(60),
                funding(2_000),
                &second_earnings,
                &assessment,
            )
            .unwrap();
        let close = second.latest_close().unwrap();
        assert_eq!(close.pending.earning_epoch, Epoch::new(6));
        assert_eq!(close.pending.accountability_epoch, Epoch::new(7));
        assert_eq!(close.pending.validators[&validator].locked_nwei, 2_000);
        let settled = close.settlement.as_ref().unwrap();
        assert_eq!(settled.earning_epoch, Epoch::new(5));
        assert_eq!(settled.accountability_epoch, Epoch::new(6));
        let receipt = &settled.validators[&validator];
        assert_eq!(receipt.payout_address, wallet(2));
        assert_eq!(receipt.release_coefficient_bps, 8_500);
        assert_eq!(
            (receipt.released_nwei, receipt.treasury_recovery_nwei),
            (850, 150)
        );
        assert_eq!(
            second.prepare_epoch_close(
                Epoch::new(6),
                Height::new(61),
                funding(2_000),
                &second_earnings,
                &assessment
            ),
            Err(ValidatorRewardError::UnexpectedEpochOrHeight)
        );
        assert_eq!(
            second.prepare_epoch_close(
                Epoch::new(8),
                Height::new(80),
                funding(2_000),
                &second_earnings,
                &assessment
            ),
            Err(ValidatorRewardError::UnexpectedEpochOrHeight)
        );
        let third = second
            .prepare_epoch_close(
                Epoch::new(7),
                Height::new(70),
                funding(0),
                &BTreeMap::new(),
                &BTreeMap::from([(validator.clone(), accountability(100_000))]),
            )
            .unwrap();
        let receipt = &third
            .latest_close()
            .unwrap()
            .settlement
            .as_ref()
            .unwrap()
            .validators[&validator];
        assert_eq!(
            (receipt.payout_address.as_str(), receipt.released_nwei),
            (wallet(3).as_str(), 2_000)
        );
    }

    #[test]
    fn funded_caps_rounding_and_unassigned_duties_preserve_conservation() {
        let (unassigned, missed) = (node(1), node(2));
        let earnings = BTreeMap::from([
            (
                unassigned.clone(),
                earning(2, ProposalContribution::Unassigned),
            ),
            (
                missed.clone(),
                earning(3, ProposalContribution::Assigned(0)),
            ),
        ]);
        let closed = ledger(100)
            .prepare_epoch_close(
                Epoch::new(5),
                Height::new(50),
                funding(1_000),
                &earnings,
                &BTreeMap::new(),
            )
            .unwrap();
        let pending = &closed.latest_close().unwrap().pending;
        assert_eq!(pending.validators[&unassigned].allocation_score_bps, 10_000);
        assert_eq!(pending.validators[&missed].allocation_score_bps, 8_000);
        assert_eq!(pending.validators[&unassigned].locked_nwei, 55);
        assert_eq!(pending.validators[&missed].locked_nwei, 44);
        assert_eq!(pending.unallocated_pool_nwei, 1);
        let empty = ledger(100)
            .prepare_epoch_close(
                Epoch::new(5),
                Height::new(50),
                funding(0),
                &earnings,
                &BTreeMap::new(),
            )
            .unwrap();
        assert!(empty.latest_close().unwrap().pending.validators.is_empty());
        let mut unqualified = earnings;
        unqualified.get_mut(&unassigned).unwrap().bonded_stake_nwei -= 1;
        assert_eq!(
            ledger(100).prepare_epoch_close(
                Epoch::new(5),
                Height::new(50),
                funding(1_000),
                &unqualified,
                &BTreeMap::new()
            ),
            Err(ValidatorRewardError::InvalidEarningEvidence)
        );
    }

    #[test]
    fn finalized_world_commit_keeps_wallets_unchanged_until_next_close() {
        use std::time::{SystemTime, UNIX_EPOCH};
        use synergy_state::{
            state_root, AccountState, FinalizedState, FinalizedStateStore, WorldState,
        };

        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let scratch = Scratch(
            std::env::temp_dir().join(format!("reward-world-{}-{timestamp}", std::process::id())),
        );
        std::fs::create_dir(&scratch.0).unwrap();

        let validator = node(1);
        let payout = wallet(2);
        let treasury = wallet(9);
        let source = wallet(8);
        let earning = BTreeMap::from([(
            validator.clone(),
            earning(2, ProposalContribution::Unassigned),
        )]);
        let previous = BTreeMap::from([(validator, accountability(99_000))]);
        let no_accountability = BTreeMap::new();
        let no_debits = BTreeMap::new();
        let debits = BTreeMap::from([(source.clone(), 1_000)]);
        let policy = ProtocolHash::new([1; 32]);
        let mut world = WorldState::default();
        let first = || WorldEpochCloseInputs {
            active_policy_commitment: policy,
            closing_epoch: Epoch::new(5),
            boundary_height: Height::new(50),
            funding: funding(1_000),
            funding_debits: &debits,
            earnings: &earning,
            accountability: &no_accountability,
        };
        assert_eq!(
            prepare_world_epoch_close(&world, first()),
            Err(ValidatorRewardError::InvalidPolicy)
        );
        world.protocol.insert(
            VALIDATOR_REWARD_EPOCH_STATE_KEY.to_owned(),
            serde_json::to_vec(&ledger(10_000)).unwrap(),
        );
        let first_diff = prepare_world_epoch_close(&world, first()).unwrap();
        let empty_source = world.clone();
        assert_eq!(
            first_diff.apply(&mut world),
            Err(synergy_state::StateError::InsufficientBalance)
        );
        assert_eq!(world, empty_source);
        world.accounts.insert(
            source.clone(),
            AccountState {
                balance_nwei: 1_000,
                ..Default::default()
            },
        );
        let base = world.clone();
        first_diff.apply(&mut world).unwrap();
        assert_eq!(world.accounts[&source].balance_nwei, 0);
        assert!(!world.accounts.contains_key(&payout));
        let pending = world.clone();
        assert!(first_diff.apply(&mut world).is_err());
        assert_eq!(world, pending);

        let finalized = |height, world: &WorldState| FinalizedState {
            finalized_height: height,
            finalized_block_id: format!("test-block-{height}"),
            state_root: state_root(world).unwrap(),
        };
        {
            let mut store = FinalizedStateStore::load(&scratch.0).unwrap();
            store
                .commit_verified_world_state(finalized(49, &base), &base)
                .unwrap();
            store
                .commit_verified_world_transition(finalized(50, &pending), &base, &pending)
                .unwrap();
        }
        let store = FinalizedStateStore::load(&scratch.0).unwrap();
        let mut resumed = store.current_world_state().unwrap().unwrap();
        assert_eq!(resumed, pending);
        let settlement = prepare_world_epoch_close(
            &resumed,
            WorldEpochCloseInputs {
                active_policy_commitment: policy,
                closing_epoch: Epoch::new(6),
                boundary_height: Height::new(60),
                funding: funding(0),
                funding_debits: &no_debits,
                earnings: &BTreeMap::new(),
                accountability: &previous,
            },
        )
        .unwrap();
        settlement.apply(&mut resumed).unwrap();
        assert_eq!(resumed.accounts[&payout].balance_nwei, 850);
        assert_eq!(resumed.accounts[&treasury].balance_nwei, 150);
        let paid = resumed.clone();
        assert!(settlement.apply(&mut resumed).is_err());
        assert_eq!(resumed, paid);
    }

    #[test]
    fn exact_uptime_thresholds_and_fault_caps() {
        for (available, coefficient) in [
            (100_000, 10_000),
            (99_950, 10_000),
            (99_949, 9_500),
            (99_500, 9_500),
            (99_499, 8_500),
            (99_000, 8_500),
            (98_999, 6_000),
            (98_000, 6_000),
            (97_999, 2_500),
            (97_000, 2_500),
            (96_999, 0),
        ] {
            assert_eq!(
                accountability(available).coefficient().unwrap(),
                coefficient
            );
        }
        let mut input = accountability(100_000);
        input.fault = AccountabilityFault::ValidatorJailedCapBps(5_000);
        assert_eq!(input.coefficient().unwrap(), 5_000);
        input.fault = AccountabilityFault::ValidatorJailedCapBps(5_001);
        assert_eq!(
            input.coefficient(),
            Err(ValidatorRewardError::InvalidAccountabilityEvidence)
        );
        input.fault = AccountabilityFault::CategoryA;
        assert_eq!(input.coefficient().unwrap(), 0);
        input.expected_units = 0;
        assert_eq!(
            input.coefficient(),
            Err(ValidatorRewardError::InvalidAccountabilityEvidence)
        );
    }

    #[test]
    fn amount_limits_and_penalty_settlement_do_not_overflow_or_lose_funds() {
        let validator = node(1);
        let earnings = BTreeMap::from([(
            validator.clone(),
            earning(2, ProposalContribution::Unassigned),
        )]);
        let first = ledger(u128::MAX)
            .prepare_epoch_close(
                Epoch::new(5),
                Height::new(50),
                funding(u128::MAX),
                &earnings,
                &BTreeMap::new(),
            )
            .unwrap();
        let restored: ValidatorRewardEpochLedger =
            serde_json::from_value(serde_json::to_value(&first).unwrap()).unwrap();
        let assessment = ValidatorAccountability {
            compensation_penalty_nwei: 77,
            ..accountability(99_000)
        };
        let second = restored
            .prepare_epoch_close(
                Epoch::new(6),
                Height::new(60),
                funding(0),
                &BTreeMap::new(),
                &BTreeMap::from([(validator.clone(), assessment)]),
            )
            .unwrap();
        let receipt = &second
            .latest_close()
            .unwrap()
            .settlement
            .as_ref()
            .unwrap()
            .validators[&validator];
        assert_eq!(receipt.locked_nwei, u128::MAX);
        assert_eq!(receipt.applied_penalty_nwei, 77);
        assert_eq!(
            receipt
                .released_nwei
                .checked_add(receipt.treasury_recovery_nwei),
            Some(u128::MAX)
        );
        assert_eq!(
            EpochRewardFunding {
                finalized_fee_share_nwei: 1,
                ..funding(u128::MAX)
            }
            .total(),
            Err(ValidatorRewardError::Arithmetic)
        );
    }
}
