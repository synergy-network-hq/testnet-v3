use std::collections::BTreeMap;

use synergy_address::{is_network_burn_address, is_valid_address};
use synergy_protocol_types::{Epoch, Height, NodeAddress, ProtocolHash};
use synergy_state::{AccountChange, ProtocolChange, StateDiff, WorldState};

use super::{
    EpochRewardFunding, Result, ValidatorAccountability, ValidatorEpochContribution,
    ValidatorRewardEpochLedger, ValidatorRewardError,
};

/// Governed Genesis must initialize this key before validator rewards are
/// enabled. No public transaction can initialize it or invoke epoch settlement.
pub const VALIDATOR_REWARD_EPOCH_STATE_KEY: &str = "synergy/rewards/validator-epochs/v1";

pub struct WorldEpochCloseInputs<'a> {
    pub active_policy_commitment: ProtocolHash,
    pub closing_epoch: Epoch,
    pub boundary_height: Height,
    pub funding: EpochRewardFunding,
    /// Exact amounts to lock from authorized, already funded accounts. This
    /// module checks conservation and the state diff checks available balances;
    /// the executor must authenticate source eligibility and fee attribution.
    pub funding_debits: &'a BTreeMap<String, u128>,
    pub earnings: &'a BTreeMap<NodeAddress, ValidatorEpochContribution>,
    pub accountability: &'a BTreeMap<NodeAddress, ValidatorAccountability>,
}

/// Build one compare-and-swap state diff for the ledger, payout and recovery.
/// The old locked allocation is protocol escrow, outside all wallet balances.
/// New allocations debit only actual funded accounts. There is no mint path.
///
/// The caller must verify this is the real epoch boundary, establish all input
/// facts against authorized finalized evidence, and commit the resulting world
/// state under PoSy finality. Do not call from user transactions or telemetry.
pub fn prepare_world_epoch_close(
    world: &WorldState,
    inputs: WorldEpochCloseInputs<'_>,
) -> Result<StateDiff> {
    let old = world
        .protocol
        .get(VALIDATOR_REWARD_EPOCH_STATE_KEY)
        .ok_or(ValidatorRewardError::InvalidPolicy)?;
    let ledger: ValidatorRewardEpochLedger =
        serde_json::from_slice(old).map_err(|_| ValidatorRewardError::InvalidLedger)?;
    if inputs.active_policy_commitment != ledger.policy.policy_commitment {
        return Err(ValidatorRewardError::InvalidPolicy);
    }
    let candidate = ledger.prepare_epoch_close(
        inputs.closing_epoch,
        inputs.boundary_height,
        inputs.funding,
        inputs.earnings,
        inputs.accountability,
    )?;
    let close = candidate
        .latest_close()
        .ok_or(ValidatorRewardError::InvalidLedger)?;
    let locked = close.pending.validator_pool_nwei - close.pending.unallocated_pool_nwei;
    let mut debited = 0_u128;
    let mut changes = BTreeMap::new();
    for (source, amount) in inputs.funding_debits {
        if !is_valid_address(source) || is_network_burn_address(source) || *amount == 0 {
            return Err(ValidatorRewardError::InvalidFundingDebits);
        }
        debited = debited
            .checked_add(*amount)
            .ok_or(ValidatorRewardError::Arithmetic)?;
        changes.insert(source.clone(), (*amount, 0_u128));
    }
    if locked != debited {
        return Err(ValidatorRewardError::InvalidFundingDebits);
    }
    if let Some(settlement) = &close.settlement {
        for reward in settlement.validators.values() {
            let payout = &reward.payout_address;
            if synergy_address::address_kind(payout) != synergy_address::AddressKind::Wallet
                || !synergy_address::is_spendable_user_address(payout)
            {
                return Err(ValidatorRewardError::InvalidLedger);
            }
            add_credit(&mut changes, payout, reward.released_nwei)?;
            add_credit(
                &mut changes,
                &settlement.treasury_recovery_address,
                reward.treasury_recovery_nwei,
            )?;
        }
    }
    let diff = StateDiff {
        changes: changes
            .into_iter()
            .map(|(account, (debit_nwei, credit_nwei))| AccountChange {
                account,
                debit_nwei,
                credit_nwei,
                expected_nonce: None,
                code_hash: None,
            })
            .collect(),
        protocol_changes: vec![ProtocolChange {
            key: VALIDATOR_REWARD_EPOCH_STATE_KEY.to_owned(),
            expected_value: Some(old.clone()),
            value: Some(
                serde_json::to_vec(&candidate).map_err(|_| ValidatorRewardError::InvalidLedger)?,
            ),
        }],
    };
    diff.validate()
        .map_err(|_| ValidatorRewardError::InvalidLedger)?;
    Ok(diff)
}

fn add_credit(
    changes: &mut BTreeMap<String, (u128, u128)>,
    address: &str,
    amount: u128,
) -> Result<()> {
    if amount != 0 {
        let (_, credit) = changes.entry(address.to_owned()).or_default();
        *credit = credit
            .checked_add(amount)
            .ok_or(ValidatorRewardError::Arithmetic)?;
    }
    Ok(())
}
