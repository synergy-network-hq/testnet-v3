use serde::{Deserialize, Serialize};
use synergy_node_ownership::NodeOwnerResolver;
use synergy_protocol_types::{BlockReference, NodeAddress};

use crate::{
    authorization::{validate_id, validate_proof, validate_wallet},
    RewardAccount, RewardAuthorizationVerifier, RewardError, RewardWithdrawalAction,
    RewardWithdrawalRequest, WithdrawalRecord, WithdrawalStatus,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RewardTransition {
    Credit {
        node_address: NodeAddress,
        amount_nwei: u128,
        source_id: String,
    },
    AuthorizeWithdrawal {
        action: RewardWithdrawalAction,
    },
    SettleWithdrawal {
        withdrawal_id: String,
    },
    CancelWithdrawal {
        withdrawal_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedRewardBatch {
    pub finalized_at: BlockReference,
    pub transitions: Vec<RewardTransition>,
}

/// Prepares deterministic reward transitions without assigning finality.
pub struct RewardEngine<O, V> {
    owners: O,
    verifier: V,
}

impl<O, V> RewardEngine<O, V>
where
    O: NodeOwnerResolver,
    V: RewardAuthorizationVerifier,
{
    pub fn new(owners: O, verifier: V) -> Self {
        Self { owners, verifier }
    }

    /// Creates a credit transition supplied by canonical reward policy.
    ///
    /// This crate intentionally does not calculate reward amounts.
    pub fn prepare_credit(
        &self,
        node_address: NodeAddress,
        amount_nwei: u128,
        source_id: String,
    ) -> Result<RewardTransition, RewardError> {
        if amount_nwei == 0 {
            return Err(RewardError::InvalidAmount);
        }
        validate_id(&source_id)?;
        Ok(RewardTransition::Credit {
            node_address,
            amount_nwei,
            source_id,
        })
    }

    pub fn prepare_withdrawal(
        &self,
        state: &RewardLedgerSnapshot,
        request: RewardWithdrawalRequest,
    ) -> Result<RewardTransition, RewardError> {
        validate_id(&request.withdrawal_id)?;
        validate_wallet(&request.owner_wallet)?;
        validate_wallet(&request.destination_wallet)?;
        validate_proof(&request.owner_proof)?;
        if request.amount_nwei == 0 {
            return Err(RewardError::InvalidAmount);
        }
        if request.nonce == 0 || request.nonce <= state.last_nonce(&request.node_address) {
            return Err(RewardError::InvalidNonce);
        }
        if state.withdrawal(&request.withdrawal_id).is_some() {
            return Err(RewardError::DuplicateWithdrawal);
        }
        let is_owner = self
            .owners
            .is_current_owner(&request.node_address, &request.owner_wallet)
            .map_err(RewardError::Ownership)?;
        if !is_owner {
            return Err(RewardError::OwnerMismatch);
        }
        let account = state
            .account(&request.node_address)
            .ok_or(RewardError::InsufficientAvailable)?;
        if account.available_nwei()? < request.amount_nwei {
            return Err(RewardError::InsufficientAvailable);
        }
        let action = RewardWithdrawalAction {
            withdrawal_id: request.withdrawal_id,
            node_address: request.node_address,
            owner_wallet: request.owner_wallet,
            destination_wallet: request.destination_wallet,
            amount_nwei: request.amount_nwei,
            nonce: request.nonce,
        };
        let payload = action.signing_payload()?;
        self.verifier
            .verify_owner_proof(&action.owner_wallet, &payload, &request.owner_proof)
            .map_err(RewardError::Authorization)?;
        Ok(RewardTransition::AuthorizeWithdrawal { action })
    }

    pub fn prepare_settlement(
        &self,
        state: &RewardLedgerSnapshot,
        withdrawal_id: String,
    ) -> Result<RewardTransition, RewardError> {
        validate_id(&withdrawal_id)?;
        let record = state
            .withdrawal(&withdrawal_id)
            .ok_or(RewardError::WithdrawalNotFound)?;
        if record.status != WithdrawalStatus::Pending {
            return Err(RewardError::WithdrawalNotPending);
        }
        Ok(RewardTransition::SettleWithdrawal { withdrawal_id })
    }

    pub fn prepare_cancellation(
        &self,
        state: &RewardLedgerSnapshot,
        withdrawal_id: String,
    ) -> Result<RewardTransition, RewardError> {
        validate_id(&withdrawal_id)?;
        let record = state
            .withdrawal(&withdrawal_id)
            .ok_or(RewardError::WithdrawalNotFound)?;
        if record.status != WithdrawalStatus::Pending {
            return Err(RewardError::WithdrawalNotPending);
        }
        Ok(RewardTransition::CancelWithdrawal { withdrawal_id })
    }
}

impl RewardLedgerSnapshot {
    /// Applies one deterministic transition inside the block execution overlay.
    /// It does not create a finalized cache record; PoSy finality and the
    /// finalized state store remain the authority for that promotion.
    pub fn apply_at_height(
        &mut self,
        height: u64,
        transition: RewardTransition,
    ) -> Result<(), RewardError> {
        if height == 0 {
            return Err(RewardError::CorruptState);
        }
        let mut candidate = self.clone();
        candidate.apply_transition(height, transition)?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    pub fn apply_finalized(&mut self, batch: FinalizedRewardBatch) -> Result<(), RewardError> {
        if batch.transitions.is_empty() {
            return Err(RewardError::EmptyFinalizedBatch);
        }
        self.ensure_next_finalized(&batch.finalized_at)?;
        let mut candidate = self.clone();
        for transition in batch.transitions {
            candidate.apply_transition(batch.finalized_at.height.get(), transition)?;
        }
        candidate.finalized_at = Some(batch.finalized_at);
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    fn apply_transition(
        &mut self,
        height: u64,
        transition: RewardTransition,
    ) -> Result<(), RewardError> {
        match transition {
            RewardTransition::Credit {
                node_address,
                amount_nwei,
                source_id,
            } => self.apply_credit(node_address, amount_nwei, source_id),
            RewardTransition::AuthorizeWithdrawal { action } => {
                self.apply_withdrawal(height, action)
            }
            RewardTransition::SettleWithdrawal { withdrawal_id } => {
                self.finish_withdrawal(height, &withdrawal_id, WithdrawalStatus::Settled)
            }
            RewardTransition::CancelWithdrawal { withdrawal_id } => {
                self.finish_withdrawal(height, &withdrawal_id, WithdrawalStatus::Cancelled)
            }
        }
    }

    fn apply_credit(
        &mut self,
        node_address: NodeAddress,
        amount_nwei: u128,
        source_id: String,
    ) -> Result<(), RewardError> {
        if amount_nwei == 0 {
            return Err(RewardError::InvalidAmount);
        }
        validate_id(&source_id)?;
        if !self.credit_sources.insert(source_id) {
            return Err(RewardError::DuplicateCredit);
        }
        let account = self
            .accounts
            .entry(node_address.clone())
            .or_insert(RewardAccount {
                node_address,
                total_earned_nwei: 0,
                pending_withdrawal_nwei: 0,
                withdrawn_nwei: 0,
                sequence: 0,
            });
        account.total_earned_nwei = account
            .total_earned_nwei
            .checked_add(amount_nwei)
            .ok_or(RewardError::AmountOverflow)?;
        account.sequence = account
            .sequence
            .checked_add(1)
            .ok_or(RewardError::CorruptState)?;
        Ok(())
    }

    fn apply_withdrawal(
        &mut self,
        height: u64,
        action: RewardWithdrawalAction,
    ) -> Result<(), RewardError> {
        validate_id(&action.withdrawal_id)?;
        validate_wallet(&action.owner_wallet)?;
        validate_wallet(&action.destination_wallet)?;
        if action.amount_nwei == 0
            || action.nonce == 0
            || action.nonce <= self.last_nonce(&action.node_address)
        {
            return Err(RewardError::InvalidNonce);
        }
        if self.withdrawals.contains_key(&action.withdrawal_id) {
            return Err(RewardError::DuplicateWithdrawal);
        }
        let account = self
            .accounts
            .get_mut(&action.node_address)
            .ok_or(RewardError::InsufficientAvailable)?;
        if account.available_nwei()? < action.amount_nwei {
            return Err(RewardError::InsufficientAvailable);
        }
        account.pending_withdrawal_nwei = account
            .pending_withdrawal_nwei
            .checked_add(action.amount_nwei)
            .ok_or(RewardError::AmountOverflow)?;
        account.sequence = account
            .sequence
            .checked_add(1)
            .ok_or(RewardError::CorruptState)?;
        self.last_nonce_by_node
            .insert(action.node_address.clone(), action.nonce);
        self.withdrawals.insert(
            action.withdrawal_id.clone(),
            WithdrawalRecord {
                record_version: 1,
                withdrawal_id: action.withdrawal_id,
                node_address: action.node_address,
                authorized_by_wallet: action.owner_wallet,
                destination_wallet: action.destination_wallet,
                amount_nwei: action.amount_nwei,
                authorization_nonce: action.nonce,
                status: WithdrawalStatus::Pending,
                created_height: height,
                completed_height: None,
            },
        );
        Ok(())
    }

    fn finish_withdrawal(
        &mut self,
        height: u64,
        withdrawal_id: &str,
        status: WithdrawalStatus,
    ) -> Result<(), RewardError> {
        let record = self
            .withdrawals
            .get_mut(withdrawal_id)
            .ok_or(RewardError::WithdrawalNotFound)?;
        if record.status != WithdrawalStatus::Pending {
            return Err(RewardError::WithdrawalNotPending);
        }
        let account = self
            .accounts
            .get_mut(&record.node_address)
            .ok_or(RewardError::CorruptState)?;
        account.pending_withdrawal_nwei = account
            .pending_withdrawal_nwei
            .checked_sub(record.amount_nwei)
            .ok_or(RewardError::CorruptState)?;
        if status == WithdrawalStatus::Settled {
            account.withdrawn_nwei = account
                .withdrawn_nwei
                .checked_add(record.amount_nwei)
                .ok_or(RewardError::AmountOverflow)?;
        }
        account.sequence = account
            .sequence
            .checked_add(1)
            .ok_or(RewardError::CorruptState)?;
        record.status = status;
        record.completed_height = Some(height);
        Ok(())
    }
}

use crate::RewardLedgerSnapshot;
