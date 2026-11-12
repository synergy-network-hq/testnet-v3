use synergy_block::{Block, BlockBody};
use synergy_state::world_resources::{resource_state_error, BudgetedWorld};
use synergy_state::{state_root, StateOverlay, WorldState};
use synergy_transaction::{
    verify_aegis_signature, verify_aegis_signature_with_admission, AegisTransactionVerifier,
    NetworkBinding, ReceiptStatus, TransactionAdmissionContext, TransactionClass, TransactionError,
    TransactionReceipt,
};

use crate::{
    BlockExecutionError, BlockExecutionOutcome, FeeSchedule, TransactionExecutionContext,
    TransactionExecutor,
};

fn actual_parent_rejection(error: &synergy_state::StateError) -> Option<&'static str> {
    use synergy_state::StateError;
    match error {
        StateError::InsufficientBalance => Some("async_parent_insufficient_balance_v1"),
        StateError::BalanceOverflow => Some("async_parent_balance_overflow_v1"),
        StateError::ProtocolValueMismatch(_) => Some("async_parent_protocol_mismatch_v1"),
        _ => None,
    }
}

fn async_nonce_is_stale(
    world: &WorldState,
    sender: &str,
    supplied: u64,
) -> Result<bool, TransactionError> {
    if supplied == u64::MAX {
        return Err(TransactionError::NonceOverflow);
    }
    let current = world
        .accounts
        .get(sender)
        .map_or(0, |account| account.nonce);
    if supplied > current {
        return Err(TransactionError::NonceNotReady);
    }
    Ok(supplied < current)
}

fn consume_async_rejection_nonce<O: ExecutionOverlay>(
    overlay: &mut O,
    sender: &str,
    nonce: u64,
) -> Result<(), synergy_state::StateError> {
    overlay.apply(&synergy_state::StateDiff {
        changes: vec![synergy_state::AccountChange {
            account: sender.to_owned(),
            debit_nwei: 0,
            credit_nwei: 0,
            expected_nonce: Some(nonce),
            code_hash: None,
        }],
        ..Default::default()
    })
}

fn apply_async_effects<O: ExecutionOverlay>(
    overlay: &mut O,
    action: &synergy_state::StateDiff,
    fee: &synergy_state::StateDiff,
) -> Result<Option<&'static str>, synergy_state::StateError> {
    match overlay.apply_ordered_atomic(&[action, fee]) {
        Ok(()) => Ok(None),
        Err(error) => match actual_parent_rejection(&error) {
            Some(code) => Ok(Some(code)),
            None => Err(error),
        },
    }
}

fn add_first_use_binding(
    diff: &mut synergy_state::StateDiff,
    protocol: &std::collections::BTreeMap<String, Vec<u8>>,
    sender: &str,
    binding: &synergy_identity::authorization::IdentityAuthorizationBindingCommitment,
    block_height: u64,
) -> Result<(), String> {
    use synergy_identity::authorization::{
        first_use_binding_update, IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY as KEY,
    };
    let Some(updated) = first_use_binding_update(protocol, sender, binding)? else {
        return Ok(());
    };
    if let Some(change) = diff
        .protocol_changes
        .iter_mut()
        .find(|change| change.key == KEY)
    {
        if change.expected_value.as_ref() != protocol.get(KEY) {
            return Err("native authorization update has a conflicting parent".into());
        }
        let mut action_protocol = std::collections::BTreeMap::new();
        action_protocol.insert(
            KEY.into(),
            change
                .value
                .clone()
                .ok_or("native action removes authorization table")?,
        );
        if let Some(merged) = first_use_binding_update(&action_protocol, sender, binding)? {
            change.value = Some(merged);
        }
    } else {
        diff.protocol_changes.push(synergy_state::ProtocolChange {
            key: KEY.into(),
            expected_value: protocol.get(KEY).cloned(),
            value: Some(updated),
        });
    }
    let marker = synergy_identity::registration::AUTHORIZATION_UPDATED_HEIGHT_STATE_KEY;
    let height = serde_json::to_vec(&block_height).map_err(|error| error.to_string())?;
    if let Some(change) = diff
        .protocol_changes
        .iter()
        .find(|change| change.key == marker)
    {
        if change.expected_value.as_ref() != protocol.get(marker)
            || change.value.as_ref() != Some(&height)
        {
            return Err("native authorization height update conflicts with first use".into());
        }
    } else {
        diff.protocol_changes.push(synergy_state::ProtocolChange {
            key: marker.into(),
            expected_value: protocol.get(marker).cloned(),
            value: Some(height),
        });
    }
    Ok(())
}

trait ExecutionOverlay {
    type State;
    fn staged(&self) -> &WorldState;
    fn apply(&mut self, diff: &synergy_state::StateDiff) -> Result<(), synergy_state::StateError>;
    fn apply_ordered_atomic(
        &mut self,
        diffs: &[&synergy_state::StateDiff],
    ) -> Result<(), synergy_state::StateError>;
    fn finish(self) -> Self::State;
}
impl ExecutionOverlay for StateOverlay<'_> {
    type State = WorldState;
    fn staged(&self) -> &WorldState {
        StateOverlay::staged(self)
    }
    fn apply(&mut self, diff: &synergy_state::StateDiff) -> Result<(), synergy_state::StateError> {
        StateOverlay::apply(self, diff)
    }
    fn apply_ordered_atomic(
        &mut self,
        diffs: &[&synergy_state::StateDiff],
    ) -> Result<(), synergy_state::StateError> {
        StateOverlay::apply_ordered_atomic(self, diffs)
    }
    fn finish(self) -> WorldState {
        self.into_staged()
    }
}
impl ExecutionOverlay for WorldState {
    type State = Self;
    fn staged(&self) -> &WorldState {
        self
    }
    fn apply(&mut self, diff: &synergy_state::StateDiff) -> Result<(), synergy_state::StateError> {
        diff.apply(self)
    }
    fn apply_ordered_atomic(
        &mut self,
        diffs: &[&synergy_state::StateDiff],
    ) -> Result<(), synergy_state::StateError> {
        synergy_state::StateDiff::apply_ordered_atomic(diffs, self)
    }
    fn finish(self) -> Self {
        self
    }
}
impl ExecutionOverlay for BudgetedWorld {
    type State = Self;
    fn staged(&self) -> &WorldState {
        self.as_ref()
    }
    fn apply(&mut self, diff: &synergy_state::StateDiff) -> Result<(), synergy_state::StateError> {
        self.try_apply(diff)
    }
    fn apply_ordered_atomic(
        &mut self,
        diffs: &[&synergy_state::StateDiff],
    ) -> Result<(), synergy_state::StateError> {
        self.try_apply_ordered_atomic(diffs)
    }
    fn finish(self) -> Self {
        self
    }
}

/// Executes a canonical block body against an isolated state overlay. Every
/// transaction must validate and succeed; otherwise no candidate state escapes.
pub struct BlockExecutionScheduler<D, V> {
    dispatcher: D,
    verifier: V,
    fees: FeeSchedule,
}

impl<D, V> BlockExecutionScheduler<D, V>
where
    D: TransactionExecutor,
    V: AegisTransactionVerifier,
{
    pub fn new(dispatcher: D, verifier: V, fees: FeeSchedule) -> Result<Self, BlockExecutionError> {
        fees.validate()?;
        Ok(Self {
            dispatcher,
            verifier,
            fees,
        })
    }

    /// Compatibility path for structural/empty execution. Nonempty input needs
    /// explicit governed time and finalized authorization via `execute_at`.
    pub fn execute(
        &self,
        body: &BlockBody,
        network: &NetworkBinding,
        block_height: u64,
        base_state: &WorldState,
    ) -> Result<BlockExecutionOutcome, BlockExecutionError> {
        self.execute_internal(body, network, block_height, base_state, None)
    }

    /// Canonical candidate execution. Authorization state is supplied separately
    /// from speculative account state and must be finalized or signed Genesis.
    pub fn execute_at(
        &self,
        body: &BlockBody,
        network: &NetworkBinding,
        block_height: u64,
        consensus_timestamp_unix: u64,
        base_state: &WorldState,
        finalized_authorization_state: &WorldState,
    ) -> Result<BlockExecutionOutcome, BlockExecutionError> {
        self.execute_internal(
            body,
            network,
            block_height,
            base_state,
            Some((consensus_timestamp_unix, finalized_authorization_state)),
        )
    }

    /// Speculative execution shares the explicit base pool. Clone and every
    /// write-set allocation reserve before mutation; success moves the permit.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_at_budgeted(
        &self,
        body: &BlockBody,
        network: &NetworkBinding,
        block_height: u64,
        consensus_timestamp_unix: u64,
        base_state: &BudgetedWorld,
        finalized_authorization_state: &WorldState,
    ) -> Result<crate::BudgetedBlockExecutionOutcome, BlockExecutionError> {
        self.execute_with_overlay(
            body,
            network,
            block_height,
            Some((consensus_timestamp_unix, finalized_authorization_state)),
            || {
                base_state
                    .try_clone()
                    .map_err(|error| BlockExecutionError::StateRoot(resource_state_error(error)))
            },
        )
    }

    pub fn execute_budgeted(
        &self,
        body: &BlockBody,
        network: &NetworkBinding,
        block_height: u64,
        base_state: &BudgetedWorld,
    ) -> Result<crate::BudgetedBlockExecutionOutcome, BlockExecutionError> {
        self.execute_with_overlay(body, network, block_height, None, || {
            base_state
                .try_clone()
                .map_err(|error| BlockExecutionError::StateRoot(resource_state_error(error)))
        })
    }

    fn execute_internal(
        &self,
        body: &BlockBody,
        network: &NetworkBinding,
        block_height: u64,
        base_state: &WorldState,
        admission: Option<(u64, &WorldState)>,
    ) -> Result<BlockExecutionOutcome, BlockExecutionError> {
        self.execute_with_overlay(body, network, block_height, admission, || {
            Ok(StateOverlay::from_base(base_state))
        })
    }

    fn execute_with_overlay<O: ExecutionOverlay>(
        &self,
        body: &BlockBody,
        network: &NetworkBinding,
        block_height: u64,
        admission: Option<(u64, &WorldState)>,
        make_overlay: impl FnOnce() -> Result<O, BlockExecutionError>,
    ) -> Result<BlockExecutionOutcome<O::State>, BlockExecutionError> {
        self.execute_with_overlay_mode(body, network, block_height, admission, make_overlay, false)
    }

    /// Execute only under the separately governed asynchronous processing
    /// profile. Typed actual-parent state rejections produce terminal Reverted
    /// receipts consuming only the current sender nonce, with zero gas and fee
    /// totals. Stale nonces revert without another state change; future nonces
    /// must be deferred before selection. The caller must
    /// separately consume the processing identity. Signature, structure and
    /// dispatcher errors remain fatal; local resource pressure remains retryable.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_async_at(
        &self,
        body: &BlockBody,
        network: &NetworkBinding,
        block_height: u64,
        consensus_timestamp_unix: u64,
        base_state: &WorldState,
        finalized_authorization_state: &WorldState,
    ) -> Result<BlockExecutionOutcome, BlockExecutionError> {
        self.execute_with_overlay_mode(
            body,
            network,
            block_height,
            Some((consensus_timestamp_unix, finalized_authorization_state)),
            || Ok(StateOverlay::from_base(base_state)),
            true,
        )
    }
    /// Budgeted equivalent of `execute_async_at`, with the same explicit
    /// asynchronous profile and processing-identity requirements.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_async_at_budgeted(
        &self,
        body: &BlockBody,
        network: &NetworkBinding,
        block_height: u64,
        consensus_timestamp_unix: u64,
        base_state: &BudgetedWorld,
        finalized_authorization_state: &WorldState,
    ) -> Result<crate::BudgetedBlockExecutionOutcome, BlockExecutionError> {
        self.execute_with_overlay_mode(
            body,
            network,
            block_height,
            Some((consensus_timestamp_unix, finalized_authorization_state)),
            || {
                base_state
                    .try_clone()
                    .map_err(|error| BlockExecutionError::StateRoot(resource_state_error(error)))
            },
            true,
        )
    }
    fn execute_with_overlay_mode<O: ExecutionOverlay>(
        &self,
        body: &BlockBody,
        network: &NetworkBinding,
        block_height: u64,
        admission: Option<(u64, &WorldState)>,
        make_overlay: impl FnOnce() -> Result<O, BlockExecutionError>,
        async_mode: bool,
    ) -> Result<BlockExecutionOutcome<O::State>, BlockExecutionError> {
        if block_height == 0 {
            return Err(BlockExecutionError::InvalidHeight);
        }
        network
            .validate()
            .map_err(|source| BlockExecutionError::Transaction {
                transaction_index: 0,
                source,
            })?;
        body.validate_structure()
            .map_err(BlockExecutionError::Block)?;

        let mut overlay = make_overlay()?;
        let mut receipts = Vec::with_capacity(body.transactions.len());
        let mut total_gas_used = 0_u64;
        let mut total_fees_nwei = 0_u128;

        for (transaction_index, transaction) in body.transactions.iter().enumerate() {
            transaction.validate_structure().map_err(|source| {
                BlockExecutionError::Transaction {
                    transaction_index,
                    source,
                }
            })?;
            if transaction.unsigned.network != *network {
                return Err(BlockExecutionError::NetworkMismatch { transaction_index });
            }
            let mut first_use_binding = None;
            let verify_signature = match admission {
                Some((consensus_timestamp_unix, finalized_authorization_state)) => {
                    let existing =
                        synergy_identity::authorization::canonical_binding_commitment_if_present(
                            &finalized_authorization_state.protocol,
                            &transaction.unsigned.sender,
                        )
                        .map_err(|error| {
                            BlockExecutionError::Signature {
                                transaction_index,
                                source: synergy_transaction::TransactionError::SignatureVerifier(
                                    error,
                                ),
                            }
                        })?;
                    let binding = match existing {
                        Some(binding) => binding,
                        None => {
                            let carrier = transaction.identity_authorization.as_ref().ok_or_else(|| BlockExecutionError::Signature {
                                transaction_index,
                                source: TransactionError::SignatureVerifier("first-use transaction requires its identity authorization carrier".into()),
                            })?;
                            let binding =
                                synergy_identity::authorization::resolve_transaction_binding_with_verifier(
                                    &overlay.staged().protocol,
                                    &transaction.unsigned.sender,
                                    carrier,
                                    &transaction.signer_public_key,
                                    network.chain_id,
                                    &network.network_id,
                                    consensus_timestamp_unix,
                                    self.verifier.authorization_verifier(),
                                )
                                .map_err(|error| {
                                    BlockExecutionError::Signature {
                                        transaction_index,
                                        source: TransactionError::SignatureVerifier(error),
                                    }
                                })?;
                            first_use_binding = Some(binding.clone());
                            binding
                        }
                    };
                    verify_aegis_signature_with_admission(
                        transaction,
                        &self.verifier,
                        TransactionAdmissionContext {
                            consensus_timestamp_unix,
                            canonical_binding: &binding,
                        },
                    )
                }
                None => verify_aegis_signature(transaction, &self.verifier),
            };
            verify_signature.map_err(|source| BlockExecutionError::Signature {
                transaction_index,
                source,
            })?;
            let transaction_id =
                transaction
                    .id()
                    .map_err(|source| BlockExecutionError::Transaction {
                        transaction_index,
                        source,
                    })?;
            if async_mode {
                if transaction.unsigned.class != TransactionClass::User {
                    return Err(BlockExecutionError::Transaction {
                        transaction_index,
                        source: TransactionError::UnauthorizedTransactionClass,
                    });
                }
                let stale = async_nonce_is_stale(
                    overlay.staged(),
                    &transaction.unsigned.sender,
                    transaction.unsigned.nonce,
                )
                .map_err(|source| BlockExecutionError::Transaction {
                    transaction_index,
                    source,
                })?;
                if stale {
                    let receipt = TransactionReceipt {
                        transaction_id,
                        status: ReceiptStatus::Reverted,
                        gas_used: 0,
                        state_root_after: state_root(overlay.staged())
                            .map_err(BlockExecutionError::StateRoot)?,
                        error_code: Some("async_parent_nonce_stale_v1".into()),
                    };
                    if !receipt.validate() {
                        return Err(BlockExecutionError::InvalidReceipt { transaction_index });
                    }
                    receipts.push(receipt);
                    continue;
                }
            }
            let action = transaction.unsigned.action().map_err(|source| {
                BlockExecutionError::Transaction {
                    transaction_index,
                    source,
                }
            })?;
            let transaction_position =
                u32::try_from(transaction_index).map_err(|_| BlockExecutionError::Dispatcher {
                    transaction_index,
                    message: "transaction index exceeds canonical range".into(),
                })?;
            let mut dispatch = self
                .dispatcher
                .execute(
                    transaction,
                    &action,
                    TransactionExecutionContext {
                        network,
                        block_height,
                        transaction_index: transaction_position,
                    },
                    overlay.staged(),
                )
                .map_err(|error| BlockExecutionError::Dispatcher {
                    transaction_index,
                    message: error.to_string(),
                })?;
            if let Some(binding) = first_use_binding {
                add_first_use_binding(
                    &mut dispatch.state_diff,
                    &overlay.staged().protocol,
                    &transaction.unsigned.sender,
                    &binding,
                    block_height,
                )
                .map_err(|error| BlockExecutionError::Signature {
                    transaction_index,
                    source: TransactionError::SignatureVerifier(error),
                })?;
            }
            // Legacy preserves its original action/fee order and errors.
            if !async_mode {
                overlay.apply(&dispatch.state_diff).map_err(|source| {
                    BlockExecutionError::State {
                        transaction_index,
                        source,
                    }
                })?;
            }
            let (settlement, fee_diff) =
                self.fees
                    .settle(transaction, dispatch.gas_used, transaction_index)?;
            let rejected = if async_mode {
                apply_async_effects(&mut overlay, &dispatch.state_diff, &fee_diff)
            } else {
                overlay.apply(&fee_diff).map(|()| None)
            };
            match rejected {
                Ok(Some(code)) => {
                    // Action/fee staging has rolled back. Consume only the
                    // authenticated current sender nonce so these signed bytes
                    // cannot become executable after subsequent funding.
                    consume_async_rejection_nonce(
                        &mut overlay,
                        &transaction.unsigned.sender,
                        transaction.unsigned.nonce,
                    )
                    .map_err(|source| BlockExecutionError::State {
                        transaction_index,
                        source,
                    })?;
                    let receipt = TransactionReceipt {
                        transaction_id,
                        status: ReceiptStatus::Reverted,
                        gas_used: 0,
                        state_root_after: state_root(overlay.staged())
                            .map_err(BlockExecutionError::StateRoot)?,
                        error_code: Some(code.into()),
                    };
                    if !receipt.validate() {
                        return Err(BlockExecutionError::InvalidReceipt { transaction_index });
                    }
                    receipts.push(receipt);
                    continue;
                }
                Ok(None) => {}
                Err(source) => {
                    return Err(BlockExecutionError::State {
                        transaction_index,
                        source,
                    })
                }
            }
            let state_root_after =
                state_root(overlay.staged()).map_err(BlockExecutionError::StateRoot)?;
            let receipt = TransactionReceipt {
                transaction_id,
                status: ReceiptStatus::Applied,
                gas_used: settlement.gas_used,
                state_root_after,
                error_code: None,
            };
            if !receipt.validate() {
                return Err(BlockExecutionError::InvalidReceipt { transaction_index });
            }
            total_gas_used = total_gas_used
                .checked_add(settlement.gas_used)
                .ok_or(BlockExecutionError::GasTotalOverflow)?;
            total_fees_nwei = total_fees_nwei
                .checked_add(settlement.fee_nwei)
                .ok_or(BlockExecutionError::FeeTotalOverflow)?;
            receipts.push(receipt);
        }

        let state_root = state_root(overlay.staged()).map_err(BlockExecutionError::StateRoot)?;
        Ok(BlockExecutionOutcome {
            block_height,
            state: overlay.finish(),
            state_root,
            receipts,
            total_gas_used,
            total_fees_nwei,
        })
    }

    /// Replays a complete canonical block and verifies its execution-owned
    /// state and receipt commitments. Proposer/QC/finality checks stay in PoSy.
    pub fn execute_block(
        &self,
        block: &Block,
        base_state: &WorldState,
    ) -> Result<BlockExecutionOutcome, BlockExecutionError> {
        block
            .validate_structure()
            .map_err(BlockExecutionError::Block)?;
        let outcome = self.execute_at(
            &block.body,
            &block.header.network,
            block.header.height,
            block.header.timestamp_unix,
            base_state,
            base_state,
        )?;
        if outcome.state_root != block.header.state_root {
            return Err(BlockExecutionError::StateRootMismatch {
                expected: block.header.state_root.clone(),
                actual: outcome.state_root,
            });
        }
        if outcome.receipts != block.receipts {
            return Err(BlockExecutionError::ReceiptMismatch);
        }
        Ok(outcome)
    }

    pub fn execute_block_budgeted(
        &self,
        block: &Block,
        base_state: &BudgetedWorld,
    ) -> Result<crate::BudgetedBlockExecutionOutcome, BlockExecutionError> {
        block
            .validate_structure()
            .map_err(BlockExecutionError::Block)?;
        let outcome = self.execute_at_budgeted(
            &block.body,
            &block.header.network,
            block.header.height,
            block.header.timestamp_unix,
            base_state,
            base_state.as_ref(),
        )?;
        if outcome.state_root != block.header.state_root {
            return Err(BlockExecutionError::StateRootMismatch {
                expected: block.header.state_root.clone(),
                actual: outcome.state_root,
            });
        }
        if outcome.receipts != block.receipts {
            return Err(BlockExecutionError::ReceiptMismatch);
        }
        Ok(outcome)
    }

    /// Replay only under the separately governed asynchronous profile. The
    /// caller must enforce that profile and provide finalized authorization
    /// independently of the actual parent being executed. PoSy still owns all
    /// proposal, QC and finality validation.
    pub fn execute_async_block(
        &self,
        block: &Block,
        base_state: &WorldState,
        finalized_authorization_state: &WorldState,
    ) -> Result<BlockExecutionOutcome, BlockExecutionError> {
        block
            .validate_structure()
            .map_err(BlockExecutionError::Block)?;
        let outcome = self.execute_async_at(
            &block.body,
            &block.header.network,
            block.header.height,
            block.header.timestamp_unix,
            base_state,
            finalized_authorization_state,
        )?;
        if outcome.state_root != block.header.state_root {
            return Err(BlockExecutionError::StateRootMismatch {
                expected: block.header.state_root.clone(),
                actual: outcome.state_root,
            });
        }
        if outcome.receipts != block.receipts {
            return Err(BlockExecutionError::ReceiptMismatch);
        }
        Ok(outcome)
    }

    /// Budgeted asynchronous replay with explicit finalized authorization.
    /// The caller must enforce the new governed profile; this method performs
    /// no profile inference and changes no legacy replay behavior.
    pub fn execute_async_block_budgeted(
        &self,
        block: &Block,
        base_state: &BudgetedWorld,
        finalized_authorization_state: &WorldState,
    ) -> Result<crate::BudgetedBlockExecutionOutcome, BlockExecutionError> {
        block
            .validate_structure()
            .map_err(BlockExecutionError::Block)?;
        let outcome = self.execute_async_at_budgeted(
            &block.body,
            &block.header.network,
            block.header.height,
            block.header.timestamp_unix,
            base_state,
            finalized_authorization_state,
        )?;
        if outcome.state_root != block.header.state_root {
            return Err(BlockExecutionError::StateRootMismatch {
                expected: block.header.state_root.clone(),
                actual: outcome.state_root,
            });
        }
        if outcome.receipts != block.receipts {
            return Err(BlockExecutionError::ReceiptMismatch);
        }
        Ok(outcome)
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod budgeted_tests {
    use super::*;
    use synergy_state::world_resources::{world_owned_bytes, WorldResourceBudget};
    #[test]
    fn first_use_binding_and_transfer_commit_atomically_and_cannot_replace() {
        use synergy_identity::authorization::{
            IdentityAuthorizationBindingCommitment,
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY as KEY,
        };
        use synergy_state::{AccountChange, AccountState, StateDiff};
        let binding = IdentityAuthorizationBindingCommitment {
            binding_payload_sha3_256: "a".repeat(64),
            identity_root_public_key_sha3_256: "b".repeat(64),
            effective_at_unix: 1,
        };
        let mut original = WorldState::default();
        original.protocol.insert(KEY.into(), b"{}".to_vec());
        original.accounts.insert(
            "sender".into(),
            AccountState {
                balance_nwei: 10,
                ..Default::default()
            },
        );
        let mut action = StateDiff {
            changes: vec![
                AccountChange {
                    account: "sender".into(),
                    debit_nwei: 7,
                    credit_nwei: 0,
                    expected_nonce: Some(0),
                    code_hash: None,
                },
                AccountChange {
                    account: "receiver".into(),
                    debit_nwei: 0,
                    credit_nwei: 7,
                    expected_nonce: None,
                    code_hash: None,
                },
            ],
            ..Default::default()
        };
        add_first_use_binding(&mut action, &original.protocol, "sender", &binding, 5).unwrap();
        let mut fee = StateDiff {
            changes: vec![AccountChange {
                account: "sender".into(),
                debit_nwei: 5,
                credit_nwei: 0,
                expected_nonce: None,
                code_hash: None,
            }],
            ..Default::default()
        };
        let mut world = original.clone();
        assert_eq!(
            apply_async_effects(&mut world, &action, &fee).unwrap(),
            Some("async_parent_insufficient_balance_v1")
        );
        assert_eq!(
            world, original,
            "failed fees must not install a first-use binding"
        );
        fee.changes[0].debit_nwei = 3;
        assert_eq!(
            apply_async_effects(&mut world, &action, &fee).unwrap(),
            None
        );
        assert_eq!(world.accounts["sender"].nonce, 1);
        assert_eq!(world.accounts["sender"].balance_nwei, 0);
        assert_eq!(world.accounts["receiver"].balance_nwei, 7);
        assert_eq!(
            synergy_identity::authorization::canonical_binding_commitment(
                &world.protocol,
                "sender"
            )
            .unwrap(),
            binding
        );
        let mut next = StateDiff::default();
        add_first_use_binding(&mut next, &world.protocol, "sender", &binding, 6).unwrap();
        assert!(
            next.protocol_changes.is_empty(),
            "same binding is idempotent"
        );
        let mut forged = binding;
        forged.binding_payload_sha3_256 = "c".repeat(64);
        assert!(add_first_use_binding(&mut next, &world.protocol, "sender", &forged, 6).is_err());
        assert_eq!(world.accounts["sender"].nonce, 1);
    }
    struct UnusedVerifier;
    impl AegisTransactionVerifier for UnusedVerifier {
        type Error = String;
        fn verify_transaction(
            &self,
            _: &[u8],
            _: &[u8],
            _: &[u8],
            _: &str,
        ) -> Result<bool, String> {
            panic!("empty block must not verify transactions")
        }
    }
    #[test]
    fn async_actual_parent_rejection_is_atomic_and_resource_failure_is_retryable() {
        use synergy_state::{AccountChange, AccountState, StateDiff, StateError};
        let mut original = WorldState::default();
        original.accounts.insert(
            "sender".into(),
            AccountState {
                balance_nwei: 10,
                ..Default::default()
            },
        );
        original.protocol.insert("unrelated".into(), vec![8; 65536]);
        let action = StateDiff {
            changes: vec![
                AccountChange {
                    account: "sender".into(),
                    debit_nwei: 7,
                    credit_nwei: 0,
                    expected_nonce: Some(0),
                    code_hash: None,
                },
                AccountChange {
                    account: "receiver".into(),
                    debit_nwei: 0,
                    credit_nwei: 7,
                    expected_nonce: None,
                    code_hash: None,
                },
            ],
            ..Default::default()
        };
        let fee = StateDiff {
            changes: vec![AccountChange {
                account: "sender".into(),
                debit_nwei: 5,
                credit_nwei: 0,
                expected_nonce: None,
                code_hash: None,
            }],
            ..Default::default()
        };
        let mut plain = original.clone();
        assert_eq!(
            apply_async_effects(&mut plain, &action, &fee).unwrap(),
            Some("async_parent_insufficient_balance_v1")
        );
        assert_eq!(plain, original);
        let mut stale = action.clone();
        stale.changes[0].expected_nonce = Some(1);
        assert!(matches!(
            apply_async_effects(&mut plain, &stale, &fee),
            Err(StateError::NonceMismatch { .. })
        ));
        assert_eq!(plain, original);
        let owned = world_owned_bytes(&original).unwrap();
        let budget = WorldResourceBudget::new(owned * 8);
        let mut wrapped =
            BudgetedWorld::from_reserved(original.clone(), budget.reserve(owned).unwrap()).unwrap();
        let blocker = budget.reserve(budget.available()).unwrap();
        let before = budget.used();
        assert!(matches!(
            apply_async_effects(&mut wrapped, &action, &fee),
            Err(StateError::ResourcePressure { .. })
        ));
        assert_eq!(budget.used(), before);
        assert_eq!(wrapped.as_ref(), &original);
        drop(blocker);
        assert_eq!(
            apply_async_effects(&mut wrapped, &action, &fee).unwrap(),
            Some("async_parent_insufficient_balance_v1")
        );
        assert_eq!(wrapped.as_ref(), &original);
        assert_eq!(budget.used(), owned);
        // A terminal current-nonce rejection consumes only that nonce. Later
        // funding cannot revive its signed bytes; a future nonce is untouched.
        assert_eq!(
            async_nonce_is_stale(wrapped.as_ref(), "sender", 0),
            Ok(false)
        );
        assert_eq!(
            async_nonce_is_stale(wrapped.as_ref(), "sender", 1),
            Err(TransactionError::NonceNotReady)
        );
        assert_eq!(wrapped.accounts["sender"].nonce, 0);
        let blocker = budget.reserve(budget.available()).unwrap();
        assert!(matches!(
            consume_async_rejection_nonce(&mut wrapped, "sender", 0),
            Err(StateError::ResourcePressure { .. })
        ));
        assert_eq!(wrapped.as_ref(), &original);
        drop(blocker);
        consume_async_rejection_nonce(&mut wrapped, "sender", 0).unwrap();
        assert_eq!(wrapped.accounts["sender"].nonce, 1);
        assert_eq!(wrapped.accounts["sender"].balance_nwei, 10);
        assert!(!wrapped.accounts.contains_key("receiver"));
        let funding = StateDiff {
            changes: vec![AccountChange {
                account: "sender".into(),
                debit_nwei: 0,
                credit_nwei: 100,
                expected_nonce: None,
                code_hash: None,
            }],
            ..Default::default()
        };
        wrapped.try_apply(&funding).unwrap();
        assert_eq!(
            async_nonce_is_stale(wrapped.as_ref(), "sender", 0),
            Ok(true)
        );
        assert_eq!(
            async_nonce_is_stale(wrapped.as_ref(), "sender", u64::MAX),
            Err(TransactionError::NonceOverflow)
        );
        // Restore a fresh parent for the successful-state equivalence check.
        drop(wrapped);
        let mut wrapped =
            BudgetedWorld::from_reserved(original.clone(), budget.reserve(owned).unwrap()).unwrap();
        let good_fee = StateDiff {
            changes: vec![AccountChange {
                debit_nwei: 3,
                ..fee.changes[0].clone()
            }],
            ..Default::default()
        };
        let mut expected = original.clone();
        action.apply(&mut expected).unwrap();
        good_fee.apply(&mut expected).unwrap();
        let pointer = wrapped.protocol["unrelated"].as_ptr();
        assert_eq!(
            apply_async_effects(&mut wrapped, &action, &good_fee).unwrap(),
            None
        );
        assert_eq!(wrapped.as_ref(), &expected);
        assert_eq!(pointer, wrapped.protocol["unrelated"].as_ptr());
        // A later diff can read a value introduced by the first. Its temporary
        // clones must also be reserved although it is absent from the base.
        let introduced = vec![4; 128 * 1024];
        let protocol_action = StateDiff {
            protocol_changes: vec![synergy_state::ProtocolChange {
                key: "sequential".into(),
                expected_value: None,
                value: Some(introduced.clone()),
            }],
            ..Default::default()
        };
        let mut protocol_fee = StateDiff {
            protocol_changes: vec![synergy_state::ProtocolChange {
                key: "sequential".into(),
                expected_value: Some(vec![5]),
                value: Some(vec![6]),
            }],
            ..Default::default()
        };
        let protocol_budget = WorldResourceBudget::new(32 * 1024 * 1024);
        let mut protocol_world = BudgetedWorld::from_reserved(
            WorldState::default(),
            protocol_budget
                .reserve(world_owned_bytes(&WorldState::default()).unwrap())
                .unwrap(),
        )
        .unwrap();
        let protocol_before = protocol_budget.used();
        assert_eq!(
            apply_async_effects(&mut protocol_world, &protocol_action, &protocol_fee).unwrap(),
            Some("async_parent_protocol_mismatch_v1")
        );
        assert_eq!(protocol_world.as_ref(), &WorldState::default());
        assert_eq!(protocol_budget.used(), protocol_before);
        protocol_fee.protocol_changes[0].expected_value = Some(introduced);
        assert_eq!(
            apply_async_effects(&mut protocol_world, &protocol_action, &protocol_fee).unwrap(),
            None
        );
        assert_eq!(protocol_world.protocol["sequential"], vec![6]);
        assert_eq!(
            protocol_budget.used(),
            world_owned_bytes(protocol_world.as_ref()).unwrap()
        );
        for error in [
            StateError::InvalidDiff,
            StateError::Corrupt("bad".into()),
            StateError::Storage("io".into()),
            StateError::InvalidCommitment,
            StateError::NonceOverflow,
            StateError::NonceMismatch {
                expected: 0,
                supplied: 1,
            },
            StateError::ResourcePressure {
                requested: 2,
                limit: 1,
            },
        ] {
            assert_eq!(actual_parent_rejection(&error), None);
        }
        // Legacy application still returns the original typed rejection rather
        // than manufacturing a receipt; no global error conversion is added.
        let mut legacy = StateOverlay::from_base(&original);
        legacy.apply(&action).unwrap();
        assert_eq!(legacy.apply(&fee), Err(StateError::InsufficientBalance));
    }

    #[test]
    fn budgeted_scheduler_reserves_clone_and_moves_successful_state_without_escape() {
        let mut world = WorldState::default();
        world.protocol.insert("large".into(), vec![3; 64 * 1024]);
        let owned = world_owned_bytes(&world).unwrap();
        let budget = WorldResourceBudget::new(owned * 3);
        let base = BudgetedWorld::from_reserved(world, budget.reserve(owned).unwrap()).unwrap();
        let scheduler = BlockExecutionScheduler::new(
            crate::NativeTransferDispatcher,
            UnusedVerifier,
            FeeSchedule {
                base_fee_per_gas_nwei: 1,
                collector: "collector".into(),
            },
        )
        .unwrap();
        let network = NetworkBinding::new(1266, "budget-test").unwrap();
        let body = BlockBody {
            transactions: vec![],
        };
        let blocker = budget.reserve(budget.available()).unwrap();
        assert!(matches!(
            scheduler.execute_budgeted(&body, &network, 1, &base),
            Err(BlockExecutionError::StateRoot(
                synergy_state::StateError::ResourcePressure { .. }
            ))
        ));
        assert_eq!(base.protocol["large"].len(), 64 * 1024);
        drop(blocker);
        let outcome = scheduler
            .execute_budgeted(&body, &network, 1, &base)
            .unwrap();
        let expected = scheduler
            .execute(&body, &network, 1, base.as_ref())
            .unwrap();
        assert_eq!(outcome.state.as_ref(), &expected.state);
        assert_eq!(outcome.state_root, expected.state_root);
        assert_eq!(
            budget.used(),
            base.charged_bytes() + outcome.state.charged_bytes()
        );
        let moved = std::sync::Arc::new(outcome.state);
        let shared = std::sync::Arc::clone(&moved);
        drop(moved);
        assert!(budget.used() > base.charged_bytes());
        drop(shared);
        assert_eq!(budget.used(), base.charged_bytes());
        let mut overlay = base.try_clone().unwrap();
        let diff = synergy_state::StateDiff {
            changes: vec![],
            protocol_changes: vec![synergy_state::ProtocolChange {
                key: "new".into(),
                expected_value: None,
                value: Some(vec![8; 1024]),
            }],
        };
        let blocker = budget.reserve(budget.available()).unwrap();
        let before = budget.used();
        assert!(matches!(
            ExecutionOverlay::apply(&mut overlay, &diff),
            Err(synergy_state::StateError::ResourcePressure { .. })
        ));
        assert_eq!(budget.used(), before);
        assert!(!overlay.protocol.contains_key("new"));
        drop(blocker);
        ExecutionOverlay::apply(&mut overlay, &diff).unwrap();
        assert_eq!(overlay.protocol["new"], vec![8; 1024]);
        assert!(!base.protocol.contains_key("new"));
        drop(overlay);
        assert_eq!(budget.used(), base.charged_bytes());
        drop(base);
        assert_eq!(budget.used(), 0);
    }
}

#[cfg(test)]
mod permissionless_tests {
    use super::*;
    use aegis_pqvm::pqc::signatures::{fndsa::fndsa1024, mldsa::mldsa87};
    use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};
    use sha3::{Digest, Sha3_256};
    use synergy_identity::authorization::*;
    use synergy_transaction::{FeeLimit, SignedTransaction, UnsignedTransaction};
    struct RealVerifier;
    impl AegisTransactionVerifier for RealVerifier {
        type Error = String;
        fn verify_transaction(
            &self,
            message: &[u8],
            key: &[u8],
            signature: &[u8],
            algorithm: &str,
        ) -> Result<bool, String> {
            if algorithm != "ML-DSA-87" {
                return Ok(false);
            }
            let key = mldsa87::PublicKey::from_bytes(key).map_err(|_| "key")?;
            let signature =
                mldsa87::DetachedSignature::from_bytes(signature).map_err(|_| "signature")?;
            Ok(mldsa87::verify_detached_signature(&signature, message, &key).is_ok())
        }
    }
    fn hash(bytes: &[u8]) -> String {
        hex::encode(Sha3_256::digest(bytes))
    }
    fn identity(
        root: &fndsa1024::PublicKey,
        root_secret: &fndsa1024::SecretKey,
    ) -> (IdentityAuthorizationCarrier, mldsa87::SecretKey, Vec<u8>) {
        let (key, secret) = mldsa87::keypair();
        let sender =
            synergy_address::derive_key_controlled_address("synw", root.as_bytes()).unwrap();
        let key_hash = hash(key.as_bytes());
        let mut binding: IdentityAuthorizationBinding = serde_json::from_value(serde_json::json!({
            "schema_version":AUTH_BINDING_SCHEMA_VERSION,"binary_encoding":AUTH_BINDING_BINARY_ENCODING,
            "identity_id":"permissionless-user","identity_address":sender,
            "identity_root":{"algorithm":"FN-DSA-1024","public_key":hex::encode(root.as_bytes()),"public_key_sha3_256":hash(root.as_bytes())},
            "authorization_policy":{"policy_type":"single-key","threshold":1,"principals":[{"principal_id":"account","principal_type":"public-key","algorithm":"ML-DSA-87","public_key":hex::encode(key.as_bytes()),"public_key_sha3_256":key_hash,"status":"active","purposes":["transaction-signing"]}]},
            "authorization_scopes":[{"signature_domain":AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,"chain_id":9001,"network_id":"public-network","purpose":"transaction-signing"}],
            "current_auth_key_hash":key_hash,"auth_key_history":[],"supersession_history":[],"effective_at":"1970-01-01T00:00:10Z","binding_payload_sha3_256":"",
            "proofs":{"identity_root":{"algorithm":"FN-DSA-1024","signature":""}}
        })).unwrap();
        let payload = canonical_binding_payload(&binding).unwrap();
        binding.binding_payload_sha3_256 = hash(&payload);
        let mut message = AUTH_BINDING_SIGNATURE_DOMAIN.to_vec();
        message.extend(payload);
        binding.proofs.identity_root.signature =
            hex::encode(fndsa1024::detached_sign(&message, root_secret).as_bytes());
        binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
            principal_id: "account".into(),
            algorithm: "ML-DSA-87".into(),
            signature: hex::encode(mldsa87::detached_sign(&message, &secret).as_bytes()),
        }];
        (
            IdentityAuthorizationCarrier {
                schema_version: AUTHORIZATION_CARRIER_SCHEMA_VERSION,
                signature_domain: AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN.into(),
                binding,
            },
            secret,
            key.as_bytes().to_vec(),
        )
    }
    fn transaction(
        carrier: &IdentityAuthorizationCarrier,
        secret: &mldsa87::SecretKey,
        key: &[u8],
        nonce: u64,
    ) -> SignedTransaction {
        let unsigned = UnsignedTransaction {
            network: NetworkBinding::new(9001, "public-network").unwrap(),
            class: TransactionClass::User,
            sender: carrier.binding.identity_address.clone(),
            receiver: synergy_address::derive_object_address("synq", b"receiver").unwrap(),
            amount_nwei: 7,
            nonce,
            fee_limit: FeeLimit {
                gas_limit: 21000,
                max_fee_per_gas_nwei: 2,
            },
            timestamp_unix: 10,
            payload: vec![],
        };
        let signature = mldsa87::detached_sign(&unsigned.signing_bytes().unwrap(), secret)
            .as_bytes()
            .to_vec();
        SignedTransaction {
            unsigned,
            signer_public_key: key.to_vec(),
            signature,
            signature_algorithm: "ML-DSA-87".into(),
            identity_authorization: Some(carrier.clone()),
        }
    }
    fn world(sender: &str, balance: u128) -> WorldState {
        let mut state = WorldState::default();
        state.accounts.insert(
            sender.into(),
            synergy_state::AccountState {
                balance_nwei: balance,
                ..Default::default()
            },
        );
        state.protocol.insert(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            b"{}".to_vec(),
        );
        state
    }
    fn execute(
        txs: Vec<SignedTransaction>,
        parent: &WorldState,
    ) -> Result<BlockExecutionOutcome, BlockExecutionError> {
        BlockExecutionScheduler::new(
            crate::NativeTransferDispatcher,
            RealVerifier,
            FeeSchedule {
                base_fee_per_gas_nwei: 1,
                collector: "fees".into(),
            },
        )
        .unwrap()
        .execute_async_at(
            &BlockBody { transactions: txs },
            &NetworkBinding::new(9001, "public-network").unwrap(),
            5,
            10,
            parent,
            parent,
        )
    }
    #[test]
    fn unregistered_real_crypto_sender_binds_atomically_and_replays_deterministically() {
        let (root, root_secret) = fndsa1024::keypair();
        let (c, s, k) = identity(&root, &root_secret);
        let sender = &c.binding.identity_address;
        let parent = world(sender, 100000);
        let first = transaction(&c, &s, &k, 0);
        let second = transaction(&c, &s, &k, 1);
        let outcome = execute(vec![first.clone(), second.clone()], &parent).unwrap();
        assert!(outcome
            .receipts
            .iter()
            .all(|r| r.status == ReceiptStatus::Applied));
        assert_eq!(outcome.state.accounts[sender].nonce, 2);
        assert_eq!(
            outcome.state.accounts[sender].balance_nwei,
            100000 - 42000 - 14
        );
        assert!(
            canonical_binding_commitment_if_present(&parent.protocol, sender)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            canonical_binding_commitment(&outcome.state.protocol, sender)
                .unwrap()
                .binding_payload_sha3_256,
            c.binding.binding_payload_sha3_256
        );
        let replay = execute(vec![first.clone(), second], &parent).unwrap();
        assert_eq!(outcome.state_root, replay.state_root);
        assert_eq!(outcome.receipts, replay.receipts);
        let stale = execute(vec![first], &outcome.state).unwrap();
        assert_eq!(stale.receipts[0].status, ReceiptStatus::Reverted);
        assert_eq!(stale.state, outcome.state);
    }
    #[test]
    fn independent_first_use_bindings_merge_and_imported_carriers_preserve_existing_authority() {
        let (root_a, secret_a) = fndsa1024::keypair();
        let (root_b, secret_b) = fndsa1024::keypair();
        let (a, signing_a, key_a) = identity(&root_a, &secret_a);
        let (b, signing_b, key_b) = identity(&root_b, &secret_b);
        let sender_a = &a.binding.identity_address;
        let sender_b = &b.binding.identity_address;
        let mut parent = world(sender_a, 100000);
        parent
            .accounts
            .insert(sender_b.clone(), parent.accounts[sender_a].clone());
        let first_a = transaction(&a, &signing_a, &key_a, 0);
        let first_b = transaction(&b, &signing_b, &key_b, 0);
        let first = execute(vec![first_a.clone(), first_b.clone()], &parent).unwrap();
        assert!(first
            .receipts
            .iter()
            .all(|r| r.status == ReceiptStatus::Applied));
        for carrier in [&a, &b] {
            assert_eq!(
                canonical_binding_commitment(
                    &first.state.protocol,
                    &carrier.binding.identity_address
                )
                .unwrap()
                .binding_payload_sha3_256,
                carrier.binding.binding_payload_sha3_256
            );
        }
        assert_eq!(first.state.accounts[sender_a].nonce, 1);
        assert_eq!(first.state.accounts[sender_b].nonce, 1);
        let reversed = execute(vec![first_b, first_a], &parent).unwrap();
        assert_eq!(first.state, reversed.state);

        // Import/recovery preserves the original signed carrier and delegated
        // key; it does not create a new enrollment or replace canonical authority.
        let imported: IdentityAuthorizationCarrier =
            serde_json::from_slice(&serde_json::to_vec(&a).unwrap()).unwrap();
        let bindings = first.state.protocol[IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY].clone();
        let next = execute(
            vec![transaction(&imported, &signing_a, &key_a, 1)],
            &first.state,
        )
        .unwrap();
        assert_eq!(next.receipts[0].status, ReceiptStatus::Applied);
        assert_eq!(next.state.accounts[sender_a].nonce, 2);
        assert_eq!(
            next.state.protocol[IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY],
            bindings
        );
        assert_eq!(
            next.state.accounts[sender_b],
            first.state.accounts[sender_b]
        );
    }
    #[test]
    fn conflicting_concurrent_binding_invalid_proof_and_failed_fee_never_take_over() {
        let (root, root_secret) = fndsa1024::keypair();
        let (c, s, k) = identity(&root, &root_secret);
        let (other, os, ok) = identity(&root, &root_secret);
        let sender = &c.binding.identity_address;
        let parent = world(sender, 100000);
        let first = transaction(&c, &s, &k, 0);
        assert!(execute(vec![transaction(&c, &s, &k, 1)], &parent).is_err());
        let competing = transaction(&other, &os, &ok, 1);
        assert!(execute(vec![first.clone(), competing.clone()], &parent).is_err());
        let finalized = execute(vec![first.clone()], &parent).unwrap();
        assert!(execute(vec![competing], &finalized.state).is_err());
        let mut forged = first.clone();
        forged.signature[0] ^= 1;
        assert!(execute(vec![forged], &parent).is_err());
        let mut forged = first.clone();
        forged
            .identity_authorization
            .as_mut()
            .unwrap()
            .binding
            .proofs
            .identity_root
            .signature
            .replace_range(..1, "z");
        assert!(execute(vec![forged], &parent).is_err());
        let mut other_chain = first.clone();
        other_chain.unsigned.network.chain_id = 9002;
        assert!(execute(vec![other_chain], &parent).is_err());
        let poor = world(sender, 10);
        let reverted = execute(vec![first.clone()], &poor).unwrap();
        assert_eq!(reverted.receipts[0].status, ReceiptStatus::Reverted);
        assert!(
            canonical_binding_commitment_if_present(&reverted.state.protocol, sender)
                .unwrap()
                .is_none()
        );
        assert!(!reverted
            .state
            .accounts
            .contains_key(&first.unsigned.receiver));
        assert_eq!(reverted.state.accounts[sender].balance_nwei, 10);
        assert_eq!(reverted.state.accounts[sender].nonce, 1);
        assert_eq!(reverted.state.protocol, poor.protocol);
        let replay = execute(vec![first.clone()], &reverted.state).unwrap();
        assert_eq!(replay.receipts[0].status, ReceiptStatus::Reverted);
        assert_eq!(replay.state, reverted.state);
        let mut malformed = parent.clone();
        malformed.protocol.insert(
            IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
            b"bad".to_vec(),
        );
        assert!(execute(vec![first], &malformed).is_err());
    }
}
