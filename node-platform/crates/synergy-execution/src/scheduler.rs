use synergy_block::{Block, BlockBody};
use synergy_state::{state_root, StateOverlay, WorldState};
use synergy_transaction::{
    verify_aegis_signature, AegisTransactionVerifier, NetworkBinding, ReceiptStatus,
    TransactionReceipt,
};

use crate::{
    BlockExecutionError, BlockExecutionOutcome, FeeSchedule, TransactionExecutionContext,
    TransactionExecutor,
};

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

    pub fn execute(
        &self,
        body: &BlockBody,
        network: &NetworkBinding,
        block_height: u64,
        base_state: &WorldState,
    ) -> Result<BlockExecutionOutcome, BlockExecutionError> {
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

        let mut overlay = StateOverlay::new(base_state.clone());
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
            verify_aegis_signature(transaction, &self.verifier).map_err(|source| {
                BlockExecutionError::Signature {
                    transaction_index,
                    source,
                }
            })?;
            let transaction_id =
                transaction
                    .id()
                    .map_err(|source| BlockExecutionError::Transaction {
                        transaction_index,
                        source,
                    })?;
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
            let dispatch = self
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
            overlay
                .apply(&dispatch.state_diff)
                .map_err(|source| BlockExecutionError::State {
                    transaction_index,
                    source,
                })?;
            let (settlement, fee_diff) =
                self.fees
                    .settle(transaction, dispatch.gas_used, transaction_index)?;
            overlay
                .apply(&fee_diff)
                .map_err(|source| BlockExecutionError::State {
                    transaction_index,
                    source,
                })?;
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
            state: overlay.staged().clone(),
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
        let outcome = self.execute(
            &block.body,
            &block.header.network,
            block.header.height,
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

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
