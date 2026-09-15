use synergy_etdag::EtdagDigest;
use synergy_state::{FinalizedState, WorldState};
use synergy_transaction::TransactionReceipt;

use crate::BlockExecutionError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutcome {
    pub target_height: u64,
    pub applied_envelope_ids: Vec<EtdagDigest>,
    pub state_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionError<E> {
    Input(crate::ExecutionInputError),
    Transition(E),
    EmptyStateRoot,
}

/// Fully executed candidate state for one block body. This is proposal
/// material only; it has no authority to finalize or persist itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockExecutionOutcome {
    pub block_height: u64,
    pub state: WorldState,
    pub state_root: String,
    pub receipts: Vec<TransactionReceipt>,
    pub total_gas_used: u64,
    pub total_fees_nwei: u128,
}

impl BlockExecutionOutcome {
    /// Constructs metadata accepted by the finalized-state store. The caller
    /// must invoke durable commit only after PoSy verifies finality.
    pub fn finalized_state(
        &self,
        finalized_block_id: impl Into<String>,
    ) -> Result<FinalizedState, BlockExecutionError> {
        let finalized_block_id = finalized_block_id.into();
        if finalized_block_id.trim().is_empty() {
            return Err(BlockExecutionError::InvalidBlockId);
        }
        Ok(FinalizedState {
            finalized_height: self.block_height,
            finalized_block_id,
            state_root: self.state_root.clone(),
        })
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
