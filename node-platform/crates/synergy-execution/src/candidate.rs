use serde::{Deserialize, Serialize};
use synergy_block::hash_block_bytes;
use synergy_state::{state_root, WorldState};
use synergy_transaction::{SignedTransaction, TransactionReceipt};

/// Complete deterministic execution material committed by a candidate block.
///
/// PoSy certifies the block and protected-execution commitments; execution
/// remains responsible for recomputing this structure before state import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCandidate {
    pub height: u64,
    pub block_id: String,
    pub parent_block_id: String,
    pub protected_execution_root: String,
    pub state_root: String,
    pub transactions: Vec<SignedTransaction>,
    pub receipts: Vec<TransactionReceipt>,
    pub state: WorldState,
}

impl ExecutionCandidate {
    /// Verifies structural, account-root, and canonical block commitments.
    pub fn validate(&self) -> Result<(), String> {
        if self.height == 0
            || self.parent_block_id.trim().is_empty()
            || self.protected_execution_root.trim().is_empty()
            || self.transactions.len() != self.receipts.len()
            || state_root(&self.state)
                .map_err(|error| format!("root candidate state: {error:?}"))?
                != self.state_root
        {
            return Err("execution candidate has invalid shape or account root".into());
        }
        if self.commitment_id()? != self.block_id {
            return Err("execution candidate block commitment mismatch".into());
        }
        Ok(())
    }

    /// Recomputes the canonical block identifier from committed execution data.
    pub fn commitment_id(&self) -> Result<String, String> {
        serde_json::to_vec(&(
            self.height,
            &self.parent_block_id,
            &self.protected_execution_root,
            &self.state_root,
            &self.transactions,
            &self.receipts,
        ))
        .map(|bytes| hash_block_bytes(&bytes))
        .map_err(|error| format!("encode execution candidate commitment: {error}"))
    }
}
