use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::methods::{AccountQuery, BlockQuery, TransactionQuery};
use crate::RpcError;

/// Public representation of one PoSy-finalized execution candidate.
///
/// The provider must admit only records whose block, state, and finality
/// commitments agree. RPC never decides that a candidate is finalized.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FinalizedBlockView {
    pub height: u64,
    pub block_hash: String,
    pub parent_block_hash: String,
    pub protected_execution_root: String,
    pub state_root: String,
    pub finality_certificate_id: String,
    pub transactions: Vec<Value>,
    pub receipts: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FinalizedTransactionView {
    pub transaction_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub finality_certificate_id: String,
    pub status: String,
    pub transaction: Value,
    pub receipt: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedAccountView {
    pub address: String,
    pub finalized_height: u64,
    pub finalized_block_hash: String,
    pub state_root: String,
    pub balance_nwei: String,
    pub nonce: u64,
    pub code_hash: Option<String>,
    /// Public commitment from this exact finalized world's governed state.
    /// A funded account may legitimately have no transaction authorization.
    #[serde(default)]
    pub authorization_binding: Option<Value>,
}

/// A finalized commitment observation, not an archived account-world read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedBlockCommitment {
    pub height: u64,
    pub block_id: String,
    pub protected_execution_root: String,
    pub state_root: String,
    pub finality_certificate_id: String,
    pub transaction_count: usize,
}

/// Protocol-neutral access to canonical finalized data.
///
/// Implementations are responsible for revalidating durable ownership
/// boundaries before returning data. Missing records are represented by
/// `None`; corrupt or unverifiable records fail closed.
pub trait CanonicalReadProvider: Send + Sync {
    /// Optional process resource observations; these confer no chain authority.
    fn resource_observations(&self) -> Option<Value> {
        None
    }

    /// Resolve wallet aliases only from canonical PoSy-finalized WorldState.
    fn wallet_syn_id(&self, _value: &str, _reverse: bool) -> Result<Value, RpcError> {
        Err(RpcError::unavailable(
            "finalized wallet naming is unavailable",
        ))
    }

    fn latest_finalized_height(&self) -> Result<Option<u64>, RpcError>;

    fn block(&self, query: &BlockQuery) -> Result<Option<FinalizedBlockView>, RpcError>;

    /// Rebind latest and optionally pinned commitments to durable ownership.
    /// Implementations may avoid reading archived worlds; this observation
    /// does not attest their availability. Other query semantics are unchanged.
    fn telemetry_commitments(
        &self,
        at_height: Option<u64>,
    ) -> Result<(Option<u64>, Option<FinalizedBlockCommitment>), RpcError> {
        let latest = self.latest_finalized_height()?;
        let block = at_height
            .or(latest)
            .map(|height| {
                self.block(&BlockQuery {
                    height: Some(height),
                    hash: None,
                })
            })
            .transpose()?
            .flatten();
        Ok((
            latest,
            block.map(|block| FinalizedBlockCommitment {
                height: block.height,
                block_id: block.block_hash,
                protected_execution_root: block.protected_execution_root,
                state_root: block.state_root,
                finality_certificate_id: block.finality_certificate_id,
                transaction_count: block.transactions.len(),
            }),
        ))
    }

    fn transaction(
        &self,
        query: &TransactionQuery,
    ) -> Result<Option<FinalizedTransactionView>, RpcError>;

    fn account(&self, query: &AccountQuery) -> Result<Option<FinalizedAccountView>, RpcError>;
}
