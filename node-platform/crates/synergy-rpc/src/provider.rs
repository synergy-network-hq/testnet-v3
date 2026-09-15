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
}

/// Protocol-neutral access to canonical finalized data.
///
/// Implementations are responsible for revalidating durable ownership
/// boundaries before returning data. Missing records are represented by
/// `None`; corrupt or unverifiable records fail closed.
pub trait CanonicalReadProvider: Send + Sync {
    fn latest_finalized_height(&self) -> Result<Option<u64>, RpcError>;

    fn block(&self, query: &BlockQuery) -> Result<Option<FinalizedBlockView>, RpcError>;

    fn transaction(
        &self,
        query: &TransactionQuery,
    ) -> Result<Option<FinalizedTransactionView>, RpcError>;

    fn account(&self, query: &AccountQuery) -> Result<Option<FinalizedAccountView>, RpcError>;
}
