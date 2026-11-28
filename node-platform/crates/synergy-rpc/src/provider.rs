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
    /// Omitted for full retained candidates. Compact data is not an inclusion proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub representation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payloads_available: Option<bool>,
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
    /// Optional shared-process response reservation. Socket owners retain it
    /// through serialization and the final write, not only through store lookup.
    fn reserve_response_capacity(&self) -> Result<Option<RpcResponseCapacity>, RpcError> {
        Ok(None)
    }
    fn reserve_response_capacity_for(&self, _method: &str) -> Result<Option<RpcResponseCapacity>, RpcError> {
        self.reserve_response_capacity()
    }
    fn reserve_current_read_input(&self, _encoded_bytes: usize) -> Result<RpcResponseCapacity, RpcError> {
        Err(RpcError::unavailable("current read input capacity unavailable"))
    }
    fn preflight_current_read(&self, _method: &str, _params: &Value) -> Result<(), RpcError> {
        Err(RpcError::unavailable("current read native preflight unavailable"))
    }
    fn reserve_current_read_aggregate(&self, _encoded_bytes: usize) -> Result<RpcResponseCapacity, RpcError> {
        Err(RpcError::unavailable("current read aggregate capacity unavailable"))
    }
    /// Selects the read contract only. This is not an authentication token;
    /// production R1 owners require the private verified Genesis constructor.
    fn read_contract(&self) -> ReadContract {
        ReadContract::HistoricalV1
    }
    /// Public context data, not an authority constructor. Current native owners
    /// expose the coordinate held by their private verified Genesis provider.
    fn current_read_coordinate(&self) -> Option<&synergy_protocol_types::R1NetworkCoordinate> {
        None
    }

    /// Full-width R1 requests never fall through to historical32 read methods.
    fn r1_read(&self, _method: &str, _params: Value) -> Result<Value, RpcError> {
        Err(RpcError::unavailable("authenticated R1 read provider unavailable"))
    }
    /// Ethereum views must be served from the same authenticated finalized
    /// native World. The default grants no compatibility capability.
    fn ethereum_query(&self, _method: &str, _params: &Value) -> Result<Value, RpcError> {
        Err(RpcError::unavailable("signed Ethereum compatibility is unavailable"))
    }

    /// Original canonical commitment bytes, bounded and pinned by height.
    /// A page is evidence transport; clients still authenticate its three-QC witness.
    fn finalized_proof_page(&self, _query: &Value) -> Result<Value, RpcError> {
        Err(RpcError::unavailable("finalized proof pages unavailable"))
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadContract {
    HistoricalV1,
    NativeR1V1,
}

/// An owning allocation guard, not an authentication or activation token.
pub struct RpcResponseCapacity {
    maximum_encoded_bytes: usize,
    _guard: Box<dyn Send>,
}
impl RpcResponseCapacity {
    pub fn new(maximum_encoded_bytes: usize, guard: Box<dyn Send>) -> Result<Self, RpcError> {
        if maximum_encoded_bytes < 256 {
            return Err(RpcError::unavailable("invalid response capacity"));
        }
        Ok(Self { maximum_encoded_bytes, _guard: guard })
    }
    pub fn maximum_encoded_bytes(&self) -> usize { self.maximum_encoded_bytes }
}
