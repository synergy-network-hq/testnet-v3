use serde::{Deserialize, Serialize};
use synergy_protocol_types::NodeAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalStatus {
    Pending,
    Settled,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewardWithdrawalRequest {
    pub withdrawal_id: String,
    pub node_address: NodeAddress,
    pub owner_wallet: String,
    pub destination_wallet: String,
    pub amount_nwei: u128,
    pub nonce: u64,
    pub owner_proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawalRecord {
    pub record_version: u32,
    pub withdrawal_id: String,
    pub node_address: NodeAddress,
    /// Historical authorizer only; current ownership comes from node ownership.
    pub authorized_by_wallet: String,
    pub destination_wallet: String,
    pub amount_nwei: u128,
    pub authorization_nonce: u64,
    pub status: WithdrawalStatus,
    pub created_height: u64,
    pub completed_height: Option<u64>,
}
