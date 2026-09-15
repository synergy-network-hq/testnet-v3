use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalChain {
    Bitcoin,
    Ethereum,
    Solana,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SxcpTransfer {
    pub transfer_id: String,
    pub source_chain: ExternalChain,
    pub source_asset: String,
    pub source_transaction: String,
    pub source_height: u64,
    pub destination: String,
    pub amount: u128,
    pub nonce: u64,
}

impl SxcpTransfer {
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.transfer_id.trim().is_empty()
            || self.source_asset.trim().is_empty()
            || self.source_transaction.trim().is_empty()
            || self.destination.trim().is_empty()
            || self.amount == 0
        {
            return Err("invalid SXCP transfer".into());
        }
        Ok(())
    }
}
