use serde::{Deserialize, Serialize};

use synergy_transaction::NetworkBinding;

use crate::{hash_block_bytes, BlockError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub network: NetworkBinding,
    pub height: u64,
    pub parent_block_id: String,
    pub timestamp_unix: u64,
    pub proposer_id: String,
    pub transaction_root: String,
    pub receipt_root: String,
    pub state_root: String,
}

impl BlockHeader {
    pub fn validate_structure(&self) -> Result<(), BlockError> {
        self.network.validate().map_err(BlockError::Transaction)?;
        if self.height == 0
            || self.parent_block_id.trim().is_empty()
            || self.timestamp_unix == 0
            || self.proposer_id.trim().is_empty()
            || self.transaction_root.len() != 64
            || self.receipt_root.len() != 64
            || self.state_root.trim().is_empty()
        {
            return Err(BlockError::InvalidHeader);
        }
        Ok(())
    }

    pub fn commitment_bytes(&self) -> Result<Vec<u8>, BlockError> {
        self.validate_structure()?;
        let mut output = Vec::new();
        output.extend_from_slice(b"SYNERGY_BLOCK_HEADER_V1");
        output.extend_from_slice(&self.network.chain_id.to_be_bytes());
        append(&mut output, self.network.network_id.as_bytes());
        output.extend_from_slice(&self.height.to_be_bytes());
        append(&mut output, self.parent_block_id.as_bytes());
        output.extend_from_slice(&self.timestamp_unix.to_be_bytes());
        append(&mut output, self.proposer_id.as_bytes());
        append(&mut output, self.transaction_root.as_bytes());
        append(&mut output, self.receipt_root.as_bytes());
        append(&mut output, self.state_root.as_bytes());
        Ok(output)
    }

    pub fn id(&self) -> Result<String, BlockError> {
        Ok(hash_block_bytes(&self.commitment_bytes()?))
    }
}

fn append(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
}
