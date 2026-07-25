use crate::block::{compute_merkle_root, Block, BlockHeader};
use crate::sync::manager::SyncError;

/// Run light header validations so the sync loop can bail early on malformed data.
pub fn validate_header_chain(
    headers: &[BlockHeader],
    previous_hash: Option<String>,
) -> Result<(), SyncError> {
    let mut expected_parent = previous_hash;

    for header in headers {
        if let Some(expected) = expected_parent.clone() {
            if !expected.is_empty() && header.parent_hash != expected {
                return Err(SyncError::InvalidParentHash {
                    height: header.number,
                    expected,
                    got: header.parent_hash.clone(),
                });
            }
        }

        expected_parent = Some(header.hash.clone());
    }

    Ok(())
}

/// Verify block contents match their header snapshots.
pub fn validate_block(block: &Block) -> Result<(), SyncError> {
    let tx_root = compute_merkle_root(&block.transactions);
    if tx_root != block.transactions_root {
        return Err(SyncError::InvalidTransactionsRoot);
    }

    // Future: validate validator signature and PoSy-specific logic.

    Ok(())
}
