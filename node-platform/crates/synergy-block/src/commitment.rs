use sha3::{Digest, Sha3_256};

use synergy_transaction::{TransactionId, TransactionReceipt};

use crate::BlockError;

pub fn transaction_root(transactions: &[TransactionId]) -> Result<String, BlockError> {
    let leaves = transactions
        .iter()
        .map(|transaction| {
            transaction.validate().map_err(BlockError::Transaction)?;
            Ok(transaction.0.as_bytes().to_vec())
        })
        .collect::<Result<Vec<_>, _>>()?;
    merkle_root(b"SYNERGY_BLOCK_TRANSACTION_ROOT_V1", leaves)
}

pub fn receipt_root(receipts: &[TransactionReceipt]) -> Result<String, BlockError> {
    let leaves = receipts
        .iter()
        .map(|receipt| {
            if !receipt.validate() {
                return Err(BlockError::InvalidReceipt);
            }
            receipt
                .commitment()
                .map(|commitment| commitment.into_bytes())
                .ok_or(BlockError::InvalidReceipt)
        })
        .collect::<Result<Vec<_>, _>>()?;
    merkle_root(b"SYNERGY_BLOCK_RECEIPT_ROOT_V1", leaves)
}

pub fn hash_block_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b"SYNERGY_BLOCK_ID_V1");
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn merkle_root(domain: &[u8], mut leaves: Vec<Vec<u8>>) -> Result<String, BlockError> {
    if leaves.is_empty() {
        return Ok(hash_block_bytes(domain));
    }
    leaves = leaves
        .into_iter()
        .map(|leaf| {
            let mut bytes = Vec::with_capacity(domain.len() + leaf.len());
            bytes.extend_from_slice(domain);
            bytes.extend_from_slice(&leaf);
            hash_block_bytes(&bytes).into_bytes()
        })
        .collect();
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut bytes = Vec::with_capacity(pair[0].len() + right.len());
            bytes.extend_from_slice(&pair[0]);
            bytes.extend_from_slice(right);
            next.push(hash_block_bytes(&bytes).into_bytes());
        }
        leaves = next;
    }
    String::from_utf8(leaves.pop().expect("nonempty leaves"))
        .map_err(|_| BlockError::InvalidCommitment)
}
