use synergy_transaction::TransactionReceipt;

use crate::{receipt_root, Block, BlockBody, BlockError, BlockHeader};

#[derive(Debug, Default)]
pub struct BlockBuilder {
    transactions: Vec<synergy_transaction::SignedTransaction>,
    receipts: Vec<TransactionReceipt>,
}

impl BlockBuilder {
    pub fn push(
        &mut self,
        transaction: synergy_transaction::SignedTransaction,
        receipt: TransactionReceipt,
    ) -> Result<(), BlockError> {
        if transaction.id().map_err(BlockError::Transaction)? != receipt.transaction_id
            || !receipt.validate()
        {
            return Err(BlockError::InvalidReceipt);
        }
        self.transactions.push(transaction);
        self.receipts.push(receipt);
        Ok(())
    }

    pub fn build(
        self,
        network: synergy_transaction::NetworkBinding,
        height: u64,
        parent_block_id: impl Into<String>,
        timestamp_unix: u64,
        proposer_id: impl Into<String>,
        state_root: impl Into<String>,
        proposer_signature: Vec<u8>,
        proposer_signature_algorithm: impl Into<String>,
    ) -> Result<Block, BlockError> {
        let body = BlockBody {
            transactions: self.transactions,
        };
        let header = BlockHeader {
            network,
            height,
            parent_block_id: parent_block_id.into(),
            timestamp_unix,
            proposer_id: proposer_id.into(),
            transaction_root: body.transaction_root()?,
            receipt_root: receipt_root(&self.receipts)?,
            state_root: state_root.into(),
        };
        let block = Block {
            header,
            body,
            receipts: self.receipts,
            proposer_signature,
            proposer_signature_algorithm: proposer_signature_algorithm.into(),
        };
        block.validate_structure()?;
        Ok(block)
    }
}
