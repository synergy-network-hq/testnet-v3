use serde::{Deserialize, Serialize};
use synergy_transaction::TransactionReceipt;

use crate::{receipt_root, BlockBody, BlockError, BlockHeader};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub receipts: Vec<TransactionReceipt>,
    pub proposer_signature: Vec<u8>,
    pub proposer_signature_algorithm: String,
}

impl Block {
    pub fn id(&self) -> Result<String, BlockError> {
        self.header.id()
    }

    pub fn validate_structure(&self) -> Result<(), BlockError> {
        self.header.validate_structure()?;
        self.body.validate_structure()?;
        if self.header.transaction_root != self.body.transaction_root()? {
            return Err(BlockError::TransactionRootMismatch);
        }
        if self.receipts.len() != self.body.transactions.len() {
            return Err(BlockError::ReceiptCountMismatch);
        }
        for (transaction, receipt) in self.body.transactions.iter().zip(&self.receipts) {
            if transaction.id().map_err(BlockError::Transaction)? != receipt.transaction_id
                || !receipt.validate()
            {
                return Err(BlockError::InvalidReceipt);
            }
        }
        if self.header.receipt_root != receipt_root(&self.receipts)? {
            return Err(BlockError::ReceiptRootMismatch);
        }
        if self.proposer_signature.is_empty() || self.proposer_signature_algorithm.trim().is_empty()
        {
            return Err(BlockError::MissingProposerSignature);
        }
        Ok(())
    }

    pub fn validate_successor_of(&self, parent: &BlockHeader) -> Result<(), BlockError> {
        self.validate_structure()?;
        if self.header.network != parent.network {
            return Err(BlockError::NetworkMismatch);
        }
        if self.header.height
            != parent
                .height
                .checked_add(1)
                .ok_or(BlockError::HeightMismatch)?
        {
            return Err(BlockError::HeightMismatch);
        }
        if self.header.parent_block_id != parent.id()? {
            return Err(BlockError::ParentMismatch);
        }
        if self.header.timestamp_unix < parent.timestamp_unix {
            return Err(BlockError::TimestampRegression);
        }
        Ok(())
    }

    pub fn verify_proposer_signature<V: crate::BlockSignatureVerifier>(
        &self,
        proposer_public_key: &[u8],
        verifier: &V,
    ) -> Result<(), BlockError> {
        self.validate_structure()?;
        let verified = verifier
            .verify(
                &self.header.commitment_bytes()?,
                proposer_public_key,
                &self.proposer_signature,
                &self.proposer_signature_algorithm,
            )
            .map_err(|error| BlockError::SignatureVerifier(error.to_string()))?;
        verified.then_some(()).ok_or(BlockError::InvalidSignature)
    }

    /// Header validity and a cryptographic signature are not a PoSy certificate.
    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
