use serde::{Deserialize, Serialize};

use crate::{EncryptedTransactionEnvelope, EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionVertex {
    pub vertex_id: EtdagDigest,
    pub target_context_root: EtdagDigest,
    pub target_height: u64,
    pub envelope: EncryptedTransactionEnvelope,
    pub parents: Vec<EtdagDigest>,
    pub author_id: String,
    pub author_signature: Vec<u8>,
}

impl TransactionVertex {
    pub fn validate(&self) -> Result<(), EtdagError> {
        self.vertex_id.validate()?;
        self.target_context_root.validate()?;
        self.envelope.validate()?;
        if self.target_height == 0
            || self.target_context_root != self.envelope.target_context_root
            || self.target_height != self.envelope.target_height
            || self.author_id.trim().is_empty()
            || self.author_signature.is_empty()
            || self.parents.iter().any(|parent| parent == &self.vertex_id)
        {
            return Err(EtdagError::InvalidEnvelope(
                "invalid ETDAG transaction vertex".into(),
            ));
        }
        crate::dag::canonical_parents(&self.parents, crate::dag::MAX_VERTEX_PARENTS)?;
        Ok(())
    }
}
