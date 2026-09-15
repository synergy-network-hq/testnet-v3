use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedOrderingProof {
    pub proof_version: u32,
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub certified_cut_root: EtdagDigest,
    pub order_seed: EtdagDigest,
    pub ordered_vertex_ids: Vec<EtdagDigest>,
    pub order_root: EtdagDigest,
}

impl ProtectedOrderingProof {
    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        self.certified_cut_root.validate()?;
        self.order_seed.validate()?;
        self.order_root.validate()?;
        if self.proof_version != 1 || self.target_height == 0 || self.ordered_vertex_ids.is_empty()
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        Ok(())
    }
}
