use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicProtectedBatch {
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub ordered_vertices: Vec<EtdagDigest>,
    pub order_root: EtdagDigest,
}

impl DeterministicProtectedBatch {
    pub fn new(
        context_root: EtdagDigest,
        target_height: u64,
        ordered_vertices: Vec<EtdagDigest>,
    ) -> Result<Self, EtdagError> {
        let order_root = crate::protected_order_root(&ordered_vertices)?;
        let batch = Self {
            context_root,
            target_height,
            ordered_vertices,
            order_root,
        };
        batch.validate()?;
        Ok(batch)
    }

    pub fn validate(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        self.order_root.validate()?;
        if self.target_height == 0 || self.ordered_vertices.is_empty() {
            return Err(EtdagError::InvalidExecutionInput);
        }
        for vertex in &self.ordered_vertices {
            vertex.validate()?;
        }
        let mut seen = std::collections::BTreeSet::new();
        if self.ordered_vertices.iter().any(|id| !seen.insert(id))
            || crate::protected_order_root(&self.ordered_vertices)? != self.order_root
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        Ok(())
    }
}
