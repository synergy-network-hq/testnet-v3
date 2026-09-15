use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedCutMarker {
    pub marker_version: u32,
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub cut_root: EtdagDigest,
    pub last_included_vertex: EtdagDigest,
    pub included_vertex_count: u64,
}

impl ProtectedCutMarker {
    pub fn validate(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        self.cut_root.validate()?;
        self.last_included_vertex.validate()?;
        if self.marker_version != 1 || self.target_height == 0 || self.included_vertex_count == 0 {
            return Err(EtdagError::InvalidExecutionInput);
        }
        Ok(())
    }
}
