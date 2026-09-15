use serde::{Deserialize, Serialize};

/// Verified synchronization boundary; advertised height alone is never sufficient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynchronizationEvidence {
    pub local_finalized_height: u64,
    pub target_finalized_height: u64,
    pub finalized_block_id: String,
    pub finality_evidence_verified: bool,
}

impl SynchronizationEvidence {
    pub fn synchronized(&self) -> bool {
        self.finality_evidence_verified
            && !self.finalized_block_id.is_empty()
            && self.local_finalized_height >= self.target_finalized_height
    }
}
