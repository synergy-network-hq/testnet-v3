use crate::{execution::PreparedProtectedBatch, EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutcome {
    pub target_height: u64,
    pub protected_batch_root: EtdagDigest,
    pub state_root: EtdagDigest,
    pub receipt_root: EtdagDigest,
}

/// Execution consumes an already-finality-authorized deterministic batch. The
/// adapter exposes no proposal, vote, QC, height progression, or finality API.
pub trait ExecutionAdapter {
    fn execute_protected_batch(
        &mut self,
        batch: &PreparedProtectedBatch,
    ) -> Result<ExecutionOutcome, EtdagError>;

    fn may_determine_finality(&self) -> bool {
        false
    }
}
