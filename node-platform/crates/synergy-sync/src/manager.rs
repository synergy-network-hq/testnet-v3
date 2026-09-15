use crate::{SourceSelectionError, SyncPeerCandidate, VerifiedHead, VerifiedSourceSelector};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPlan {
    pub target_height: u64,
    pub target_block_id: String,
    pub sources: Vec<VerifiedHead>,
}

#[derive(Debug, Clone)]
pub struct SyncManager {
    selector: VerifiedSourceSelector,
}

impl SyncManager {
    pub fn new(local_genesis_hash: impl Into<String>) -> Self {
        Self {
            selector: VerifiedSourceSelector::new(local_genesis_hash),
        }
    }

    pub fn plan(
        &self,
        candidates: &[SyncPeerCandidate],
        verified_heads: &[VerifiedHead],
    ) -> Result<SyncPlan, SourceSelectionError> {
        let sources = self.selector.select(candidates, verified_heads)?;
        let head = sources
            .first()
            .ok_or(SourceSelectionError::NoEligibleVerifiedSource)?;
        Ok(SyncPlan {
            target_height: head.finalized_height,
            target_block_id: head.finalized_hash.clone(),
            sources,
        })
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
