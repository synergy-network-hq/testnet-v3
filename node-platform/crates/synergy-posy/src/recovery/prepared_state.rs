use serde::{Deserialize, Serialize};

use crate::{
    is_hash, PosyError, PosyResult, QuorumCertificateReference, SimplifiedEpochContext,
    SimplifiedFinalityParent,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Minimal safety checkpoint required to resume the single PoSy driver.
pub struct PreparedConsensusState {
    pub epoch_context_root: String,
    pub active_height: u64,
    pub active_round: u64,
    pub highest_parent: SimplifiedFinalityParent,
    pub locked_qc: Option<QuorumCertificateReference>,
    pub takeover_tc_id: Option<String>,
    pub last_finalized_height: u64,
}

impl PreparedConsensusState {
    /// Validates slot, ancestry, lock, and epoch bindings without mutation.
    pub fn validate(&self, epoch: &SimplifiedEpochContext) -> PosyResult<()> {
        if self.epoch_context_root != epoch.root()?
            || !epoch.contains_height(self.active_height)
            || self.highest_parent.height().checked_add(1) != Some(self.active_height)
            || self.last_finalized_height > self.highest_parent.height()
            || self
                .takeover_tc_id
                .as_deref()
                .is_some_and(|id| !is_hash(id))
            || self.active_round == 0 && self.takeover_tc_id.is_some()
        {
            return Err(PosyError::invalid("invalid prepared PoSy recovery state"));
        }
        if let Some(locked) = &self.locked_qc {
            if locked.height > self.highest_parent.height() || !is_hash(&locked.qc_id) {
                return Err(PosyError::invalid("prepared state has an invalid QC lock"));
            }
        }
        Ok(())
    }
}
