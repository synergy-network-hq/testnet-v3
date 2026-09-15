use serde::{Deserialize, Serialize};

use crate::{
    canonical_hash, is_hash, FinalizedBlockRecord, PosyError, PosyResult, SimplifiedEpochContext,
};

/// Finalized authority for preparing membership changes in the next epoch.
///
/// This type cannot alter the active frozen registry. It binds a change-set
/// commitment to the finality certificate that closes the preceding epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipAuthority {
    pub previous_epoch: u64,
    pub previous_epoch_context_root: String,
    pub finalized_height: u64,
    pub finality_certificate_id: String,
    pub target_epoch: u64,
    pub change_set_root: String,
}

impl MembershipAuthority {
    /// Validates this authority against an epoch context and finalized record.
    pub fn validate(
        &self,
        previous: &SimplifiedEpochContext,
        finalized: &FinalizedBlockRecord,
    ) -> PosyResult<()> {
        let target_epoch = previous
            .epoch
            .checked_add(1)
            .ok_or_else(|| PosyError::invalid("membership target epoch overflow"))?;
        if self.previous_epoch != previous.epoch
            || self.previous_epoch_context_root != previous.root()?
            || self.finalized_height != previous.epoch_end_height
            || self.finalized_height != finalized.height
            || self.finality_certificate_id != finalized.finality_certificate_id
            || self.target_epoch != target_epoch
            || !is_hash(&self.finality_certificate_id)
            || !is_hash(&self.change_set_root)
        {
            return Err(PosyError::invalid(
                "membership authority is not bound to finalized epoch closure",
            ));
        }
        Ok(())
    }

    /// Returns the canonical identifier referenced by next-epoch changes.
    pub fn id(&self) -> PosyResult<String> {
        canonical_hash("Synergy/PoSy/v3/membership-authority", self)
    }
}
