use crate::{EtdagError, MIN_TARGET_HEIGHT_OFFSET};

pub fn protected_target_height(finalized_height: u64) -> Result<u64, EtdagError> {
    finalized_height
        .checked_add(MIN_TARGET_HEIGHT_OFFSET)
        .ok_or(EtdagError::InvalidTargetOffset)
}
