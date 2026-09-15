use super::PreparedConsensusState;
use crate::{PosyError, PosyResult};

/// Determines whether the local checkpoint may advance to the quorum
/// checkpoint without rolling back or contradicting certified safety state.
pub fn reconcile_local_with_quorum(
    local: &PreparedConsensusState,
    quorum: &PreparedConsensusState,
) -> PosyResult<bool> {
    if local.epoch_context_root != quorum.epoch_context_root {
        return Err(PosyError::Conflict(
            "recovery checkpoints belong to different epochs".into(),
        ));
    }
    if local.last_finalized_height > quorum.last_finalized_height
        || local.highest_parent.height() > quorum.highest_parent.height()
    {
        return Err(PosyError::Conflict(
            "quorum recovery would roll back local safety state".into(),
        ));
    }
    if local.last_finalized_height == quorum.last_finalized_height
        && local.highest_parent.height() == quorum.highest_parent.height()
        && local.highest_parent != quorum.highest_parent
    {
        return Err(PosyError::Conflict(
            "peer recovery conflicts at the same certified height".into(),
        ));
    }
    Ok(local != quorum)
}
