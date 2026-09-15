use crate::recovery::PreparedConsensusState;
use crate::{PosyError, PosyResult, SimplifiedEpochContext, SimplifiedProposal};

/// Validates a recovered proposal against the persisted single-driver checkpoint
/// without advancing height, round, locks, or finality.
pub fn validate_recovered_proposal(
    proposal: &SimplifiedProposal,
    prepared: &PreparedConsensusState,
    epoch: &SimplifiedEpochContext,
) -> PosyResult<()> {
    prepared.validate(epoch)?;
    proposal.context.validate_against(epoch)?;
    proposal.validate_shape()?;
    if proposal.context.height != prepared.active_height
        || proposal.context.round > prepared.active_round
        || proposal.parent != prepared.highest_parent
        || proposal.takeover_tc_id != prepared.takeover_tc_id
    {
        return Err(PosyError::invalid(
            "recovered proposal does not match prepared PoSy state",
        ));
    }
    Ok(())
}
