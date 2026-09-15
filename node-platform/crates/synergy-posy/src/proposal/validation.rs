use crate::{
    ConsensusSignatureVerifier, FrozenValidatorRegistry, PosyError, PosyResult,
    SimplifiedEpochContext, SimplifiedProposal, POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
};

pub fn validate_proposal(
    proposal: &SimplifiedProposal,
    epoch_context: &SimplifiedEpochContext,
    validators: &FrozenValidatorRegistry,
    verifier: &impl ConsensusSignatureVerifier,
) -> PosyResult<()> {
    proposal.context.validate_against(epoch_context)?;
    proposal.validate_shape()?;
    let expected =
        epoch_context.authorized_proposer(proposal.context.height, proposal.context.round)?;
    if proposal.proposer_id != expected {
        return Err(PosyError::invalid(
            "proposal is not from the authorized proposer",
        ));
    }
    let proposer = validators.active_validator(&proposal.proposer_id)?;
    if proposal.proposer_key_id != proposer.consensus_key_id {
        return Err(PosyError::invalid(
            "proposal uses a non-frozen consensus key",
        ));
    }
    verifier.verify_consensus_signature(
        POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
        &proposal.signing_bytes()?,
        proposer,
        &proposal.proposer_key_id,
        proposal.context.epoch,
        &proposal.proposer_signature,
    )
}
