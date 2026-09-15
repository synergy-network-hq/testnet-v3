use serde::Serialize;

use crate::{
    is_hash, BlockVote, ConsensusSignatureVerifier, FrozenValidatorRegistry, PosyError, PosyResult,
    SimplifiedEpochContext, TimeoutVote, POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
    POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
};

#[derive(Serialize)]
struct VotePayload<'a> {
    context: &'a crate::ConsensusObjectContext,
    block_id: &'a str,
    parent_block_id: &'a str,
    parent: &'a crate::SimplifiedFinalityParent,
    takeover_tc_id: &'a Option<String>,
    protected_execution_root: &'a str,
    validator_id: &'a str,
    key_id: &'a str,
}

#[derive(Serialize)]
struct TimeoutPayload<'a> {
    context: &'a crate::ConsensusObjectContext,
    lease_index: u64,
    timed_out_proposer: &'a str,
    highest_parent: &'a crate::SimplifiedFinalityParent,
    previous_tc_id: &'a Option<String>,
    last_voted_candidate: &'a Option<crate::CertifiedCandidateSubject>,
    validator_id: &'a str,
    key_id: &'a str,
}

pub fn block_vote_signing_bytes(vote: &BlockVote) -> PosyResult<Vec<u8>> {
    serde_json::to_vec(&VotePayload {
        context: &vote.context,
        block_id: &vote.block_id,
        parent_block_id: &vote.parent_block_id,
        parent: &vote.parent,
        takeover_tc_id: &vote.takeover_tc_id,
        protected_execution_root: &vote.protected_execution_root,
        validator_id: &vote.validator_id,
        key_id: &vote.key_id,
    })
    .map_err(|error| PosyError::invalid(format!("serialize block vote: {error}")))
}

pub fn timeout_vote_signing_bytes(vote: &TimeoutVote) -> PosyResult<Vec<u8>> {
    serde_json::to_vec(&TimeoutPayload {
        context: &vote.context,
        lease_index: vote.lease_index,
        timed_out_proposer: &vote.timed_out_proposer,
        highest_parent: &vote.highest_parent,
        previous_tc_id: &vote.previous_tc_id,
        last_voted_candidate: &vote.last_voted_candidate,
        validator_id: &vote.validator_id,
        key_id: &vote.key_id,
    })
    .map_err(|error| PosyError::invalid(format!("serialize timeout vote: {error}")))
}

pub fn validate_block_vote(
    vote: &BlockVote,
    epoch_context: &SimplifiedEpochContext,
    validators: &FrozenValidatorRegistry,
    verifier: &impl ConsensusSignatureVerifier,
) -> PosyResult<()> {
    vote.context.validate_against(epoch_context)?;
    vote.parent.validate_for_child_height(vote.context.height)?;
    if vote.parent_block_id != vote.parent.block_id()
        || vote.block_id.trim().is_empty()
        || !is_hash(&vote.protected_execution_root)
        || vote
            .takeover_tc_id
            .as_deref()
            .is_some_and(|id| !is_hash(id))
    {
        return Err(PosyError::invalid("invalid block-vote transcript"));
    }
    let validator = validators.active_validator(&vote.validator_id)?;
    if validator.consensus_key_id != vote.key_id {
        return Err(PosyError::invalid(
            "block vote uses non-frozen consensus key",
        ));
    }
    verifier.verify_consensus_signature(
        POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
        &block_vote_signing_bytes(vote)?,
        validator,
        &vote.key_id,
        vote.context.epoch,
        &vote.signature,
    )
}

pub fn validate_timeout_vote(
    vote: &TimeoutVote,
    epoch_context: &SimplifiedEpochContext,
    validators: &FrozenValidatorRegistry,
    verifier: &impl ConsensusSignatureVerifier,
) -> PosyResult<()> {
    vote.context.validate_against(epoch_context)?;
    if vote.lease_index != epoch_context.lease_index(vote.context.height)?
        || vote.timed_out_proposer
            != epoch_context.authorized_proposer(vote.context.height, vote.context.round)?
        || vote
            .previous_tc_id
            .as_deref()
            .is_some_and(|id| !is_hash(id))
    {
        return Err(PosyError::invalid("invalid timeout vote closure"));
    }
    let next_parent_height = vote
        .highest_parent
        .height()
        .checked_add(1)
        .ok_or_else(|| PosyError::invalid("timeout parent height overflow"))?;
    vote.highest_parent
        .validate_for_child_height(next_parent_height)?;
    if vote.highest_parent.height() >= vote.context.height {
        return Err(PosyError::invalid(
            "timeout vote carries a future highest finality parent",
        ));
    }
    if let Some(candidate) = &vote.last_voted_candidate {
        candidate.validate()?;
        if candidate.context.height != vote.context.height
            || candidate.context.epoch_context_root != vote.context.epoch_context_root
        {
            return Err(PosyError::invalid(
                "timeout candidate is from another height or epoch context",
            ));
        }
    }
    let validator = validators.active_validator(&vote.validator_id)?;
    if validator.consensus_key_id != vote.key_id {
        return Err(PosyError::invalid(
            "timeout vote uses non-frozen consensus key",
        ));
    }
    verifier.verify_consensus_signature(
        POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
        &timeout_vote_signing_bytes(vote)?,
        validator,
        &vote.key_id,
        vote.context.epoch,
        &vote.signature,
    )
}
