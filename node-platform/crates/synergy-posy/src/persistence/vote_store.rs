use std::path::PathBuf;

use super::CanonicalObjectStore;
use crate::{
    validate_block_vote, BlockVote, ConsensusSignatureVerifier, FrozenValidatorRegistry,
    PosyResult, SimplifiedEpochContext,
};

#[derive(Debug)]
/// Durable immutable storage for signature-verified block votes.
pub struct VerifiedVoteStore(CanonicalObjectStore<BlockVote>);

impl VerifiedVoteStore {
    /// Opens the vote namespace beneath `root`.
    pub fn new(root: impl Into<PathBuf>) -> PosyResult<Self> {
        CanonicalObjectStore::new(root, "votes").map(Self)
    }

    /// Verifies a vote and immutably binds it to its validator and slot.
    pub fn put_verified(
        &self,
        vote: &BlockVote,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<bool> {
        validate_block_vote(vote, epoch, validators, verifier)?;
        self.0.put_once(
            &key(vote.context.height, vote.context.round, &vote.validator_id)?,
            vote,
        )
    }

    /// Loads one validator's vote for the requested consensus slot.
    pub fn get(
        &self,
        height: u64,
        round: u64,
        validator_id: &str,
    ) -> PosyResult<Option<BlockVote>> {
        self.0.get(&key(height, round, validator_id)?)
    }
}

fn key(height: u64, round: u64, validator_id: &str) -> PosyResult<String> {
    Ok(format!(
        "h{height}-r{round}-{}",
        crate::canonical_hash("Synergy/PoSy/v3/vote-store-key", &validator_id)?
    ))
}
