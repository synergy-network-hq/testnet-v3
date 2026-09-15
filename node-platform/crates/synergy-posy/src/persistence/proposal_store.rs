use std::path::PathBuf;

use super::CanonicalObjectStore;
use crate::{
    validate_proposal, ConsensusSignatureVerifier, FrozenValidatorRegistry, PosyResult,
    SimplifiedEpochContext, SimplifiedProposal,
};

#[derive(Debug)]
/// Durable immutable storage for signature-verified proposals.
pub struct VerifiedProposalStore(CanonicalObjectStore<SimplifiedProposal>);

impl VerifiedProposalStore {
    /// Opens the proposal namespace beneath `root`.
    pub fn new(root: impl Into<PathBuf>) -> PosyResult<Self> {
        CanonicalObjectStore::new(root, "proposals").map(Self)
    }

    /// Verifies and stores a proposal before any durable-state mutation.
    pub fn put_verified(
        &self,
        proposal: &SimplifiedProposal,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<bool> {
        validate_proposal(proposal, epoch, validators, verifier)?;
        self.0.put_once(
            &key(proposal.context.height, proposal.context.round),
            proposal,
        )
    }

    /// Loads the proposal bound to a consensus slot, when present.
    pub fn get(&self, height: u64, round: u64) -> PosyResult<Option<SimplifiedProposal>> {
        self.0.get(&key(height, round))
    }
}

fn key(height: u64, round: u64) -> String {
    format!("h{height}-r{round}")
}
