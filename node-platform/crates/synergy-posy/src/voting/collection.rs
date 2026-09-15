use std::collections::BTreeMap;

use crate::{BlockVote, PosyError, PosyResult, SimplifiedQuorumCertificate, VoteDuplicateGuard};

#[derive(Debug, Default)]
pub struct VoteCollection {
    votes: BTreeMap<(u64, u64, String), Vec<BlockVote>>,
    duplicate_guard: VoteDuplicateGuard,
}

impl VoteCollection {
    pub fn insert(&mut self, vote: BlockVote) -> PosyResult<bool> {
        if !self.duplicate_guard.record(&vote)? {
            return Ok(false);
        }
        let key = (
            vote.context.height,
            vote.context.round,
            format!("{}:{}", vote.block_id, vote.protected_execution_root),
        );
        self.votes.entry(key).or_default().push(vote);
        Ok(true)
    }

    pub fn certificate(
        &self,
        height: u64,
        round: u64,
        candidate: &str,
    ) -> PosyResult<SimplifiedQuorumCertificate> {
        self.votes
            .get(&(height, round, candidate.into()))
            .cloned()
            .ok_or_else(|| PosyError::NotReady("no votes for candidate".into()))
            .and_then(SimplifiedQuorumCertificate::from_votes)
    }

    pub fn clear_height(&mut self, height: u64) {
        self.votes
            .retain(|(vote_height, _, _), _| *vote_height != height);
        self.duplicate_guard.clear_height(height);
    }
}
