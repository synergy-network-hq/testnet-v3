use std::collections::BTreeMap;

use crate::{PosyError, PosyResult, SimplifiedTimeoutCertificate, TimeoutVote};

#[derive(Debug, Default)]
pub struct TimeoutVoteCollection {
    votes: BTreeMap<(u64, u64, String), BTreeMap<String, TimeoutVote>>,
}

impl TimeoutVoteCollection {
    pub fn insert(&mut self, vote: TimeoutVote) -> PosyResult<bool> {
        let key = (
            vote.context.height,
            vote.context.round,
            vote.timed_out_proposer.clone(),
        );
        let votes = self.votes.entry(key).or_default();
        match votes.get(&vote.validator_id) {
            Some(existing) if existing == &vote => Ok(false),
            Some(_) => Err(PosyError::Conflict(
                "conflicting timeout vote for validator/height/round".into(),
            )),
            None => {
                votes.insert(vote.validator_id.clone(), vote);
                Ok(true)
            }
        }
    }

    pub fn votes(&self, height: u64, round: u64, proposer: &str) -> Vec<TimeoutVote> {
        self.votes
            .get(&(height, round, proposer.into()))
            .map(|votes| votes.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn certificate(
        &self,
        height: u64,
        round: u64,
        proposer: &str,
    ) -> PosyResult<SimplifiedTimeoutCertificate> {
        let votes = self.votes(height, round, proposer);
        if votes.is_empty() {
            return Err(PosyError::NotReady("no timeout votes for slot".into()));
        }
        SimplifiedTimeoutCertificate::from_votes(votes)
    }

    pub fn clear_height(&mut self, height: u64) {
        self.votes
            .retain(|(vote_height, _, _), _| *vote_height != height);
    }
}
