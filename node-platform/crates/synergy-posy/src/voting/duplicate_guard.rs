use std::collections::BTreeMap;

use crate::{BlockVote, PosyError, PosyResult};

#[derive(Debug, Default)]
pub struct VoteDuplicateGuard {
    subjects: BTreeMap<(u64, u64, String), String>,
}

impl VoteDuplicateGuard {
    pub fn record(&mut self, vote: &BlockVote) -> PosyResult<bool> {
        let slot = (
            vote.context.height,
            vote.context.round,
            vote.validator_id.clone(),
        );
        let subject = format!("{}:{}", vote.block_id, vote.protected_execution_root);
        match self.subjects.get(&slot) {
            Some(existing) if existing == &subject => Ok(false),
            Some(_) => Err(PosyError::Conflict(
                "conflicting vote for one signing slot".into(),
            )),
            None => {
                self.subjects.insert(slot, subject);
                Ok(true)
            }
        }
    }

    pub fn clear_height(&mut self, height: u64) {
        self.subjects
            .retain(|(vote_height, _, _), _| *vote_height != height);
    }
}
