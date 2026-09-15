use synergy_state::WorldState;

/// In-memory checkpoint for discarding a speculative execution candidate.
/// Durable finalized state is deliberately outside this type: only PoSy may
/// authorize a finalized-state commit.
#[derive(Debug, Clone)]
pub struct ExecutionCheckpoint {
    parent_height: u64,
    parent_state: WorldState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackError {
    InvalidParentHeight,
    InvalidCandidateHeight {
        parent_height: u64,
        candidate_height: u64,
    },
}

impl ExecutionCheckpoint {
    pub fn capture(parent_height: u64, parent_state: &WorldState) -> Result<Self, RollbackError> {
        if parent_height == 0 {
            return Err(RollbackError::InvalidParentHeight);
        }
        Ok(Self {
            parent_height,
            parent_state: parent_state.clone(),
        })
    }

    pub const fn parent_height(&self) -> u64 {
        self.parent_height
    }

    /// Drops an unfinalized candidate state. A candidate must be strictly newer
    /// than the captured parent; this helper cannot roll back finalized state.
    pub fn discard_candidate(
        &self,
        candidate_height: u64,
        candidate_state: &mut WorldState,
    ) -> Result<(), RollbackError> {
        if candidate_height <= self.parent_height {
            return Err(RollbackError::InvalidCandidateHeight {
                parent_height: self.parent_height,
                candidate_height,
            });
        }
        *candidate_state = self.parent_state.clone();
        Ok(())
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}

impl std::fmt::Display for RollbackError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RollbackError {}
