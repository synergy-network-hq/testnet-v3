use crate::{StateDiff, StateError, WorldState};

/// Isolated speculative execution state. Only a caller holding a verified
/// finalization may persist its root through FinalizedStateStore.
#[derive(Debug, Clone)]
pub struct StateOverlay {
    base: WorldState,
    staged: WorldState,
}

impl StateOverlay {
    pub fn new(base: WorldState) -> Self {
        Self {
            staged: base.clone(),
            base,
        }
    }

    pub fn apply(&mut self, diff: &StateDiff) -> Result<(), StateError> {
        diff.apply(&mut self.staged)
    }

    pub fn staged(&self) -> &WorldState {
        &self.staged
    }

    pub fn discard(self) -> WorldState {
        self.base
    }

    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
