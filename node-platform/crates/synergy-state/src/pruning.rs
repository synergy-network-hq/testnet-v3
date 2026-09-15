use crate::StateError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub retain_finalized_from_height: u64,
}

impl RetentionPolicy {
    pub fn prune_before(self, height: u64) -> Result<Option<u64>, StateError> {
        if height == 0 {
            return Err(StateError::InvalidPruneRequest);
        }
        Ok((height > self.retain_finalized_from_height)
            .then_some(height - self.retain_finalized_from_height))
    }
}
