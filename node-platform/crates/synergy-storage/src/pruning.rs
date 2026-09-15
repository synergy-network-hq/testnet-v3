use crate::StorageError;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PruneReport {
    pub examined_records: u64,
    pub removed_records: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruneBoundary {
    pub finalized_height: u64,
    pub retain_from_height: u64,
}

impl PruneBoundary {
    /// Returns the inclusive highest height that may be removed while keeping
    /// exactly `retain_from_height` finalized heights when enough history
    /// exists. Height zero is never selected for deletion.
    pub fn oldest_prunable_height(self) -> Result<Option<u64>, StorageError> {
        if self.retain_from_height == 0 {
            return Err(StorageError::InvalidPruneBoundary);
        }
        Ok(self
            .finalized_height
            .checked_sub(self.retain_from_height)
            .filter(|height| *height > 0))
    }
}
