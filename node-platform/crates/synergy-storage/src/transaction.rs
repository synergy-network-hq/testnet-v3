use std::{collections::BTreeSet, path::PathBuf};

use crate::StorageError;

pub(crate) const MAXIMUM_TRANSACTION_WRITES: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageWrite {
    pub relative_path: PathBuf,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequiredRecord {
    Missing,
    Exact(Vec<u8>),
    MissingOrExact(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePrecondition {
    pub relative_path: PathBuf,
    pub required: RequiredRecord,
}

/// Backend boundary for a genuinely atomic multi-record commit.
pub trait TransactionBackend {
    fn commit_atomic(&mut self, writes: &[StorageWrite]) -> Result<(), StorageError>;
}

/// Backend boundary for a compare-and-commit transaction whose preconditions
/// are evaluated under the same cross-process lock as the write set.
pub trait GuardedTransactionBackend {
    fn commit_atomic_if(
        &mut self,
        preconditions: &[StoragePrecondition],
        writes: &[StorageWrite],
    ) -> Result<(), StorageError>;
}

#[derive(Debug, Default)]
pub struct StorageTransaction {
    writes: Vec<StorageWrite>,
    paths: BTreeSet<PathBuf>,
    maximum_total_bytes: usize,
    total_bytes: usize,
}

impl StorageTransaction {
    pub fn new(maximum_total_bytes: usize) -> Result<Self, StorageError> {
        if maximum_total_bytes == 0 {
            return Err(StorageError::RecordTooLarge {
                actual: 1,
                maximum: 0,
            });
        }
        Ok(Self {
            maximum_total_bytes,
            ..Self::default()
        })
    }

    pub fn put(
        &mut self,
        relative_path: impl Into<PathBuf>,
        bytes: Vec<u8>,
    ) -> Result<(), StorageError> {
        let relative_path = relative_path.into();
        if self.writes.len() >= MAXIMUM_TRANSACTION_WRITES {
            return Err(StorageError::TooManyTransactionWrites {
                actual: self.writes.len().saturating_add(1),
                maximum: MAXIMUM_TRANSACTION_WRITES,
            });
        }
        if relative_path.as_os_str().is_empty()
            || relative_path.is_absolute()
            || relative_path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || !self.paths.insert(relative_path.clone())
        {
            return Err(StorageError::InvalidPath);
        }
        let next =
            self.total_bytes
                .checked_add(bytes.len())
                .ok_or(StorageError::RecordTooLarge {
                    actual: usize::MAX,
                    maximum: self.maximum_total_bytes,
                })?;
        if next > self.maximum_total_bytes {
            return Err(StorageError::RecordTooLarge {
                actual: next,
                maximum: self.maximum_total_bytes,
            });
        }
        self.total_bytes = next;
        self.writes.push(StorageWrite {
            relative_path,
            bytes,
        });
        Ok(())
    }

    pub fn commit(self, backend: &mut impl TransactionBackend) -> Result<(), StorageError> {
        if self.writes.is_empty() {
            return Err(StorageError::InvalidPath);
        }
        backend.commit_atomic(&self.writes)
    }

    pub fn commit_guarded(
        self,
        backend: &mut impl GuardedTransactionBackend,
        preconditions: &[StoragePrecondition],
    ) -> Result<(), StorageError> {
        if self.writes.is_empty() {
            return Err(StorageError::InvalidPath);
        }
        backend.commit_atomic_if(preconditions, &self.writes)
    }
}
