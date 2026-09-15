use crate::{StorageError, WalRecord, WriteAheadLog};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    pub recovered_records: usize,
    pub last_sequence: Option<u64>,
}

/// WAL recovery validates every durable record before returning it. Callers
/// apply domain-specific recovery only after they validate consensus/ETDAG
/// semantics; storage never reconstructs authority or finality itself.
pub fn recover_wal(log: &WriteAheadLog) -> Result<RecoveryReport, StorageError> {
    let records: Vec<WalRecord> = log.replay()?;
    Ok(RecoveryReport {
        recovered_records: records.len(),
        last_sequence: records.last().map(|record| record.sequence),
    })
}
