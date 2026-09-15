use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};

use synergy_storage::AtomicStore;

use crate::persistence::{JournalError, SigningSlot};

/// Opaque PoSy safety records. Their validation remains in the PoSy driver; this
/// journal supplies durable conflict refusal and crash-recovery loading only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RecoveryRecordKind {
    Prepared,
    Proposal,
    Vote,
    Certificate,
    Finality,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecoverySlot {
    pub kind: RecoveryRecordKind,
    pub height: u64,
    pub round: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableRecoveryJournal {
    format: String,
    records: Vec<DurableRecoveryRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableRecoveryRecord {
    slot: RecoverySlot,
    subject: String,
}

/// Persistence owner for prepared/proposal/vote/certificate/finality safety
/// evidence. It deliberately stores opaque validated subjects.
#[derive(Debug)]
pub struct PosyRecoveryJournal {
    store: AtomicStore,
    record_name: PathBuf,
    state: DurableRecoveryJournal,
}

impl PosyRecoveryJournal {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, JournalError> {
        let path = path.into();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let record_name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| JournalError::Io("recovery journal has no file name".into()))?;
        let store = AtomicStore::new(parent, 16 * 1024 * 1024).map_err(storage_error)?;
        let state = if store.exists(&record_name).map_err(storage_error)? {
            let bytes = store.read_bounded(&record_name).map_err(storage_error)?;
            let parsed: DurableRecoveryJournal = serde_json::from_slice(&bytes)
                .map_err(|error| JournalError::Corrupt(error.to_string()))?;
            if parsed.format != "synergy-posy-recovery-v1" {
                return Err(JournalError::Corrupt(
                    "unsupported recovery journal format".into(),
                ));
            }
            validate_recovery_journal(&parsed)?;
            parsed
        } else {
            DurableRecoveryJournal {
                format: "synergy-posy-recovery-v1".into(),
                records: Vec::new(),
            }
        };
        Ok(Self {
            store,
            record_name,
            state,
        })
    }

    pub fn record(&mut self, slot: RecoverySlot, subject: String) -> Result<bool, JournalError> {
        if slot.height == 0 || subject.trim().is_empty() {
            return Err(JournalError::Corrupt("invalid recovery record".into()));
        }
        if let Some(existing) = self
            .state
            .records
            .iter()
            .find(|record| record.slot == slot)
            .map(|record| &record.subject)
        {
            return if existing == &subject {
                Ok(false)
            } else {
                Err(JournalError::ConflictingSubject {
                    slot: SigningSlot {
                        height: slot.height,
                        round: slot.round,
                        domain: format!("{:?}", slot.kind),
                    },
                    existing: existing.clone(),
                    requested: subject,
                })
            };
        }

        let mut next = self.state.clone();
        next.records.push(DurableRecoveryRecord { slot, subject });
        let bytes =
            serde_json::to_vec(&next).map_err(|error| JournalError::Corrupt(error.to_string()))?;
        self.store
            .write_atomic(&self.record_name, &bytes)
            .map_err(storage_error)?;
        self.state = next;
        Ok(true)
    }

    pub fn subject(&self, slot: &RecoverySlot) -> Option<&str> {
        self.state
            .records
            .iter()
            .find(|record| &record.slot == slot)
            .map(|record| record.subject.as_str())
    }
}

fn storage_error(error: synergy_storage::StorageError) -> JournalError {
    JournalError::Io(error.to_string())
}

fn validate_recovery_journal(journal: &DurableRecoveryJournal) -> Result<(), JournalError> {
    if journal
        .records
        .iter()
        .any(|record| record.subject.trim().is_empty() || record.slot.height == 0)
    {
        return Err(JournalError::Corrupt("invalid recovery record".into()));
    }
    if journal
        .records
        .iter()
        .map(|record| &record.slot)
        .collect::<BTreeSet<_>>()
        .len()
        != journal.records.len()
    {
        return Err(JournalError::Corrupt("invalid recovery record".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn recovery_journal_persists_all_safety_record_kinds_without_interpreting_them() {
        let dir =
            std::env::temp_dir().join(format!("synergy-posy-recovery-{}", std::process::id()));
        let path = dir.join("recovery.json");
        let mut journal = PosyRecoveryJournal::load(&path).unwrap();
        for (index, kind) in [
            RecoveryRecordKind::Prepared,
            RecoveryRecordKind::Proposal,
            RecoveryRecordKind::Vote,
            RecoveryRecordKind::Certificate,
            RecoveryRecordKind::Finality,
        ]
        .into_iter()
        .enumerate()
        {
            assert!(journal
                .record(
                    RecoverySlot {
                        kind,
                        height: 10,
                        round: index as u64,
                    },
                    format!("opaque-{index}"),
                )
                .unwrap());
        }
        drop(journal);

        let mut journal = PosyRecoveryJournal::load(&path).unwrap();
        let vote = RecoverySlot {
            kind: RecoveryRecordKind::Vote,
            height: 10,
            round: 2,
        };
        assert_eq!(journal.subject(&vote), Some("opaque-2"));
        assert!(!journal.record(vote.clone(), "opaque-2".into()).unwrap());
        assert!(matches!(
            journal.record(vote, "conflict".into()),
            Err(JournalError::ConflictingSubject { .. })
        ));
        let _ = fs::remove_dir_all(dir);
    }
}
