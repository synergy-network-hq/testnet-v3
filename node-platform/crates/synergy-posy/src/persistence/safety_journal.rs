use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};
use synergy_storage::AtomicStore;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SigningSlot {
    pub height: u64,
    pub round: u64,
    pub domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    Io(String),
    Corrupt(String),
    ConflictingSubject {
        slot: SigningSlot,
        existing: String,
        requested: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableJournal {
    format: String,
    records: Vec<DurableSigningRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableSigningRecord {
    slot: SigningSlot,
    subject: String,
}

/// Durable sign-once journal. A slot can be replayed with the same subject but
/// can never be rebound to a conflicting subject across restart.
#[derive(Debug)]
pub struct SignOnceJournal {
    store: AtomicStore,
    record_name: PathBuf,
    state: DurableJournal,
}

impl SignOnceJournal {
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
            .ok_or_else(|| JournalError::Io("journal has no file name".into()))?;
        let store = AtomicStore::new(parent, 4 * 1024 * 1024).map_err(storage_error)?;
        let state = if store.exists(&record_name).map_err(storage_error)? {
            let bytes = store.read_bounded(&record_name).map_err(storage_error)?;
            let parsed: DurableJournal = serde_json::from_slice(&bytes)
                .map_err(|error| JournalError::Corrupt(error.to_string()))?;
            if parsed.format != "synergy-posy-sign-once-v1" {
                return Err(JournalError::Corrupt("unsupported journal format".into()));
            }
            validate_journal(&parsed)?;
            parsed
        } else {
            DurableJournal {
                format: "synergy-posy-sign-once-v1".into(),
                records: Vec::new(),
            }
        };
        Ok(Self {
            store,
            record_name,
            state,
        })
    }

    pub fn record(&mut self, slot: SigningSlot, subject: String) -> Result<bool, JournalError> {
        if let Some(existing) = self
            .state
            .records
            .iter()
            .find(|record| record.slot == slot)
            .map(|record| &record.subject)
        {
            if existing == &subject {
                return Ok(false);
            }
            return Err(JournalError::ConflictingSubject {
                slot,
                existing: existing.clone(),
                requested: subject,
            });
        }

        let mut next = self.state.clone();
        next.records.push(DurableSigningRecord { slot, subject });
        self.persist_state(&next)?;
        self.state = next;
        Ok(true)
    }

    pub fn subject(&self, slot: &SigningSlot) -> Option<&str> {
        self.state
            .records
            .iter()
            .find(|record| &record.slot == slot)
            .map(|record| record.subject.as_str())
    }

    fn persist_state(&self, state: &DurableJournal) -> Result<(), JournalError> {
        let bytes =
            serde_json::to_vec(state).map_err(|error| JournalError::Corrupt(error.to_string()))?;
        self.store
            .write_atomic(&self.record_name, &bytes)
            .map_err(storage_error)
    }
}

fn storage_error(error: synergy_storage::StorageError) -> JournalError {
    JournalError::Io(error.to_string())
}

fn validate_journal(journal: &DurableJournal) -> Result<(), JournalError> {
    let mut slots = BTreeSet::new();
    for record in &journal.records {
        if record.slot.domain.trim().is_empty() || record.subject.trim().is_empty() {
            return Err(JournalError::Corrupt(
                "journal contains empty signing binding".into(),
            ));
        }
        if !slots.insert(record.slot.clone()) {
            return Err(JournalError::Corrupt(
                "journal contains duplicate signing slot".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn sign_once_journal_survives_restart_and_refuses_conflict() {
        let dir = std::env::temp_dir().join(format!("synergy-posy-test-{}", std::process::id()));
        let path = dir.join("journal.json");
        let slot = SigningSlot {
            height: 8,
            round: 2,
            domain: "vote".into(),
        };
        let mut journal = SignOnceJournal::load(&path).unwrap();
        assert!(journal.record(slot.clone(), "block-a".into()).unwrap());
        drop(journal);

        let mut journal = SignOnceJournal::load(&path).unwrap();
        assert_eq!(journal.subject(&slot), Some("block-a"));
        assert!(!journal.record(slot.clone(), "block-a".into()).unwrap());
        assert!(matches!(
            journal.record(slot, "block-b".into()),
            Err(JournalError::ConflictingSubject { .. })
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn duplicate_persisted_slot_fails_closed_on_recovery() {
        let dir = std::env::temp_dir().join(format!("synergy-posy-corrupt-{}", std::process::id()));
        let path = dir.join("journal.json");
        let slot = SigningSlot {
            height: 9,
            round: 1,
            domain: "vote".into(),
        };
        let journal = DurableJournal {
            format: "synergy-posy-sign-once-v1".into(),
            records: vec![
                DurableSigningRecord {
                    slot: slot.clone(),
                    subject: "a".into(),
                },
                DurableSigningRecord {
                    slot,
                    subject: "b".into(),
                },
            ],
        };
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
        assert!(matches!(
            SignOnceJournal::load(&path),
            Err(JournalError::Corrupt(_))
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_durable_write_does_not_mutate_signing_memory() {
        let root =
            std::env::temp_dir().join(format!("synergy-posy-write-failure-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let not_directory = root.join("not-directory");
        fs::write(&not_directory, b"file").unwrap();
        let path = not_directory.join("journal.json");
        let mut journal = SignOnceJournal::load(&path).unwrap();
        let slot = SigningSlot {
            height: 20,
            round: 0,
            domain: "vote".into(),
        };
        assert!(matches!(
            journal.record(slot.clone(), "subject".into()),
            Err(JournalError::Io(_))
        ));
        assert_eq!(journal.subject(&slot), None);
        let _ = fs::remove_dir_all(root);
    }
}
