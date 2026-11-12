use super::evidence_store::EvidenceStore;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};
use synergy_storage::{AtomicStore, StorageWrite};

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
    #[serde(default)]
    finalized_floor: u64,
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
    evidence: EvidenceStore,
    record_name: PathBuf,
    state: DurableJournal,
    loaded_bytes: Option<Vec<u8>>,
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
        let loaded_bytes = store
            .read_optional_bounded(&record_name)
            .map_err(storage_error)?;
        let state = if let Some(bytes) = &loaded_bytes {
            let parsed: DurableJournal = serde_json::from_slice(bytes)
                .map_err(|error| JournalError::Corrupt(error.to_string()))?;
            if parsed.format != "synergy-posy-sign-once-v1" {
                return Err(JournalError::Corrupt("unsupported journal format".into()));
            }
            validate_journal(&parsed)?;
            parsed
        } else {
            DurableJournal {
                format: "synergy-posy-sign-once-v1".into(),
                finalized_floor: 0,
                records: Vec::new(),
            }
        };
        Ok(Self {
            evidence: EvidenceStore::open(parent).map_err(evidence_error)?,
            store,
            record_name,
            state,
            loaded_bytes,
        })
    }

    /// Durable lower bound already established by verified finalized commits.
    /// A caller must still authenticate the corresponding finality witness.
    pub fn finalized_floor(&self) -> u64 {
        self.state.finalized_floor
    }

    pub fn record(&mut self, slot: SigningSlot, subject: String) -> Result<bool, JournalError> {
        self.check_current()?;
        if slot.height <= self.state.finalized_floor {
            return Err(JournalError::Corrupt(
                "signing at or below finalized safety floor".into(),
            ));
        }
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

    /// Called only after independently verified finalized commit. The permanent
    /// floor replaces old signing reservations; exact signature evidence remains indexed.
    pub fn advance_finalized_floor(&mut self, height: u64) -> Result<(), JournalError> {
        self.check_current()?;
        if height <= self.state.finalized_floor {
            return Ok(());
        }
        let mut next = self.state.clone();
        next.finalized_floor = height;
        next.records.retain(|r| r.slot.height > height);
        self.persist_state(&next)?;
        self.state = next;
        Ok(())
    }

    pub fn recover_last_block_vote(
        &self,
        height: u64,
    ) -> Result<Option<crate::BlockVote>, JournalError> {
        let Some(record) = self
            .state
            .records
            .iter()
            .filter(|r| r.slot.height == height && r.slot.domain == "block-vote")
            .max_by_key(|r| r.slot.round)
        else {
            return Ok(None);
        };
        let name = signature_record_name(&record.slot)?;
        let Some(bytes) = self.evidence.get(name).map_err(evidence_error)? else {
            return Ok(None);
        };
        let (slot, domain, transcript, signature): (SigningSlot, String, Vec<u8>, Vec<u8>) =
            serde_json::from_slice(&bytes).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        if slot != record.slot || domain != crate::POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN {
            return Err(JournalError::Corrupt(
                "block vote cache slot mismatch".into(),
            ));
        }
        let mut value: serde_json::Value = serde_json::from_slice(&transcript)
            .map_err(|e| JournalError::Corrupt(e.to_string()))?;
        value
            .as_object_mut()
            .ok_or_else(|| JournalError::Corrupt("block vote cache transcript malformed".into()))?
            .insert("signature".into(), serde_json::json!(signature));
        let vote: crate::BlockVote =
            serde_json::from_value(value).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        if vote.context.height != height || vote.context.round != slot.round {
            return Err(JournalError::Corrupt(
                "block vote cached context mismatch".into(),
            ));
        }
        let subject = crate::CertifiedCandidateSubject::new(
            vote.context.clone(),
            vote.block_id.clone(),
            vote.parent_block_id.clone(),
            vote.parent.clone(),
            vote.protected_execution_root.clone(),
        )
        .and_then(|candidate| candidate.id())
        .map_err(|e| JournalError::Corrupt(e.to_string()))?;
        if subject != record.subject {
            return Err(JournalError::Corrupt(
                "cached vote subject differs from reservation".into(),
            ));
        }
        Ok(Some(vote))
    }

    pub fn last_block_vote(&self, height: u64) -> Option<(u64, &str)> {
        self.state
            .records
            .iter()
            .filter(|r| r.slot.height == height && r.slot.domain == "block-vote")
            .max_by_key(|r| r.slot.round)
            .map(|r| (r.slot.round, r.subject.as_str()))
    }

    pub fn subject(&self, slot: &SigningSlot) -> Option<&str> {
        self.state
            .records
            .iter()
            .find(|record| &record.slot == slot)
            .map(|record| record.subject.as_str())
    }

    pub fn signed_bytes(
        &self,
        slot: &SigningSlot,
        domain: &str,
        transcript: &[u8],
    ) -> Result<Option<Vec<u8>>, JournalError> {
        let name = signature_record_name(slot)?;
        let Some(bytes) = self.evidence.get(&name).map_err(evidence_error)? else {
            return Ok(None);
        };
        let (saved_slot, saved_domain, saved_transcript, signature): (
            SigningSlot,
            String,
            Vec<u8>,
            Vec<u8>,
        ) = serde_json::from_slice(&bytes).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        if saved_slot != *slot
            || saved_domain != domain
            || saved_transcript != transcript
            || signature.is_empty()
            || signature.len() > 16384
        {
            return Err(JournalError::Corrupt(
                "signed slot transcript changed".into(),
            ));
        }
        Ok(Some(signature))
    }

    pub fn record_signature(
        &self,
        slot: &SigningSlot,
        domain: &str,
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<(), JournalError> {
        self.check_current()?;
        if signature.is_empty() || signature.len() > 16384 || transcript.len() > 1048576 {
            return Err(JournalError::Corrupt("invalid signed journal bytes".into()));
        }
        if self.subject(slot).is_none() {
            return Err(JournalError::Corrupt("signature lacks reservation".into()));
        }
        if let Some(existing) = self.signed_bytes(slot, domain, transcript)? {
            return if existing == signature {
                Ok(())
            } else {
                Err(JournalError::Corrupt(
                    "conflicting exact signature bytes".into(),
                ))
            };
        }
        let bytes = serde_json::to_vec(&(slot, domain, transcript, signature))
            .map_err(|e| JournalError::Corrupt(e.to_string()))?;
        self.evidence
            .put_once_atomic(&[StorageWrite {
                relative_path: signature_record_name(slot)?.into(),
                bytes,
            }])
            .map(|_| ())
            .map_err(evidence_error)
    }

    fn check_current(&self) -> Result<(), JournalError> {
        if self
            .store
            .read_optional_bounded(&self.record_name)
            .map_err(storage_error)?
            != self.loaded_bytes
        {
            return Err(JournalError::Corrupt(
                "stale signing journal owner; reload required".into(),
            ));
        }
        Ok(())
    }

    fn persist_state(&mut self, state: &DurableJournal) -> Result<(), JournalError> {
        let bytes = serde_json::to_vec(state).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        let mut transaction =
            synergy_storage::StorageTransaction::new(4 * 1024 * 1024).map_err(storage_error)?;
        transaction
            .put(&self.record_name, bytes.clone())
            .map_err(storage_error)?;
        transaction
            .commit_guarded(
                &mut self.store,
                &[synergy_storage::StoragePrecondition {
                    relative_path: self.record_name.clone(),
                    required: self.loaded_bytes.clone().map_or(
                        synergy_storage::RequiredRecord::Missing,
                        synergy_storage::RequiredRecord::Exact,
                    ),
                }],
            )
            .map_err(storage_error)?;
        self.loaded_bytes = Some(bytes);
        Ok(())
    }
}

fn signature_record_name(slot: &SigningSlot) -> Result<String, JournalError> {
    crate::canonical_hash("SYNERGY_POSY_SIGNED_SLOT_V1", slot)
        .map(|id| format!("signature-{id}.json"))
        .map_err(|e| JournalError::Corrupt(e.to_string()))
}

fn storage_error(error: synergy_storage::StorageError) -> JournalError {
    JournalError::Io(error.to_string())
}

fn validate_journal(journal: &DurableJournal) -> Result<(), JournalError> {
    let mut slots = BTreeSet::new();
    for record in &journal.records {
        if record.slot.height <= journal.finalized_floor
            || record.slot.domain.trim().is_empty()
            || record.subject.trim().is_empty()
        {
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

fn evidence_error(error: crate::PosyError) -> JournalError {
    match error {
        crate::PosyError::NotReady(message) => JournalError::Io(message),
        error => JournalError::Corrupt(error.to_string()),
    }
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
    fn signed_transcript_replays_exact_bytes_and_rejects_changed_transcript() {
        let root =
            std::env::temp_dir().join(format!("posy-exact-signature-{}", std::process::id()));
        let path = root.join("journal.json");
        let slot = SigningSlot {
            height: 4,
            round: 1,
            domain: "proposal-echo".into(),
        };
        let mut journal = SignOnceJournal::load(&path).unwrap();
        journal.record(slot.clone(), "candidate".into()).unwrap();
        journal
            .record_signature(&slot, "echo-domain", b"exact-transcript", &[1, 2, 3])
            .unwrap();
        drop(journal);
        let journal = SignOnceJournal::load(&path).unwrap();
        assert_eq!(
            journal
                .signed_bytes(&slot, "echo-domain", b"exact-transcript")
                .unwrap(),
            Some(vec![1, 2, 3])
        );
        assert!(journal
            .signed_bytes(&slot, "echo-domain", b"changed-transcript")
            .is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn finalized_floor_compacts_reservations_without_reopening_signing() {
        let root = std::env::temp_dir().join(format!("posy-signing-floor-{}", std::process::id()));
        let path = root.join("journal.json");
        let mut journal = SignOnceJournal::load(&path).unwrap();
        let slot = |height| SigningSlot {
            height,
            round: 0,
            domain: "proposal".into(),
        };
        for height in 1..=10 {
            journal
                .record(slot(height), format!("candidate-{height}"))
                .unwrap();
        }
        journal.advance_finalized_floor(8).unwrap();
        assert_eq!(journal.state.records.len(), 2);
        drop(journal);
        let mut journal = SignOnceJournal::load(&path).unwrap();
        assert!(journal.record(slot(7), "candidate-7".into()).is_err());
        assert!(!journal.record(slot(9), "candidate-9".into()).unwrap());
        let _ = fs::remove_dir_all(root);
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
            finalized_floor: 0,
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
    fn stale_signing_owners_cannot_erase_reservations_or_reopen_finalized_slots() {
        let root = std::env::temp_dir().join(format!("posy-stale-journal-{}", std::process::id()));
        let path = root.join("journal.json");
        let mut first = SignOnceJournal::load(&path).unwrap();
        let mut stale = SignOnceJournal::load(&path).unwrap();
        let slot = SigningSlot {
            height: 8,
            round: 0,
            domain: "block-vote".into(),
        };
        first.record(slot.clone(), "subject-a".into()).unwrap();
        assert!(stale.record(slot.clone(), "subject-b".into()).is_err());
        let mut stale = SignOnceJournal::load(&path).unwrap();
        first.advance_finalized_floor(8).unwrap();
        assert!(stale.record(slot.clone(), "subject-a".into()).is_err());
        assert!(stale
            .record_signature(&slot, "domain", b"transcript", &[1])
            .is_err());
        let recovered = SignOnceJournal::load(&path).unwrap();
        assert_eq!(recovered.finalized_floor(), 8);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_exact_signature_survives_floor_and_conflicting_signature_is_refused() {
        let root =
            std::env::temp_dir().join(format!("posy-legacy-signature-{}", std::process::id()));
        let path = root.join("journal.json");
        let mut journal = SignOnceJournal::load(&path).unwrap();
        let slot = SigningSlot {
            height: 8,
            round: 0,
            domain: "block-vote".into(),
        };
        journal.record(slot.clone(), "candidate".into()).unwrap();
        let bytes =
            serde_json::to_vec(&(&slot, "domain", b"exact-transcript".as_slice(), [1u8, 2, 3]))
                .unwrap();
        let name = signature_record_name(&slot).unwrap();
        journal.store.write_atomic(&name, &bytes).unwrap();
        assert_eq!(
            journal
                .signed_bytes(&slot, "domain", b"exact-transcript")
                .unwrap(),
            Some(vec![1, 2, 3])
        );
        assert!(journal
            .record_signature(&slot, "domain", b"exact-transcript", &[9, 9, 9])
            .is_err());
        journal.advance_finalized_floor(8).unwrap();
        drop(journal);
        let journal = SignOnceJournal::load(&path).unwrap();
        assert_eq!(
            journal
                .signed_bytes(&slot, "domain", b"exact-transcript")
                .unwrap(),
            Some(vec![1, 2, 3])
        );
        assert_eq!(fs::read(root.join(name)).unwrap(), bytes);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_durable_write_does_not_mutate_signing_memory() {
        let root =
            std::env::temp_dir().join(format!("synergy-posy-write-failure-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let journal_dir = root.join("journal");
        let path = journal_dir.join("journal.json");
        let mut journal = SignOnceJournal::load(&path).unwrap();
        fs::remove_dir_all(&journal_dir).unwrap();
        fs::write(&journal_dir, b"file").unwrap();
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
