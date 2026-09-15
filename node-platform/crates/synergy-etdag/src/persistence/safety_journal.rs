use std::{collections::BTreeMap, path::Path};

use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};

const STATE_PATH: &str = "safety/journal-v1.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyDecision {
    pub domain: String,
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub subject_root: EtdagDigest,
    pub decision_root: EtdagDigest,
}

impl SafetyDecision {
    pub fn validate(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        self.subject_root.validate()?;
        self.decision_root.validate()?;
        if self.target_height == 0
            || self.domain.is_empty()
            || self.domain.len() > 128
            || !self
                .domain
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        Ok(())
    }

    fn slot(&self) -> Result<EtdagDigest, EtdagError> {
        EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_SAFETY_SLOT_V1",
            &(
                self.domain.as_str(),
                &self.context_root,
                self.target_height,
                &self.subject_root,
            ),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableSafetyJournal {
    format_version: u32,
    decisions: BTreeMap<EtdagDigest, SafetyDecision>,
}

#[derive(Debug)]
pub struct SafetyJournal {
    store: synergy_storage::AtomicStore,
    state: DurableSafetyJournal,
}

impl SafetyJournal {
    pub fn open(root: impl AsRef<Path>, max_record_bytes: usize) -> Result<Self, EtdagError> {
        if max_record_bytes == 0 {
            return Err(EtdagError::InvalidCapacity);
        }
        let store = synergy_storage::AtomicStore::new(root.as_ref(), max_record_bytes)
            .map_err(storage_error)?;
        let state = if store.exists(STATE_PATH).map_err(storage_error)? {
            let bytes = store.read_bounded(STATE_PATH).map_err(storage_error)?;
            let state: DurableSafetyJournal = serde_json::from_slice(&bytes)
                .map_err(|error| EtdagError::Corrupt(error.to_string()))?;
            if state.format_version != 1 {
                return Err(EtdagError::Corrupt(
                    "unsupported safety journal format".into(),
                ));
            }
            for (slot, decision) in &state.decisions {
                decision.validate()?;
                if decision.slot()? != *slot {
                    return Err(EtdagError::Corrupt("safety journal slot mismatch".into()));
                }
            }
            state
        } else {
            DurableSafetyJournal {
                format_version: 1,
                decisions: BTreeMap::new(),
            }
        };
        Ok(Self { store, state })
    }

    pub fn record(&mut self, decision: SafetyDecision) -> Result<(), EtdagError> {
        decision.validate()?;
        let slot = decision.slot()?;
        if let Some(existing) = self.state.decisions.get(&slot) {
            return if existing == &decision {
                Ok(())
            } else {
                Err(EtdagError::ConflictingArtifact(slot.0))
            };
        }
        let mut next = self.state.clone();
        next.decisions.insert(slot, decision);
        let bytes =
            serde_json::to_vec(&next).map_err(|error| EtdagError::Corrupt(error.to_string()))?;
        self.store
            .write_atomic(STATE_PATH, &bytes)
            .map_err(storage_error)?;
        self.state = next;
        Ok(())
    }
}

fn storage_error(error: synergy_storage::StorageError) -> EtdagError {
    EtdagError::Storage(error.to_string())
}
