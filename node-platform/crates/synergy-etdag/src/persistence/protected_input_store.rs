use std::{collections::BTreeMap, path::Path};

use serde::{Deserialize, Serialize};

use crate::{EncryptedTransactionEnvelope, EtdagDigest, EtdagError};

const STATE_PATH: &str = "protected-inputs-v1.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableProtectedInputs {
    format_version: u32,
    envelopes: BTreeMap<EtdagDigest, EncryptedTransactionEnvelope>,
}

#[derive(Debug)]
pub struct ProtectedInputStore {
    store: synergy_storage::AtomicStore,
    state: DurableProtectedInputs,
}

impl ProtectedInputStore {
    pub fn open(root: impl AsRef<Path>, max_record_bytes: usize) -> Result<Self, EtdagError> {
        if max_record_bytes == 0 {
            return Err(EtdagError::InvalidCapacity);
        }
        let store = synergy_storage::AtomicStore::new(root.as_ref(), max_record_bytes)
            .map_err(storage_error)?;
        let state = if store.exists(STATE_PATH).map_err(storage_error)? {
            let bytes = store.read_bounded(STATE_PATH).map_err(storage_error)?;
            let state: DurableProtectedInputs = serde_json::from_slice(&bytes)
                .map_err(|error| EtdagError::Corrupt(error.to_string()))?;
            if state.format_version != 1 {
                return Err(EtdagError::Corrupt(
                    "unsupported protected input format".into(),
                ));
            }
            for (id, envelope) in &state.envelopes {
                envelope.validate()?;
                if id != &envelope.envelope_id {
                    return Err(EtdagError::Corrupt("protected input key mismatch".into()));
                }
            }
            state
        } else {
            DurableProtectedInputs {
                format_version: 1,
                envelopes: BTreeMap::new(),
            }
        };
        Ok(Self { store, state })
    }

    pub fn get(&self, envelope_id: &EtdagDigest) -> Option<&EncryptedTransactionEnvelope> {
        self.state.envelopes.get(envelope_id)
    }

    pub fn insert(&mut self, envelope: EncryptedTransactionEnvelope) -> Result<(), EtdagError> {
        envelope.validate()?;
        if let Some(existing) = self.state.envelopes.get(&envelope.envelope_id) {
            return if existing == &envelope {
                Ok(())
            } else {
                Err(EtdagError::ConflictingArtifact(envelope.envelope_id.0))
            };
        }
        let mut next = self.state.clone();
        next.envelopes
            .insert(envelope.envelope_id.clone(), envelope);
        self.persist(&next)?;
        self.state = next;
        Ok(())
    }

    fn persist(&self, state: &DurableProtectedInputs) -> Result<(), EtdagError> {
        let bytes =
            serde_json::to_vec(state).map_err(|error| EtdagError::Corrupt(error.to_string()))?;
        self.store
            .write_atomic(STATE_PATH, &bytes)
            .map_err(storage_error)
    }
}

fn storage_error(error: synergy_storage::StorageError) -> EtdagError {
    EtdagError::Storage(error.to_string())
}
