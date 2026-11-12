use std::{marker::PhantomData, path::PathBuf};

use super::evidence_store::EvidenceStore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use synergy_storage::StorageWrite;

use crate::{canonical_hash, PosyError, PosyResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedRecord<T> {
    format: String,
    object_root: String,
    value: T,
}

/// Bounded atomic store for one canonical PoSy object per explicit key.
/// Existing keys are immutable: byte-identical replay is accepted and a
/// conflicting rewrite fails closed.
#[derive(Debug)]
pub struct CanonicalObjectStore<T> {
    store: EvidenceStore,
    namespace: String,
    marker: PhantomData<T>,
}

impl<T> CanonicalObjectStore<T>
where
    T: Clone + PartialEq + Serialize + DeserializeOwned,
{
    /// Opens a bounded atomic object namespace beneath `root`.
    pub fn new(root: impl Into<PathBuf>, namespace: impl Into<String>) -> PosyResult<Self> {
        let namespace = namespace.into();
        if !safe_component(&namespace) {
            return Err(PosyError::invalid("invalid PoSy persistence namespace"));
        }
        Ok(Self {
            store: EvidenceStore::open(root)
                .map_err(|error| PosyError::NotReady(error.to_string()))?,
            namespace,
            marker: PhantomData,
        })
    }

    pub(crate) fn evidence(&self) -> super::evidence_store::EvidenceStore {
        self.store.clone()
    }

    /// Persists `value` under an immutable key.
    ///
    /// Returns `Ok(false)` for an identical replay and a conflict for a
    /// different value already bound to the key.
    pub fn put_once(&self, key: &str, value: &T) -> PosyResult<bool> {
        let write = self.storage_write(key, value)?;
        self.store.put_once_atomic(&[write])
    }

    pub(crate) fn storage_write(&self, key: &str, value: &T) -> PosyResult<StorageWrite> {
        let path = self.path(key)?;
        let record = PersistedRecord {
            format: "synergy-posy-canonical-object-v1".into(),
            object_root: canonical_hash("Synergy/PoSy/v3/persisted-object", value)?,
            value: value.clone(),
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| PosyError::invalid(format!("serialize PoSy record: {error}")))?;
        Ok(StorageWrite {
            relative_path: path,
            bytes,
        })
    }

    /// Loads and integrity-checks the object bound to `key`, when present.
    pub fn get(&self, key: &str) -> PosyResult<Option<T>> {
        let path = self.path(key)?;
        let Some(bytes) = self.store.get(&path)? else {
            return Ok(None);
        };
        Ok(Some(self.read_record(&bytes)?.value))
    }

    fn path(&self, key: &str) -> PosyResult<PathBuf> {
        if !safe_component(key) {
            return Err(PosyError::invalid("invalid PoSy persistence key"));
        }
        Ok(PathBuf::from(&self.namespace).join(format!("{key}.json")))
    }

    fn read_record(&self, bytes: &[u8]) -> PosyResult<PersistedRecord<T>> {
        let record: PersistedRecord<T> = serde_json::from_slice(bytes)
            .map_err(|error| PosyError::invalid(format!("corrupt PoSy record: {error}")))?;
        if record.format != "synergy-posy-canonical-object-v1"
            || record.object_root
                != canonical_hash("Synergy/PoSy/v3/persisted-object", &record.value)?
        {
            return Err(PosyError::invalid("PoSy persistence integrity mismatch"));
        }
        Ok(record)
    }
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
