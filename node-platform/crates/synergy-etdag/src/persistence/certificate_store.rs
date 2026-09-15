use std::{collections::BTreeMap, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    certificates::{canonical_certificate_root, CanonicalCertificate},
    EtdagDigest, EtdagError,
};

const STATE_PATH: &str = "certificates-v1.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableCertificates {
    format_version: u32,
    certificates: BTreeMap<EtdagDigest, CanonicalCertificate>,
}

#[derive(Debug)]
pub struct CertificateStore {
    store: synergy_storage::AtomicStore,
    state: DurableCertificates,
}

impl CertificateStore {
    pub fn open(root: impl AsRef<Path>, max_record_bytes: usize) -> Result<Self, EtdagError> {
        if max_record_bytes == 0 {
            return Err(EtdagError::InvalidCapacity);
        }
        let store = synergy_storage::AtomicStore::new(root.as_ref(), max_record_bytes)
            .map_err(storage_error)?;
        let state = if store.exists(STATE_PATH).map_err(storage_error)? {
            let bytes = store.read_bounded(STATE_PATH).map_err(storage_error)?;
            let state: DurableCertificates = serde_json::from_slice(&bytes)
                .map_err(|error| EtdagError::Corrupt(error.to_string()))?;
            if state.format_version != 1 {
                return Err(EtdagError::Corrupt(
                    "unsupported certificate store format".into(),
                ));
            }
            for (root, certificate) in &state.certificates {
                if canonical_certificate_root(certificate)? != *root {
                    return Err(EtdagError::Corrupt("certificate root mismatch".into()));
                }
            }
            state
        } else {
            DurableCertificates {
                format_version: 1,
                certificates: BTreeMap::new(),
            }
        };
        Ok(Self { store, state })
    }

    pub fn get(&self, root: &EtdagDigest) -> Option<&CanonicalCertificate> {
        self.state.certificates.get(root)
    }

    pub fn insert(&mut self, certificate: CanonicalCertificate) -> Result<EtdagDigest, EtdagError> {
        let root = canonical_certificate_root(&certificate)?;
        if let Some(existing) = self.state.certificates.get(&root) {
            return if existing == &certificate {
                Ok(root)
            } else {
                Err(EtdagError::ConflictingArtifact(root.0))
            };
        }
        let mut next = self.state.clone();
        next.certificates.insert(root.clone(), certificate);
        let bytes =
            serde_json::to_vec(&next).map_err(|error| EtdagError::Corrupt(error.to_string()))?;
        self.store
            .write_atomic(STATE_PATH, &bytes)
            .map_err(storage_error)?;
        self.state = next;
        Ok(root)
    }
}

fn storage_error(error: synergy_storage::StorageError) -> EtdagError {
    EtdagError::Storage(error.to_string())
}
