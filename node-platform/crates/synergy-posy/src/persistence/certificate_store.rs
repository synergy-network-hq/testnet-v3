use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use synergy_storage::{AtomicStore, StorageWrite};

use crate::{
    ConsensusSignatureVerifier, FrozenValidatorRegistry, PosyError, PosyResult,
    SimplifiedEpochContext, SimplifiedQuorumCertificate,
};

const FORMAT: &str = "synergy-posy-verified-qc-v1";
pub(super) const MAX_QC_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableVerifiedQc {
    format: String,
    epoch_context_root: String,
    candidate_id: String,
    certificate: SimplifiedQuorumCertificate,
}

/// One bounded authenticated QC per certified height. This avoids rewriting
/// the whole safety journal for each height, and loaded proof is reverified
/// before it can become consensus authority.
#[derive(Debug)]
pub struct VerifiedQuorumCertificateStore {
    store: AtomicStore,
}

impl VerifiedQuorumCertificateStore {
    pub fn new(root: impl Into<PathBuf>) -> PosyResult<Self> {
        let store = AtomicStore::new(root, MAX_QC_BYTES)
            .map_err(|error| PosyError::invalid(format!("open QC store: {error}")))?;
        Ok(Self { store })
    }

    pub fn put_verified(
        &self,
        certificate: &SimplifiedQuorumCertificate,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<bool> {
        let write = verified_qc_write(certificate, epoch, validators, verifier)?;
        self.store
            .put_once_atomic(&[write])
            .map_err(persistence_error)
    }

    pub fn get_verified(
        &self,
        height: u64,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Option<SimplifiedQuorumCertificate>> {
        let path = record_path(height);
        if !self
            .store
            .exists(&path)
            .map_err(|error| PosyError::invalid(format!("stat QC: {error}")))?
        {
            return Ok(None);
        }
        let bytes = self
            .store
            .read_bounded(&path)
            .map_err(|error| PosyError::invalid(format!("read QC: {error}")))?;
        let record: DurableVerifiedQc = serde_json::from_slice(&bytes)
            .map_err(|error| PosyError::invalid(format!("decode QC: {error}")))?;
        if record.format != FORMAT
            || record.epoch_context_root != epoch.root()?
            || record.certificate.context.height != height
            || record.candidate_id != record.certificate.id()?
            || serde_json::to_vec(&record)
                .map_err(|error| PosyError::invalid(format!("re-encode QC: {error}")))?
                != bytes
        {
            return Err(PosyError::invalid(
                "QC record has invalid canonical binding",
            ));
        }
        record.certificate.verify(epoch, validators, verifier)?;
        Ok(Some(record.certificate))
    }
}

pub(super) fn verified_qc_write(
    certificate: &SimplifiedQuorumCertificate,
    epoch: &SimplifiedEpochContext,
    validators: &FrozenValidatorRegistry,
    verifier: &impl ConsensusSignatureVerifier,
) -> PosyResult<StorageWrite> {
    certificate.verify(epoch, validators, verifier)?;
    let record = DurableVerifiedQc {
        format: FORMAT.into(),
        epoch_context_root: epoch.root()?,
        candidate_id: certificate.id()?,
        certificate: certificate.clone(),
    };
    let bytes = serde_json::to_vec(&record)
        .map_err(|error| PosyError::invalid(format!("serialize QC: {error}")))?;
    Ok(StorageWrite {
        relative_path: record_path(certificate.context.height),
        bytes,
    })
}

fn persistence_error(error: synergy_storage::StorageError) -> PosyError {
    match error {
        synergy_storage::StorageError::ConflictingWrite => {
            PosyError::Conflict("different certified candidate already stored at height".into())
        }
        error => PosyError::NotReady(format!("persist QC: {error}")),
    }
}

fn record_path(height: u64) -> PathBuf {
    PathBuf::from(format!("verified-qcs/qc/{height:020}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConsensusObjectContext, ParticipantSignature, SimplifiedFinalityParent, ValidatorRecord,
        ValidatorStatus,
    };
    use std::fs;

    struct AcceptSignatures;
    impl ConsensusSignatureVerifier for AcceptSignatures {
        fn verify_consensus_signature(
            &self,
            _domain: &str,
            _payload: &[u8],
            _validator: &ValidatorRecord,
            _key_id: &str,
            _epoch: u64,
            _signature: &[u8],
        ) -> PosyResult<()> {
            Ok(())
        }
    }

    fn hash(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn fixture() -> (
        SimplifiedEpochContext,
        FrozenValidatorRegistry,
        SimplifiedQuorumCertificate,
    ) {
        let validators = FrozenValidatorRegistry::new(
            7,
            (0..5)
                .map(|index| ValidatorRecord {
                    validator_id: format!("validator-{index}"),
                    consensus_key_id: format!("key-{index}"),
                    frozen_voting_weight: if index == 0 { 7 } else { 3 },
                    status: ValidatorStatus::Active,
                })
                .collect(),
        )
        .unwrap();
        let epoch = SimplifiedEpochContext::from_frozen_registry(
            1266,
            "testnet".into(),
            7,
            1,
            20,
            hash('a'),
            hash('b'),
            &validators,
        )
        .unwrap();
        let parent = SimplifiedFinalityParent::Genesis {
            genesis_hash: hash('c'),
            block_id: "genesis".into(),
            reference_id: hash('d'),
        };
        let certificate = SimplifiedQuorumCertificate {
            context: ConsensusObjectContext::for_height(&epoch, 1, 0).unwrap(),
            block_id: "block-one".into(),
            parent_block_id: "genesis".into(),
            parent,
            takeover_tc_id: None,
            protected_execution_root: hash('e'),
            participants: (0..4)
                .map(|index| ParticipantSignature {
                    validator_id: format!("validator-{index}"),
                    key_id: format!("key-{index}"),
                    signature: vec![index as u8 + 1],
                })
                .collect(),
        };
        (epoch, validators, certificate)
    }

    #[test]
    fn verified_qc_is_idempotent_and_revalidated_on_restart() {
        let root = std::env::temp_dir().join(format!(
            "synergy-posy-qc-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let (epoch, validators, certificate) = fixture();
        let verifier = AcceptSignatures;
        let store = VerifiedQuorumCertificateStore::new(&root).unwrap();
        assert!(store
            .put_verified(&certificate, &epoch, &validators, &verifier)
            .unwrap());
        drop(store);
        let store = VerifiedQuorumCertificateStore::new(&root).unwrap();
        assert_eq!(
            store
                .get_verified(1, &epoch, &validators, &verifier)
                .unwrap(),
            Some(certificate.clone())
        );
        assert!(!store
            .put_verified(&certificate, &epoch, &validators, &verifier)
            .unwrap());
        let mut conflict = certificate.clone();
        conflict.block_id = "another-block".into();
        assert!(matches!(
            store.put_verified(&conflict, &epoch, &validators, &verifier),
            Err(PosyError::Conflict(_))
        ));
        fs::write(root.join(record_path(1)), b"{\"format\":\"bad\"}").unwrap();
        assert!(store
            .get_verified(1, &epoch, &validators, &verifier)
            .is_err());
        let _ = fs::remove_dir_all(root);
    }
}
