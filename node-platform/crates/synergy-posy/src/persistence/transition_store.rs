use std::path::PathBuf;

use super::evidence_store::EvidenceStore;

use super::{certificate_store::verified_qc_write, FinalityStore};
use crate::{
    ConsensusSignatureVerifier, FinalizedBlockRecord, FrozenValidatorRegistry, PosyError,
    PosyResult, SimplifiedEpochContext, SimplifiedQuorumCertificate,
};

/// One crash-atomic durable boundary for the QC that closes a three-QC witness
/// and the finality record authorized by that exact certificate.
#[derive(Debug)]
pub struct AtomicConsensusTransitionStore {
    store: EvidenceStore,
    finality: FinalityStore,
}

impl AtomicConsensusTransitionStore {
    pub fn new(root: impl Into<PathBuf>) -> PosyResult<Self> {
        let root = root.into();
        Ok(Self {
            store: EvidenceStore::open(&root)
                .map_err(|error| PosyError::NotReady(error.to_string()))?,
            finality: FinalityStore::new(root)?,
        })
    }

    pub fn commit_verified_qc_and_finality(
        &self,
        certificate: &SimplifiedQuorumCertificate,
        record: &FinalizedBlockRecord,
        previous: Option<&FinalizedBlockRecord>,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<bool> {
        if certificate.context.height.checked_sub(2) != Some(record.height)
            || certificate.id()? != record.finality_certificate_id
        {
            return Err(PosyError::Conflict(
                "finality record is not authorized by the paired three-QC closure".into(),
            ));
        }
        let qc = verified_qc_write(certificate, epoch, validators, verifier)?;
        let finality = self.finality.prepared_write(record, previous)?;
        self.store
            .commit_finality_atomic(&[qc, finality], record.height)
    }
}
