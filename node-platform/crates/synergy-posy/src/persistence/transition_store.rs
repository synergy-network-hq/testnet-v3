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

    /// Imports an independently authenticated sparse snapshot anchor, including
    /// all three QCs in the same atomic evidence commit. This never changes a
    /// signing journal or supplies authorization for a current validator to roll
    /// back. Native startup restricts it to an admitted, non-voting new identity.
    pub fn commit_verified_snapshot_anchor(
        &self,
        record: &FinalizedBlockRecord,
        witness: &crate::FinalitySyncWitness,
        epoch: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<bool> {
        if witness.timeout_certificates.len() > 128 {
            return Err(PosyError::invalid("snapshot timeout work exceeds bound"));
        }
        witness.verified_timeout_closure(epoch, validators, verifier)?;
        let mut verified = crate::ThreeQcFinality::default();
        let mut writes = vec![];
        for qc in &witness.quorum_certificates {
            writes.push(verified_qc_write(qc, epoch, validators, verifier)?);
            verified.accept(qc.clone())?;
        }
        if verified.last_finalized() != Some(record) {
            return Err(PosyError::Conflict(
                "snapshot anchor differs from its complete three-QC finality".into(),
            ));
        }
        writes.push(self.finality.snapshot_anchor_write(record)?);
        self.store.commit_finality_atomic(&writes, record.height)
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
