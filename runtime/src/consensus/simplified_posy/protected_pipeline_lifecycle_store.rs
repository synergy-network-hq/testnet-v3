//! Crash-safe journal for the PoSy-to-protected-pipeline lifecycle bridge.
//!
//! Consensus callbacks are edge-triggered and may not repeat after restart.
//! This store fsyncs their complete typed production evidence before emitting
//! the compact protected-pipeline observation. Parent H material is kept
//! separate from target H+1 execution material.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::{
    protected_pipeline_consumed_evidence_root, protected_pipeline_finality_evidence_root,
    protected_pipeline_finality_id, protected_pipeline_proposal_evidence_root,
    protected_pipeline_proposal_id, protected_pipeline_qc_evidence_root, protected_pipeline_qc_id,
    ConsensusSignatureVerifier, ProtectedPipelineLifecycleBridge, ProtectedPipelineLifecycleEvent,
    ProtectedPipelineLifecycleSink, ProtectedPipelineLifecycleUpdate, SimplifiedEpochContext,
    SimplifiedProposal, VerifiedSimplifiedProposalMaterial,
};
use crate::consensus::protected_pipeline::ProtectedPipelineObservation;
use crate::consensus::protected_pipeline_evidence_verifier::{
    ProductionProtectedPipelineEvidence, ProtectedFinalityEvidence,
    ProtectedParentProposalEvidence, ProtectedQcEvidence, ProtectedRevealAuthorizationEvidence,
    ProtectedRevealShareEvidence,
};
use crate::crypto::aegis_pqvm::AegisPqvmVerifier;
use crate::etdag::{
    verify_protected_reveal_share, DeterministicProtectedExecutionInput, EtdagDigest,
    NextProtectedBatchCommitment, ProtectedPipelinePhase, ProtectedRevealAuthorization,
    ProtectedRevealShareMessage, TargetAdmissionContext,
};
use crate::synergy_types::{CanonicalSerialize, Hash, ValidatorId, ValidatorSet};

pub const PROTECTED_PIPELINE_LIFECYCLE_STORE_FORMAT: &str =
    "synergy-posy-protected-pipeline-lifecycle-v2";
pub const PROTECTED_PIPELINE_LIFECYCLE_RECORD_VERSION: u32 = 2;
pub const DOMAIN_PROTECTED_REVEAL_SHARE_BUNDLE: &str =
    "PoSy/ProtectedPipeline/RevealShareBundle/v1";
const MAX_PROTECTED_PIPELINE_LIFECYCLE_STORE_BYTES: usize = 128 * 1024 * 1024;

static LIFECYCLE_STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Complete restart evidence for one target. The parent always names H-1 and
/// its future protected commitment names this record's target H.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedPipelineLifecycleRecord {
    pub record_version: u32,
    pub target: TargetAdmissionContext,
    pub parent: ProtectedParentProposalEvidence,
    pub parent_commitment: NextProtectedBatchCommitment,
    pub parent_observation: ProtectedPipelineObservation,
    pub reveal_authorization: Option<ProtectedRevealAuthorizationEvidence>,
    pub reveal_authorization_observation: Option<ProtectedPipelineObservation>,
    /// Full repeated authorization proof and signed share, keyed by
    /// transaction then validator. Partial bundles survive restart.
    pub reveal_shares: BTreeMap<EtdagDigest, BTreeMap<ValidatorId, ProtectedRevealShareEvidence>>,
    pub reveal_share_observations: BTreeMap<ValidatorId, ProtectedPipelineObservation>,
    /// Current target-H material is deliberately separate from the H-1 parent.
    pub execution_proposal: Option<SimplifiedProposal>,
    pub execution_material: Option<VerifiedSimplifiedProposalMaterial>,
    pub consumed_observation: Option<ProtectedPipelineObservation>,
    pub quorum_certificate: Option<ProtectedQcEvidence>,
    pub qc_observation: Option<ProtectedPipelineObservation>,
    pub finality: Option<ProtectedFinalityEvidence>,
    pub finality_observation: Option<ProtectedPipelineObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProtectedPipelineLifecycleEnvelope {
    format: String,
    record: ProtectedPipelineLifecycleRecord,
    record_root: Hash,
}

/// Level-triggered state reconstructed solely from durable typed evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedPipelineLifecycleRecovery {
    pub target: TargetAdmissionContext,
    pub parent_proposal: SimplifiedProposal,
    pub parent_proposal_identity: EtdagDigest,
    pub parent_commitment: NextProtectedBatchCommitment,
    pub reveal_authorization: Option<ProtectedRevealAuthorization>,
    /// Exact content-addressed proof roots for every transaction share. The
    /// outer transaction key is essential: a validator signs one share per
    /// protected transaction, so collapsing these roots by validator would
    /// make a multi-transaction batch unrecoverable.
    pub reveal_share_references: BTreeMap<EtdagDigest, BTreeMap<ValidatorId, EtdagDigest>>,
    pub reveal_shares: BTreeMap<EtdagDigest, BTreeMap<ValidatorId, ProtectedRevealShareMessage>>,
    pub current_phase: ProtectedPipelinePhase,
    pub before_execution: Vec<ProtectedPipelineLifecycleUpdate>,
    pub execution_input: Option<DeterministicProtectedExecutionInput>,
    pub after_execution: Vec<ProtectedPipelineLifecycleUpdate>,
}

/// Recovery adapter implemented by the durable target coordinator. Concrete
/// input has a separate method because root-only `ExecutionReady` is invalid.
pub trait ProtectedPipelineLifecycleRecoverySink: ProtectedPipelineLifecycleSink {
    fn apply_recovered_protected_execution_input(
        &mut self,
        target: &TargetAdmissionContext,
        input: DeterministicProtectedExecutionInput,
    ) -> Result<(), String>;
}

#[derive(Debug, Clone)]
pub struct DurableProtectedPipelineLifecycleStore {
    path: PathBuf,
}

impl DurableProtectedPipelineLifecycleStore {
    pub fn at_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verify a lifecycle event, require its matching complete production
    /// proof, persist it, then dispatch the stored compact observation.
    /// `ExecutionConsumed` is itself complete and requires `evidence == None`.
    pub fn persist_event_before_dispatch<V, S>(
        &self,
        bridge: &ProtectedPipelineLifecycleBridge<'_, V>,
        event: ProtectedPipelineLifecycleEvent,
        evidence: Option<ProductionProtectedPipelineEvidence>,
        sink: &mut S,
    ) -> Result<(), String>
    where
        V: ConsensusSignatureVerifier,
        S: ProtectedPipelineLifecycleSink,
    {
        let mapped = bridge.map_event(event.clone())?;
        let durable_update = self.merge_verified_event(&event, evidence.as_ref(), &mapped)?;
        sink.apply_protected_pipeline_lifecycle_update(durable_update)
    }

    /// Persist one complete share proof before dispatching its aggregate
    /// validator-bundle reference. Partial batches return `Ok(false)`.
    pub fn persist_reveal_share_before_dispatch<S: ProtectedPipelineLifecycleSink>(
        &self,
        evidence: ProtectedRevealShareEvidence,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
        sink: &mut S,
    ) -> Result<bool, String> {
        let update = self.merge_verified_share(evidence, verifier, validator_set)?;
        match update {
            Some(update) => {
                sink.apply_protected_pipeline_lifecycle_update(update)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub fn load(&self) -> Result<Option<ProtectedPipelineLifecycleRecord>, String> {
        let _guard = lifecycle_store_guard()?;
        self.load_unlocked()
    }

    /// Re-authenticate VC, shares, current QC, and finality using the frozen
    /// authorities, then construct a callback-independent restart plan.
    pub fn recover_verified(
        &self,
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        verifier: &AegisPqvmVerifier,
    ) -> Result<Option<ProtectedPipelineLifecycleRecovery>, String> {
        let Some(record) = self.load()? else {
            return Ok(None);
        };
        record.validate_authenticated(epoch_context, validator_set, verifier)?;
        record.recovery().map(Some)
    }

    pub fn replay_verified<S: ProtectedPipelineLifecycleRecoverySink>(
        &self,
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        verifier: &AegisPqvmVerifier,
        sink: &mut S,
    ) -> Result<bool, String> {
        let Some(recovery) = self.recover_verified(epoch_context, validator_set, verifier)? else {
            return Ok(false);
        };
        for update in recovery.before_execution {
            sink.apply_protected_pipeline_lifecycle_update(update)?;
        }
        if let Some(input) = recovery.execution_input {
            sink.apply_recovered_protected_execution_input(&recovery.target, input)?;
        }
        for update in recovery.after_execution {
            sink.apply_protected_pipeline_lifecycle_update(update)?;
        }
        Ok(true)
    }

    fn merge_verified_event(
        &self,
        event: &ProtectedPipelineLifecycleEvent,
        evidence: Option<&ProductionProtectedPipelineEvidence>,
        update: &ProtectedPipelineLifecycleUpdate,
    ) -> Result<ProtectedPipelineLifecycleUpdate, String> {
        let _guard = lifecycle_store_guard()?;
        let mut record = self.load_unlocked()?;
        let durable_update = match event {
            ProtectedPipelineLifecycleEvent::ParentProposalCommitted {
                target,
                proposal,
                material,
            } => {
                let parent = match evidence {
                    Some(ProductionProtectedPipelineEvidence::ParentProposal(parent)) => parent,
                    _ => return Err("parent callback lacks complete parent evidence".to_string()),
                };
                require_parent_event(parent, target, proposal, material)?;
                match &record {
                    Some(existing) => existing.require_same_parent(parent)?,
                    None => {
                        record = Some(ProtectedPipelineLifecycleRecord::new(
                            parent.clone(),
                            update.observation.clone(),
                        )?);
                    }
                }
                update_for_stored_observation(
                    target,
                    record
                        .as_ref()
                        .ok_or_else(|| "parent lifecycle record was lost".to_string())?
                        .parent_observation
                        .clone(),
                    None,
                )
            }
            ProtectedPipelineLifecycleEvent::ProposalValidationCertified {
                target,
                proposal,
                material,
                certificate,
            } => {
                let authorization = match evidence {
                    Some(ProductionProtectedPipelineEvidence::RevealAuthorization(value)) => value,
                    _ => {
                        return Err(
                            "VC callback lacks complete authorization and protected batch"
                                .to_string(),
                        )
                    }
                };
                require_parent_event(&authorization.parent, target, proposal, material)?;
                if &authorization.validation_certificate != certificate
                    || update.reveal_authorization.as_ref() != Some(&authorization.authorization)
                {
                    return Err("VC lifecycle event differs from production evidence".to_string());
                }
                authorization
                    .parent
                    .material
                    .future_protected_batch_commitment
                    .as_ref()
                    .ok_or_else(|| "parent future commitment is missing".to_string())?
                    .validate_against(target, &authorization.protected_batch)?;
                let record = record
                    .as_mut()
                    .ok_or_else(|| "cannot persist VC before parent evidence".to_string())?;
                record.require_same_parent(&authorization.parent)?;
                merge_once(
                    &mut record.reveal_authorization,
                    authorization.clone(),
                    "reveal authorization evidence",
                )?;
                merge_once(
                    &mut record.reveal_authorization_observation,
                    update.observation.clone(),
                    "reveal authorization observation",
                )?;
                update_for_stored_observation(
                    target,
                    record
                        .reveal_authorization_observation
                        .clone()
                        .ok_or_else(|| "stored reveal observation was lost".to_string())?,
                    Some(authorization.authorization.clone()),
                )
            }
            ProtectedPipelineLifecycleEvent::ExecutionConsumed {
                target,
                proposal,
                material,
            } => {
                if evidence.is_some() {
                    return Err("execution callback has unexpected side evidence".to_string());
                }
                let record = record
                    .as_mut()
                    .ok_or_else(|| "cannot persist execution before parent evidence".to_string())?;
                record.require_execution_target(target, proposal, material)?;
                record.install_execution(proposal, material)?;
                merge_once(
                    &mut record.consumed_observation,
                    update.observation.clone(),
                    "consumed observation",
                )?;
                update_for_stored_observation(
                    target,
                    record
                        .consumed_observation
                        .clone()
                        .ok_or_else(|| "stored consumed observation was lost".to_string())?,
                    None,
                )
            }
            ProtectedPipelineLifecycleEvent::QuorumCertified {
                target,
                proposal,
                material,
                certificate,
            } => {
                let qc = match evidence {
                    Some(ProductionProtectedPipelineEvidence::QuorumCertificate(qc)) => qc,
                    _ => return Err("QC callback lacks complete QC evidence".to_string()),
                };
                if &qc.target != target
                    || &qc.material != material
                    || &qc.certificate != certificate
                {
                    return Err("QC lifecycle event differs from production evidence".to_string());
                }
                let record = record
                    .as_mut()
                    .ok_or_else(|| "cannot persist QC before parent evidence".to_string())?;
                record.require_execution_target(target, proposal, material)?;
                if record.consumed_observation.is_none() {
                    return Err("cannot persist QC before protected consumption".to_string());
                }
                record.install_execution(proposal, material)?;
                merge_semantic_qc(record, qc, &update.observation)?;
                update_for_stored_observation(
                    target,
                    record
                        .qc_observation
                        .clone()
                        .ok_or_else(|| "stored QC observation was lost".to_string())?,
                    None,
                )
            }
            ProtectedPipelineLifecycleEvent::FinalizationCommitted {
                target,
                proposal,
                material,
                transaction,
            } => {
                let finality = match evidence {
                    Some(ProductionProtectedPipelineEvidence::Finality(finality)) => finality,
                    _ => return Err("finality callback lacks complete evidence".to_string()),
                };
                if &finality.target != target
                    || &finality.material != material
                    || &finality.transaction != transaction
                {
                    return Err(
                        "finality lifecycle event differs from production evidence".to_string()
                    );
                }
                let record = record
                    .as_mut()
                    .ok_or_else(|| "cannot persist finality before parent evidence".to_string())?;
                record.require_execution_target(target, proposal, material)?;
                if record.qc_observation.is_none() {
                    return Err("cannot persist finality before target QC".to_string());
                }
                record.install_execution(proposal, material)?;
                merge_once(&mut record.finality, finality.clone(), "finality evidence")?;
                merge_once(
                    &mut record.finality_observation,
                    update.observation.clone(),
                    "finality observation",
                )?;
                update_for_stored_observation(
                    target,
                    record
                        .finality_observation
                        .clone()
                        .ok_or_else(|| "stored finality observation was lost".to_string())?,
                    None,
                )
            }
        };
        let record = record.ok_or_else(|| "lifecycle event produced no record".to_string())?;
        record.validate_structural()?;
        self.persist_unlocked(&record)?;
        Ok(durable_update)
    }

    fn merge_verified_share(
        &self,
        evidence: ProtectedRevealShareEvidence,
        verifier: &AegisPqvmVerifier,
        validator_set: &ValidatorSet,
    ) -> Result<Option<ProtectedPipelineLifecycleUpdate>, String> {
        let _guard = lifecycle_store_guard()?;
        let mut record = self
            .load_unlocked()?
            .ok_or_else(|| "cannot persist share before parent evidence".to_string())?;
        let authorization = record
            .reveal_authorization
            .as_ref()
            .ok_or_else(|| "cannot persist share before VC authorization".to_string())?;
        if &evidence.authorization != authorization {
            return Err("share repeats another reveal authorization".to_string());
        }
        verify_protected_reveal_share(
            &evidence.share,
            &authorization.authorization,
            &record.parent_commitment,
            &authorization.protected_batch,
            verifier,
            &record.target,
            validator_set,
        )?;
        let tx = evidence.share.tx_commitment.clone();
        let validator = evidence.share.validator_id.clone();
        merge_map_once(
            record.reveal_shares.entry(tx).or_default(),
            validator.clone(),
            evidence,
            "reveal share",
        )?;
        let expected = authorization
            .protected_batch
            .ordered_transaction_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let complete = record
            .reveal_shares
            .iter()
            .filter_map(|(tx, shares)| shares.contains_key(&validator).then_some(tx.clone()))
            .collect::<BTreeSet<_>>();
        let update = if complete == expected {
            let bundle = share_bundle(&record, &validator, &expected)?;
            let observation = ProtectedPipelineObservation::RevealShare {
                validator_id: validator.clone(),
                commitment_root: record.parent_commitment.root()?,
                share_root: EtdagDigest::from_canonical(
                    DOMAIN_PROTECTED_REVEAL_SHARE_BUNDLE,
                    &bundle,
                )?,
            };
            merge_map_once(
                &mut record.reveal_share_observations,
                validator,
                observation.clone(),
                "reveal-share observation",
            )?;
            Some(update_for_stored_observation(
                &record.target,
                observation,
                None,
            ))
        } else {
            None
        };
        record.validate_structural()?;
        self.persist_unlocked(&record)?;
        Ok(update)
    }

    fn load_unlocked(&self) -> Result<Option<ProtectedPipelineLifecycleRecord>, String> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&self.path).map_err(|error| {
            format!("read protected lifecycle {}: {error}", self.path.display())
        })?;
        if bytes.is_empty() || bytes.len() > MAX_PROTECTED_PIPELINE_LIFECYCLE_STORE_BYTES {
            return Err("protected lifecycle store violates its decode bound".to_string());
        }
        let envelope: ProtectedPipelineLifecycleEnvelope = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse protected lifecycle store: {error}"))?;
        if envelope.format != PROTECTED_PIPELINE_LIFECYCLE_STORE_FORMAT {
            return Err("unsupported protected lifecycle store format".to_string());
        }
        envelope.record.validate_structural()?;
        if envelope.record_root != lifecycle_record_root(&envelope.record)? {
            return Err("protected lifecycle store root mismatch".to_string());
        }
        Ok(Some(envelope.record))
    }

    fn persist_unlocked(&self, record: &ProtectedPipelineLifecycleRecord) -> Result<(), String> {
        let envelope = ProtectedPipelineLifecycleEnvelope {
            format: PROTECTED_PIPELINE_LIFECYCLE_STORE_FORMAT.to_string(),
            record: record.clone(),
            record_root: lifecycle_record_root(record)?,
        };
        let bytes = serde_json::to_vec_pretty(&envelope)
            .map_err(|error| format!("serialize protected lifecycle store: {error}"))?;
        if bytes.len() > MAX_PROTECTED_PIPELINE_LIFECYCLE_STORE_BYTES {
            return Err("protected lifecycle store exceeds its durable bound".to_string());
        }
        atomic_write(&self.path, &bytes)
    }
}

impl ProtectedPipelineLifecycleRecord {
    fn new(
        parent: ProtectedParentProposalEvidence,
        parent_observation: ProtectedPipelineObservation,
    ) -> Result<Self, String> {
        let parent_commitment = parent
            .material
            .future_protected_batch_commitment
            .clone()
            .ok_or_else(|| "parent evidence has no future protected commitment".to_string())?;
        let record = Self {
            record_version: PROTECTED_PIPELINE_LIFECYCLE_RECORD_VERSION,
            target: parent.target.clone(),
            parent,
            parent_commitment,
            parent_observation,
            reveal_authorization: None,
            reveal_authorization_observation: None,
            reveal_shares: BTreeMap::new(),
            reveal_share_observations: BTreeMap::new(),
            execution_proposal: None,
            execution_material: None,
            consumed_observation: None,
            quorum_certificate: None,
            qc_observation: None,
            finality: None,
            finality_observation: None,
        };
        record.validate_structural()?;
        Ok(record)
    }

    fn require_same_parent(&self, parent: &ProtectedParentProposalEvidence) -> Result<(), String> {
        if &self.parent != parent || self.target != parent.target {
            return Err("durable target already owns another parent proposal".to_string());
        }
        Ok(())
    }

    fn require_execution_target(
        &self,
        target: &TargetAdmissionContext,
        proposal: &SimplifiedProposal,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<(), String> {
        let input = material
            .protected_execution_input
            .as_ref()
            .ok_or_else(|| "target execution material has no concrete input".to_string())?;
        if target != &self.target
            || proposal.context.height != target.target_height
            || material.candidate_subject.block_id != proposal.block_id
            || material.next_protected_batch_commitment.as_ref() != Some(&self.parent_commitment)
            || input.next_commitment != self.parent_commitment
        {
            return Err("target execution differs from durable parent commitment".to_string());
        }
        let authorization = self
            .reveal_authorization
            .as_ref()
            .ok_or_else(|| "target execution exists before reveal authorization".to_string())?;
        if input.reveal_authorization.as_ref() != Some(&authorization.authorization) {
            return Err("target execution names another reveal authorization".to_string());
        }
        Ok(())
    }

    fn install_execution(
        &mut self,
        proposal: &SimplifiedProposal,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<(), String> {
        merge_once(
            &mut self.execution_proposal,
            proposal.clone(),
            "execution proposal",
        )?;
        merge_once(
            &mut self.execution_material,
            material.clone(),
            "execution material",
        )
    }

    fn validate_structural(&self) -> Result<(), String> {
        if self.record_version != PROTECTED_PIPELINE_LIFECYCLE_RECORD_VERSION
            || self.parent.target != self.target
            || self
                .parent
                .material
                .future_protected_batch_commitment
                .as_ref()
                != Some(&self.parent_commitment)
            || self
                .parent
                .proposal
                .context
                .height
                .0
                .checked_add(1)
                .map(crate::synergy_types::Height)
                != Some(self.target.target_height)
        {
            return Err("invalid protected lifecycle parent record".to_string());
        }
        self.target.validate()?;
        self.parent_commitment
            .validate_against_context(&self.target)?;
        self.parent
            .material
            .validate(self.parent.proposal.context.epoch_context_root)?;
        let expected_parent = ProtectedPipelineObservation::ParentCommitment {
            proposal_id: protected_pipeline_proposal_id(&self.parent.material.candidate_subject)?,
            commitment_root: self.parent_commitment.root()?,
            evidence_root: protected_pipeline_proposal_evidence_root(
                &self.parent.proposal,
                &self.parent.material,
            )?,
        };
        require_same_observation(&self.parent_observation, &expected_parent)?;
        match (
            &self.reveal_authorization,
            &self.reveal_authorization_observation,
        ) {
            (None, None) => {
                if !self.reveal_shares.is_empty() || !self.reveal_share_observations.is_empty() {
                    return Err("share evidence exists before reveal authorization".to_string());
                }
            }
            (Some(evidence), Some(observation)) => {
                if evidence.parent != self.parent {
                    return Err("reveal authorization names another parent".to_string());
                }
                self.parent_commitment
                    .validate_against(&self.target, &evidence.protected_batch)?;
                evidence.authorization.validate_against(
                    &self.target,
                    &self.parent_commitment,
                    &evidence.protected_batch,
                )?;
                let expected = ProtectedPipelineObservation::RevealAuthorization {
                    proposal_id: protected_pipeline_proposal_id(
                        &self.parent.material.candidate_subject,
                    )?,
                    vc_root: evidence.authorization.certificate_evidence_root.clone(),
                    commitment_root: self.parent_commitment.root()?,
                    evidence_root: evidence.authorization.root()?,
                };
                require_same_observation(observation, &expected)?;
                self.validate_share_references(evidence)?;
            }
            _ => return Err("incomplete durable reveal authorization".to_string()),
        }
        match (&self.execution_proposal, &self.execution_material) {
            (None, None) => {
                if self.consumed_observation.is_some()
                    || self.quorum_certificate.is_some()
                    || self.finality.is_some()
                {
                    return Err("target consensus evidence exists before execution".to_string());
                }
            }
            (Some(proposal), Some(material)) => {
                self.require_execution_target(&self.target, proposal, material)?;
                if let Some(observation) = &self.consumed_observation {
                    let input = material
                        .protected_execution_input
                        .as_ref()
                        .ok_or_else(|| "execution input disappeared".to_string())?;
                    let expected = ProtectedPipelineObservation::Consumed {
                        commitment_root: self.parent_commitment.root()?,
                        execution_root: input.digest()?,
                        evidence_root: protected_pipeline_consumed_evidence_root(
                            proposal, material,
                        )?,
                    };
                    require_same_observation(observation, &expected)?;
                }
                self.validate_qc_and_finality(material)?;
            }
            _ => return Err("incomplete durable target execution evidence".to_string()),
        }
        Ok(())
    }

    fn validate_share_references(
        &self,
        authorization: &ProtectedRevealAuthorizationEvidence,
    ) -> Result<(), String> {
        let expected = authorization
            .protected_batch
            .ordered_transaction_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if !self.reveal_shares.keys().all(|tx| expected.contains(tx)) {
            return Err("share evidence names an uncommitted transaction".to_string());
        }
        for (tx, shares) in &self.reveal_shares {
            for (validator, share) in shares {
                if &share.authorization != authorization
                    || &share.share.tx_commitment != tx
                    || &share.share.validator_id != validator
                {
                    return Err("durable share evidence binding mismatch".to_string());
                }
            }
        }
        for (validator, observation) in &self.reveal_share_observations {
            let bundle = share_bundle(self, validator, &expected)?;
            let expected = ProtectedPipelineObservation::RevealShare {
                validator_id: validator.clone(),
                commitment_root: self.parent_commitment.root()?,
                share_root: EtdagDigest::from_canonical(
                    DOMAIN_PROTECTED_REVEAL_SHARE_BUNDLE,
                    &bundle,
                )?,
            };
            require_same_observation(observation, &expected)?;
        }
        Ok(())
    }

    fn validate_qc_and_finality(
        &self,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<(), String> {
        match (&self.quorum_certificate, &self.qc_observation) {
            (None, None) => {}
            (Some(qc), Some(observation)) => {
                if qc.target != self.target || &qc.material != material {
                    return Err("durable QC names another target material".to_string());
                }
                let expected = ProtectedPipelineObservation::QcObserved {
                    commitment_root: self.parent_commitment.root()?,
                    qc_root: protected_pipeline_qc_id(&qc.certificate)?,
                    evidence_root: protected_pipeline_qc_evidence_root(&qc.certificate)?,
                };
                require_same_observation(observation, &expected)?;
            }
            _ => return Err("incomplete durable QC evidence".to_string()),
        }
        match (&self.finality, &self.finality_observation) {
            (None, None) => {}
            (Some(finality), Some(observation)) => {
                if finality.target != self.target || &finality.material != material {
                    return Err("durable finality names another target material".to_string());
                }
                finality.transaction.validate()?;
                let expected = ProtectedPipelineObservation::Finalized {
                    commitment_root: self.parent_commitment.root()?,
                    finality_root: protected_pipeline_finality_id(&finality.transaction),
                    evidence_root: protected_pipeline_finality_evidence_root(
                        &finality.transaction,
                    )?,
                };
                require_same_observation(observation, &expected)?;
                if self.qc_observation.is_none() {
                    return Err("durable finality exists before target QC".to_string());
                }
            }
            _ => return Err("incomplete durable finality evidence".to_string()),
        }
        Ok(())
    }

    fn validate_authenticated(
        &self,
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        verifier: &AegisPqvmVerifier,
    ) -> Result<(), String> {
        self.validate_structural()?;
        epoch_context.validate_against(validator_set)?;
        if let Some(authorization) = &self.reveal_authorization {
            authorization
                .validation_certificate
                .validate_authenticated(
                    &authorization.parent.material,
                    epoch_context,
                    validator_set,
                    verifier,
                )?;
            for shares in self.reveal_shares.values() {
                for share in shares.values() {
                    verify_protected_reveal_share(
                        &share.share,
                        &authorization.authorization,
                        &self.parent_commitment,
                        &authorization.protected_batch,
                        verifier,
                        &self.target,
                        validator_set,
                    )?;
                }
            }
        }
        if let Some(qc) = &self.quorum_certificate {
            qc.certificate
                .verify(epoch_context, validator_set, verifier)?;
        }
        if let Some(finality) = &self.finality {
            for commitment in &finality.transaction.commitments {
                commitment
                    .certificate
                    .verify(epoch_context, validator_set, verifier)?;
            }
        }
        Ok(())
    }

    fn recovery(&self) -> Result<ProtectedPipelineLifecycleRecovery, String> {
        self.validate_structural()?;
        let mut before_execution = vec![update_for_stored_observation(
            &self.target,
            self.parent_observation.clone(),
            None,
        )];
        if let (Some(evidence), Some(observation)) = (
            &self.reveal_authorization,
            &self.reveal_authorization_observation,
        ) {
            before_execution.push(update_for_stored_observation(
                &self.target,
                observation.clone(),
                Some(evidence.authorization.clone()),
            ));
        }
        for observation in self.reveal_share_observations.values() {
            before_execution.push(update_for_stored_observation(
                &self.target,
                observation.clone(),
                None,
            ));
        }
        let mut after_execution = Vec::new();
        for observation in [
            self.consumed_observation.as_ref(),
            self.qc_observation.as_ref(),
            self.finality_observation.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            after_execution.push(update_for_stored_observation(
                &self.target,
                observation.clone(),
                None,
            ));
        }
        let execution_input = self
            .execution_material
            .as_ref()
            .and_then(|material| material.protected_execution_input.clone());
        Ok(ProtectedPipelineLifecycleRecovery {
            target: self.target.clone(),
            parent_proposal: self.parent.proposal.clone(),
            parent_proposal_identity: protected_pipeline_proposal_id(
                &self.parent.material.candidate_subject,
            )?,
            parent_commitment: self.parent_commitment.clone(),
            reveal_authorization: self
                .reveal_authorization
                .as_ref()
                .map(|evidence| evidence.authorization.clone()),
            reveal_share_references: reveal_share_reference_roots(self)?,
            reveal_shares: self
                .reveal_shares
                .iter()
                .map(|(tx, shares)| {
                    (
                        tx.clone(),
                        shares
                            .iter()
                            .map(|(validator, evidence)| {
                                (validator.clone(), evidence.share.clone())
                            })
                            .collect(),
                    )
                })
                .collect(),
            current_phase: lifecycle_phase(
                self.reveal_authorization.is_some(),
                !self.reveal_shares.is_empty(),
                execution_input.is_some(),
                self.consumed_observation.is_some(),
            ),
            before_execution,
            execution_input,
            after_execution,
        })
    }
}

fn require_parent_event(
    evidence: &ProtectedParentProposalEvidence,
    target: &TargetAdmissionContext,
    proposal: &SimplifiedProposal,
    material: &VerifiedSimplifiedProposalMaterial,
) -> Result<(), String> {
    if &evidence.target != target
        || &evidence.proposal != proposal
        || &evidence.material != material
        || material
            .future_protected_batch_commitment
            .as_ref()
            .map(|value| value.target_height)
            != Some(target.target_height)
    {
        return Err("parent lifecycle event differs from production evidence".to_string());
    }
    Ok(())
}

fn merge_semantic_qc(
    record: &mut ProtectedPipelineLifecycleRecord,
    qc: &ProtectedQcEvidence,
    observation: &ProtectedPipelineObservation,
) -> Result<(), String> {
    match &record.quorum_certificate {
        Some(existing) if existing.certificate.id()? != qc.certificate.id()? => {
            return Err("durable lifecycle has a conflicting QC subject".to_string())
        }
        Some(_) => {}
        None => {
            record.quorum_certificate = Some(qc.clone());
            record.qc_observation = Some(observation.clone());
        }
    }
    Ok(())
}

fn share_bundle(
    record: &ProtectedPipelineLifecycleRecord,
    validator: &ValidatorId,
    expected: &BTreeSet<EtdagDigest>,
) -> Result<BTreeMap<EtdagDigest, ProtectedRevealShareEvidence>, String> {
    expected
        .iter()
        .map(|tx| {
            record
                .reveal_shares
                .get(tx)
                .and_then(|shares| shares.get(validator))
                .cloned()
                .map(|share| (tx.clone(), share))
                .ok_or_else(|| "reveal-share bundle is incomplete".to_string())
        })
        .collect()
}

fn reveal_share_reference_roots(
    record: &ProtectedPipelineLifecycleRecord,
) -> Result<BTreeMap<EtdagDigest, BTreeMap<ValidatorId, EtdagDigest>>, String> {
    record
        .reveal_shares
        .iter()
        .map(|(transaction, shares)| {
            let roots = shares
                .iter()
                .map(|(validator, evidence)| Ok((validator.clone(), evidence.evidence_root()?)))
                .collect::<Result<BTreeMap<_, _>, String>>()?;
            Ok((transaction.clone(), roots))
        })
        .collect()
}

pub(crate) fn lifecycle_phase(
    reveal_authorized: bool,
    reveal_share_present: bool,
    execution_recoverable: bool,
    consumed: bool,
) -> ProtectedPipelinePhase {
    if consumed {
        ProtectedPipelinePhase::Consumed
    } else if execution_recoverable {
        ProtectedPipelinePhase::ReadyForExecution
    } else if reveal_share_present {
        ProtectedPipelinePhase::Revealing
    } else if reveal_authorized {
        ProtectedPipelinePhase::RevealAuthorized
    } else {
        ProtectedPipelinePhase::CommittedInParent
    }
}

fn update_for_stored_observation(
    target: &TargetAdmissionContext,
    observation: ProtectedPipelineObservation,
    reveal_authorization: Option<ProtectedRevealAuthorization>,
) -> ProtectedPipelineLifecycleUpdate {
    ProtectedPipelineLifecycleUpdate {
        target: target.clone(),
        observation,
        reveal_authorization,
    }
}

fn lifecycle_record_root(record: &ProtectedPipelineLifecycleRecord) -> Result<Hash, String> {
    Ok(Hash::from_domain_bytes(
        "SYNERGY_POSY_PROTECTED_PIPELINE_LIFECYCLE_RECORD_V2",
        &record.canonical_bytes()?,
    ))
}

fn merge_once<T: PartialEq>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), String> {
    match slot {
        Some(existing) if existing != &value => {
            Err(format!("durable lifecycle has conflicting {name}"))
        }
        Some(_) => Ok(()),
        None => {
            *slot = Some(value);
            Ok(())
        }
    }
}

fn merge_map_once<K: Ord, V: PartialEq>(
    map: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    name: &str,
) -> Result<(), String> {
    match map.get(&key) {
        Some(existing) if existing != &value => {
            Err(format!("durable lifecycle has conflicting {name}"))
        }
        Some(_) => Ok(()),
        None => {
            map.insert(key, value);
            Ok(())
        }
    }
}

fn require_same_observation(
    actual: &ProtectedPipelineObservation,
    expected: &ProtectedPipelineObservation,
) -> Result<(), String> {
    if actual != expected {
        return Err("durable lifecycle compact observation mismatch".to_string());
    }
    Ok(())
}

fn lifecycle_store_guard() -> Result<std::sync::MutexGuard<'static, ()>, String> {
    LIFECYCLE_STORE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "protected lifecycle store lock is poisoned".to_string())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "protected lifecycle path has no parent".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create lifecycle directory {}: {error}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "protected lifecycle path has no file name".to_string())?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("lifecycle store clock failure: {error}"))?
        .as_nanos();
    let temporary = parent.join(format!(".{name}.tmp-{}-{nonce}", std::process::id()));
    let result = (|| -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| format!("create lifecycle temp {}: {error}", temporary.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("write lifecycle temp {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("fsync lifecycle temp {}: {error}", temporary.display()))?;
        fs::rename(&temporary, path)
            .map_err(|error| format!("replace lifecycle store {}: {error}", path.display()))?;
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("fsync lifecycle directory {}: {error}", parent.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
pub(crate) fn test_atomic_round_trip(path: &Path, bytes: &[u8]) -> Result<Vec<u8>, String> {
    atomic_write(path, bytes)?;
    fs::read(path).map_err(|error| format!("read test lifecycle store: {error}"))
}
