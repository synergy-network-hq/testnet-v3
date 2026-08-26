//! Typed PoSy lifecycle events for the normal protected pipeline.
//!
//! The simplified driver owns proposal delivery, the proposal-validation
//! certificate (VC), the ordinary block QC, and three-chain finality.  The
//! protected pipeline owns the monotonic ETDAG/reveal/execution lifecycle.
//! This module is the narrow bridge between those owners: it accepts complete
//! typed PoSy artifacts, re-checks their cross-object bindings, and derives the
//! exact [`ProtectedPipelineObservation`] that a durable target coordinator may
//! merge.  It never accepts a caller-selected observation root.

use super::{
    CertifiedCandidateSubject, ConsensusSignatureVerifier, PosyProposalValidationCertificate,
    SimplifiedEpochContext, SimplifiedFinalizationTransaction, SimplifiedProposal,
    SimplifiedQuorumCertificate, VerifiedSimplifiedProposalMaterial,
};
use crate::consensus::protected_pipeline::ProtectedPipelineObservation;
use crate::etdag::{
    DeterministicProtectedExecutionInput, EtdagDigest, NextProtectedBatchCommitment,
    ProtectedBatchSource, ProtectedExecutionTargetContext, ProtectedRevealAuthorization,
    TargetAdmissionContext, PROTECTED_PIPELINE_VERSION,
};
use crate::synergy_types::{CanonicalSerialize, Hash, Height, ValidatorSet};

/// Stable domains for independently reproducible lifecycle evidence.
pub const DOMAIN_PROTECTED_POSY_PROPOSAL_ID: &str = "PoSy/ProtectedPipeline/ProposalSemanticId/v1";
pub const DOMAIN_PROTECTED_POSY_PROPOSAL_EVIDENCE: &str =
    "PoSy/ProtectedPipeline/ProposalEvidence/v1";
pub const DOMAIN_PROTECTED_POSY_CONSUMED_EVIDENCE: &str =
    "PoSy/ProtectedPipeline/ConsumedEvidence/v1";
pub const DOMAIN_PROTECTED_POSY_QC_ID: &str = "PoSy/ProtectedPipeline/QcSemanticId/v1";
pub const DOMAIN_PROTECTED_POSY_QC_EVIDENCE: &str = "PoSy/ProtectedPipeline/QcEvidence/v1";
pub const DOMAIN_PROTECTED_POSY_FINALITY_ID: &str = "PoSy/ProtectedPipeline/FinalitySemanticId/v1";
pub const DOMAIN_PROTECTED_POSY_FINALITY_EVIDENCE: &str =
    "PoSy/ProtectedPipeline/FinalityEvidence/v1";

/// A production PoSy event that can advance or annotate one normal H3+
/// protected-pipeline target.
///
/// Each variant carries the proposal material because that durable material is
/// the canonical link between a PoSy candidate and the exact ETDAG commitment.
/// This prevents a QC or finality transaction from being paired with a
/// commitment selected by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectedPipelineLifecycleEvent {
    /// An authenticated proposal and its independently verified protected
    /// material were accepted by the PoSy proposal path.
    ParentProposalCommitted {
        target: TargetAdmissionContext,
        proposal: SimplifiedProposal,
        material: VerifiedSimplifiedProposalMaterial,
    },
    /// The canonical n-1 ECHO VC was authenticated for the exact proposal.
    ProposalValidationCertified {
        target: TargetAdmissionContext,
        proposal: SimplifiedProposal,
        material: VerifiedSimplifiedProposalMaterial,
        certificate: PosyProposalValidationCertificate,
    },
    /// Deterministic execution consumed the complete replayable protected
    /// input retained in the verified proposal material.
    ExecutionConsumed {
        target: TargetAdmissionContext,
        proposal: SimplifiedProposal,
        material: VerifiedSimplifiedProposalMaterial,
    },
    /// The ordinary PoSy QC authenticated the candidate that consumed the
    /// exact protected input.
    QuorumCertified {
        target: TargetAdmissionContext,
        proposal: SimplifiedProposal,
        material: VerifiedSimplifiedProposalMaterial,
        certificate: SimplifiedQuorumCertificate,
    },
    /// The protected application sink durably committed the PoSy three-chain
    /// finalization transaction containing this exact candidate.
    FinalizationCommitted {
        target: TargetAdmissionContext,
        proposal: SimplifiedProposal,
        material: VerifiedSimplifiedProposalMaterial,
        transaction: SimplifiedFinalizationTransaction,
    },
}

/// One verified target-bound update ready for the durable protected-pipeline
/// coordinator.  A VC update also carries the exact reveal authorization that
/// validators must use when journaling decrypt-share release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedPipelineLifecycleUpdate {
    pub target: TargetAdmissionContext,
    pub observation: ProtectedPipelineObservation,
    pub reveal_authorization: Option<ProtectedRevealAuthorization>,
}

/// Durable integration boundary implemented by the normal protected-pipeline
/// coordinator (or a thin adapter around it).
pub trait ProtectedPipelineLifecycleSink {
    fn apply_protected_pipeline_lifecycle_update(
        &mut self,
        update: ProtectedPipelineLifecycleUpdate,
    ) -> Result<(), String>;
}

/// Frozen verification authority used to map typed PoSy lifecycle events.
pub struct ProtectedPipelineLifecycleBridge<'a, V> {
    epoch_context: &'a SimplifiedEpochContext,
    validator_set: &'a ValidatorSet,
    verifier: &'a V,
}

impl<'a, V: ConsensusSignatureVerifier> ProtectedPipelineLifecycleBridge<'a, V> {
    pub fn new(
        epoch_context: &'a SimplifiedEpochContext,
        validator_set: &'a ValidatorSet,
        verifier: &'a V,
    ) -> Result<Self, String> {
        epoch_context.validate_against(validator_set)?;
        Ok(Self {
            epoch_context,
            validator_set,
            verifier,
        })
    }

    /// Validate and map one lifecycle event without changing durable state.
    pub fn map_event(
        &self,
        event: ProtectedPipelineLifecycleEvent,
    ) -> Result<ProtectedPipelineLifecycleUpdate, String> {
        match event {
            ProtectedPipelineLifecycleEvent::ParentProposalCommitted {
                target,
                proposal,
                material,
            } => {
                let binding = self.validate_normal_binding(&target, &proposal, &material)?;
                Ok(ProtectedPipelineLifecycleUpdate {
                    target,
                    observation: ProtectedPipelineObservation::ParentCommitment {
                        proposal_id: protected_pipeline_proposal_id(&binding.candidate)?,
                        commitment_root: binding.commitment.root()?,
                        evidence_root: protected_pipeline_proposal_evidence_root(
                            &proposal, &material,
                        )?,
                    },
                    reveal_authorization: None,
                })
            }
            ProtectedPipelineLifecycleEvent::ProposalValidationCertified {
                target,
                proposal,
                material,
                certificate,
            } => {
                let binding = self.validate_normal_binding(&target, &proposal, &material)?;
                certificate.validate_authenticated(
                    &material,
                    self.epoch_context,
                    self.validator_set,
                    self.verifier,
                )?;
                if certificate.candidate != binding.candidate
                    || certificate.context != proposal.context
                    || certificate.next_protected_batch_commitment_root
                        != binding.commitment.root()?
                {
                    return Err(
                        "proposal VC does not certify the exact protected parent proposal"
                            .to_string(),
                    );
                }
                let authorization = build_protected_reveal_authorization(
                    &target,
                    &proposal,
                    binding.input,
                    &certificate,
                )?;
                let observation = ProtectedPipelineObservation::RevealAuthorization {
                    proposal_id: protected_pipeline_proposal_id(&binding.candidate)?,
                    vc_root: authorization.certificate_evidence_root.clone(),
                    commitment_root: binding.commitment.root()?,
                    evidence_root: authorization.root()?,
                };
                Ok(ProtectedPipelineLifecycleUpdate {
                    target,
                    observation,
                    reveal_authorization: Some(authorization),
                })
            }
            ProtectedPipelineLifecycleEvent::ExecutionConsumed {
                target,
                proposal,
                material,
            } => {
                let binding = self.validate_normal_binding(&target, &proposal, &material)?;
                require_consumed_reveal_binding(&target, &proposal, binding.input)?;
                let execution_root = binding.input.digest()?;
                Ok(ProtectedPipelineLifecycleUpdate {
                    target,
                    observation: ProtectedPipelineObservation::Consumed {
                        commitment_root: binding.commitment.root()?,
                        execution_root,
                        evidence_root: protected_pipeline_consumed_evidence_root(
                            &proposal, &material,
                        )?,
                    },
                    reveal_authorization: None,
                })
            }
            ProtectedPipelineLifecycleEvent::QuorumCertified {
                target,
                proposal,
                material,
                certificate,
            } => {
                let binding = self.validate_normal_binding(&target, &proposal, &material)?;
                require_consumed_reveal_binding(&target, &proposal, binding.input)?;
                certificate.verify(self.epoch_context, self.validator_set, self.verifier)?;
                if certificate.subject()? != binding.candidate
                    || certificate.context != proposal.context
                    || certificate.protected_execution_root
                        != binding.candidate.protected_execution_root
                {
                    return Err(
                        "PoSy QC does not certify the exact protected proposal material"
                            .to_string(),
                    );
                }
                Ok(ProtectedPipelineLifecycleUpdate {
                    target,
                    observation: ProtectedPipelineObservation::QcObserved {
                        commitment_root: binding.commitment.root()?,
                        qc_root: protected_pipeline_qc_id(&certificate)?,
                        evidence_root: protected_pipeline_qc_evidence_root(&certificate)?,
                    },
                    reveal_authorization: None,
                })
            }
            ProtectedPipelineLifecycleEvent::FinalizationCommitted {
                target,
                proposal,
                material,
                transaction,
            } => {
                let binding = self.validate_normal_binding(&target, &proposal, &material)?;
                require_consumed_reveal_binding(&target, &proposal, binding.input)?;
                transaction.validate()?;
                let matching = transaction
                    .commitments
                    .iter()
                    .filter(|entry| {
                        entry.height == proposal.context.height
                            && entry.block_id == proposal.block_id
                            && entry.qc_id == material.stable_candidate_id
                            && entry.protected_execution_root
                                == material.candidate_subject.protected_execution_root
                    })
                    .collect::<Vec<_>>();
                if matching.len() != 1 {
                    return Err(
                        "finalization transaction does not contain exactly one exact protected candidate"
                            .to_string(),
                    );
                }
                matching[0].certificate.verify(
                    self.epoch_context,
                    self.validator_set,
                    self.verifier,
                )?;
                Ok(ProtectedPipelineLifecycleUpdate {
                    target,
                    observation: ProtectedPipelineObservation::Finalized {
                        commitment_root: binding.commitment.root()?,
                        finality_root: protected_pipeline_finality_id(&transaction),
                        evidence_root: protected_pipeline_finality_evidence_root(&transaction)?,
                    },
                    reveal_authorization: None,
                })
            }
        }
    }

    /// Validate, map, and synchronously hand one update to its durable owner.
    /// Returning success means the sink accepted the update; it does not imply
    /// that a later pipeline phase was skipped or manufactured.
    pub fn dispatch<S: ProtectedPipelineLifecycleSink>(
        &self,
        event: ProtectedPipelineLifecycleEvent,
        sink: &mut S,
    ) -> Result<(), String> {
        sink.apply_protected_pipeline_lifecycle_update(self.map_event(event)?)
    }

    fn validate_normal_binding<'b>(
        &self,
        target: &TargetAdmissionContext,
        proposal: &SimplifiedProposal,
        material: &'b VerifiedSimplifiedProposalMaterial,
    ) -> Result<NormalProtectedBinding<'b>, String> {
        target.validate()?;
        if target.target_height.0 < 3 {
            return Err("normal protected lifecycle is unavailable before H3".to_string());
        }
        proposal.context.validate_against(self.epoch_context)?;
        if proposal.context.chain_id != target.chain_id
            || proposal.context.network_id != target.network_id
            || proposal.context.protocol_version != target.protocol_version
            || proposal.context.epoch != target.epoch
            || proposal.context.height != target.target_height
            || proposal.context.active_validator_set_root != target.active_validator_set_root
            || proposal.context.validator_consensus_key_root != target.validator_consensus_key_root
            || proposal.context.frozen_voting_weight_root != target.frozen_bonded_weight_root
            || proposal.context.consensus_parameter_root != target.consensus_parameter_root.to_hex()
        {
            return Err(
                "PoSy proposal context does not match the normal protected target".to_string(),
            );
        }
        material.validate(proposal.context.epoch_context_root)?;
        let candidate = CertifiedCandidateSubject::new(
            proposal.context.clone(),
            proposal.block_id.clone(),
            proposal.parent_block_id.clone(),
            proposal.parent.clone(),
            proposal.protected_execution_root,
        )?;
        if candidate != material.candidate_subject
            || candidate.id()? != material.stable_candidate_id
        {
            return Err("verified proposal material names another PoSy candidate".to_string());
        }
        let input = material.protected_execution_input.as_ref().ok_or_else(|| {
            "normal protected proposal material has no concrete execution input".to_string()
        })?;
        let commitment = material
            .next_protected_batch_commitment
            .as_ref()
            .ok_or_else(|| {
                "normal protected proposal material has no exact batch commitment".to_string()
            })?;
        let expected_source = if target.target_height == Height(3) {
            ProtectedBatchSource::NormalEtdag
        } else {
            ProtectedBatchSource::NormalEtdagSteadyState
        };
        if &input.next_commitment != commitment || input.source != expected_source {
            return Err("normal protected proposal material has a wrong source".to_string());
        }
        match &input.target_context {
            ProtectedExecutionTargetContext::NormalEtdag { admission_context }
                if admission_context == target => {}
            _ => {
                return Err(
                    "normal protected execution input names another target context".to_string(),
                )
            }
        }
        commitment.validate_against(target, &input.protected_batch)?;
        Ok(NormalProtectedBinding {
            candidate,
            commitment,
            input,
        })
    }
}

struct NormalProtectedBinding<'a> {
    candidate: CertifiedCandidateSubject,
    commitment: &'a NextProtectedBatchCommitment,
    input: &'a DeterministicProtectedExecutionInput,
}

/// Deterministic pipeline proposal identity derived from the signer-independent
/// PoSy candidate.  Retransmission rounds and valid signer subsets cannot
/// change it.
pub fn protected_pipeline_proposal_id(
    candidate: &CertifiedCandidateSubject,
) -> Result<EtdagDigest, String> {
    let candidate_id = candidate.id()?;
    Ok(EtdagDigest::from_domain_bytes(
        DOMAIN_PROTECTED_POSY_PROPOSAL_ID,
        &candidate_id.0,
    ))
}

pub fn protected_pipeline_proposal_evidence_root(
    proposal: &SimplifiedProposal,
    material: &VerifiedSimplifiedProposalMaterial,
) -> Result<EtdagDigest, String> {
    lifecycle_evidence_root(
        DOMAIN_PROTECTED_POSY_PROPOSAL_EVIDENCE,
        &(proposal.clone(), material.clone()),
    )
}

pub fn protected_pipeline_consumed_evidence_root(
    proposal: &SimplifiedProposal,
    material: &VerifiedSimplifiedProposalMaterial,
) -> Result<EtdagDigest, String> {
    lifecycle_evidence_root(
        DOMAIN_PROTECTED_POSY_CONSUMED_EVIDENCE,
        &(proposal.clone(), material.clone()),
    )
}

pub fn protected_pipeline_qc_id(
    certificate: &SimplifiedQuorumCertificate,
) -> Result<EtdagDigest, String> {
    let qc_id = certificate.id()?;
    Ok(EtdagDigest::from_domain_bytes(
        DOMAIN_PROTECTED_POSY_QC_ID,
        &qc_id.0,
    ))
}

pub fn protected_pipeline_qc_evidence_root(
    certificate: &SimplifiedQuorumCertificate,
) -> Result<EtdagDigest, String> {
    lifecycle_evidence_root(
        DOMAIN_PROTECTED_POSY_QC_EVIDENCE,
        &certificate.canonicalized(),
    )
}

pub fn protected_pipeline_finality_id(
    transaction: &SimplifiedFinalizationTransaction,
) -> EtdagDigest {
    EtdagDigest::from_domain_bytes(
        DOMAIN_PROTECTED_POSY_FINALITY_ID,
        &transaction.transaction_id.0,
    )
}

pub fn protected_pipeline_finality_evidence_root(
    transaction: &SimplifiedFinalizationTransaction,
) -> Result<EtdagDigest, String> {
    lifecycle_evidence_root(DOMAIN_PROTECTED_POSY_FINALITY_EVIDENCE, transaction)
}

/// Construct the only reveal authorization accepted by the normal lifecycle:
/// the exact target commitment plus the stable candidate and canonical n-1
/// ECHO proof roots.
pub fn build_protected_reveal_authorization(
    target: &TargetAdmissionContext,
    proposal: &SimplifiedProposal,
    input: &DeterministicProtectedExecutionInput,
    certificate: &PosyProposalValidationCertificate,
) -> Result<ProtectedRevealAuthorization, String> {
    let commitment = &input.next_commitment;
    commitment.validate_against(target, &input.protected_batch)?;
    let candidate = CertifiedCandidateSubject::new(
        proposal.context.clone(),
        proposal.block_id.clone(),
        proposal.parent_block_id.clone(),
        proposal.parent.clone(),
        proposal.protected_execution_root,
    )?;
    if certificate.candidate != candidate
        || certificate.context != proposal.context
        || certificate.next_protected_batch_commitment_root != commitment.root()?
    {
        return Err("reveal authorization VC names another protected proposal".to_string());
    }
    let authorization = ProtectedRevealAuthorization {
        authorization_version: PROTECTED_PIPELINE_VERSION,
        chain_id: target.chain_id,
        network_id: target.network_id.clone(),
        protocol_version: target.protocol_version.clone(),
        epoch: target.epoch,
        target_height: target.target_height,
        cluster_id: target.assigned_cluster_id,
        target_context_root: target.root()?,
        validator_set_commitment: target.active_validator_set_root,
        parameter_root: target.consensus_parameter_root,
        parent_proposal_id: proposal.block_id.clone(),
        parent_block_id: proposal.parent_block_id.clone(),
        next_commitment_root: commitment.root()?,
        protected_batch_root: input.protected_batch.protected_batch_root.clone(),
        proposal_validation_certificate_root: certificate.semantic_candidate_id()?,
        certificate_evidence_root: certificate.proof_root()?,
    };
    authorization.validate_against(target, commitment, &input.protected_batch)?;
    Ok(authorization)
}

fn require_consumed_reveal_binding(
    target: &TargetAdmissionContext,
    proposal: &SimplifiedProposal,
    input: &DeterministicProtectedExecutionInput,
) -> Result<(), String> {
    let authorization = input.reveal_authorization.as_ref().ok_or_else(|| {
        "consumed protected execution input has no proposal-VC reveal authorization".to_string()
    })?;
    authorization.validate_against(target, &input.next_commitment, &input.protected_batch)?;
    if authorization.parent_proposal_id != proposal.block_id
        || authorization.parent_block_id != proposal.parent_block_id
    {
        return Err("consumed protected execution input names another parent proposal".to_string());
    }
    Ok(())
}

fn lifecycle_evidence_root<T: CanonicalSerialize>(
    domain: &str,
    value: &T,
) -> Result<EtdagDigest, String> {
    let bytes = value.canonical_bytes()?;
    let root = EtdagDigest::from_domain_bytes(domain, &bytes);
    root.validate("protected PoSy lifecycle evidence root")?;
    if root.is_zero() {
        return Err("protected PoSy lifecycle evidence root is zero".to_string());
    }
    Ok(root)
}

/// Returns the target height without exposing the event's large artifacts.
pub fn protected_pipeline_lifecycle_target_height(
    event: &ProtectedPipelineLifecycleEvent,
) -> Height {
    match event {
        ProtectedPipelineLifecycleEvent::ParentProposalCommitted { target, .. }
        | ProtectedPipelineLifecycleEvent::ProposalValidationCertified { target, .. }
        | ProtectedPipelineLifecycleEvent::ExecutionConsumed { target, .. }
        | ProtectedPipelineLifecycleEvent::QuorumCertified { target, .. }
        | ProtectedPipelineLifecycleEvent::FinalizationCommitted { target, .. } => {
            target.target_height
        }
    }
}

/// Convert a non-zero 256-bit PoSy semantic root to an explicitly
/// domain-separated 512-bit ETDAG evidence identity.
pub fn protected_pipeline_hash_identity(domain: &str, root: Hash) -> Result<EtdagDigest, String> {
    if domain.trim().is_empty() || root.is_zero() {
        return Err("protected PoSy semantic identity is empty".to_string());
    }
    Ok(EtdagDigest::from_domain_bytes(domain, &root.0))
}
