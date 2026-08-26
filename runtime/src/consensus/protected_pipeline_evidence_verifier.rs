//! Production verification for root-addressed protected-pipeline evidence.
//!
//! The durable pipeline intentionally stores compact observations.  A compact
//! root is never authority by itself: this verifier resolves the root through
//! a receiver-owned evidence source and replays the complete authenticated
//! PoSy, ETDAG, or reveal proof before allowing a state transition.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::consensus::protected_pipeline::{
    ProtectedOrderSeedEvidence, ProtectedPipelineEvidenceVerifier, ProtectedPipelineObservation,
};
use crate::consensus::simplified_posy::{
    simplified_protected_finality_context_digest_from_state_root, CertifiedCandidateSubject,
    ConsensusSignatureVerifier, FinalizedBlockRecord, PosyProposalValidationCertificate,
    SimplifiedEpochContext, SimplifiedFinalizationTransaction, SimplifiedProposal,
    SimplifiedQuorumCertificate, VerifiedSimplifiedProposalMaterial,
    POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
};
use crate::crypto::aegis_pqvm::AegisPqvmVerifier;
use crate::etdag::{
    target_admission_source_finality_root, verify_protected_reveal_share,
    DeterministicProtectedBatch, EtdagDigest, EtdagParameters, NextProtectedBatchCommitment,
    ProtectedExecutionTargetContext, ProtectedRevealAuthorization, ProtectedRevealShareMessage,
    TargetAdmissionContext,
};
use crate::synergy_types::{
    CanonicalSerialize, ClusterMap, ConsensusDomain, Hash, ValidatorSet,
    TESTNET_V3_FRESH_P3_CHAIN_INCARNATION,
};

/// Domain for the normal H+3 seed derived from finalized PoSy authority.
///
/// This deliberately does not accept a DCC, BOC, local clock, or caller-
/// selected entropy source.  The target-context root already commits the
/// frozen topology, governed parameters, ingress KEM registry, and source
/// finality pointer.
pub const DOMAIN_PROTECTED_POSY_ORDER_SEED: &str = "PoSy/ProtectedPipeline/PosyOrderSeed/v1";
/// Domain for the complete finalized-authority proof consumed by the seed
/// verifier.
pub const DOMAIN_PROTECTED_POSY_ORDER_AUTHORITY: &str =
    "PoSy/ProtectedPipeline/PosyOrderAuthority/v1";
/// Domain for an exact proposer-signed proposal proof.
pub const DOMAIN_PROTECTED_PROPOSAL_EVIDENCE: &str = "PoSy/ProtectedPipeline/ProposalEvidence/v1";
/// Domain for the semantic, retransmission-stable proposal identifier exposed
/// to the protected pipeline.
pub const DOMAIN_PROTECTED_PROPOSAL_ID: &str = "PoSy/ProtectedPipeline/ProposalId/v1";
/// Domain for the signer-independent proposal-VC subject.
pub const DOMAIN_PROTECTED_PROPOSAL_VC_ROOT: &str = "PoSy/ProtectedPipeline/ProposalVcRoot/v1";
/// Domain for an exact QC proof bundle.  The separate semantic root below is
/// stable across different valid signature subsets.
pub const DOMAIN_PROTECTED_QC_EVIDENCE: &str = "PoSy/ProtectedPipeline/QcEvidence/v1";
pub const DOMAIN_PROTECTED_QC_ROOT: &str = "PoSy/ProtectedPipeline/QcRoot/v1";
/// Domains for exact and semantic three-chain finality evidence.
pub const DOMAIN_PROTECTED_FINALITY_EVIDENCE: &str = "PoSy/ProtectedPipeline/FinalityEvidence/v1";
pub const DOMAIN_PROTECTED_FINALITY_ROOT: &str = "PoSy/ProtectedPipeline/FinalityRoot/v1";
/// Domain for the complete signed reveal-share message used as its evidence
/// root.
pub const DOMAIN_PROTECTED_REVEAL_SHARE_EVIDENCE: &str =
    "PoSy/ProtectedPipeline/RevealShareEvidence/v1";

const MAX_PRODUCTION_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

/// Complete finalized authority from which one normal H+3 ordering seed is
/// derived.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedPosyOrderAuthorityEvidence {
    pub consensus_domain: ConsensusDomain,
    pub target: TargetAdmissionContext,
    pub finalized: FinalizedBlockRecord,
    pub finalized_execution_state_root: Hash,
    pub canonical_finality_context_digest: EtdagDigest,
}

impl ProtectedPosyOrderAuthorityEvidence {
    pub fn authority_root(&self) -> Result<EtdagDigest, String> {
        bounded_evidence_root(DOMAIN_PROTECTED_POSY_ORDER_AUTHORITY, self)
    }
}

/// Exact signed proposal plus the material whose protected-execution root it
/// authenticates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedParentProposalEvidence {
    pub consensus_domain: ConsensusDomain,
    pub target: TargetAdmissionContext,
    pub proposal: SimplifiedProposal,
    pub material: VerifiedSimplifiedProposalMaterial,
}

impl ProtectedParentProposalEvidence {
    pub fn evidence_root(&self) -> Result<EtdagDigest, String> {
        bounded_evidence_root(DOMAIN_PROTECTED_PROPOSAL_EVIDENCE, self)
    }
}

/// Complete n-1 ECHO proposal VC and its exact reveal authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedRevealAuthorizationEvidence {
    pub parent: ProtectedParentProposalEvidence,
    pub validation_certificate: PosyProposalValidationCertificate,
    pub authorization: ProtectedRevealAuthorization,
}

/// Complete signed share together with the VC-authorized reveal proof it
/// names.  Repeating the authorization proof is intentional: a receiver can
/// validate this record without trusting an earlier in-memory transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedRevealShareEvidence {
    pub authorization: ProtectedRevealAuthorizationEvidence,
    pub share: ProtectedRevealShareMessage,
}

impl ProtectedRevealShareEvidence {
    pub fn evidence_root(&self) -> Result<EtdagDigest, String> {
        bounded_evidence_root(DOMAIN_PROTECTED_REVEAL_SHARE_EVIDENCE, self)
    }
}

/// Exact ordinary PoSy QC plus the material bound by its protected execution
/// root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedQcEvidence {
    pub consensus_domain: ConsensusDomain,
    pub target: TargetAdmissionContext,
    pub certificate: SimplifiedQuorumCertificate,
    pub material: VerifiedSimplifiedProposalMaterial,
}

impl ProtectedQcEvidence {
    pub fn evidence_root(&self) -> Result<EtdagDigest, String> {
        bounded_evidence_root(DOMAIN_PROTECTED_QC_EVIDENCE, self)
    }
}

/// Exact three-QC finalization transaction and the target material it commits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtectedFinalityEvidence {
    pub consensus_domain: ConsensusDomain,
    pub target: TargetAdmissionContext,
    pub transaction: SimplifiedFinalizationTransaction,
    pub material: VerifiedSimplifiedProposalMaterial,
}

impl ProtectedFinalityEvidence {
    pub fn evidence_root(&self) -> Result<EtdagDigest, String> {
        bounded_evidence_root(DOMAIN_PROTECTED_FINALITY_EVIDENCE, self)
    }
}

/// Typed proof object returned by the receiver-owned durable evidence source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductionProtectedPipelineEvidence {
    OrderSeed(ProtectedPosyOrderAuthorityEvidence),
    ParentProposal(ProtectedParentProposalEvidence),
    RevealAuthorization(ProtectedRevealAuthorizationEvidence),
    RevealShare(ProtectedRevealShareEvidence),
    QuorumCertificate(ProtectedQcEvidence),
    Finality(ProtectedFinalityEvidence),
}

impl ProductionProtectedPipelineEvidence {
    /// Root by which this exact proof must be retrieved.  This method does not
    /// verify the proof; callers must pass the result to the production
    /// verifier before treating it as authority.
    pub fn lookup_root(&self) -> Result<EtdagDigest, String> {
        match self {
            Self::OrderSeed(evidence) => evidence.authority_root(),
            Self::ParentProposal(evidence) => evidence.evidence_root(),
            Self::RevealAuthorization(evidence) => evidence.validation_certificate.proof_root(),
            Self::RevealShare(evidence) => evidence.evidence_root(),
            Self::QuorumCertificate(evidence) => evidence.evidence_root(),
            Self::Finality(evidence) => evidence.evidence_root(),
        }
    }
}

/// Receiver-owned lookup boundary for complete evidence.
///
/// Implementations are expected to read a bounded, durable/content-addressed
/// store.  `None`, a decode failure, or a key/root mismatch is rejected; there
/// is no accept-all or root-only fallback.
pub trait ProductionProtectedPipelineEvidenceSource: Send + Sync {
    fn load_evidence(
        &self,
        root: &EtdagDigest,
    ) -> Result<Option<ProductionProtectedPipelineEvidence>, String>;
}

/// Fail-closed verifier used by the normal protected-pipeline coordinator.
pub struct ProductionProtectedPipelineEvidenceVerifier {
    consensus_domain: ConsensusDomain,
    epoch_context: SimplifiedEpochContext,
    validator_set: ValidatorSet,
    cluster_map: ClusterMap,
    parameters: EtdagParameters,
    verifier: AegisPqvmVerifier,
    source: Arc<dyn ProductionProtectedPipelineEvidenceSource>,
}

impl ProductionProtectedPipelineEvidenceVerifier {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        consensus_domain: ConsensusDomain,
        epoch_context: SimplifiedEpochContext,
        validator_set: ValidatorSet,
        cluster_map: ClusterMap,
        parameters: EtdagParameters,
        verifier: AegisPqvmVerifier,
        source: Arc<dyn ProductionProtectedPipelineEvidenceSource>,
    ) -> Result<Self, String> {
        consensus_domain.validate()?;
        if consensus_domain.chain_incarnation != TESTNET_V3_FRESH_P3_CHAIN_INCARNATION
            || consensus_domain.chain_id != epoch_context.chain_id
        {
            return Err("protected evidence verifier names another chain incarnation".to_string());
        }
        epoch_context.validate_against(&validator_set.active_for_epoch(epoch_context.epoch))?;
        let active = validator_set.active_for_epoch(epoch_context.epoch);
        if cluster_map.epoch != epoch_context.epoch
            || cluster_map
                != ClusterMap::derive_from_finalized_epoch_seed(
                    &active,
                    epoch_context.finalized_epoch_seed_root,
                )?
        {
            return Err("protected evidence verifier has a noncanonical cluster map".to_string());
        }
        cluster_map.validate_complete_balanced_assignment(&active)?;
        parameters.validate()?;
        Ok(Self {
            consensus_domain,
            epoch_context,
            validator_set,
            cluster_map,
            parameters,
            verifier,
            source,
        })
    }

    fn validate_target(&self, target: &TargetAdmissionContext) -> Result<(), String> {
        target.validate_validator_and_cluster_bindings(&self.validator_set, &self.cluster_map)?;
        let expected_source_target = target
            .source_finalized_height
            .0
            .checked_add(3)
            .ok_or_else(|| "protected H+3 target height overflowed".to_string())?;
        if self.consensus_domain.chain_id != target.chain_id
            || target.chain_id != self.epoch_context.chain_id
            || target.network_id != self.epoch_context.network_id
            || target.protocol_version != self.epoch_context.protocol_version
            || target.epoch != self.epoch_context.epoch
            || target.target_height.0 != expected_source_target
            || target.active_validator_set_root != self.epoch_context.active_validator_set_root
            || target.validator_consensus_key_root
                != self.epoch_context.validator_consensus_key_root
            || target.frozen_bonded_weight_root != self.epoch_context.frozen_voting_weight_root
            || target.finalized_epoch_seed_root != self.epoch_context.finalized_epoch_seed_root
            || target.consensus_parameter_root.to_hex()
                != self.epoch_context.consensus_parameter_root
        {
            return Err("protected evidence target differs from frozen PoSy authority".to_string());
        }
        Ok(())
    }

    fn load_exact(
        &self,
        root: &EtdagDigest,
    ) -> Result<ProductionProtectedPipelineEvidence, String> {
        root.validate("protected evidence lookup root")?;
        if root.is_zero() {
            return Err("protected evidence lookup root is zero".to_string());
        }
        let evidence = self
            .source
            .load_evidence(root)?
            .ok_or_else(|| "complete protected evidence is unavailable".to_string())?;
        if evidence.lookup_root()? != *root {
            return Err("protected evidence source returned another proof root".to_string());
        }
        Ok(evidence)
    }

    fn validate_domain_and_target(
        &self,
        domain: &ConsensusDomain,
        target: &TargetAdmissionContext,
        embedded_target: &TargetAdmissionContext,
    ) -> Result<(), String> {
        self.validate_target(target)?;
        domain.validate()?;
        if domain != &self.consensus_domain || embedded_target != target {
            return Err("protected evidence domain or target replay mismatch".to_string());
        }
        Ok(())
    }

    fn validate_material<'a>(
        &self,
        target: &TargetAdmissionContext,
        expected_commitment: &NextProtectedBatchCommitment,
        material: &'a VerifiedSimplifiedProposalMaterial,
    ) -> Result<&'a DeterministicProtectedBatch, String> {
        material.validate(self.epoch_context.root()?)?;
        if material.candidate_subject.context.height != target.target_height
            || material.candidate_subject.context.epoch != target.epoch
            || material.next_protected_batch_commitment.as_ref() != Some(expected_commitment)
        {
            return Err(
                "protected proposal material names another target or commitment".to_string(),
            );
        }
        let input = material.protected_execution_input.as_ref().ok_or_else(|| {
            "protected proposal material has no concrete execution input".to_string()
        })?;
        match &input.target_context {
            ProtectedExecutionTargetContext::NormalEtdag { admission_context }
                if admission_context == target => {}
            _ => return Err("protected proposal material has another execution target".to_string()),
        }
        if input.next_commitment != *expected_commitment || input.cut_proof.is_none() {
            return Err(
                "protected proposal material omits its exact cut or commitment".to_string(),
            );
        }
        expected_commitment.validate_against(target, &input.protected_batch)?;
        input.verify_and_extract_transactions(
            &self.verifier,
            &self.validator_set,
            &self.cluster_map,
            &self.parameters,
        )?;
        Ok(&input.protected_batch)
    }

    fn validate_parent(
        &self,
        target: &TargetAdmissionContext,
        expected_commitment: &NextProtectedBatchCommitment,
        evidence: &ProtectedParentProposalEvidence,
    ) -> Result<(), String> {
        self.validate_domain_and_target(&evidence.consensus_domain, target, &evidence.target)?;
        evidence
            .proposal
            .context
            .validate_against(&self.epoch_context)?;
        let expected_candidate = CertifiedCandidateSubject::new(
            evidence.proposal.context.clone(),
            evidence.proposal.block_id.clone(),
            evidence.proposal.parent_block_id.clone(),
            evidence.proposal.parent.clone(),
            evidence.proposal.protected_execution_root,
        )?;
        if expected_candidate != evidence.material.candidate_subject
            || evidence.proposal.context.height != target.target_height
        {
            return Err("protected parent proposal material binding mismatch".to_string());
        }
        let expected_proposer = self.epoch_context.authorized_proposer(
            evidence.proposal.context.height,
            evidence.proposal.context.round.0,
        )?;
        if expected_proposer != &evidence.proposal.proposer_id {
            return Err("protected parent proposal has an unauthorized proposer".to_string());
        }
        let active = self.validator_set.active_for_epoch(target.epoch);
        let proposer = active
            .validators
            .iter()
            .find(|record| record.validator_id == evidence.proposal.proposer_id)
            .ok_or_else(|| "protected parent proposer is outside the frozen set".to_string())?;
        if proposer.consensus_public_key.key_id != evidence.proposal.proposer_key_id {
            return Err("protected parent proposal uses another consensus key".to_string());
        }
        self.verifier.verify_consensus_signature(
            POSY_SIMPLIFIED_PROPOSAL_DOMAIN,
            &evidence.proposal.signing_bytes()?,
            proposer,
            &evidence.proposal.proposer_key_id,
            target.epoch,
            &evidence.proposal.proposer_signature,
        )?;
        self.validate_material(target, expected_commitment, &evidence.material)?;
        Ok(())
    }

    fn validate_authorization(
        &self,
        target: &TargetAdmissionContext,
        expected_commitment: &NextProtectedBatchCommitment,
        evidence: &ProtectedRevealAuthorizationEvidence,
    ) -> Result<(), String> {
        self.validate_parent(target, expected_commitment, &evidence.parent)?;
        let batch =
            self.validate_material(target, expected_commitment, &evidence.parent.material)?;
        evidence.validation_certificate.validate_authenticated(
            &evidence.parent.material,
            &self.epoch_context,
            &self.validator_set,
            &self.verifier,
        )?;
        let semantic_vc_root = evidence.validation_certificate.semantic_candidate_id()?;
        let exact_vc_root = evidence.validation_certificate.proof_root()?;
        if evidence.authorization.parent_proposal_id != evidence.parent.proposal.block_id
            || evidence.authorization.parent_block_id != evidence.parent.proposal.parent_block_id
            || evidence.authorization.proposal_validation_certificate_root != semantic_vc_root
            || evidence.authorization.certificate_evidence_root != exact_vc_root
        {
            return Err("protected reveal authorization has another proposal VC".to_string());
        }
        evidence
            .authorization
            .validate_against(target, expected_commitment, batch)
    }

    fn validate_qc(
        &self,
        target: &TargetAdmissionContext,
        expected_commitment: &NextProtectedBatchCommitment,
        evidence: &ProtectedQcEvidence,
    ) -> Result<(), String> {
        self.validate_domain_and_target(&evidence.consensus_domain, target, &evidence.target)?;
        self.validate_material(target, expected_commitment, &evidence.material)?;
        evidence
            .certificate
            .verify(&self.epoch_context, &self.validator_set, &self.verifier)?;
        if evidence.certificate.subject()? != evidence.material.candidate_subject
            || evidence.certificate.context.height != target.target_height
        {
            return Err("protected QC certifies another proposal material".to_string());
        }
        Ok(())
    }

    fn validate_finality(
        &self,
        target: &TargetAdmissionContext,
        expected_commitment: &NextProtectedBatchCommitment,
        evidence: &ProtectedFinalityEvidence,
    ) -> Result<(), String> {
        self.validate_domain_and_target(&evidence.consensus_domain, target, &evidence.target)?;
        self.validate_material(target, expected_commitment, &evidence.material)?;
        evidence.transaction.validate()?;
        if evidence.transaction.epoch_context_root != self.epoch_context.root()?
            || evidence.transaction.target_finalized.height != target.target_height
        {
            return Err("protected finality transaction names another target".to_string());
        }
        let target_commitments = evidence
            .transaction
            .commitments
            .iter()
            .filter(|commitment| commitment.height == target.target_height)
            .collect::<Vec<_>>();
        let [target_commitment] = target_commitments.as_slice() else {
            return Err(
                "protected finality transaction must contain one exact target commitment"
                    .to_string(),
            );
        };
        if target_commitment.certificate.subject()? != evidence.material.candidate_subject {
            return Err("protected finality commits another proposal material".to_string());
        }
        let mut verified = BTreeSet::new();
        for certificate in evidence
            .transaction
            .commitments
            .iter()
            .map(|commitment| &commitment.certificate)
            .chain(evidence.transaction.finality_witness.iter())
        {
            if certificate.context.epoch != target.epoch
                || certificate.context.epoch_context_root != self.epoch_context.root()?
            {
                return Err("protected finality crosses an unpinned epoch".to_string());
            }
            if verified.insert(certificate.id()?) {
                certificate.verify(&self.epoch_context, &self.validator_set, &self.verifier)?;
            }
        }
        Ok(())
    }
}

impl ProtectedPipelineEvidenceVerifier for ProductionProtectedPipelineEvidenceVerifier {
    fn verify_order_seed(
        &self,
        target: &TargetAdmissionContext,
        evidence: &ProtectedOrderSeedEvidence,
    ) -> Result<(), String> {
        self.validate_target(target)?;
        let ProductionProtectedPipelineEvidence::OrderSeed(authority) =
            self.load_exact(&evidence.authority_root)?
        else {
            return Err("protected order-seed root resolved to another evidence kind".to_string());
        };
        self.validate_domain_and_target(&authority.consensus_domain, target, &authority.target)?;
        authority.finalized.validate()?;
        if authority.finalized.height != target.source_finalized_height
            || authority.finalized_execution_state_root.is_zero()
        {
            return Err("protected order seed names another finalized authority".to_string());
        }
        let finality_context = simplified_protected_finality_context_digest_from_state_root(
            &self.epoch_context,
            &authority.finalized,
            authority.finalized_execution_state_root,
            &self.validator_set,
            &self.cluster_map,
        )?;
        if finality_context != authority.canonical_finality_context_digest
            || target.source_finality_context_root
                != target_admission_source_finality_root(&finality_context)?
        {
            return Err("protected order seed has a substituted finality context".to_string());
        }
        let expected_seed = derive_protected_posy_order_seed(
            &authority.consensus_domain,
            target,
            &finality_context,
        )?;
        if evidence.order_seed != expected_seed {
            return Err(
                "protected order seed does not derive from finalized PoSy authority".to_string(),
            );
        }
        Ok(())
    }

    fn verify_observation(
        &self,
        target: &TargetAdmissionContext,
        expected_commitment: &NextProtectedBatchCommitment,
        observation: &ProtectedPipelineObservation,
    ) -> Result<(), String> {
        self.validate_target(target)?;
        let expected_root = expected_commitment.root()?;
        expected_root.validate("protected commitment root")?;
        match observation {
            ProtectedPipelineObservation::ParentCommitment {
                proposal_id,
                commitment_root,
                evidence_root,
            } => {
                let ProductionProtectedPipelineEvidence::ParentProposal(evidence) =
                    self.load_exact(evidence_root)?
                else {
                    return Err("parent root resolved to another evidence kind".to_string());
                };
                self.validate_parent(target, expected_commitment, &evidence)?;
                if proposal_id != &protected_proposal_id(&evidence.proposal)?
                    || commitment_root != &expected_root
                {
                    return Err("protected parent observation root binding mismatch".to_string());
                }
            }
            ProtectedPipelineObservation::RevealAuthorization {
                proposal_id,
                vc_root,
                commitment_root,
                evidence_root,
            } => {
                let ProductionProtectedPipelineEvidence::RevealAuthorization(evidence) =
                    self.load_exact(evidence_root)?
                else {
                    return Err("reveal root resolved to another evidence kind".to_string());
                };
                self.validate_authorization(target, expected_commitment, &evidence)?;
                if proposal_id != &protected_proposal_id(&evidence.parent.proposal)?
                    || vc_root
                        != &protected_proposal_vc_root(
                            evidence.validation_certificate.semantic_candidate_id()?,
                        )?
                    || commitment_root != &expected_root
                    || evidence_root != &evidence.validation_certificate.proof_root()?
                {
                    return Err("protected reveal observation root binding mismatch".to_string());
                }
            }
            ProtectedPipelineObservation::RevealShare {
                validator_id,
                commitment_root,
                share_root,
            } => {
                let ProductionProtectedPipelineEvidence::RevealShare(evidence) =
                    self.load_exact(share_root)?
                else {
                    return Err("share root resolved to another evidence kind".to_string());
                };
                self.validate_authorization(target, expected_commitment, &evidence.authorization)?;
                let batch = self.validate_material(
                    target,
                    expected_commitment,
                    &evidence.authorization.parent.material,
                )?;
                verify_protected_reveal_share(
                    &evidence.share,
                    &evidence.authorization.authorization,
                    expected_commitment,
                    batch,
                    &self.verifier,
                    target,
                    &self.validator_set,
                )?;
                if validator_id != &evidence.share.validator_id || commitment_root != &expected_root
                {
                    return Err("protected reveal-share observation binding mismatch".to_string());
                }
            }
            ProtectedPipelineObservation::ExecutionReady { .. } => {
                return Err(
                    "root-only execution readiness is forbidden; install concrete input"
                        .to_string(),
                )
            }
            ProtectedPipelineObservation::QcObserved {
                commitment_root,
                qc_root,
                evidence_root,
            } => {
                let ProductionProtectedPipelineEvidence::QuorumCertificate(evidence) =
                    self.load_exact(evidence_root)?
                else {
                    return Err("QC root resolved to another evidence kind".to_string());
                };
                self.validate_qc(target, expected_commitment, &evidence)?;
                if commitment_root != &expected_root
                    || qc_root != &protected_qc_root(evidence.certificate.id()?)?
                {
                    return Err("protected QC observation root binding mismatch".to_string());
                }
            }
            ProtectedPipelineObservation::Finalized {
                commitment_root,
                finality_root,
                evidence_root,
            } => {
                let ProductionProtectedPipelineEvidence::Finality(evidence) =
                    self.load_exact(evidence_root)?
                else {
                    return Err("finality root resolved to another evidence kind".to_string());
                };
                self.validate_finality(target, expected_commitment, &evidence)?;
                if commitment_root != &expected_root
                    || finality_root
                        != &protected_finality_root(&evidence.transaction.target_finalized)?
                {
                    return Err("protected finality observation root binding mismatch".to_string());
                }
            }
            ProtectedPipelineObservation::Consumed {
                commitment_root,
                execution_root,
                evidence_root,
            } => {
                let ProductionProtectedPipelineEvidence::Finality(evidence) =
                    self.load_exact(evidence_root)?
                else {
                    return Err("consumption root resolved to another evidence kind".to_string());
                };
                self.validate_finality(target, expected_commitment, &evidence)?;
                let input = evidence
                    .material
                    .protected_execution_input
                    .as_ref()
                    .ok_or_else(|| {
                        "consumed material has no concrete execution input".to_string()
                    })?;
                if commitment_root != &expected_root || execution_root != &input.digest()? {
                    return Err("protected consumption observation binding mismatch".to_string());
                }
            }
        }
        Ok(())
    }
}

/// Derive the content-blind normal H+3 seed from finalized PoSy authority.
pub fn derive_protected_posy_order_seed(
    consensus_domain: &ConsensusDomain,
    target: &TargetAdmissionContext,
    canonical_finality_context_digest: &EtdagDigest,
) -> Result<EtdagDigest, String> {
    consensus_domain.validate()?;
    target.validate()?;
    canonical_finality_context_digest.validate("protected PoSy finality context")?;
    if canonical_finality_context_digest.is_zero() {
        return Err("protected PoSy finality context is zero".to_string());
    }
    EtdagDigest::from_canonical(
        DOMAIN_PROTECTED_POSY_ORDER_SEED,
        &(
            consensus_domain.clone(),
            target.root()?,
            target.finalized_epoch_seed_root,
            canonical_finality_context_digest.clone(),
            target.target_height,
        ),
    )
}

pub fn protected_proposal_id(proposal: &SimplifiedProposal) -> Result<EtdagDigest, String> {
    let candidate = CertifiedCandidateSubject::new(
        proposal.context.clone(),
        proposal.block_id.clone(),
        proposal.parent_block_id.clone(),
        proposal.parent.clone(),
        proposal.protected_execution_root,
    )?;
    EtdagDigest::from_canonical(DOMAIN_PROTECTED_PROPOSAL_ID, &candidate.id()?)
}

pub fn protected_proposal_vc_root(candidate_id: Hash) -> Result<EtdagDigest, String> {
    if candidate_id.is_zero() {
        return Err("protected proposal VC candidate root is zero".to_string());
    }
    EtdagDigest::from_canonical(DOMAIN_PROTECTED_PROPOSAL_VC_ROOT, &candidate_id)
}

pub fn protected_qc_root(qc_id: Hash) -> Result<EtdagDigest, String> {
    if qc_id.is_zero() {
        return Err("protected QC semantic root is zero".to_string());
    }
    EtdagDigest::from_canonical(DOMAIN_PROTECTED_QC_ROOT, &qc_id)
}

pub fn protected_finality_root(finalized: &FinalizedBlockRecord) -> Result<EtdagDigest, String> {
    finalized.validate()?;
    EtdagDigest::from_canonical(DOMAIN_PROTECTED_FINALITY_ROOT, finalized)
}

fn bounded_evidence_root<T>(domain: &str, evidence: &T) -> Result<EtdagDigest, String>
where
    T: CanonicalSerialize,
{
    let bytes = evidence.canonical_bytes()?;
    if bytes.is_empty() || bytes.len() > MAX_PRODUCTION_EVIDENCE_BYTES {
        return Err("protected production evidence violates its size bound".to_string());
    }
    Ok(EtdagDigest::from_domain_bytes(domain, &bytes))
}
