//! Monotonic durable ownership for the PoSy v3 protected-data pipeline.
//!
//! Exact ETDAG evidence is retained for audit and recovery, while consensus
//! identity is derived only from marker-subset-independent semantic roots.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::aegis_pqvm::AegisPqvmVerifier;
use crate::etdag::{
    canonical_content_blind_order, CertifiedEnvelopeRef, CertifiedVertex,
    DeterministicProtectedBatch, EtdagDigest, EtdagParameters, NextProtectedBatchCommitment,
    ProtectedBatchSource, ProtectedCutProof, ProtectedPipelineDiagnostic, ProtectedPipelinePhase,
    TargetAdmissionContext, VertexKind, DOMAIN_PROTECTED_CUT_MARKER_EVIDENCE,
    DOMAIN_PROTECTED_ORDER_ROOT, ETDAG_PROFILE_ID, PROTECTED_PIPELINE_VERSION,
};
use crate::synergy_types::{CanonicalSerialize, ClusterMap, Hash, ValidatorId, ValidatorSet};

/// Durable envelope format for one target-height pipeline record.
pub const PROTECTED_PIPELINE_STORE_FORMAT: &str = "synergy-protected-pipeline-v1";
const DOMAIN_CAUSAL_CLOSURE: &str = "PoSy/ProtectedPipeline/CausalClosure/v1";
const DOMAIN_ELIGIBLE_SET: &str = "PoSy/ProtectedPipeline/EligibleSet/v1";
const MAX_CAUSAL_DEPTH: usize = 64;

/// Result category for protected-pipeline operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedPipelineErrorKind {
    /// More authenticated objects are needed before a transition is possible.
    NotReady,
    /// Supplied evidence failed validation or cryptographic verification.
    InvalidEvidence,
    /// Valid-looking state disagrees with an already durable semantic subject.
    Conflict,
    /// Durable state could not be read or atomically replaced.
    Persistence,
    /// A durable record is malformed or violates phase invariants.
    CorruptState,
}

/// Structured protected-pipeline failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedPipelineError {
    /// Stable error category.
    pub kind: ProtectedPipelineErrorKind,
    /// Stable diagnostic code suitable for operator snapshots.
    pub code: String,
    /// Human-readable detail that must not contain secrets.
    pub detail: String,
}

impl ProtectedPipelineError {
    fn new(kind: ProtectedPipelineErrorKind, code: &str, detail: impl Into<String>) -> Self {
        Self {
            kind,
            code: code.to_string(),
            detail: detail.into(),
        }
    }

    fn not_ready(code: &str, detail: impl Into<String>) -> Self {
        Self::new(ProtectedPipelineErrorKind::NotReady, code, detail)
    }

    fn invalid(code: &str, detail: impl Into<String>) -> Self {
        Self::new(ProtectedPipelineErrorKind::InvalidEvidence, code, detail)
    }

    fn conflict(code: &str, detail: impl Into<String>) -> Self {
        Self::new(ProtectedPipelineErrorKind::Conflict, code, detail)
    }

    fn persistence(code: &str, detail: impl Into<String>) -> Self {
        Self::new(ProtectedPipelineErrorKind::Persistence, code, detail)
    }

    fn corrupt(code: &str, detail: impl Into<String>) -> Self {
        Self::new(ProtectedPipelineErrorKind::CorruptState, code, detail)
    }
}

impl fmt::Display for ProtectedPipelineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ProtectedPipelineError {}

/// Convenient result alias for protected-pipeline operations.
pub type ProtectedPipelineResult<T> = Result<T, ProtectedPipelineError>;

/// Immutable cryptographic and governed-policy inputs to reconciliation.
pub struct ProtectedPipelineReconcileContext<'a> {
    /// Exact target-height admission context.
    pub target: &'a TargetAdmissionContext,
    /// Aegis verifier configured with the frozen validator keys.
    pub verifier: &'a AegisPqvmVerifier,
    /// Frozen validator set for the target epoch.
    pub validator_set: &'a ValidatorSet,
    /// Frozen cluster assignment for the target epoch.
    pub cluster_map: &'a ClusterMap,
    /// Governed ETDAG gas and byte capacity policy.
    pub parameters: &'a EtdagParameters,
}

/// Proof that a PoSy-derived order seed was independently validated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedOrderSeedEvidence {
    /// Exact seed used for content-blind order.
    pub order_seed: EtdagDigest,
    /// Root of the finalized PoSy authority from which the seed was derived.
    pub authority_root: EtdagDigest,
}

/// Authenticated non-ETDAG observation that can advance the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectedPipelineObservation {
    /// A parent proposal carried the exact required next-batch commitment.
    ParentCommitment {
        proposal_id: EtdagDigest,
        commitment_root: EtdagDigest,
        evidence_root: EtdagDigest,
    },
    /// A PoSy proposal-validation certificate authorizes reveal.
    RevealAuthorization {
        proposal_id: EtdagDigest,
        vc_root: EtdagDigest,
        commitment_root: EtdagDigest,
        evidence_root: EtdagDigest,
    },
    /// One authenticated, replay-bound reveal share was accepted.
    RevealShare {
        validator_id: ValidatorId,
        commitment_root: EtdagDigest,
        share_root: EtdagDigest,
    },
    /// Deterministic decryption and execution input are complete.
    ExecutionReady {
        commitment_root: EtdagDigest,
        execution_root: EtdagDigest,
        evidence_root: EtdagDigest,
    },
    /// The ordinary PoSy QC for the protected execution was observed.
    QcObserved {
        commitment_root: EtdagDigest,
        qc_root: EtdagDigest,
        evidence_root: EtdagDigest,
    },
    /// The ordinary PoSy block carrying this execution was finalized.
    Finalized {
        commitment_root: EtdagDigest,
        finality_root: EtdagDigest,
        evidence_root: EtdagDigest,
    },
    /// The exact protected input was consumed by deterministic execution.
    Consumed {
        commitment_root: EtdagDigest,
        execution_root: EtdagDigest,
        evidence_root: EtdagDigest,
    },
}

impl ProtectedPipelineObservation {
    fn commitment_root(&self) -> &EtdagDigest {
        match self {
            Self::ParentCommitment {
                commitment_root, ..
            }
            | Self::RevealAuthorization {
                commitment_root, ..
            }
            | Self::RevealShare {
                commitment_root, ..
            }
            | Self::ExecutionReady {
                commitment_root, ..
            }
            | Self::QcObserved {
                commitment_root, ..
            }
            | Self::Finalized {
                commitment_root, ..
            }
            | Self::Consumed {
                commitment_root, ..
            } => commitment_root,
        }
    }

    fn validate_roots(&self) -> ProtectedPipelineResult<()> {
        self.commitment_root()
            .validate("protected observation commitment")
            .map_err(|error| {
                ProtectedPipelineError::invalid("PROTECTED_OBSERVATION_INVALID", error)
            })?;
        if self.commitment_root().is_zero() {
            return Err(ProtectedPipelineError::invalid(
                "PROTECTED_OBSERVATION_INVALID",
                "observation commitment root is zero",
            ));
        }
        let roots: Vec<&EtdagDigest> = match self {
            Self::ParentCommitment {
                proposal_id,
                evidence_root,
                ..
            } => vec![proposal_id, evidence_root],
            Self::RevealAuthorization {
                proposal_id,
                vc_root,
                evidence_root,
                ..
            } => vec![proposal_id, vc_root, evidence_root],
            Self::RevealShare { share_root, .. } => vec![share_root],
            Self::ExecutionReady {
                execution_root,
                evidence_root,
                ..
            }
            | Self::Consumed {
                execution_root,
                evidence_root,
                ..
            } => vec![execution_root, evidence_root],
            Self::QcObserved {
                qc_root,
                evidence_root,
                ..
            } => vec![qc_root, evidence_root],
            Self::Finalized {
                finality_root,
                evidence_root,
                ..
            } => vec![finality_root, evidence_root],
        };
        for root in roots {
            root.validate("protected observation root")
                .map_err(|error| {
                    ProtectedPipelineError::invalid("PROTECTED_OBSERVATION_INVALID", error)
                })?;
            if root.is_zero() {
                return Err(ProtectedPipelineError::invalid(
                    "PROTECTED_OBSERVATION_INVALID",
                    "observation contains a zero root",
                ));
            }
        }
        Ok(())
    }
}

/// Verification boundary supplied by PoSy/reveal integration.
///
/// Implementations must authenticate the complete source proof, bind it to
/// `target`, and compare it to `expected_commitment`. The core never advances
/// from a caller assertion alone.
pub trait ProtectedPipelineEvidenceVerifier {
    /// Verify a PoSy-derived order seed and its finalized authority.
    fn verify_order_seed(
        &self,
        target: &TargetAdmissionContext,
        evidence: &ProtectedOrderSeedEvidence,
    ) -> Result<(), String>;

    /// Verify one consensus, reveal, execution, or finality observation.
    fn verify_observation(
        &self,
        target: &TargetAdmissionContext,
        expected_commitment: &NextProtectedBatchCommitment,
        observation: &ProtectedPipelineObservation,
    ) -> Result<(), String>;
}

/// Fail-closed diagnostic retained in the atomic durable record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedPipelineFault {
    /// Stable machine-readable safety code.
    pub code: String,
    /// Non-secret operator detail.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
struct DurableObservations {
    parent_proposals: BTreeSet<EtdagDigest>,
    reveal_authorizations: BTreeSet<EtdagDigest>,
    reveal_shares: BTreeMap<ValidatorId, EtdagDigest>,
    execution_roots: BTreeSet<EtdagDigest>,
    qc_roots: BTreeSet<EtdagDigest>,
    finality_roots: BTreeSet<EtdagDigest>,
    consumed_roots: BTreeSet<EtdagDigest>,
}

/// The single atomic durable record for one target height.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedPipelineRecord {
    /// Schema version of this record.
    pub record_version: u32,
    /// Exact governed target context.
    pub target: TargetAdmissionContext,
    /// Bootstrap or normal ETDAG source classification.
    pub source: ProtectedBatchSource,
    /// Highest durable monotonic phase.
    pub phase: ProtectedPipelinePhase,
    /// Verified vertices keyed by their canonical semantic digest.
    pub certified_vertices: BTreeMap<EtdagDigest, CertifiedVertex>,
    /// Verified quorum-marker candidates seen for this target.
    pub cutoff_marker_digests: BTreeSet<EtdagDigest>,
    /// Frozen exact proof retained for recovery and audit.
    pub cut_proof: Option<ProtectedCutProof>,
    /// Independently verified PoSy order-seed evidence.
    pub order_seed_evidence: Option<ProtectedOrderSeedEvidence>,
    /// Deterministic protected batch.
    pub protected_batch: Option<DeterministicProtectedBatch>,
    /// Exact semantic commitment required in the parent PoSy proposal.
    pub next_commitment: Option<NextProtectedBatchCommitment>,
    observations: DurableObservations,
    /// First fail-closed conflict or invalid-evidence diagnostic.
    pub fault: Option<ProtectedPipelineFault>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProtectedPipelineStoreEnvelope {
    format: String,
    record: ProtectedPipelineRecord,
}

/// Read-only state exported to operators and the Node Control Panel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedPipelineSnapshot {
    /// Stable shared diagnostic fields.
    pub diagnostic: ProtectedPipelineDiagnostic,
    /// Semantic cut identity when available.
    pub cut_root: Option<EtdagDigest>,
    /// Exact evidence-bundle proof root retained only for audit.
    pub exact_cut_proof_root: Option<EtdagDigest>,
    /// Deterministic batch identity when available.
    pub protected_batch_root: Option<EtdagDigest>,
    /// Parent proposal commitment identity when available.
    pub next_commitment_root: Option<EtdagDigest>,
    /// Latched fail-closed state, if any.
    pub fault: Option<ProtectedPipelineFault>,
}

/// Outcome of one level-triggered reconciliation pass.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectedPipelineReconcileOutcome {
    /// Phase before reconciliation.
    pub previous_phase: ProtectedPipelinePhase,
    /// Highest phase reached after processing all currently durable evidence.
    pub current_phase: ProtectedPipelinePhase,
    /// Whether the atomic durable record changed.
    pub changed: bool,
    /// Current read-only diagnostic snapshot.
    pub snapshot: ProtectedPipelineSnapshot,
}

/// Build a marker-subset-independent protected cut from authenticated ETDAG
/// vertices and a strict marker quorum.
///
/// Marker vertices are verified and bound into the exact proof evidence root,
/// but are deliberately excluded from `causal_closure_root` and `cut_root`.
#[allow(clippy::too_many_arguments)]
pub fn construct_protected_cut_proof<'a, I>(
    target: &TargetAdmissionContext,
    certified_vertices: I,
    cutoff_marker_digests: &[EtdagDigest],
    verifier: &AegisPqvmVerifier,
    validator_set: &ValidatorSet,
    cluster_map: &ClusterMap,
) -> ProtectedPipelineResult<ProtectedCutProof>
where
    I: IntoIterator<Item = (&'a EtdagDigest, &'a CertifiedVertex)>,
{
    target
        .validate_validator_and_cluster_bindings(validator_set, cluster_map)
        .map_err(|error| {
            ProtectedPipelineError::invalid("PROTECTED_TARGET_CONTEXT_INVALID", error)
        })?;
    let graph = canonical_verified_graph(
        certified_vertices,
        verifier,
        target,
        validator_set,
        cluster_map,
    )?;
    let mut markers = cutoff_marker_digests.to_vec();
    markers.sort();
    markers.dedup();
    let required = strict_count_quorum(target.assigned_cluster_validator_count)?;
    if markers.len() < required {
        return Err(ProtectedPipelineError::not_ready(
            "PROTECTED_CUTOFF_QUORUM_NOT_READY",
            format!("have {} distinct markers, need {required}", markers.len()),
        ));
    }

    let members = validator_set
        .active_for_epoch(target.epoch)
        .active_for_cluster(target.assigned_cluster_id);
    let mut marker_authors = BTreeSet::new();
    let mut marker_weight = 0u64;
    let mut cutoff_context_root: Option<Hash> = None;
    for marker_digest in &markers {
        let marker = graph.get(marker_digest).ok_or_else(|| {
            ProtectedPipelineError::not_ready(
                "PROTECTED_CUTOFF_MARKER_MISSING",
                format!("missing certified cutoff marker {}", marker_digest.0),
            )
        })?;
        if marker.vertex.kind != VertexKind::CutoffMarker {
            return Err(ProtectedPipelineError::invalid(
                "PROTECTED_CUTOFF_MARKER_INVALID",
                "marker set contains a transaction vertex",
            ));
        }
        if !marker_authors.insert(marker.vertex.author_validator_id.clone()) {
            return Err(ProtectedPipelineError::invalid(
                "PROTECTED_CUTOFF_MARKER_DUPLICATE_AUTHOR",
                "marker quorum contains duplicate authors",
            ));
        }
        let member = members
            .iter()
            .find(|member| member.validator_id == marker.vertex.author_validator_id)
            .ok_or_else(|| {
                ProtectedPipelineError::invalid(
                    "PROTECTED_CUTOFF_MARKER_AUTHOR_INVALID",
                    "marker author is outside the assigned cluster",
                )
            })?;
        marker_weight = marker_weight
            .checked_add(member.voting_weight)
            .ok_or_else(|| {
                ProtectedPipelineError::invalid(
                    "PROTECTED_CUTOFF_MARKER_WEIGHT_OVERFLOW",
                    "marker voting weight overflow",
                )
            })?;
        let marker_cutoff_root = marker.vertex.cutoff_vc_context_root.ok_or_else(|| {
            ProtectedPipelineError::invalid(
                "PROTECTED_CUTOFF_MARKER_INVALID",
                "cutoff marker has no VC context root",
            )
        })?;
        if cutoff_context_root.is_some_and(|existing| existing != marker_cutoff_root) {
            return Err(ProtectedPipelineError::conflict(
                "PROTECTED_CUTOFF_CONTEXT_CONFLICT",
                "valid cutoff markers disagree on the cutoff VC context",
            ));
        }
        cutoff_context_root = Some(marker_cutoff_root);
    }
    if u128::try_from(marker_authors.len())
        .ok()
        .and_then(|count| count.checked_mul(3))
        .is_none_or(|weighted| weighted <= u128::from(target.assigned_cluster_validator_count) * 2)
        || u128::from(marker_weight)
            .checked_mul(3)
            .is_none_or(|weighted| {
                weighted <= u128::from(target.assigned_cluster_total_voting_weight) * 2
            })
    {
        return Err(ProtectedPipelineError::invalid(
            "PROTECTED_CUTOFF_DUAL_QUORUM_INVALID",
            "cutoff markers do not form a strict count-and-weight quorum",
        ));
    }

    let mut closure = BTreeSet::new();
    for marker_digest in &markers {
        let marker = graph.get(marker_digest).ok_or_else(|| {
            ProtectedPipelineError::not_ready(
                "PROTECTED_CUTOFF_MARKER_MISSING",
                "cutoff marker disappeared during construction",
            )
        })?;
        verify_parent_set(marker_digest, marker, &graph, target)?;
        let mut visiting = BTreeSet::new();
        for parent in &marker.vertex.parent_certified_vertex_digests {
            collect_transaction_ancestors(parent, &graph, target, &mut closure, &mut visiting, 0)?;
        }
    }
    let causal_closure_digests = closure.into_iter().collect::<Vec<_>>();
    let mut eligible = BTreeMap::<EtdagDigest, CertifiedEnvelopeRef>::new();
    for digest in &causal_closure_digests {
        let certified = graph.get(digest).ok_or_else(|| {
            ProtectedPipelineError::not_ready(
                "PROTECTED_CAUSAL_VERTEX_MISSING",
                "causal vertex disappeared during construction",
            )
        })?;
        for envelope in &certified.vertex.envelopes {
            match eligible.get(&envelope.tx_commitment) {
                Some(existing) if existing != envelope => {
                    return Err(ProtectedPipelineError::conflict(
                        "PROTECTED_ENVELOPE_METADATA_CONFLICT",
                        "certified vertices bind conflicting metadata to one transaction",
                    ));
                }
                Some(_) => {}
                None => {
                    eligible.insert(envelope.tx_commitment.clone(), envelope.clone());
                }
            }
        }
    }
    let eligible_envelopes = eligible.into_values().collect::<Vec<_>>();
    let cutoff_marker_evidence_root =
        EtdagDigest::from_canonical(DOMAIN_PROTECTED_CUT_MARKER_EVIDENCE, &markers)
            .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_CUT_HASH_FAILED", error))?;
    let causal_closure_root =
        EtdagDigest::from_canonical(DOMAIN_CAUSAL_CLOSURE, &causal_closure_digests)
            .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_CUT_HASH_FAILED", error))?;
    let eligible_set_root =
        EtdagDigest::from_canonical(DOMAIN_ELIGIBLE_SET, &eligible_envelopes)
            .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_CUT_HASH_FAILED", error))?;
    let mut proof = ProtectedCutProof {
        proof_version: PROTECTED_PIPELINE_VERSION,
        chain_id: target.chain_id,
        network_id: target.network_id.clone(),
        protocol_version: target.protocol_version.clone(),
        profile_id: ETDAG_PROFILE_ID.to_string(),
        epoch: target.epoch,
        target_height: target.target_height,
        cluster_id: target.assigned_cluster_id,
        target_context_root: target.root().map_err(|error| {
            ProtectedPipelineError::invalid("PROTECTED_TARGET_CONTEXT_INVALID", error)
        })?,
        validator_set_commitment: target.active_validator_set_root,
        parameter_root: target.consensus_parameter_root,
        cutoff_vc_context_root: cutoff_context_root.ok_or_else(|| {
            ProtectedPipelineError::not_ready(
                "PROTECTED_CUTOFF_QUORUM_NOT_READY",
                "no cutoff VC context is available",
            )
        })?,
        cutoff_marker_digests: markers,
        cutoff_marker_evidence_root,
        causal_closure_digests,
        causal_closure_root,
        eligible_envelopes,
        eligible_set_root,
        cut_root: EtdagDigest::zero(),
    };
    proof.cut_root = proof
        .semantic_root()
        .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_CUT_HASH_FAILED", error))?;
    validate_protected_cut_proof(&proof, target)?;
    Ok(proof)
}

/// Derive the exact content-blind protected batch under governed capacity.
pub fn derive_protected_batch(
    target: &TargetAdmissionContext,
    cut_proof: &ProtectedCutProof,
    order_seed: &EtdagDigest,
    parameters: &EtdagParameters,
) -> ProtectedPipelineResult<DeterministicProtectedBatch> {
    validate_protected_cut_proof(cut_proof, target)?;
    parameters.validate().map_err(|error| {
        ProtectedPipelineError::invalid("PROTECTED_BATCH_POLICY_INVALID", error)
    })?;
    order_seed
        .validate("protected order seed")
        .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_ORDER_SEED_INVALID", error))?;
    if order_seed.is_zero() {
        return Err(ProtectedPipelineError::invalid(
            "PROTECTED_ORDER_SEED_INVALID",
            "order seed is zero",
        ));
    }
    let ordered = canonical_content_blind_order(
        &cut_proof.eligible_envelopes,
        order_seed,
        parameters.max_protected_gas,
        parameters.max_protected_bytes,
    )
    .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_ORDER_INVALID", error))?;
    let protected_gas = checked_resource_total(&ordered, |envelope| envelope.gas_class_units)?;
    let protected_bytes = checked_resource_total(&ordered, |envelope| envelope.ciphertext_bytes)?;
    let ordered_transaction_ids = ordered
        .iter()
        .map(|envelope| envelope.tx_commitment.clone())
        .collect::<Vec<_>>();
    let order_root =
        EtdagDigest::from_canonical(DOMAIN_PROTECTED_ORDER_ROOT, &ordered_transaction_ids)
            .map_err(|error| {
                ProtectedPipelineError::invalid("PROTECTED_ORDER_HASH_FAILED", error)
            })?;
    let mut batch = DeterministicProtectedBatch {
        batch_version: PROTECTED_PIPELINE_VERSION,
        chain_id: target.chain_id,
        network_id: target.network_id.clone(),
        protocol_version: target.protocol_version.clone(),
        profile_id: ETDAG_PROFILE_ID.to_string(),
        epoch: target.epoch,
        target_height: target.target_height,
        cluster_id: target.assigned_cluster_id,
        target_context_root: target.root().map_err(|error| {
            ProtectedPipelineError::invalid("PROTECTED_TARGET_CONTEXT_INVALID", error)
        })?,
        validator_set_commitment: target.active_validator_set_root,
        parameter_root: target.consensus_parameter_root,
        cut_root: cut_proof.cut_root.clone(),
        eligible_set_root: cut_proof.eligible_set_root.clone(),
        order_seed: order_seed.clone(),
        ordered_transaction_ids,
        order_root,
        protected_count: u64::try_from(ordered.len()).map_err(|_| {
            ProtectedPipelineError::invalid(
                "PROTECTED_BATCH_COUNT_OVERFLOW",
                "protected transaction count exceeds u64",
            )
        })?,
        protected_gas,
        protected_bytes,
        protected_batch_root: EtdagDigest::zero(),
    };
    batch.protected_batch_root = batch
        .semantic_root()
        .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_BATCH_HASH_FAILED", error))?;
    batch
        .validate_declared_roots()
        .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_BATCH_INVALID", error))?;
    Ok(batch)
}

/// Derive the proposal-visible semantic commitment for the next protected
/// batch. Exact marker evidence is intentionally absent from this identity.
pub fn derive_next_protected_batch_commitment(
    target: &TargetAdmissionContext,
    cut_proof: &ProtectedCutProof,
    batch: &DeterministicProtectedBatch,
) -> ProtectedPipelineResult<NextProtectedBatchCommitment> {
    validate_protected_cut_proof(cut_proof, target)?;
    batch
        .validate_declared_roots()
        .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_BATCH_INVALID", error))?;
    if batch.chain_id != target.chain_id
        || batch.network_id != target.network_id
        || batch.protocol_version != target.protocol_version
        || batch.epoch != target.epoch
        || batch.target_height != target.target_height
        || batch.cluster_id != target.assigned_cluster_id
        || batch.target_context_root
            != target.root().map_err(|error| {
                ProtectedPipelineError::invalid("PROTECTED_TARGET_CONTEXT_INVALID", error)
            })?
        || batch.validator_set_commitment != target.active_validator_set_root
        || batch.parameter_root != target.consensus_parameter_root
        || batch.cut_root != cut_proof.cut_root
        || batch.eligible_set_root != cut_proof.eligible_set_root
    {
        return Err(ProtectedPipelineError::conflict(
            "PROTECTED_BATCH_BINDING_CONFLICT",
            "batch does not bind the exact target and semantic cut",
        ));
    }
    Ok(NextProtectedBatchCommitment {
        commitment_version: PROTECTED_PIPELINE_VERSION,
        chain_id: target.chain_id,
        network_id: target.network_id.clone(),
        protocol_version: target.protocol_version.clone(),
        epoch: target.epoch,
        target_height: target.target_height,
        cluster_id: target.assigned_cluster_id,
        target_context_root: batch.target_context_root,
        validator_set_commitment: target.active_validator_set_root,
        parameter_root: target.consensus_parameter_root,
        cut_root: cut_proof.cut_root.clone(),
        eligible_set_root: cut_proof.eligible_set_root.clone(),
        order_seed: batch.order_seed.clone(),
        order_root: batch.order_root.clone(),
        protected_batch_root: batch.protected_batch_root.clone(),
        protected_count: batch.protected_count,
        protected_gas: batch.protected_gas,
        protected_bytes: batch.protected_bytes,
    })
}

/// Single-writer owner of one target-height atomic durable record.
#[derive(Debug)]
pub struct ProtectedPipeline {
    path: PathBuf,
    record: ProtectedPipelineRecord,
}

impl ProtectedPipeline {
    /// Open an existing record or atomically create a collecting record.
    pub fn open(
        path: impl Into<PathBuf>,
        target: TargetAdmissionContext,
        source: ProtectedBatchSource,
    ) -> ProtectedPipelineResult<Self> {
        target.validate().map_err(|error| {
            ProtectedPipelineError::invalid("PROTECTED_TARGET_CONTEXT_INVALID", error)
        })?;
        let path = path.into();
        if path.exists() {
            let bytes = fs::read(&path).map_err(|error| {
                ProtectedPipelineError::persistence(
                    "PROTECTED_STORE_READ_FAILED",
                    format!("read {}: {error}", path.display()),
                )
            })?;
            let envelope: ProtectedPipelineStoreEnvelope =
                serde_json::from_slice(&bytes).map_err(|error| {
                    ProtectedPipelineError::corrupt(
                        "PROTECTED_STORE_DECODE_FAILED",
                        format!("decode {}: {error}", path.display()),
                    )
                })?;
            if envelope.format != PROTECTED_PIPELINE_STORE_FORMAT {
                return Err(ProtectedPipelineError::corrupt(
                    "PROTECTED_STORE_FORMAT_INVALID",
                    "unsupported protected-pipeline durable format",
                ));
            }
            if envelope.record.target != target || envelope.record.source != source {
                return Err(ProtectedPipelineError::conflict(
                    "PROTECTED_STORE_TARGET_CONFLICT",
                    "durable record belongs to another target or source",
                ));
            }
            validate_durable_record(&envelope.record)?;
            return Ok(Self {
                path,
                record: envelope.record,
            });
        }
        let record = ProtectedPipelineRecord {
            record_version: PROTECTED_PIPELINE_VERSION,
            target,
            source,
            phase: ProtectedPipelinePhase::Collecting,
            certified_vertices: BTreeMap::new(),
            cutoff_marker_digests: BTreeSet::new(),
            cut_proof: None,
            order_seed_evidence: None,
            protected_batch: None,
            next_commitment: None,
            observations: DurableObservations::default(),
            fault: None,
        };
        persist_record(&path, &record)?;
        Ok(Self { path, record })
    }

    /// Borrow the exact current durable record.
    pub fn record(&self) -> &ProtectedPipelineRecord {
        &self.record
    }

    /// Return a read-only diagnostic derived without clocks or mutable caches.
    pub fn snapshot(&self) -> ProtectedPipelineResult<ProtectedPipelineSnapshot> {
        snapshot_for(&self.record)
    }

    /// Verify, idempotently merge, and reconcile ETDAG vertices and markers.
    pub fn merge_etdag_evidence(
        &mut self,
        certified_vertices: &[CertifiedVertex],
        cutoff_marker_digests: &[EtdagDigest],
        inputs: &ProtectedPipelineReconcileContext<'_>,
    ) -> ProtectedPipelineResult<ProtectedPipelineReconcileOutcome> {
        self.ensure_live()?;
        let previous_phase = self.record.phase;
        let mut candidate = self.record.clone();
        if let Err(error) = validate_reconcile_inputs(&candidate, inputs) {
            return self.latch_and_return(candidate, error);
        }
        for certified in certified_vertices {
            if let Err(error) = certified.vertex.digest().and_then(|digest| {
                certified
                    .verify(
                        inputs.verifier,
                        inputs.target,
                        inputs.validator_set,
                        inputs.cluster_map,
                    )
                    .map(|()| digest)
            }) {
                return self.latch_and_return(
                    candidate,
                    ProtectedPipelineError::invalid("PROTECTED_CERTIFIED_VERTEX_INVALID", error),
                );
            }
            let digest = certified.vertex.digest().map_err(|error| {
                ProtectedPipelineError::invalid("PROTECTED_VERTEX_DIGEST_INVALID", error)
            })?;
            match candidate.certified_vertices.get(&digest) {
                Some(existing) => {
                    let existing_bytes = existing.canonical_bytes().map_err(|error| {
                        ProtectedPipelineError::invalid(
                            "PROTECTED_VERTEX_CANONICALIZATION_FAILED",
                            error,
                        )
                    })?;
                    let incoming_bytes = certified.canonical_bytes().map_err(|error| {
                        ProtectedPipelineError::invalid(
                            "PROTECTED_VERTEX_CANONICALIZATION_FAILED",
                            error,
                        )
                    })?;
                    if incoming_bytes < existing_bytes {
                        candidate
                            .certified_vertices
                            .insert(digest, certified.clone());
                    }
                }
                None => {
                    candidate
                        .certified_vertices
                        .insert(digest, certified.clone());
                }
            }
        }
        for marker_digest in cutoff_marker_digests {
            let Some(marker) = candidate.certified_vertices.get(marker_digest) else {
                return self.latch_and_return(
                    candidate,
                    ProtectedPipelineError::invalid(
                        "PROTECTED_MARKER_REFERENCE_INVALID",
                        "marker evidence does not reference a supplied certified vertex",
                    ),
                );
            };
            if marker.vertex.kind != VertexKind::CutoffMarker {
                return self.latch_and_return(
                    candidate,
                    ProtectedPipelineError::invalid(
                        "PROTECTED_MARKER_REFERENCE_INVALID",
                        "marker evidence references a transaction vertex",
                    ),
                );
            }
            candidate
                .cutoff_marker_digests
                .insert(marker_digest.clone());
        }
        self.reconcile_candidate(candidate, inputs, previous_phase)
    }

    /// Verify and durably merge the exact PoSy-derived ordering seed.
    pub fn merge_order_seed(
        &mut self,
        evidence: ProtectedOrderSeedEvidence,
        evidence_verifier: &impl ProtectedPipelineEvidenceVerifier,
        inputs: &ProtectedPipelineReconcileContext<'_>,
    ) -> ProtectedPipelineResult<ProtectedPipelineReconcileOutcome> {
        self.ensure_live()?;
        let previous_phase = self.record.phase;
        let mut candidate = self.record.clone();
        if let Err(error) = validate_reconcile_inputs(&candidate, inputs) {
            return self.latch_and_return(candidate, error);
        }
        if let Err(error) = evidence_verifier.verify_order_seed(inputs.target, &evidence) {
            return self.latch_and_return(
                candidate,
                ProtectedPipelineError::invalid("PROTECTED_ORDER_SEED_EVIDENCE_INVALID", error),
            );
        }
        if evidence.order_seed.is_zero() || evidence.authority_root.is_zero() {
            return self.latch_and_return(
                candidate,
                ProtectedPipelineError::invalid(
                    "PROTECTED_ORDER_SEED_EVIDENCE_INVALID",
                    "order seed evidence contains a zero root",
                ),
            );
        }
        match &candidate.order_seed_evidence {
            Some(existing) if existing != &evidence => {
                return self.latch_and_return(
                    candidate,
                    ProtectedPipelineError::conflict(
                        "PROTECTED_ORDER_SEED_CONFLICT",
                        "a different order seed is already durable for this target",
                    ),
                );
            }
            Some(_) => {}
            None => candidate.order_seed_evidence = Some(evidence),
        }
        self.reconcile_candidate(candidate, inputs, previous_phase)
    }

    /// Verify and durably merge one PoSy/reveal/execution observation.
    pub fn merge_observation(
        &mut self,
        observation: ProtectedPipelineObservation,
        evidence_verifier: &impl ProtectedPipelineEvidenceVerifier,
        inputs: &ProtectedPipelineReconcileContext<'_>,
    ) -> ProtectedPipelineResult<ProtectedPipelineReconcileOutcome> {
        self.ensure_live()?;
        let previous_phase = self.record.phase;
        let mut candidate = self.record.clone();
        if let Err(error) = validate_reconcile_inputs(&candidate, inputs) {
            return self.latch_and_return(candidate, error);
        }
        let Some(expected) = candidate.next_commitment.as_ref() else {
            return Err(ProtectedPipelineError::not_ready(
                "PROTECTED_COMMITMENT_NOT_READY",
                "cannot authenticate a bound observation before commitment derivation",
            ));
        };
        if let Err(error) = observation.validate_roots() {
            return self.latch_and_return(candidate, error);
        }
        let expected_root = expected.root().map_err(|error| {
            ProtectedPipelineError::invalid("PROTECTED_COMMITMENT_HASH_FAILED", error)
        })?;
        if observation.commitment_root() != &expected_root {
            return self.latch_and_return(
                candidate,
                ProtectedPipelineError::conflict(
                    "PROTECTED_OBSERVATION_COMMITMENT_CONFLICT",
                    "observation is bound to another protected commitment",
                ),
            );
        }
        if let Err(error) =
            evidence_verifier.verify_observation(inputs.target, expected, &observation)
        {
            return self.latch_and_return(
                candidate,
                ProtectedPipelineError::invalid("PROTECTED_OBSERVATION_INVALID", error),
            );
        }
        if let Err(error) = merge_observation_into(&mut candidate, observation) {
            return self.latch_and_return(candidate, error);
        }
        self.reconcile_candidate(candidate, inputs, previous_phase)
    }

    /// Re-evaluate all durable evidence until no further legal phase exists.
    pub fn reconcile(
        &mut self,
        inputs: &ProtectedPipelineReconcileContext<'_>,
    ) -> ProtectedPipelineResult<ProtectedPipelineReconcileOutcome> {
        self.ensure_live()?;
        let previous_phase = self.record.phase;
        let candidate = self.record.clone();
        self.reconcile_candidate(candidate, inputs, previous_phase)
    }

    fn ensure_live(&self) -> ProtectedPipelineResult<()> {
        if let Some(fault) = &self.record.fault {
            return Err(ProtectedPipelineError::conflict(
                &fault.code,
                fault.detail.clone(),
            ));
        }
        Ok(())
    }

    fn reconcile_candidate(
        &mut self,
        mut candidate: ProtectedPipelineRecord,
        inputs: &ProtectedPipelineReconcileContext<'_>,
        previous_phase: ProtectedPipelinePhase,
    ) -> ProtectedPipelineResult<ProtectedPipelineReconcileOutcome> {
        if let Err(error) = validate_reconcile_inputs(&candidate, inputs) {
            return self.latch_and_return(candidate, error);
        }
        if candidate.cutoff_marker_digests.len()
            >= strict_count_quorum(candidate.target.assigned_cluster_validator_count)?
        {
            reconcile_phase(&mut candidate, ProtectedPipelinePhase::CutoffReady)?;
            let marker_digests = candidate
                .cutoff_marker_digests
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            match construct_protected_cut_proof(
                inputs.target,
                &candidate.certified_vertices,
                &marker_digests,
                inputs.verifier,
                inputs.validator_set,
                inputs.cluster_map,
            ) {
                Ok(derived) => match &candidate.cut_proof {
                    Some(existing) if existing.cut_root != derived.cut_root => {
                        return self.latch_and_return(
                            candidate,
                            ProtectedPipelineError::conflict(
                                "PROTECTED_CUT_ROOT_CONFLICT",
                                "new valid marker evidence derives a different semantic cut",
                            ),
                        );
                    }
                    Some(_) => {}
                    None => {
                        candidate.cut_proof = Some(derived);
                    }
                },
                Err(error) if error.kind == ProtectedPipelineErrorKind::NotReady => {}
                Err(error) => return self.latch_and_return(candidate, error),
            }
        }
        if candidate.cut_proof.is_some() {
            reconcile_phase(&mut candidate, ProtectedPipelinePhase::CutReady)?;
        }
        if let (Some(cut), Some(seed_evidence)) = (
            candidate.cut_proof.as_ref(),
            candidate.order_seed_evidence.as_ref(),
        ) {
            let batch = derive_protected_batch(
                inputs.target,
                cut,
                &seed_evidence.order_seed,
                inputs.parameters,
            )?;
            let commitment = derive_next_protected_batch_commitment(inputs.target, cut, &batch)?;
            if candidate
                .protected_batch
                .as_ref()
                .is_some_and(|existing| existing != &batch)
                || candidate
                    .next_commitment
                    .as_ref()
                    .is_some_and(|existing| existing != &commitment)
            {
                return self.latch_and_return(
                    candidate,
                    ProtectedPipelineError::conflict(
                        "PROTECTED_ORDER_ROOT_CONFLICT",
                        "reconciliation derived a different durable batch or commitment",
                    ),
                );
            }
            candidate.protected_batch = Some(batch);
            candidate.next_commitment = Some(commitment);
            reconcile_phase(&mut candidate, ProtectedPipelinePhase::OrderReady)?;
        }
        if !candidate.observations.parent_proposals.is_empty() {
            reconcile_phase(&mut candidate, ProtectedPipelinePhase::CommittedInParent)?;
        }
        if !candidate.observations.reveal_authorizations.is_empty() {
            reconcile_phase(&mut candidate, ProtectedPipelinePhase::RevealAuthorized)?;
        }
        if !candidate.observations.reveal_shares.is_empty() {
            reconcile_phase(&mut candidate, ProtectedPipelinePhase::Revealing)?;
        }
        if !candidate.observations.execution_roots.is_empty() {
            reconcile_phase(&mut candidate, ProtectedPipelinePhase::ReadyForExecution)?;
        }
        if !candidate.observations.consumed_roots.is_empty() {
            reconcile_phase(&mut candidate, ProtectedPipelinePhase::Consumed)?;
        }
        validate_durable_record(&candidate)?;
        let changed = candidate != self.record;
        if changed {
            persist_record(&self.path, &candidate)?;
            self.record = candidate;
        }
        Ok(ProtectedPipelineReconcileOutcome {
            previous_phase,
            current_phase: self.record.phase,
            changed,
            snapshot: snapshot_for(&self.record)?,
        })
    }

    fn latch_and_return<T>(
        &mut self,
        mut candidate: ProtectedPipelineRecord,
        error: ProtectedPipelineError,
    ) -> ProtectedPipelineResult<T> {
        if matches!(
            error.kind,
            ProtectedPipelineErrorKind::InvalidEvidence | ProtectedPipelineErrorKind::Conflict
        ) && candidate.fault.is_none()
        {
            candidate.fault = Some(ProtectedPipelineFault {
                code: error.code.clone(),
                detail: error.detail.clone(),
            });
            persist_record(&self.path, &candidate)?;
            self.record = candidate;
        }
        Err(error)
    }
}

fn canonical_verified_graph<'a, I>(
    certified_vertices: I,
    verifier: &AegisPqvmVerifier,
    target: &TargetAdmissionContext,
    validator_set: &ValidatorSet,
    cluster_map: &ClusterMap,
) -> ProtectedPipelineResult<BTreeMap<EtdagDigest, CertifiedVertex>>
where
    I: IntoIterator<Item = (&'a EtdagDigest, &'a CertifiedVertex)>,
{
    let mut graph = BTreeMap::new();
    for (declared_digest, certified) in certified_vertices {
        let actual_digest = certified.vertex.digest().map_err(|error| {
            ProtectedPipelineError::invalid("PROTECTED_VERTEX_DIGEST_INVALID", error)
        })?;
        if declared_digest != &actual_digest {
            return Err(ProtectedPipelineError::invalid(
                "PROTECTED_VERTEX_MAP_KEY_INVALID",
                "certified-vertex map key differs from the vertex digest",
            ));
        }
        certified
            .verify(verifier, target, validator_set, cluster_map)
            .map_err(|error| {
                ProtectedPipelineError::invalid("PROTECTED_CERTIFIED_VERTEX_INVALID", error)
            })?;
        if graph.insert(actual_digest, certified.clone()).is_some() {
            return Err(ProtectedPipelineError::invalid(
                "PROTECTED_VERTEX_DUPLICATE",
                "certified-vertex source contains a duplicate digest",
            ));
        }
    }
    Ok(graph)
}

fn verify_parent_set(
    digest: &EtdagDigest,
    certified: &CertifiedVertex,
    graph: &BTreeMap<EtdagDigest, CertifiedVertex>,
    target: &TargetAdmissionContext,
) -> ProtectedPipelineResult<()> {
    if certified.vertex.dag_round == 0 {
        return Ok(());
    }
    let expected_round = certified.vertex.dag_round.checked_sub(1).ok_or_else(|| {
        ProtectedPipelineError::invalid("PROTECTED_PARENT_ROUND_INVALID", "parent round underflow")
    })?;
    let mut authors = BTreeSet::new();
    for parent_digest in &certified.vertex.parent_certified_vertex_digests {
        let parent = graph.get(parent_digest).ok_or_else(|| {
            ProtectedPipelineError::not_ready(
                "PROTECTED_CAUSAL_VERTEX_MISSING",
                format!("missing certified parent {}", parent_digest.0),
            )
        })?;
        if parent.vertex.dag_round != expected_round {
            return Err(ProtectedPipelineError::invalid(
                "PROTECTED_PARENT_ROUND_INVALID",
                format!(
                    "vertex {} has a parent outside the previous round",
                    digest.0
                ),
            ));
        }
        if !authors.insert(parent.vertex.author_validator_id.clone()) {
            return Err(ProtectedPipelineError::invalid(
                "PROTECTED_PARENT_AUTHOR_DUPLICATE",
                "certified parents do not have distinct authors",
            ));
        }
    }
    let required = strict_count_quorum(target.assigned_cluster_validator_count)?;
    if authors.len() < required {
        return Err(ProtectedPipelineError::invalid(
            "PROTECTED_PARENT_QUORUM_INVALID",
            format!("have {} parent authors, need {required}", authors.len()),
        ));
    }
    Ok(())
}

fn collect_transaction_ancestors(
    digest: &EtdagDigest,
    graph: &BTreeMap<EtdagDigest, CertifiedVertex>,
    target: &TargetAdmissionContext,
    closure: &mut BTreeSet<EtdagDigest>,
    visiting: &mut BTreeSet<EtdagDigest>,
    depth: usize,
) -> ProtectedPipelineResult<()> {
    if depth > MAX_CAUSAL_DEPTH {
        return Err(ProtectedPipelineError::invalid(
            "PROTECTED_CAUSAL_DEPTH_INVALID",
            "causal graph exceeds the bounded depth",
        ));
    }
    if closure.contains(digest) {
        return Ok(());
    }
    if !visiting.insert(digest.clone()) {
        return Err(ProtectedPipelineError::invalid(
            "PROTECTED_CAUSAL_CYCLE_INVALID",
            "causal graph contains a cycle",
        ));
    }
    let certified = graph.get(digest).ok_or_else(|| {
        ProtectedPipelineError::not_ready(
            "PROTECTED_CAUSAL_VERTEX_MISSING",
            format!("missing causal vertex {}", digest.0),
        )
    })?;
    verify_parent_set(digest, certified, graph, target)?;
    for parent in &certified.vertex.parent_certified_vertex_digests {
        collect_transaction_ancestors(parent, graph, target, closure, visiting, depth + 1)?;
    }
    visiting.remove(digest);
    if certified.vertex.kind == VertexKind::Transactions {
        closure.insert(digest.clone());
    }
    Ok(())
}

fn validate_protected_cut_proof(
    proof: &ProtectedCutProof,
    target: &TargetAdmissionContext,
) -> ProtectedPipelineResult<()> {
    target.validate().map_err(|error| {
        ProtectedPipelineError::invalid("PROTECTED_TARGET_CONTEXT_INVALID", error)
    })?;
    if proof.proof_version != PROTECTED_PIPELINE_VERSION
        || proof.chain_id != target.chain_id
        || proof.network_id != target.network_id
        || proof.protocol_version != target.protocol_version
        || proof.profile_id != ETDAG_PROFILE_ID
        || proof.epoch != target.epoch
        || proof.target_height != target.target_height
        || proof.cluster_id != target.assigned_cluster_id
        || proof.target_context_root
            != target.root().map_err(|error| {
                ProtectedPipelineError::invalid("PROTECTED_TARGET_CONTEXT_INVALID", error)
            })?
        || proof.validator_set_commitment != target.active_validator_set_root
        || proof.parameter_root != target.consensus_parameter_root
        || proof.cutoff_vc_context_root.is_zero()
    {
        return Err(ProtectedPipelineError::invalid(
            "PROTECTED_CUT_CONTEXT_INVALID",
            "cut proof does not bind the exact target context",
        ));
    }
    if proof.cutoff_marker_digests.len()
        < strict_count_quorum(target.assigned_cluster_validator_count)?
        || !strictly_sorted_unique(&proof.cutoff_marker_digests)
        || !strictly_sorted_unique(&proof.causal_closure_digests)
    {
        return Err(ProtectedPipelineError::invalid(
            "PROTECTED_CUT_CANONICALITY_INVALID",
            "cut proof evidence is not canonical quorum data",
        ));
    }
    let marker_root = EtdagDigest::from_canonical(
        DOMAIN_PROTECTED_CUT_MARKER_EVIDENCE,
        &proof.cutoff_marker_digests,
    )
    .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_CUT_HASH_FAILED", error))?;
    let closure_root =
        EtdagDigest::from_canonical(DOMAIN_CAUSAL_CLOSURE, &proof.causal_closure_digests)
            .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_CUT_HASH_FAILED", error))?;
    let eligible_root = EtdagDigest::from_canonical(DOMAIN_ELIGIBLE_SET, &proof.eligible_envelopes)
        .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_CUT_HASH_FAILED", error))?;
    let semantic_root = proof
        .semantic_root()
        .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_CUT_HASH_FAILED", error))?;
    if proof.cutoff_marker_evidence_root != marker_root
        || proof.causal_closure_root != closure_root
        || proof.eligible_set_root != eligible_root
        || proof.cut_root != semantic_root
    {
        return Err(ProtectedPipelineError::invalid(
            "PROTECTED_CUT_ROOT_INVALID",
            "cut proof declared roots do not recompute",
        ));
    }
    Ok(())
}

fn checked_resource_total(
    envelopes: &[CertifiedEnvelopeRef],
    value: impl Fn(&CertifiedEnvelopeRef) -> u64,
) -> ProtectedPipelineResult<u64> {
    envelopes.iter().try_fold(0u64, |total, envelope| {
        total.checked_add(value(envelope)).ok_or_else(|| {
            ProtectedPipelineError::invalid(
                "PROTECTED_BATCH_RESOURCE_OVERFLOW",
                "protected batch resource total exceeds u64",
            )
        })
    })
}

fn strict_count_quorum(validator_count: u64) -> ProtectedPipelineResult<usize> {
    if validator_count == 0 {
        return Err(ProtectedPipelineError::invalid(
            "PROTECTED_VALIDATOR_COUNT_INVALID",
            "assigned cluster has no validators",
        ));
    }
    let threshold = validator_count
        .checked_mul(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            ProtectedPipelineError::invalid(
                "PROTECTED_QUORUM_OVERFLOW",
                "strict quorum calculation overflow",
            )
        })?;
    usize::try_from(threshold).map_err(|_| {
        ProtectedPipelineError::invalid(
            "PROTECTED_QUORUM_OVERFLOW",
            "strict quorum exceeds addressable memory",
        )
    })
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_reconcile_inputs(
    record: &ProtectedPipelineRecord,
    inputs: &ProtectedPipelineReconcileContext<'_>,
) -> ProtectedPipelineResult<()> {
    if &record.target != inputs.target {
        return Err(ProtectedPipelineError::conflict(
            "PROTECTED_TARGET_CONTEXT_CONFLICT",
            "reconciliation supplied another target context",
        ));
    }
    inputs
        .target
        .validate_validator_and_cluster_bindings(inputs.validator_set, inputs.cluster_map)
        .map_err(|error| {
            ProtectedPipelineError::invalid("PROTECTED_TARGET_CONTEXT_INVALID", error)
        })?;
    inputs
        .parameters
        .validate()
        .map_err(|error| ProtectedPipelineError::invalid("PROTECTED_BATCH_POLICY_INVALID", error))
}

fn merge_observation_into(
    record: &mut ProtectedPipelineRecord,
    observation: ProtectedPipelineObservation,
) -> ProtectedPipelineResult<()> {
    match observation {
        ProtectedPipelineObservation::ParentCommitment { proposal_id, .. } => {
            record.observations.parent_proposals.insert(proposal_id);
        }
        ProtectedPipelineObservation::RevealAuthorization {
            proposal_id,
            vc_root,
            ..
        } => {
            if !record.observations.parent_proposals.contains(&proposal_id) {
                return Err(ProtectedPipelineError::conflict(
                    "PROTECTED_REVEAL_PARENT_CONFLICT",
                    "reveal VC names a proposal not observed with the exact commitment",
                ));
            }
            record.observations.reveal_authorizations.insert(vc_root);
        }
        ProtectedPipelineObservation::RevealShare {
            validator_id,
            share_root,
            ..
        } => match record.observations.reveal_shares.get(&validator_id) {
            Some(existing) if existing != &share_root => {
                return Err(ProtectedPipelineError::conflict(
                    "PROTECTED_REVEAL_SHARE_CONFLICT",
                    "one validator supplied conflicting verified reveal shares",
                ));
            }
            Some(_) => {}
            None => {
                record
                    .observations
                    .reveal_shares
                    .insert(validator_id, share_root);
            }
        },
        ProtectedPipelineObservation::ExecutionReady { execution_root, .. } => {
            record.observations.execution_roots.insert(execution_root);
        }
        ProtectedPipelineObservation::QcObserved { qc_root, .. } => {
            record.observations.qc_roots.insert(qc_root);
        }
        ProtectedPipelineObservation::Finalized { finality_root, .. } => {
            record.observations.finality_roots.insert(finality_root);
        }
        ProtectedPipelineObservation::Consumed { execution_root, .. } => {
            if !record
                .observations
                .execution_roots
                .contains(&execution_root)
            {
                return Err(ProtectedPipelineError::conflict(
                    "PROTECTED_CONSUMED_EXECUTION_CONFLICT",
                    "consumed observation names an execution that was not ready",
                ));
            }
            record.observations.consumed_roots.insert(execution_root);
        }
    }
    Ok(())
}

fn advance_phase(
    record: &mut ProtectedPipelineRecord,
    requested: ProtectedPipelinePhase,
) -> ProtectedPipelineResult<()> {
    if requested < record.phase {
        return Err(ProtectedPipelineError::conflict(
            "PROTECTED_PHASE_ROLLBACK",
            "attempted to lower the durable protected-pipeline phase",
        ));
    }
    if requested > record.phase {
        record.phase = requested;
    }
    Ok(())
}

fn reconcile_phase(
    record: &mut ProtectedPipelineRecord,
    requested: ProtectedPipelinePhase,
) -> ProtectedPipelineResult<()> {
    if requested > record.phase {
        advance_phase(record, requested)?;
    }
    Ok(())
}

fn validate_durable_record(record: &ProtectedPipelineRecord) -> ProtectedPipelineResult<()> {
    if record.record_version != PROTECTED_PIPELINE_VERSION {
        return Err(ProtectedPipelineError::corrupt(
            "PROTECTED_RECORD_VERSION_INVALID",
            "unsupported protected-pipeline record version",
        ));
    }
    record.target.validate().map_err(|error| {
        ProtectedPipelineError::corrupt("PROTECTED_RECORD_TARGET_INVALID", error)
    })?;
    if record.phase >= ProtectedPipelinePhase::CutReady && record.cut_proof.is_none() {
        return Err(ProtectedPipelineError::corrupt(
            "PROTECTED_RECORD_PHASE_INVALID",
            "CUT_READY record has no cut proof",
        ));
    }
    if record.phase >= ProtectedPipelinePhase::OrderReady
        && (record.order_seed_evidence.is_none()
            || record.protected_batch.is_none()
            || record.next_commitment.is_none())
    {
        return Err(ProtectedPipelineError::corrupt(
            "PROTECTED_RECORD_PHASE_INVALID",
            "ORDER_READY record lacks seed, batch, or commitment",
        ));
    }
    if record.phase >= ProtectedPipelinePhase::CommittedInParent
        && record.observations.parent_proposals.is_empty()
    {
        return Err(ProtectedPipelineError::corrupt(
            "PROTECTED_RECORD_PHASE_INVALID",
            "COMMITTED_IN_PARENT record has no verified parent observation",
        ));
    }
    if record.phase >= ProtectedPipelinePhase::RevealAuthorized
        && record.observations.reveal_authorizations.is_empty()
    {
        return Err(ProtectedPipelineError::corrupt(
            "PROTECTED_RECORD_PHASE_INVALID",
            "REVEAL_AUTHORIZED record has no verified VC observation",
        ));
    }
    if record.phase >= ProtectedPipelinePhase::Revealing
        && record.observations.reveal_shares.is_empty()
    {
        return Err(ProtectedPipelineError::corrupt(
            "PROTECTED_RECORD_PHASE_INVALID",
            "REVEALING record has no verified reveal share",
        ));
    }
    if record.phase >= ProtectedPipelinePhase::ReadyForExecution
        && record.observations.execution_roots.is_empty()
    {
        return Err(ProtectedPipelineError::corrupt(
            "PROTECTED_RECORD_PHASE_INVALID",
            "READY_FOR_EXECUTION record has no verified execution root",
        ));
    }
    if record.phase >= ProtectedPipelinePhase::Consumed
        && record.observations.consumed_roots.is_empty()
    {
        return Err(ProtectedPipelineError::corrupt(
            "PROTECTED_RECORD_PHASE_INVALID",
            "CONSUMED record has no verified consumed root",
        ));
    }
    Ok(())
}

fn snapshot_for(
    record: &ProtectedPipelineRecord,
) -> ProtectedPipelineResult<ProtectedPipelineSnapshot> {
    let exact_cut_proof_root = record
        .cut_proof
        .as_ref()
        .map(ProtectedCutProof::proof_root)
        .transpose()
        .map_err(|error| {
            ProtectedPipelineError::corrupt("PROTECTED_RECORD_CUT_PROOF_INVALID", error)
        })?;
    let next_commitment_root = record
        .next_commitment
        .as_ref()
        .map(NextProtectedBatchCommitment::root)
        .transpose()
        .map_err(|error| {
            ProtectedPipelineError::corrupt("PROTECTED_RECORD_COMMITMENT_INVALID", error)
        })?;
    Ok(ProtectedPipelineSnapshot {
        diagnostic: ProtectedPipelineDiagnostic {
            target_height: record.target.target_height,
            phase: record.phase,
            source: record.source,
            availability_count: record
                .certified_vertices
                .values()
                .filter(|certified| certified.vertex.kind == VertexKind::Transactions)
                .count() as u64,
            cutoff_marker_count: record.cutoff_marker_digests.len() as u64,
            cut_ready: record.cut_proof.is_some(),
            order_ready: record.protected_batch.is_some(),
            parent_commitment: !record.observations.parent_proposals.is_empty(),
            reveal_authorized: !record.observations.reveal_authorizations.is_empty(),
            reveal_share_count: record.observations.reveal_shares.len() as u64,
            execution_ready: !record.observations.execution_roots.is_empty(),
            proposal_seen: !record.observations.parent_proposals.is_empty(),
            vc_seen: !record.observations.reveal_authorizations.is_empty(),
            qc_seen: !record.observations.qc_roots.is_empty(),
            finalized: !record.observations.finality_roots.is_empty(),
        },
        cut_root: record
            .cut_proof
            .as_ref()
            .map(|proof| proof.cut_root.clone()),
        exact_cut_proof_root,
        protected_batch_root: record
            .protected_batch
            .as_ref()
            .map(|batch| batch.protected_batch_root.clone()),
        next_commitment_root,
        fault: record.fault.clone(),
    })
}

fn persist_record(path: &Path, record: &ProtectedPipelineRecord) -> ProtectedPipelineResult<()> {
    validate_durable_record(record)?;
    let parent = path.parent().ok_or_else(|| {
        ProtectedPipelineError::persistence(
            "PROTECTED_STORE_PATH_INVALID",
            "durable path has no parent directory",
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        ProtectedPipelineError::persistence(
            "PROTECTED_STORE_DIRECTORY_FAILED",
            format!("create {}: {error}", parent.display()),
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ProtectedPipelineError::persistence(
                "PROTECTED_STORE_PATH_INVALID",
                "durable path has no UTF-8 file name",
            )
        })?;
    let temporary = parent.join(format!(".{file_name}.tmp"));
    let bytes = serde_json::to_vec_pretty(&ProtectedPipelineStoreEnvelope {
        format: PROTECTED_PIPELINE_STORE_FORMAT.to_string(),
        record: record.clone(),
    })
    .map_err(|error| {
        ProtectedPipelineError::persistence(
            "PROTECTED_STORE_ENCODE_FAILED",
            format!("serialize durable record: {error}"),
        )
    })?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| {
                ProtectedPipelineError::persistence(
                    "PROTECTED_STORE_TEMP_FAILED",
                    format!("open {}: {error}", temporary.display()),
                )
            })?;
        file.write_all(&bytes).map_err(|error| {
            ProtectedPipelineError::persistence(
                "PROTECTED_STORE_WRITE_FAILED",
                format!("write {}: {error}", temporary.display()),
            )
        })?;
        file.sync_all().map_err(|error| {
            ProtectedPipelineError::persistence(
                "PROTECTED_STORE_SYNC_FAILED",
                format!("fsync {}: {error}", temporary.display()),
            )
        })?;
        fs::rename(&temporary, path).map_err(|error| {
            ProtectedPipelineError::persistence(
                "PROTECTED_STORE_REPLACE_FAILED",
                format!("replace {}: {error}", path.display()),
            )
        })?;
        let directory = OpenOptions::new()
            .read(true)
            .open(parent)
            .map_err(|error| {
                ProtectedPipelineError::persistence(
                    "PROTECTED_STORE_DIRECTORY_FAILED",
                    format!("open {}: {error}", parent.display()),
                )
            })?;
        directory.sync_all().map_err(|error| {
            ProtectedPipelineError::persistence(
                "PROTECTED_STORE_DIRECTORY_SYNC_FAILED",
                format!("fsync {}: {error}", parent.display()),
            )
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests;
