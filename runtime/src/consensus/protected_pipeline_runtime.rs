//! Durable, level-triggered owner for one normal ETDAG protected target.
//!
//! This layer deliberately owns no consensus rule of its own.  It serializes
//! access to the already-atomic [`ProtectedPipeline`] record and exposes the
//! exact concrete execution input only after that record has replayed it.  A
//! PoSy caller therefore cannot substitute a root, a queue entry, or a
//! different subset of encrypted envelopes for the durable target material.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use crate::crypto::aegis_pqvm::AegisPqvmVerifier;
use crate::etdag::{
    CertifiedVertex, DeterministicProtectedExecutionInput, EtdagAuthenticatedIngressPeer,
    EtdagDigest, EtdagParameters, NextProtectedBatchCommitment, ProtectedBatchSource,
    ProtectedPipelinePhase, TargetAdmissionContext,
};
use crate::p2p::messages::{ProtectedPipelineEvidenceMessage, ProtectedPipelineSemanticObject};
use crate::p2p::networking::{
    ProtectedPipelineCoordinatorIngress, ProtectedPipelineEvidenceEnvelope,
};
use crate::synergy_types::{ClusterMap, Hash, Height, ValidatorSet, ValidatorStatus};

use super::protected_pipeline::{
    ProtectedOrderSeedEvidence, ProtectedPipeline, ProtectedPipelineError,
    ProtectedPipelineErrorKind, ProtectedPipelineEvidenceVerifier, ProtectedPipelineObservation,
    ProtectedPipelineReconcileContext, ProtectedPipelineReconcileOutcome, ProtectedPipelineResult,
    ProtectedPipelineSnapshot,
};
use super::testnet_v3_bootstrap::GenesisBootstrapProtectedMaterial;

/// Directory segment used beneath a node's durable data directory.
pub const PROTECTED_PIPELINE_RUNTIME_DIRECTORY: &str = "protected-pipeline-v1";

type SharedPipeline = Arc<Mutex<ProtectedPipeline>>;

/// Process-owned ingress coordinator for normal H3+ protected targets.
///
/// It owns the only mapping from an authenticated P2P semantic object to the
/// target's durable [`ProtectedPipelineRuntime`].  P2P performs transport
/// authentication/deduplication first; this layer rebinds the envelope to the
/// immutable target context and durable record before accepting it.  It does
/// not manufacture a PoSy observation or an execution input: those require
/// the later VC/reveal/finality bridge and remain fail-closed here.
#[derive(Clone)]
pub struct NormalProtectedPipelineCoordinator {
    data_directory: PathBuf,
    verifier: AegisPqvmVerifier,
    validator_set: ValidatorSet,
    cluster_map: ClusterMap,
    parameters: EtdagParameters,
    runtimes: Arc<Mutex<BTreeMap<(Height, Hash), ProtectedPipelineRuntime>>>,
}

impl NormalProtectedPipelineCoordinator {
    pub fn new(
        data_directory: impl Into<PathBuf>,
        verifier: AegisPqvmVerifier,
        validator_set: ValidatorSet,
        cluster_map: ClusterMap,
        parameters: EtdagParameters,
    ) -> Result<Self, String> {
        let active = validator_set.active_for_epoch(validator_set.epoch);
        active.validate_unique_validator_and_key_ids()?;
        if active.validators.is_empty()
            || cluster_map.epoch != validator_set.epoch
            || cluster_map != cluster_map.canonicalized()
        {
            return Err("invalid normal protected-pipeline coordinator authority".to_string());
        }
        cluster_map.validate_complete_balanced_assignment(&active)?;
        parameters.validate()?;
        Ok(Self {
            data_directory: data_directory.into(),
            verifier,
            validator_set,
            cluster_map,
            parameters,
            runtimes: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    /// Bind one finality-derived normal target to its sole durable runtime.
    /// Re-registering the exact same context is idempotent; a different
    /// context for the same `(height, root)` is impossible by construction and
    /// treated as a conflict.
    pub fn register_target(
        &self,
        target: TargetAdmissionContext,
    ) -> Result<ProtectedPipelineRuntime, String> {
        target.validate()?;
        if target.epoch != self.validator_set.epoch {
            return Err("protected pipeline target is outside the frozen epoch".to_string());
        }
        let root = target.root()?;
        let key = (target.target_height, root);
        let mut runtimes = self
            .runtimes
            .lock()
            .map_err(|_| "protected-pipeline target registry lock is poisoned".to_string())?;
        if let Some(existing) = runtimes.get(&key) {
            if existing.target() != &target {
                return Err(
                    "protected-pipeline target root resolves to conflicting context".to_string(),
                );
            }
            return Ok(existing.clone());
        }
        let source = if target.target_height.0 == 3 {
            ProtectedBatchSource::NormalEtdag
        } else {
            ProtectedBatchSource::NormalEtdagSteadyState
        };
        let runtime = ProtectedPipelineRuntime::open(&self.data_directory, target, source)
            .map_err(|error| format!("open durable protected target runtime: {error}"))?;
        runtimes.insert(key, runtime.clone());
        Ok(runtime)
    }

    pub fn runtime_for_target(
        &self,
        target_height: Height,
        target_context_root: Hash,
    ) -> Result<Option<ProtectedPipelineRuntime>, String> {
        Ok(self
            .runtimes
            .lock()
            .map_err(|_| "protected-pipeline target registry lock is poisoned".to_string())?
            .get(&(target_height, target_context_root))
            .cloned())
    }

    fn authorize_peer(
        &self,
        target: &TargetAdmissionContext,
        peer: &EtdagAuthenticatedIngressPeer,
    ) -> Result<(), String> {
        let validator = self
            .validator_set
            .active_for_epoch(target.epoch)
            .validators
            .into_iter()
            .find(|validator| validator.validator_id == peer.validator_id)
            .ok_or_else(|| {
                "protected-pipeline evidence peer is outside the frozen target set".to_string()
            })?;
        if validator.status != ValidatorStatus::Active
            || validator.validator_uma_id != peer.validator_uma_id
            || validator.consensus_public_key.key_id != peer.consensus_key_id
        {
            return Err(
                "protected-pipeline evidence peer does not match frozen identity".to_string(),
            );
        }
        Ok(())
    }

    fn ingest_message(&self, envelope: ProtectedPipelineEvidenceEnvelope) -> Result<(), String> {
        let objects =
            match &envelope.message {
                ProtectedPipelineEvidenceMessage::Evidence { object } => vec![object],
                ProtectedPipelineEvidenceMessage::MissingObjectsResponse { objects, .. } => {
                    objects.iter().collect::<Vec<_>>()
                }
                ProtectedPipelineEvidenceMessage::MissingObjectsRequest { .. } => return Err(
                    "protected-pipeline coordinator does not serve unbound missing-object requests"
                        .to_string(),
                ),
            };
        if objects.is_empty() {
            return Err(
                "protected-pipeline evidence message contains no semantic objects".to_string(),
            );
        }
        let (height, root) = objects[0].target_binding();
        if objects
            .iter()
            .any(|object| object.target_binding() != (height, root))
        {
            return Err("protected-pipeline evidence message mixes target contexts".to_string());
        }
        let runtime = self.runtime_for_target(height, root)?.ok_or_else(|| {
            "protected-pipeline evidence names an unregistered target".to_string()
        })?;
        self.authorize_peer(runtime.target(), &envelope.authenticated_peer)?;

        let mut certified_vertices = Vec::new();
        let mut cutoff_marker_digests = Vec::new();
        for object in objects {
            match object {
                ProtectedPipelineSemanticObject::CertifiedVertex {
                    certified_vertex, ..
                } => {
                    certified_vertices.push(certified_vertex.clone());
                }
                ProtectedPipelineSemanticObject::CutoffMarker {
                    semantic_id,
                    certified_vertex,
                } => {
                    certified_vertices.push(certified_vertex.clone());
                    cutoff_marker_digests.push(semantic_id.clone());
                }
                // These are intentionally not translated to root-only
                // observations.  The coordinator will accept them only after
                // the concrete envelope/VC/reveal builder has verified the
                // exact execution input they authenticate.
                ProtectedPipelineSemanticObject::RevealAuthorization { .. }
                | ProtectedPipelineSemanticObject::RevealShare { .. } => {
                    return Err(
                        "protected reveal evidence requires the concrete material bridge"
                            .to_string(),
                    )
                }
            }
        }
        let inputs = ProtectedPipelineReconcileContext {
            target: runtime.target(),
            verifier: &self.verifier,
            validator_set: &self.validator_set,
            cluster_map: &self.cluster_map,
            parameters: &self.parameters,
        };
        runtime
            .ingest_authenticated_event(
                AuthenticatedProtectedPipelineEvent::EtdagEvidence {
                    certified_vertices,
                    cutoff_marker_digests,
                },
                &NoObservationVerifier,
                &inputs,
            )
            .map_err(|error| format!("merge protected ETDAG evidence: {error}"))?;
        Ok(())
    }
}

impl ProtectedPipelineCoordinatorIngress for NormalProtectedPipelineCoordinator {
    fn ingest_protected_pipeline_evidence(
        &self,
        envelope: ProtectedPipelineEvidenceEnvelope,
    ) -> Result<(), String> {
        self.ingest_message(envelope)
    }
}

/// ETDAG evidence does not consult the observation verifier.  Keeping this
/// implementation permanently rejecting prevents the ingress path from ever
/// converting unverified P2P roots into parent/VC/share/QC/finality state.
struct NoObservationVerifier;

impl ProtectedPipelineEvidenceVerifier for NoObservationVerifier {
    fn verify_order_seed(
        &self,
        _target: &TargetAdmissionContext,
        _evidence: &ProtectedOrderSeedEvidence,
    ) -> Result<(), String> {
        Err("normal protected coordinator requires a finalized PoSy order-seed bridge".to_string())
    }

    fn verify_observation(
        &self,
        _target: &TargetAdmissionContext,
        _expected_commitment: &NextProtectedBatchCommitment,
        _observation: &ProtectedPipelineObservation,
    ) -> Result<(), String> {
        Err(
            "normal protected coordinator requires a concrete PoSy/reveal observation bridge"
                .to_string(),
        )
    }
}

/// Process-local single-writer registry.  The durable `ProtectedPipeline`
/// remains the source of truth across restarts; this registry prevents two
/// in-process coordinators from racing the same target record.
static PIPELINES: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Mutex<ProtectedPipeline>>>>> =
    OnceLock::new();

/// A complete authenticated event accepted by the protected runtime.
///
/// The ETDAG and core pipeline verifiers are invoked for every variant before
/// it can alter durable state.  This enum intentionally has no root-only
/// execution-ready variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticatedProtectedPipelineEvent {
    /// Certified vertices plus the cutoff markers that reference those exact vertices.
    EtdagEvidence {
        certified_vertices: Vec<CertifiedVertex>,
        cutoff_marker_digests: Vec<EtdagDigest>,
    },
    /// PoSy-finality-bound, content-blind ordering seed.
    OrderSeed(ProtectedOrderSeedEvidence),
    /// Authenticated parent, reveal, QC, finality, or consumption evidence.
    Observation(ProtectedPipelineObservation),
    /// Fully replayable ciphertext/share/plaintext execution material.
    ExecutionInput(DeterministicProtectedExecutionInput),
}

/// Destination for a ready *concrete* protected input.
///
/// Implementations must make publication idempotent for the target and exact
/// input digest.  Publication is intentionally outside consensus state: the
/// durable pipeline is already the authoritative source and remains unchanged
/// if a consumer is temporarily unavailable.
pub trait ProtectedExecutionInputPublisher {
    fn publish(
        &self,
        target: &TargetAdmissionContext,
        input: &DeterministicProtectedExecutionInput,
    ) -> Result<(), String>;
}

/// PoSy-facing lookup boundary shared by normal ETDAG and H1/H2 bootstrap.
///
/// The expected commitment is mandatory so a proposal can consume only the
/// exact protected subset it carries in its header.
pub trait ProtectedExecutionInputSource {
    fn lookup_ready_execution_input(
        &self,
        expected_commitment: &NextProtectedBatchCommitment,
        expected_source: ProtectedBatchSource,
    ) -> ProtectedPipelineResult<Option<DeterministicProtectedExecutionInput>>;
}

/// Durable coordinator for exactly one H3+ ETDAG target.
#[derive(Debug, Clone)]
pub struct ProtectedPipelineRuntime {
    path: PathBuf,
    target: TargetAdmissionContext,
    source: ProtectedBatchSource,
    pipeline: SharedPipeline,
}

impl ProtectedPipelineRuntime {
    /// Open or retrieve the sole in-process coordinator for `target`.
    ///
    /// `ProtectedPipeline::open` verifies the durable target/source binding and
    /// atomically creates or loads its record.  A different source at the same
    /// target cannot silently reuse a file.
    pub fn open(
        data_directory: impl AsRef<Path>,
        target: TargetAdmissionContext,
        source: ProtectedBatchSource,
    ) -> ProtectedPipelineResult<Self> {
        if !matches!(
            (source, target.target_height.0),
            (ProtectedBatchSource::NormalEtdag, 3)
                | (ProtectedBatchSource::NormalEtdagSteadyState, 4..)
        ) {
            return Err(invalid(
                "PROTECTED_RUNTIME_SOURCE_INVALID",
                "normal durable coordinator requires NormalEtdag at H3 or steady state at H4+",
            ));
        }
        target
            .validate()
            .map_err(|error| invalid("PROTECTED_RUNTIME_TARGET_INVALID", error))?;
        let path = Self::record_path(data_directory, &target)?;
        let registry = PIPELINES.get_or_init(|| Mutex::new(BTreeMap::new()));
        let mut registry = registry.lock().map_err(|_| {
            persistence(
                "PROTECTED_RUNTIME_REGISTRY_POISONED",
                "protected pipeline runtime registry lock is poisoned",
            )
        })?;
        registry.retain(|_, pipeline| pipeline.strong_count() > 0);
        let pipeline = match registry.get(&path).and_then(Weak::upgrade) {
            Some(existing) => existing,
            None => {
                let opened = Arc::new(Mutex::new(ProtectedPipeline::open(
                    path.clone(),
                    target.clone(),
                    source,
                )?));
                registry.insert(path.clone(), Arc::downgrade(&opened));
                opened
            }
        };
        Ok(Self {
            path,
            target,
            source,
            pipeline,
        })
    }

    /// Deterministic per-target record location.  The context root is a
    /// fixed-width hash, not caller-controlled path material.
    pub fn record_path(
        data_directory: impl AsRef<Path>,
        target: &TargetAdmissionContext,
    ) -> ProtectedPipelineResult<PathBuf> {
        let root = target
            .root()
            .map_err(|error| invalid("PROTECTED_RUNTIME_TARGET_INVALID", error))?;
        Ok(data_directory
            .as_ref()
            .join(PROTECTED_PIPELINE_RUNTIME_DIRECTORY)
            .join(format!(
                "h{}-{}.json",
                target.target_height.0,
                root.to_hex()
            )))
    }

    /// Target context permanently bound to this coordinator.
    pub fn target(&self) -> &TargetAdmissionContext {
        &self.target
    }

    /// Source classification permanently bound to this coordinator.
    pub fn source(&self) -> ProtectedBatchSource {
        self.source
    }

    /// Exact durable-record path, useful for recovery diagnostics only.
    pub fn record_path_ref(&self) -> &Path {
        &self.path
    }

    /// Return the durable phase/snapshot without mutating state.
    pub fn snapshot(&self) -> ProtectedPipelineResult<ProtectedPipelineSnapshot> {
        self.with_pipeline(|pipeline| pipeline.snapshot())
    }

    /// Current durable phase for compact liveness/operations reporting.
    pub fn phase(&self) -> ProtectedPipelineResult<ProtectedPipelinePhase> {
        Ok(self.snapshot()?.diagnostic.phase)
    }

    /// Level-triggered startup reconciliation.  Safe to call repeatedly.
    pub fn reconcile_on_startup(
        &self,
        inputs: &ProtectedPipelineReconcileContext<'_>,
    ) -> ProtectedPipelineResult<ProtectedPipelineReconcileOutcome> {
        self.reconcile(inputs)
    }

    /// Level-triggered periodic reconciliation.  This has no timer-derived
    /// transition: it only reevaluates already durable authenticated evidence.
    pub fn reconcile_tick(
        &self,
        inputs: &ProtectedPipelineReconcileContext<'_>,
    ) -> ProtectedPipelineResult<ProtectedPipelineReconcileOutcome> {
        self.reconcile(inputs)
    }

    /// Ingest one complete authenticated event and durably reconcile it.
    pub fn ingest_authenticated_event(
        &self,
        event: AuthenticatedProtectedPipelineEvent,
        evidence_verifier: &impl ProtectedPipelineEvidenceVerifier,
        inputs: &ProtectedPipelineReconcileContext<'_>,
    ) -> ProtectedPipelineResult<ProtectedPipelineReconcileOutcome> {
        self.require_context(inputs)?;
        self.with_pipeline_mut(|pipeline| match event {
            AuthenticatedProtectedPipelineEvent::EtdagEvidence {
                certified_vertices,
                cutoff_marker_digests,
            } => pipeline.merge_etdag_evidence(&certified_vertices, &cutoff_marker_digests, inputs),
            AuthenticatedProtectedPipelineEvent::OrderSeed(evidence) => {
                pipeline.merge_order_seed(evidence, evidence_verifier, inputs)
            }
            AuthenticatedProtectedPipelineEvent::Observation(observation) => {
                pipeline.merge_observation(observation, evidence_verifier, inputs)
            }
            AuthenticatedProtectedPipelineEvent::ExecutionInput(input) => {
                pipeline.merge_execution_input(input, inputs)
            }
        })
    }

    /// Convenience entry point for replayable execution material.  Root-only
    /// readiness is rejected by the core and cannot be represented here.
    pub fn ingest_execution_input(
        &self,
        input: DeterministicProtectedExecutionInput,
        inputs: &ProtectedPipelineReconcileContext<'_>,
    ) -> ProtectedPipelineResult<ProtectedPipelineReconcileOutcome> {
        self.require_context(inputs)?;
        self.with_pipeline_mut(|pipeline| pipeline.merge_execution_input(input, inputs))
    }

    /// Look up a ready input only when it is the exact expected commitment and
    /// source.  This is the PoSy-facing API; it never returns a naked root.
    pub fn lookup_ready_execution_input(
        &self,
        expected_commitment: &NextProtectedBatchCommitment,
        expected_source: ProtectedBatchSource,
    ) -> ProtectedPipelineResult<Option<DeterministicProtectedExecutionInput>> {
        if expected_source != self.source {
            return Err(conflict(
                "PROTECTED_RUNTIME_SOURCE_CONFLICT",
                "PoSy requested a protected input for another source class",
            ));
        }
        self.with_pipeline(|pipeline| {
            let record = pipeline.record();
            if record.phase < ProtectedPipelinePhase::ReadyForExecution {
                return Ok(None);
            }
            let input = record.execution_input.as_ref().ok_or_else(|| {
                corrupt(
                    "PROTECTED_RUNTIME_READY_INPUT_MISSING",
                    "READY_FOR_EXECUTION record has no concrete execution input",
                )
            })?;
            if input.source != expected_source
                || &input.next_commitment != expected_commitment
                || record.next_commitment.as_ref() != Some(expected_commitment)
                || record.protected_batch.as_ref() != Some(&input.protected_batch)
                || record.cut_proof.as_ref() != input.cut_proof.as_ref()
            {
                return Err(conflict(
                    "PROTECTED_RUNTIME_EXACT_SUBSET_CONFLICT",
                    "ready input is not the exact durable cut/batch/commitment subset requested by PoSy",
                ));
            }
            Ok(Some(input.clone()))
        })
    }

    /// Return this coordinator's one target-bound, concrete ready input.
    ///
    /// The simplified proposal builder knows the target before it derives the
    /// header commitment, so it cannot safely provide that commitment as a
    /// lookup key.  This method is intentionally scoped to a coordinator that
    /// is already permanently bound to one target; callers must still bind the
    /// returned commitment into the candidate header during construction.
    /// It never exposes a naked root or an input from a different target.
    pub fn load_ready_execution_input_for_target(
        &self,
    ) -> ProtectedPipelineResult<Option<DeterministicProtectedExecutionInput>> {
        self.with_pipeline(|pipeline| {
            let record = pipeline.record();
            if record.phase < ProtectedPipelinePhase::ReadyForExecution {
                return Ok(None);
            }
            let input = record.execution_input.as_ref().ok_or_else(|| {
                corrupt(
                    "PROTECTED_RUNTIME_READY_INPUT_MISSING",
                    "READY_FOR_EXECUTION record has no concrete execution input",
                )
            })?;
            if input.source != self.source
                || !matches!(
                    &input.target_context,
                    crate::etdag::ProtectedExecutionTargetContext::NormalEtdag {
                        admission_context
                    } if admission_context == &self.target
                )
                || record.next_commitment.as_ref() != Some(&input.next_commitment)
                || record.protected_batch.as_ref() != Some(&input.protected_batch)
                || record.cut_proof.as_ref() != input.cut_proof.as_ref()
            {
                return Err(conflict(
                    "PROTECTED_RUNTIME_TARGET_INPUT_CONFLICT",
                    "ready input is not the exact durable concrete input for this target",
                ));
            }
            Ok(Some(input.clone()))
        })
    }

    /// Publish the exact ready input, if any.  Repeated publication is safe as
    /// long as the destination honors the documented idempotency contract.
    pub fn publish_ready_execution_input(
        &self,
        expected_commitment: &NextProtectedBatchCommitment,
        expected_source: ProtectedBatchSource,
        publisher: &impl ProtectedExecutionInputPublisher,
    ) -> ProtectedPipelineResult<bool> {
        let Some(input) =
            self.lookup_ready_execution_input(expected_commitment, expected_source)?
        else {
            return Ok(false);
        };
        publisher
            .publish(&self.target, &input)
            .map_err(|error| persistence("PROTECTED_RUNTIME_PUBLISH_FAILED", error))?;
        Ok(true)
    }

    fn reconcile(
        &self,
        inputs: &ProtectedPipelineReconcileContext<'_>,
    ) -> ProtectedPipelineResult<ProtectedPipelineReconcileOutcome> {
        self.require_context(inputs)?;
        self.with_pipeline_mut(|pipeline| pipeline.reconcile(inputs))
    }

    fn require_context(
        &self,
        inputs: &ProtectedPipelineReconcileContext<'_>,
    ) -> ProtectedPipelineResult<()> {
        if inputs.target != &self.target {
            return Err(conflict(
                "PROTECTED_RUNTIME_TARGET_CONFLICT",
                "caller supplied reconciliation inputs for another target",
            ));
        }
        Ok(())
    }

    fn with_pipeline<T>(
        &self,
        operation: impl FnOnce(&ProtectedPipeline) -> ProtectedPipelineResult<T>,
    ) -> ProtectedPipelineResult<T> {
        let pipeline = self.pipeline.lock().map_err(|_| {
            persistence(
                "PROTECTED_RUNTIME_PIPELINE_POISONED",
                "protected pipeline lock is poisoned",
            )
        })?;
        operation(&pipeline)
    }

    fn with_pipeline_mut<T>(
        &self,
        operation: impl FnOnce(&mut ProtectedPipeline) -> ProtectedPipelineResult<T>,
    ) -> ProtectedPipelineResult<T> {
        let mut pipeline = self.pipeline.lock().map_err(|_| {
            persistence(
                "PROTECTED_RUNTIME_PIPELINE_POISONED",
                "protected pipeline lock is poisoned",
            )
        })?;
        operation(&mut pipeline)
    }
}

impl ProtectedExecutionInputSource for ProtectedPipelineRuntime {
    fn lookup_ready_execution_input(
        &self,
        expected_commitment: &NextProtectedBatchCommitment,
        expected_source: ProtectedBatchSource,
    ) -> ProtectedPipelineResult<Option<DeterministicProtectedExecutionInput>> {
        ProtectedPipelineRuntime::lookup_ready_execution_input(
            self,
            expected_commitment,
            expected_source,
        )
    }
}

/// Immutable H1/H2 source.  Bootstrap is deliberately ready without P2P or
/// reveal traffic: its protocol-defined execution input is the canonical empty
/// batch derived from the finalized Genesis anchor.
#[derive(Debug, Clone)]
pub struct GenesisBootstrapProtectedExecutionSource {
    material: GenesisBootstrapProtectedMaterial,
}

impl GenesisBootstrapProtectedExecutionSource {
    /// Validate and retain the canonical H1/H2 material produced by the
    /// bootstrap module.  H3+ and any non-empty/root-only substitute fail.
    pub fn new(material: GenesisBootstrapProtectedMaterial) -> ProtectedPipelineResult<Self> {
        if material.source != ProtectedBatchSource::GenesisBootstrap
            || material.execution_input.source != ProtectedBatchSource::GenesisBootstrap
            || material.execution_input.protected_batch != material.protected_batch
            || material.execution_input.next_commitment != material.next_commitment
            || material.protected_batch.protected_count != 0
            || material.protected_batch.protected_gas != 0
            || material.protected_batch.protected_bytes != 0
            || !material.protected_batch.ordered_transaction_ids.is_empty()
            || material.execution_input.cut_proof.is_some()
            || material.execution_input.reveal_authorization.is_some()
            || !material.execution_input.envelopes.is_empty()
            || !material.execution_input.reveal_shares.is_empty()
            || !material.execution_input.ordered_transactions.is_empty()
        {
            return Err(invalid(
                "PROTECTED_BOOTSTRAP_INPUT_INVALID",
                "bootstrap source does not contain one exact canonical execution input",
            ));
        }
        match &material.execution_input.target_context {
            crate::etdag::ProtectedExecutionTargetContext::GenesisBootstrap { height_context }
                if matches!(height_context.height.0, 1 | 2) => {}
            _ => {
                return Err(invalid(
                    "PROTECTED_BOOTSTRAP_HEIGHT_INVALID",
                    "bootstrap execution source is permitted only for H1/H2",
                ));
            }
        }
        material
            .next_commitment
            .validate_against_batch(&material.protected_batch)
            .map_err(|error| invalid("PROTECTED_BOOTSTRAP_COMMITMENT_INVALID", error))?;
        material
            .execution_input
            .digest()
            .map_err(|error| invalid("PROTECTED_BOOTSTRAP_INPUT_INVALID", error))?;
        Ok(Self { material })
    }

    /// Always returns the canonical empty H1/H2 input when PoSy asks for its
    /// exact commitment.  No network evidence is required or accepted.
    pub fn lookup_ready_execution_input(
        &self,
        expected_commitment: &NextProtectedBatchCommitment,
        expected_source: ProtectedBatchSource,
    ) -> ProtectedPipelineResult<Option<DeterministicProtectedExecutionInput>> {
        if expected_source != ProtectedBatchSource::GenesisBootstrap
            || &self.material.next_commitment != expected_commitment
        {
            return Err(conflict(
                "PROTECTED_BOOTSTRAP_EXACT_SUBSET_CONFLICT",
                "PoSy bootstrap request does not match the canonical H1/H2 commitment",
            ));
        }
        Ok(Some(self.material.execution_input.clone()))
    }

    /// Return the one canonical bootstrap input retained for this source.
    /// This is target-bound by construction and is used before proposal
    /// construction derives the header commitment.  H3+ cannot instantiate
    /// this source, and the input remains fully concrete (never root-only).
    pub fn load_ready_execution_input_for_target(
        &self,
    ) -> ProtectedPipelineResult<Option<DeterministicProtectedExecutionInput>> {
        Ok(Some(self.material.execution_input.clone()))
    }
}

impl ProtectedExecutionInputSource for GenesisBootstrapProtectedExecutionSource {
    fn lookup_ready_execution_input(
        &self,
        expected_commitment: &NextProtectedBatchCommitment,
        expected_source: ProtectedBatchSource,
    ) -> ProtectedPipelineResult<Option<DeterministicProtectedExecutionInput>> {
        GenesisBootstrapProtectedExecutionSource::lookup_ready_execution_input(
            self,
            expected_commitment,
            expected_source,
        )
    }
}

fn invalid(code: &str, detail: impl Into<String>) -> ProtectedPipelineError {
    ProtectedPipelineError {
        kind: ProtectedPipelineErrorKind::InvalidEvidence,
        code: code.to_string(),
        detail: detail.into(),
    }
}

fn conflict(code: &str, detail: impl Into<String>) -> ProtectedPipelineError {
    ProtectedPipelineError {
        kind: ProtectedPipelineErrorKind::Conflict,
        code: code.to_string(),
        detail: detail.into(),
    }
}

fn corrupt(code: &str, detail: impl Into<String>) -> ProtectedPipelineError {
    ProtectedPipelineError {
        kind: ProtectedPipelineErrorKind::CorruptState,
        code: code.to_string(),
        detail: detail.into(),
    }
}

fn persistence(code: &str, detail: impl Into<String>) -> ProtectedPipelineError {
    ProtectedPipelineError {
        kind: ProtectedPipelineErrorKind::Persistence,
        code: code.to_string(),
        detail: detail.into(),
    }
}
