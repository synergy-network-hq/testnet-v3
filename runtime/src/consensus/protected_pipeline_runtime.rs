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

use crate::etdag::{
    CertifiedVertex, DeterministicProtectedExecutionInput, EtdagDigest,
    NextProtectedBatchCommitment, ProtectedBatchSource, ProtectedPipelinePhase,
    TargetAdmissionContext,
};

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
