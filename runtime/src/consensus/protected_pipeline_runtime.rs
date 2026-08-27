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

use crate::consensus::protected_pipeline_evidence_verifier::{
    DurableProductionProtectedPipelineEvidenceStore, ProductionProtectedPipelineEvidence,
    ProductionProtectedPipelineEvidenceVerifier, ProtectedConsumedEvidence,
    ProtectedFinalityEvidence, ProtectedParentProposalEvidence, ProtectedQcEvidence,
    ProtectedRevealAuthorizationEvidence,
};
use crate::consensus::simplified_posy::{
    simplified_protected_finality_context_digest_from_state_root,
    simplified_target_admission_assignment, CoordinatedProtectedExecutionInputSource,
    DurableProtectedPipelineLifecycleStore, DurableSimplifiedIngressKemRegistrySource,
    PosyProposalValidationCertificate, ProtectedPipelineLifecycleBridge,
    ProtectedPipelineLifecycleEvent, ProtectedPipelineLifecycleRecoverySink,
    ProtectedPipelineLifecycleSink, ProtectedPipelineLifecycleUpdate, SimplifiedEpochContext,
    SimplifiedFinalizationTransaction, SimplifiedIngressKemRegistrySource, SimplifiedProposal,
    SimplifiedProtectedLifecycleObserver, SimplifiedQuorumCertificate,
    VerifiedSimplifiedProposalMaterial, POSY_SIMPLIFIED_PROTOCOL_VERSION,
};
use crate::consensus_parameters::ConsensusParameterRoot;
use crate::crypto::aegis_pqvm::AegisPqvmVerifier;
use crate::etdag::{
    decrypt_inner_transaction, decryption_threshold, protected_reveal_transcript_root,
    CertifiedVertex, DeterministicProtectedExecutionInput, EncryptedTransactionEnvelope,
    EtdagAuthenticatedIngressPeer, EtdagDigest, EtdagParameters, EtdagSubmissionEnvelope,
    NextProtectedBatchCommitment, ProtectedBatchSource, ProtectedExecutionTargetContext,
    ProtectedPipelinePhase, ProtectedRevealAuthorization, ProtectedRevealShareMessage,
    TargetAdmissionContext, TargetAdmissionContextSpec, PROTECTED_PIPELINE_VERSION,
};
use crate::p2p::messages::{ProtectedPipelineEvidenceMessage, ProtectedPipelineSemanticObject};
use crate::p2p::networking::{
    ProtectedPipelineCoordinatorIngress, ProtectedPipelineEvidenceEnvelope,
};
use crate::synergy_types::{
    ClusterMap, ConsensusDomain, Hash, Height, ValidatorSet, ValidatorStatus,
    TESTNET_V3_CLUSTER_SCHEDULE_VERSION,
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
    lifecycle: Arc<Mutex<Option<Weak<Mutex<ProductionProtectedPipelineLifecycle>>>>>,
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
            lifecycle: Arc::new(Mutex::new(None)),
        })
    }

    pub fn install_lifecycle(
        &self,
        lifecycle: &Arc<Mutex<ProductionProtectedPipelineLifecycle>>,
    ) -> Result<(), String> {
        *self
            .lifecycle
            .lock()
            .map_err(|_| "protected-pipeline lifecycle registry lock is poisoned".to_string())? =
            Some(Arc::downgrade(lifecycle));
        Ok(())
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

    pub fn lifecycle_store_path(&self, target: &TargetAdmissionContext) -> Result<PathBuf, String> {
        let root = target.root()?;
        Ok(self
            .data_directory
            .join(PROTECTED_PIPELINE_RUNTIME_DIRECTORY)
            .join("lifecycle")
            .join(format!(
                "h{}-{}.json",
                target.target_height.0,
                root.to_hex()
            )))
    }

    /// Load the exact durable ciphertext objects selected by the pipeline's
    /// deterministic order and assemble the concrete execution input. A
    /// missing object remains not-ready and can be requested through the P2P
    /// recovery API; no caller-supplied ciphertext map is accepted here.
    pub fn assemble_target_execution_input(
        &self,
        target_height: Height,
        target_context_root: Hash,
        reveal_authorization: ProtectedRevealAuthorization,
        reveal_shares: BTreeMap<EtdagDigest, Vec<ProtectedRevealShareMessage>>,
    ) -> ProtectedPipelineResult<ProtectedPipelineReconcileOutcome> {
        let runtime = self
            .runtime_for_target(target_height, target_context_root)
            .map_err(|error| persistence("PROTECTED_ASSEMBLY_TARGET_LOOKUP_FAILED", error))?
            .ok_or_else(|| {
                not_ready(
                    "PROTECTED_ASSEMBLY_TARGET_NOT_REGISTERED",
                    "normal protected target is not registered",
                )
            })?;
        let commitments = runtime.ordered_transaction_commitments()?;
        let mut submissions = BTreeMap::new();
        for commitment in commitments {
            match crate::p2p::networking::load_protected_ciphertext_material(&commitment).map_err(
                |error| persistence("PROTECTED_ASSEMBLY_CIPHERTEXT_LOOKUP_FAILED", error),
            )? {
                Some(ProtectedPipelineSemanticObject::EncryptedMaterial {
                    semantic_id,
                    submission,
                }) if semantic_id == commitment => {
                    submissions.insert(commitment, submission);
                }
                Some(_) => {
                    return Err(conflict(
                        "PROTECTED_ASSEMBLY_CIPHERTEXT_CONFLICT",
                        "durable ciphertext store returned another semantic object",
                    ))
                }
                None => {
                    return Err(not_ready(
                        "PROTECTED_ASSEMBLY_CIPHERTEXT_NOT_READY",
                        format!("missing durable encrypted material {}", commitment.0),
                    ))
                }
            }
        }
        runtime.assemble_and_ingest_execution_input(
            reveal_authorization,
            submissions,
            reveal_shares,
            &ProtectedPipelineReconcileContext {
                target: runtime.target(),
                verifier: &self.verifier,
                validator_set: &self.validator_set,
                cluster_map: &self.cluster_map,
                parameters: &self.parameters,
            },
        )
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
                ProtectedPipelineSemanticObject::EncryptedMaterial {
                    semantic_id,
                    submission,
                } => {
                    submission
                        .verify(runtime.target(), &self.parameters)
                        .map_err(|error| format!("verify protected encrypted material: {error}"))?;
                    match crate::p2p::networking::load_protected_ciphertext_material(semantic_id)? {
                        Some(ProtectedPipelineSemanticObject::EncryptedMaterial {
                            semantic_id: stored_id,
                            submission: stored_submission,
                        }) if &stored_id == semantic_id && &stored_submission == submission => {}
                        Some(_) => {
                            return Err("protected ciphertext store returned conflicting material"
                                .to_string())
                        }
                        None => {
                            return Err(
                                "protected ciphertext was not durably retained before ingress"
                                    .to_string(),
                            )
                        }
                    }
                }
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
                ProtectedPipelineSemanticObject::RevealAuthorization { .. } => return Err(
                    "protected reveal authorization is derived only from the authenticated PoSy VC"
                        .to_string(),
                ),
                ProtectedPipelineSemanticObject::RevealShare {
                    authorization_id,
                    share,
                    ..
                } => {
                    let lifecycle = self
                        .lifecycle
                        .lock()
                        .map_err(|_| {
                            "protected-pipeline lifecycle registry lock is poisoned".to_string()
                        })?
                        .as_ref()
                        .and_then(Weak::upgrade)
                        .ok_or_else(|| {
                            "protected reveal share arrived before the production lifecycle bridge"
                                .to_string()
                        })?;
                    let mut lifecycle = lifecycle.lock().map_err(|_| {
                        "protected-pipeline lifecycle bridge lock is poisoned".to_string()
                    })?;
                    let target = lifecycle
                        .coordinator
                        .runtime_for_target(share.target_height, share.target_context_root)?
                        .ok_or_else(|| {
                            "protected reveal share names an unregistered target".to_string()
                        })?
                        .target()
                        .clone();
                    let store = DurableProtectedPipelineLifecycleStore::at_path(
                        lifecycle.coordinator.lifecycle_store_path(&target)?,
                    );
                    let record = store.load()?.ok_or_else(|| {
                        "protected reveal share arrived before durable lifecycle evidence"
                            .to_string()
                    })?;
                    let expected_authorization = record
                        .reveal_authorization
                        .as_ref()
                        .ok_or_else(|| {
                            "protected reveal share arrived before proposal VC authorization"
                                .to_string()
                        })?
                        .authorization
                        .root()?;
                    if *authorization_id != expected_authorization {
                        return Err("protected reveal share names another durable authorization"
                            .to_string());
                    }
                    lifecycle.on_reveal_share(share.clone())?;
                }
            }
        }
        if certified_vertices.is_empty() {
            return Ok(());
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

/// Runtime-owned bridge that makes the normal PoSy path durable and
/// receiver-verifiable. It is the only observer installed into the production
/// driver; bootstrap heights simply have no registered normal target and are
/// ignored here.
pub struct ProductionProtectedPipelineLifecycle {
    consensus_domain: ConsensusDomain,
    epoch_context: SimplifiedEpochContext,
    validator_set: ValidatorSet,
    verifier: AegisPqvmVerifier,
    coordinator: NormalProtectedPipelineCoordinator,
    execution_sources: CoordinatedProtectedExecutionInputSource,
    cryptographic_profile_root: Hash,
    evidence_store: Arc<DurableProductionProtectedPipelineEvidenceStore>,
    evidence_verifier: Arc<ProductionProtectedPipelineEvidenceVerifier>,
}

impl ProductionProtectedPipelineLifecycle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        consensus_domain: ConsensusDomain,
        epoch_context: SimplifiedEpochContext,
        validator_set: ValidatorSet,
        cluster_map: ClusterMap,
        parameters: EtdagParameters,
        verifier: AegisPqvmVerifier,
        coordinator: NormalProtectedPipelineCoordinator,
        execution_sources: CoordinatedProtectedExecutionInputSource,
        cryptographic_profile_root: Hash,
        evidence_directory: impl Into<PathBuf>,
    ) -> Result<Self, String> {
        let evidence_store = Arc::new(
            DurableProductionProtectedPipelineEvidenceStore::at_directory(evidence_directory)?,
        );
        let evidence_verifier = Arc::new(ProductionProtectedPipelineEvidenceVerifier::new(
            consensus_domain.clone(),
            epoch_context.clone(),
            validator_set.clone(),
            cluster_map,
            parameters,
            verifier.clone(),
            evidence_store.clone(),
        )?);
        Ok(Self {
            consensus_domain,
            epoch_context,
            validator_set,
            verifier,
            coordinator,
            execution_sources,
            cryptographic_profile_root,
            evidence_store,
            evidence_verifier,
        })
    }

    fn registered_target_for_commitment(
        &self,
        commitment: &NextProtectedBatchCommitment,
    ) -> Result<Option<TargetAdmissionContext>, String> {
        Ok(self
            .coordinator
            .runtime_for_target(commitment.target_height, commitment.target_context_root)?
            .map(|runtime| runtime.target().clone()))
    }

    fn dispatch_event(
        &self,
        event: ProtectedPipelineLifecycleEvent,
        evidence: ProductionProtectedPipelineEvidence,
    ) -> Result<(), String> {
        let target = lifecycle_event_target(&event)?;
        let Some(_runtime) = self
            .coordinator
            .runtime_for_target(target.target_height, target.root()?)?
        else {
            // H1/H2 are intentionally served by their Genesis-bound source.
            return Ok(());
        };
        let store = DurableProtectedPipelineLifecycleStore::at_path(
            self.coordinator.lifecycle_store_path(&target)?,
        );
        let bridge = ProtectedPipelineLifecycleBridge::new(
            &self.epoch_context,
            &self.validator_set,
            &self.verifier,
        )?;
        let mapped = bridge.map_event(event.clone())?;
        let evidence_root = lifecycle_observation_evidence_root(&mapped.observation)?;
        if self.evidence_store.install(&evidence)? != evidence_root {
            return Err("production evidence root differs from lifecycle observation".to_string());
        }
        let mut sink = RuntimeLifecycleSink {
            coordinator: self.coordinator.clone(),
            evidence_verifier: self.evidence_verifier.clone(),
        };
        store.persist_event_before_dispatch(&bridge, event, Some(evidence), &mut sink)
    }

    /// Reinstall complete durable proof objects and replay level-triggered
    /// observations before the role runtime accepts new network traffic.
    pub fn replay_target(&self, target: &TargetAdmissionContext) -> Result<bool, String> {
        let store = DurableProtectedPipelineLifecycleStore::at_path(
            self.coordinator.lifecycle_store_path(target)?,
        );
        let Some(recovery) =
            store.recover_verified(&self.epoch_context, &self.validator_set, &self.verifier)?
        else {
            return Ok(false);
        };
        for update in recovery
            .before_execution
            .iter()
            .chain(recovery.after_execution.iter())
        {
            if let Some(evidence) =
                store.production_evidence_for_observation(&update.observation)?
            {
                self.evidence_store.install(&evidence)?;
            }
        }
        let mut sink = RuntimeLifecycleSink {
            coordinator: self.coordinator.clone(),
            evidence_verifier: self.evidence_verifier.clone(),
        };
        store.replay_verified(
            &self.epoch_context,
            &self.validator_set,
            &self.verifier,
            &mut sink,
        )
    }

    pub fn replay_registered_targets(&self) -> Result<u64, String> {
        let targets = self
            .coordinator
            .runtimes
            .lock()
            .map_err(|_| "protected-pipeline target registry lock is poisoned".to_string())?
            .values()
            .map(|runtime| runtime.target().clone())
            .collect::<Vec<_>>();
        let mut replayed = 0u64;
        for target in targets {
            if self.replay_target(&target)? {
                replayed = replayed.saturating_add(1);
            }
        }
        Ok(replayed)
    }

    /// Persist and authenticate a network-delivered reveal share against the
    /// already durable parent/VC record. A compact per-validator observation
    /// is emitted only when its full multi-transaction bundle is complete.
    pub fn on_reveal_share(&mut self, share: ProtectedRevealShareMessage) -> Result<(), String> {
        let runtime = self
            .coordinator
            .runtime_for_target(share.target_height, share.target_context_root)?
            .ok_or_else(|| "reveal share names an unregistered target".to_string())?;
        let target = runtime.target().clone();
        let store = DurableProtectedPipelineLifecycleStore::at_path(
            self.coordinator.lifecycle_store_path(&target)?,
        );
        let record = store.load()?.ok_or_else(|| {
            "reveal share arrived before durable parent lifecycle evidence".to_string()
        })?;
        let authorization = record
            .reveal_authorization
            .ok_or_else(|| "reveal share arrived before proposal VC authorization".to_string())?;
        let evidence =
            crate::consensus::protected_pipeline_evidence_verifier::ProtectedRevealShareEvidence {
                authorization,
                share,
            };
        let Some(update) =
            store.persist_reveal_share(evidence, &self.verifier, &self.validator_set)?
        else {
            return Ok(());
        };
        let complete = store
            .production_evidence_for_observation(&update.observation)?
            .ok_or_else(|| "complete reveal bundle disappeared from lifecycle store".to_string())?;
        if self.evidence_store.install(&complete)?
            != lifecycle_observation_evidence_root(&update.observation)?
        {
            return Err(
                "reveal bundle evidence root differs from lifecycle observation".to_string(),
            );
        }
        let mut sink = RuntimeLifecycleSink {
            coordinator: self.coordinator.clone(),
            evidence_verifier: self.evidence_verifier.clone(),
        };
        sink.apply_protected_pipeline_lifecycle_update(update)
    }

    fn register_successor_from_finalization(
        &self,
        material: &VerifiedSimplifiedProposalMaterial,
        transaction: &SimplifiedFinalizationTransaction,
    ) -> Result<(), String> {
        if transaction.target_finalized.height != material.candidate_subject.context.height {
            return Ok(());
        }
        let target_height = transaction
            .target_finalized
            .height
            .0
            .checked_add(3)
            .map(Height)
            .ok_or_else(|| "normal protected successor target height overflowed".to_string())?;
        if target_height.0 > self.epoch_context.epoch_end_height.0 {
            return Ok(());
        }
        let (assigned_cluster_id, assigned_height_schedule_root) =
            simplified_target_admission_assignment(
                &self.epoch_context,
                target_height,
                &self.coordinator.cluster_map,
            )?;
        let epoch_context_root = self.epoch_context.root()?;
        let mut registry_source =
            DurableSimplifiedIngressKemRegistrySource::process_wide(epoch_context_root)?;
        let registry = registry_source
            .registry_for_target(self.epoch_context.epoch, target_height, assigned_cluster_id)?
            .ok_or_else(|| {
                format!(
                    "normal protected H{} requires its public ingress KEM registry artifact",
                    target_height.0
                )
            })?;
        let finality_context = simplified_protected_finality_context_digest_from_state_root(
            &self.epoch_context,
            &transaction.target_finalized,
            material.canonical_block.header.state_root_after,
            &self.validator_set,
            &self.coordinator.cluster_map,
        )?;
        let target = TargetAdmissionContext::derive_schedule_neutral(
            TargetAdmissionContextSpec {
                protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
                epoch: self.epoch_context.epoch,
                target_height,
                source_finalized_height: transaction.target_finalized.height,
                source_finality_context_root: crate::etdag::target_admission_source_finality_root(
                    &finality_context,
                )?,
                assigned_cluster_id,
                cluster_schedule_version: TESTNET_V3_CLUSTER_SCHEDULE_VERSION.to_string(),
                finalized_epoch_seed_root: self.epoch_context.finalized_epoch_seed_root,
                assigned_height_schedule_root,
                cryptographic_profile_root: self.cryptographic_profile_root,
                ingress_kem_registry_root: registry.root()?,
            },
            &self.validator_set,
            &self.coordinator.cluster_map,
            ConsensusParameterRoot::from_hex(&self.epoch_context.consensus_parameter_root)?,
        )?;
        registry.validate_against(&target, &self.validator_set)?;
        let runtime = self.coordinator.register_target(target)?;
        self.execution_sources.register_normal_target(runtime)
    }
}

impl SimplifiedProtectedLifecycleObserver for ProductionProtectedPipelineLifecycle {
    fn on_validated_proposal(
        &mut self,
        proposal: &SimplifiedProposal,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<(), String> {
        let Some(commitment) = material.future_protected_batch_commitment.as_ref() else {
            return Ok(());
        };
        let Some(target) = self.registered_target_for_commitment(commitment)? else {
            return Ok(());
        };
        self.dispatch_event(
            ProtectedPipelineLifecycleEvent::ParentProposalCommitted {
                target: target.clone(),
                proposal: proposal.clone(),
                material: material.clone(),
            },
            ProductionProtectedPipelineEvidence::ParentProposal(ProtectedParentProposalEvidence {
                consensus_domain: self.consensus_domain.clone(),
                target,
                proposal: proposal.clone(),
                material: material.clone(),
            }),
        )
    }

    fn on_proposal_validation_certificate(
        &mut self,
        proposal: &SimplifiedProposal,
        material: &VerifiedSimplifiedProposalMaterial,
        certificate: &PosyProposalValidationCertificate,
    ) -> Result<(), String> {
        let Some(commitment) = material.future_protected_batch_commitment.as_ref() else {
            return Ok(());
        };
        let Some(target) = self.registered_target_for_commitment(commitment)? else {
            return Ok(());
        };
        let runtime = self
            .coordinator
            .runtime_for_target(target.target_height, target.root()?)?
            .ok_or_else(|| "registered lifecycle target disappeared".to_string())?;
        let batch = runtime
            .pre_reveal_batch()
            .map_err(|error| format!("read durable pre-reveal batch: {error}"))?
            .ok_or_else(|| "protected VC arrived before durable cut/order batch".to_string())?;
        let bridge = ProtectedPipelineLifecycleBridge::new(
            &self.epoch_context,
            &self.validator_set,
            &self.verifier,
        )?;
        let authorization = bridge
            .map_event(
                ProtectedPipelineLifecycleEvent::ProposalValidationCertified {
                    target: target.clone(),
                    proposal: proposal.clone(),
                    material: material.clone(),
                    certificate: certificate.clone(),
                },
            )?
            .reveal_authorization
            .ok_or_else(|| "VC lifecycle mapping omitted reveal authorization".to_string())?;
        let parent = ProtectedParentProposalEvidence {
            consensus_domain: self.consensus_domain.clone(),
            target: target.clone(),
            proposal: proposal.clone(),
            material: material.clone(),
        };
        self.dispatch_event(
            ProtectedPipelineLifecycleEvent::ProposalValidationCertified {
                target,
                proposal: proposal.clone(),
                material: material.clone(),
                certificate: certificate.clone(),
            },
            ProductionProtectedPipelineEvidence::RevealAuthorization(
                ProtectedRevealAuthorizationEvidence {
                    parent,
                    validation_certificate: certificate.clone(),
                    authorization,
                    protected_batch: batch,
                },
            ),
        )
    }

    fn on_execution_consumed(
        &mut self,
        proposal: &SimplifiedProposal,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<(), String> {
        let Some(commitment) = material.next_protected_batch_commitment.as_ref() else {
            return Ok(());
        };
        let Some(target) = self.registered_target_for_commitment(commitment)? else {
            return Ok(());
        };
        self.dispatch_event(
            ProtectedPipelineLifecycleEvent::ExecutionConsumed {
                target: target.clone(),
                proposal: proposal.clone(),
                material: material.clone(),
            },
            ProductionProtectedPipelineEvidence::Consumed(ProtectedConsumedEvidence {
                consensus_domain: self.consensus_domain.clone(),
                target,
                proposal: proposal.clone(),
                material: material.clone(),
            }),
        )
    }

    fn on_quorum_certificate(
        &mut self,
        proposal: &SimplifiedProposal,
        material: &VerifiedSimplifiedProposalMaterial,
        certificate: &SimplifiedQuorumCertificate,
    ) -> Result<(), String> {
        let Some(commitment) = material.next_protected_batch_commitment.as_ref() else {
            return Ok(());
        };
        let Some(target) = self.registered_target_for_commitment(commitment)? else {
            return Ok(());
        };
        self.dispatch_event(
            ProtectedPipelineLifecycleEvent::QuorumCertified {
                target: target.clone(),
                proposal: proposal.clone(),
                material: material.clone(),
                certificate: certificate.clone(),
            },
            ProductionProtectedPipelineEvidence::QuorumCertificate(ProtectedQcEvidence {
                consensus_domain: self.consensus_domain.clone(),
                target,
                certificate: certificate.clone(),
                material: material.clone(),
            }),
        )
    }

    fn on_finalization(
        &mut self,
        proposal: &SimplifiedProposal,
        material: &VerifiedSimplifiedProposalMaterial,
        transaction: &SimplifiedFinalizationTransaction,
    ) -> Result<(), String> {
        let Some(commitment) = material.next_protected_batch_commitment.as_ref() else {
            return Ok(());
        };
        let Some(target) = self.registered_target_for_commitment(commitment)? else {
            return Ok(());
        };
        self.dispatch_event(
            ProtectedPipelineLifecycleEvent::FinalizationCommitted {
                target: target.clone(),
                proposal: proposal.clone(),
                material: material.clone(),
                transaction: transaction.clone(),
            },
            ProductionProtectedPipelineEvidence::Finality(ProtectedFinalityEvidence {
                consensus_domain: self.consensus_domain.clone(),
                target,
                transaction: transaction.clone(),
                material: material.clone(),
            }),
        )?;
        self.register_successor_from_finalization(material, transaction)
    }
}

impl SimplifiedProtectedLifecycleObserver for Arc<Mutex<ProductionProtectedPipelineLifecycle>> {
    fn on_validated_proposal(
        &mut self,
        proposal: &SimplifiedProposal,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<(), String> {
        self.lock()
            .map_err(|_| "protected lifecycle bridge lock is poisoned".to_string())?
            .on_validated_proposal(proposal, material)
    }

    fn on_proposal_validation_certificate(
        &mut self,
        proposal: &SimplifiedProposal,
        material: &VerifiedSimplifiedProposalMaterial,
        certificate: &PosyProposalValidationCertificate,
    ) -> Result<(), String> {
        self.lock()
            .map_err(|_| "protected lifecycle bridge lock is poisoned".to_string())?
            .on_proposal_validation_certificate(proposal, material, certificate)
    }

    fn on_execution_consumed(
        &mut self,
        proposal: &SimplifiedProposal,
        material: &VerifiedSimplifiedProposalMaterial,
    ) -> Result<(), String> {
        self.lock()
            .map_err(|_| "protected lifecycle bridge lock is poisoned".to_string())?
            .on_execution_consumed(proposal, material)
    }

    fn on_quorum_certificate(
        &mut self,
        proposal: &SimplifiedProposal,
        material: &VerifiedSimplifiedProposalMaterial,
        certificate: &SimplifiedQuorumCertificate,
    ) -> Result<(), String> {
        self.lock()
            .map_err(|_| "protected lifecycle bridge lock is poisoned".to_string())?
            .on_quorum_certificate(proposal, material, certificate)
    }

    fn on_finalization(
        &mut self,
        proposal: &SimplifiedProposal,
        material: &VerifiedSimplifiedProposalMaterial,
        transaction: &SimplifiedFinalizationTransaction,
    ) -> Result<(), String> {
        self.lock()
            .map_err(|_| "protected lifecycle bridge lock is poisoned".to_string())?
            .on_finalization(proposal, material, transaction)
    }
}

#[derive(Clone)]
struct RuntimeLifecycleSink {
    coordinator: NormalProtectedPipelineCoordinator,
    evidence_verifier: Arc<ProductionProtectedPipelineEvidenceVerifier>,
}

impl ProtectedPipelineLifecycleSink for RuntimeLifecycleSink {
    fn apply_protected_pipeline_lifecycle_update(
        &mut self,
        update: ProtectedPipelineLifecycleUpdate,
    ) -> Result<(), String> {
        let target_root = update.target.root()?;
        let runtime = self
            .coordinator
            .runtime_for_target(update.target.target_height, target_root)?
            .ok_or_else(|| "protected lifecycle target is not registered".to_string())?;
        let inputs = ProtectedPipelineReconcileContext {
            target: runtime.target(),
            verifier: &self.coordinator.verifier,
            validator_set: &self.coordinator.validator_set,
            cluster_map: &self.coordinator.cluster_map,
            parameters: &self.coordinator.parameters,
        };
        runtime
            .ingest_authenticated_event(
                AuthenticatedProtectedPipelineEvent::Observation(update.observation),
                self.evidence_verifier.as_ref(),
                &inputs,
            )
            .map_err(|error| format!("merge durable protected lifecycle observation: {error}"))?;
        Ok(())
    }
}

impl ProtectedPipelineLifecycleRecoverySink for RuntimeLifecycleSink {
    fn apply_recovered_protected_execution_input(
        &mut self,
        target: &TargetAdmissionContext,
        input: DeterministicProtectedExecutionInput,
    ) -> Result<(), String> {
        let runtime = self
            .coordinator
            .runtime_for_target(target.target_height, target.root()?)?
            .ok_or_else(|| "protected lifecycle recovery target is not registered".to_string())?;
        let inputs = ProtectedPipelineReconcileContext {
            target: runtime.target(),
            verifier: &self.coordinator.verifier,
            validator_set: &self.coordinator.validator_set,
            cluster_map: &self.coordinator.cluster_map,
            parameters: &self.coordinator.parameters,
        };
        runtime
            .ingest_authenticated_event(
                AuthenticatedProtectedPipelineEvent::ExecutionInput(input),
                self.evidence_verifier.as_ref(),
                &inputs,
            )
            .map_err(|error| format!("replay durable protected execution input: {error}"))?;
        Ok(())
    }
}

fn lifecycle_event_target(
    event: &ProtectedPipelineLifecycleEvent,
) -> Result<TargetAdmissionContext, String> {
    match event {
        ProtectedPipelineLifecycleEvent::ParentProposalCommitted { target, .. }
        | ProtectedPipelineLifecycleEvent::ProposalValidationCertified { target, .. }
        | ProtectedPipelineLifecycleEvent::ExecutionConsumed { target, .. }
        | ProtectedPipelineLifecycleEvent::QuorumCertified { target, .. }
        | ProtectedPipelineLifecycleEvent::FinalizationCommitted { target, .. } => {
            Ok(target.clone())
        }
    }
}

fn lifecycle_observation_evidence_root(
    observation: &ProtectedPipelineObservation,
) -> Result<EtdagDigest, String> {
    match observation {
        ProtectedPipelineObservation::ParentCommitment { evidence_root, .. }
        | ProtectedPipelineObservation::RevealAuthorization { evidence_root, .. }
        | ProtectedPipelineObservation::Consumed { evidence_root, .. }
        | ProtectedPipelineObservation::QcObserved { evidence_root, .. }
        | ProtectedPipelineObservation::Finalized { evidence_root, .. } => {
            Ok(evidence_root.clone())
        }
        ProtectedPipelineObservation::RevealShare { share_root, .. } => Ok(share_root.clone()),
        ProtectedPipelineObservation::ExecutionReady { .. } => {
            Err("root-only execution-ready observation is forbidden".to_string())
        }
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

    /// Exact transaction commitments selected by the durable cut/order. This
    /// is used only to retrieve their content-addressed ciphertext objects.
    pub fn ordered_transaction_commitments(&self) -> ProtectedPipelineResult<Vec<EtdagDigest>> {
        self.with_pipeline(|pipeline| {
            pipeline
                .record()
                .protected_batch
                .as_ref()
                .map(|batch| batch.ordered_transaction_ids.clone())
                .ok_or_else(|| {
                    not_ready(
                        "PROTECTED_RUNTIME_ORDER_NOT_READY",
                        "deterministic protected order is not durable yet",
                    )
                })
        })
    }

    /// Proposal-safe pre-reveal commitment. This becomes available after cut
    /// and deterministic ordering, before any reveal authorization or concrete
    /// execution input exists.
    pub fn pre_reveal_commitment(
        &self,
    ) -> ProtectedPipelineResult<Option<NextProtectedBatchCommitment>> {
        self.with_pipeline(|pipeline| Ok(pipeline.record().next_commitment.clone()))
    }

    /// Public deterministic cut/order result bound by the pre-reveal
    /// commitment. This excludes envelopes, reveal shares, and plaintext.
    pub fn pre_reveal_batch(
        &self,
    ) -> ProtectedPipelineResult<Option<crate::etdag::DeterministicProtectedBatch>> {
        self.with_pipeline(|pipeline| Ok(pipeline.record().protected_batch.clone()))
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

    /// Assemble the concrete normal execution input from the exact durable
    /// cut/order plus retrieved authenticated ciphertexts and VC-bound reveal
    /// shares. The caller cannot select a different order or substitute a
    /// root-only payload: the completed input is replayed by
    /// `merge_execution_input` before becoming ready for PoSy.
    pub fn assemble_and_ingest_execution_input(
        &self,
        reveal_authorization: ProtectedRevealAuthorization,
        submissions: BTreeMap<EtdagDigest, EtdagSubmissionEnvelope>,
        mut reveal_shares: BTreeMap<EtdagDigest, Vec<ProtectedRevealShareMessage>>,
        inputs: &ProtectedPipelineReconcileContext<'_>,
    ) -> ProtectedPipelineResult<ProtectedPipelineReconcileOutcome> {
        self.require_context(inputs)?;
        self.with_pipeline_mut(|pipeline| {
            let record = pipeline.record().clone();
            let cut_proof = record.cut_proof.clone().ok_or_else(|| {
                not_ready(
                    "PROTECTED_ASSEMBLY_CUT_NOT_READY",
                    "cannot assemble execution input before the durable cut is ready",
                )
            })?;
            let protected_batch = record.protected_batch.clone().ok_or_else(|| {
                not_ready(
                    "PROTECTED_ASSEMBLY_BATCH_NOT_READY",
                    "cannot assemble execution input before deterministic ordering",
                )
            })?;
            let next_commitment = record.next_commitment.clone().ok_or_else(|| {
                not_ready(
                    "PROTECTED_ASSEMBLY_COMMITMENT_NOT_READY",
                    "cannot assemble execution input before parent commitment derivation",
                )
            })?;
            reveal_authorization
                .validate_against(&self.target, &next_commitment, &protected_batch)
                .map_err(|error| {
                    invalid("PROTECTED_ASSEMBLY_REVEAL_AUTHORIZATION_INVALID", error)
                })?;

            let expected_ids = protected_batch
                .ordered_transaction_ids
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            if submissions.keys().cloned().collect::<std::collections::BTreeSet<_>>()
                != expected_ids
                || reveal_shares
                    .keys()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>()
                    != expected_ids
            {
                return Err(conflict(
                    "PROTECTED_ASSEMBLY_MATERIAL_SET_CONFLICT",
                    "retrieved ciphertext/share keys do not equal the deterministic protected order",
                ));
            }

            let threshold = decryption_threshold(
                self.target.assigned_cluster_validator_count as usize,
            )
            .map_err(|error| invalid("PROTECTED_ASSEMBLY_THRESHOLD_INVALID", error))?;
            let mut envelopes = BTreeMap::<EtdagDigest, EncryptedTransactionEnvelope>::new();
            let mut ordered_transactions = Vec::with_capacity(expected_ids.len());
            for commitment in &protected_batch.ordered_transaction_ids {
                let submission = submissions.get(commitment).ok_or_else(|| {
                    conflict(
                        "PROTECTED_ASSEMBLY_CIPHERTEXT_MISSING",
                        "deterministic protected order names a missing ciphertext",
                    )
                })?;
                submission
                    .verify(&self.target, inputs.parameters)
                    .map_err(|error| invalid("PROTECTED_ASSEMBLY_CIPHERTEXT_INVALID", error))?;
                if &submission.sealed_bundle.envelope.tx_commitment != commitment {
                    return Err(conflict(
                        "PROTECTED_ASSEMBLY_CIPHERTEXT_CONFLICT",
                        "retrieved ciphertext semantic ID does not match its envelope",
                    ));
                }
                let shares = reveal_shares.get_mut(commitment).ok_or_else(|| {
                    conflict(
                        "PROTECTED_ASSEMBLY_REVEAL_SHARES_MISSING",
                        "deterministic protected order names missing reveal shares",
                    )
                })?;
                shares.sort_by(|left, right| {
                    left.validator_id
                        .cmp(&right.validator_id)
                        .then_with(|| left.share.index.cmp(&right.share.index))
                });
                let plaintext = decrypt_inner_transaction(
                    &submission.sealed_bundle.envelope,
                    &shares
                        .iter()
                        .map(|message| message.share.clone())
                        .collect::<Vec<_>>(),
                    threshold,
                )
                .map_err(|error| invalid("PROTECTED_ASSEMBLY_DECRYPTION_FAILED", error))?;
                envelopes.insert(
                    commitment.clone(),
                    submission.sealed_bundle.envelope.clone(),
                );
                ordered_transactions.push(plaintext);
            }
            let reveal_transcript_root = protected_reveal_transcript_root(&reveal_shares)
                .map_err(|error| invalid("PROTECTED_ASSEMBLY_TRANSCRIPT_INVALID", error))?;
            pipeline.merge_execution_input(
                DeterministicProtectedExecutionInput {
                    material_version: PROTECTED_PIPELINE_VERSION,
                    source: self.source,
                    target_context: ProtectedExecutionTargetContext::NormalEtdag {
                        admission_context: self.target.clone(),
                    },
                    cut_proof: Some(cut_proof),
                    protected_batch,
                    next_commitment,
                    reveal_authorization: Some(reveal_authorization),
                    envelopes,
                    reveal_shares,
                    ordered_transactions,
                    reveal_transcript_root,
                },
                inputs,
            )
        })
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

fn not_ready(code: &str, detail: impl Into<String>) -> ProtectedPipelineError {
    ProtectedPipelineError {
        kind: ProtectedPipelineErrorKind::NotReady,
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
