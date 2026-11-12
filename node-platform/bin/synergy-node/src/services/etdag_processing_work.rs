//! Durable encrypted work on the existing ETDAG owner. The authorization
//! anchor is immutable; neither intake nor recovery uses a block-height expiry.
#[cfg(feature = "qualification-timing")]
use crate::services::qualification_timing::{
    processing_span as diagnostic_span, ProcessingStage as DiagnosticStage,
};

use super::*;
use crate::services::processing_pipeline::*;
use crate::services::processing_store::{
    PendingProcessingStore, ProcessingAdmissionAuthenticator, ProcessingStoreError,
    ProcessingStoreLimits, PROCESSING_INTAKE_HEADROOM_BYTES,
};
use synergy_etdag::execution::{ProcessingDecryptShare, ProcessingVertex};
use synergy_etdag::{CertifiedEnvelopeRef, ProcessingContext, WalletProcessingAdmission};
use synergy_execution::{BudgetedCandidateStore, BudgetedExecutionCandidate};
use synergy_posy::ProposalValidationCertificate;
use synergy_state::world_resources::{BudgetedWorld, WorldResourceBudget, WorldResourceError};

struct Frame {
    bytes: Vec<u8>,
    _permit: WorldResourcePermit,
}
struct LiveItem {
    vertex_id: EtdagDigest,
    context_root: EtdagDigest,
    evidence: ProcessingProgressEvidence,
    votes: BTreeMap<String, AvailabilityVote>,
    // One current-session receipt per frozen member, prepaid by _permit.
    // Never recovered: reconnect/restart must restore original retries.
    vertex_holders: BTreeMap<String, AuthenticatedPeer>,
    frames: BTreeMap<u8, Frame>,
    workspace: Arc<WorldResourceBudget>,
    completed: bool,
    // Immutable wallet ciphertext is not repaired or discarded on failure.
    // Re-evaluate once after restart; never spin or terminate the fleet because
    // an untrusted capsule cannot authenticate. Peers may still supply enough
    // valid shares for ordinary threshold completion.
    local_share_rejected: Option<synergy_etdag::crypto::CapsuleVerificationStage>,
    _permit: WorldResourcePermit,
}
pub(super) struct ProcessingWork {
    pending: PendingProcessingStore,
    verifier: LiveVerifier,
    items: BTreeMap<EtdagDigest, LiveItem>,
    retry: Option<Instant>,
    cursor: usize,
    finalized_scan: u64,
    observed_finality: u64,
    finalized_store: Option<synergy_state::FinalizedStateStore>,
    finalized_retry: Option<Instant>,
    finalized_retry_cursor: usize,
    authorization_root: String,
    requested_source: Option<(ProcessingContext, String)>,
    context_published: bool,
}
struct LiveVerifier {
    transition: Option<crate::services::authority::VerifiedTransitionContext>,
    authority: Arc<VerifiedAuthority>,
    genesis: Arc<BudgetedWorld>,
    context: ProcessingContext,
    candidate_root: PathBuf,
    state_root: PathBuf,
    consensus_root: PathBuf,
    // Small serial authentication scratch is held before any pending item.
    scratch: Arc<WorldResourceBudget>,
    members: BTreeMap<EtdagDigest, Arc<NativeProcessingMember>>,
    ingress: AuthenticatedIngress,
}
/// A malformed authenticated wallet request is not a fault of the ETDAG
/// service. Local governed custody/key failures remain fail-closed service
/// failures; only peer-controlled capsule material is isolated per item.
fn classify_local_capsule_failure(
    stage: synergy_etdag::crypto::CapsuleVerificationStage,
) -> Result<synergy_etdag::crypto::CapsuleVerificationStage, String> {
    use synergy_etdag::crypto::CapsuleVerificationStage as Stage;
    match stage {
        Stage::Provider | Stage::RegistryKey | Stage::SecretKey | Stage::KeyPossession => Err(
            format!("local processing custody verification failed: {stage:?}"),
        ),
        _ => Ok(stage),
    }
}

fn check<T>(result: Result<T, String>) -> Result<T, ProcessingStoreError> {
    result.map_err(ProcessingStoreError::Verification)
}
fn measure(value: &impl serde::Serialize) -> Result<usize, String> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX_ETDAG_SIGNING_BYTES)
                .ok_or_else(|| std::io::Error::other("processing message exceeds native bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Counter(0);
    serde_json::to_writer(&mut count, value).map_err(|e| e.to_string())?;
    Ok(count.0)
}
fn authorization_state_root(world: &synergy_state::WorldState) -> String {
    let bytes = world
        .protocol
        .get(synergy_identity::authorization::IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY)
        .map(Vec::as_slice)
        .unwrap_or_default();
    synergy_block::hash_block_bytes(bytes)
}
fn deliver_processing_retry_slice<'a>(
    payloads: impl Iterator<Item = &'a [u8]> + Clone,
    peers: impl Iterator<Item = &'a str> + Clone,
    cursor: &mut usize,
    last_attempt: &mut Option<Instant>,
    now: Instant,
    publish: impl FnMut(&str, &[u8]) -> Result<bool, String>,
) -> Result<(), String> {
    if last_attempt.is_some_and(|last| now.duration_since(last) < Duration::from_millis(250)) {
        return Ok(());
    }
    // A partial slice still queued frames. Pace attempts even when the bounded
    // queue fills; otherwise partial progress retries at the owner poll rate.
    // The cursor retains the first rejected pair for the next paced attempt.
    *last_attempt = Some(now);
    deliver_retry_slice(payloads, peers, cursor, publish).map(|_| ())
}
fn vertex_retry_has_current_receipt(
    ingress: &AuthenticatedIngress,
    holders: &BTreeMap<String, AuthenticatedPeer>,
    peer: &str,
    vertex_payload: &[u8],
    payload: &[u8],
) -> Result<bool, String> {
    // Both borrows refer to this poll's immutable frame collection. Match the
    // exact vertex allocation, never a vote/share/other item's frame.
    if !std::ptr::eq(vertex_payload, payload) {
        return Ok(false);
    }
    match holders.get(peer) {
        Some(receipt) => ingress.is_current_session(receipt),
        None => Ok(false),
    }
}
fn parent_at(
    root: &std::path::Path,
    vc: &ProposalValidationCertificate,
    budget: &Arc<WorldResourceBudget>,
) -> Result<BudgetedExecutionCandidate, String> {
    let store = BudgetedCandidateStore::new_budgeted(root, budget.clone())?;
    let candidate = store
        .get_budgeted(vc.context.height)
        .map_err(|e| e.to_string())?
        .ok_or("pending processing reveal World is unavailable")?;
    if candidate.block_id != vc.candidate.block_id {
        return Err("pending processing reveal World differs from native certificate".into());
    }
    Ok(candidate)
}
// The ingress supplies locally verified ordinary three-QC finality, including
// authenticated durable recovery. A proposal's ECHOs alone must not release
// threshold shares, even when its speculative order has already closed.
fn finalized_processing_order(
    certificate: &ProposalValidationCertificate,
    finalized: Option<&synergy_posy::FinalizedBlockRecord>,
) -> Result<bool, String> {
    let Some(finalized) = finalized else {
        return Ok(false);
    };
    if finalized.height != certificate.context.height
        || finalized.block_id != certificate.candidate.block_id
        || finalized.protected_execution_root != certificate.candidate.protected_execution_root
    {
        return Err("processing reveal order differs from verified PoSy finality".into());
    }
    Ok(true)
}
impl LiveVerifier {
    fn context_for_anchor(&self, target: u64) -> Result<ProcessingContext, String> {
        let source_height = self.authority.protected_source_height(target)?;
        let record = if source_height == 0 {
            None
        } else {
            Some(
                self.ingress
                    .finalized_record_with_witness(source_height)?
                    .ok_or("processing source lacks finalized three-QC history")?
                    .0,
            )
        };
        Ok(ProcessingContext {
            context_version: 1,
            profile_id: synergy_etdag::PROCESSING_PROFILE_ID.into(),
            authority: self.authority.protected_target(record.as_ref(), target)?.0,
        })
    }
    fn source<'a>(
        &'a self,
        context: &'a ProcessingContext,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<NativeProcessingContext<'a>, String> {
        // Reconstruct each immutable original anchor from local authenticated
        // history. Publishing a newer source never retargets pending bytes.
        if *context != self.context_for_anchor(context.authority.target_height)? {
            return Err("unknown frozen processing source".into());
        }
        let height = context.authority.source_finalized_height;
        if height == 0 {
            return NativeProcessingContext::verify_in(
                &self.authority,
                context,
                ProcessingSource::Genesis(&self.genesis),
                budget,
            );
        }
        let (record, witness) = self
            .ingress
            .finalized_record_with_witness(height)?
            .ok_or("processing source finality is absent")?;
        let pool = self.ingress.world_budget();
        let candidate = BudgetedCandidateStore::new_budgeted(&self.candidate_root, pool.clone())?
            .get_budgeted(height)
            .map_err(|e| e.to_string())?
            .ok_or("processing source World is absent")?;
        if candidate.block_id != record.block_id {
            return Err("processing source candidate differs from finalized record".into());
        }
        NativeProcessingContext::verify_owned_finalized_with_transition(
            &self.authority,
            context,
            candidate,
            &witness,
            pool,
            self.transition.as_ref(),
        )
    }
    fn parents<'a>(
        &'a self,
        ids: &[EtdagDigest],
    ) -> Result<Vec<&'a NativeProcessingMember>, String> {
        ids.iter()
            .map(|id| {
                self.members
                    .get(id)
                    .map(AsRef::as_ref)
                    .ok_or_else(|| "processing DAG parent unavailable".into())
            })
            .collect()
    }
}
impl ProcessingAdmissionAuthenticator for LiveVerifier {
    fn verify_finalized(
        &self,
        identity: &crate::services::processing_store::PendingProcessingIdentity,
        height: u64,
        block_id: &str,
        state_root: &str,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        use crate::services::processing_store::ProcessingRetirementVerifier;
        let proof = NativeProcessingRetirement::recover(
            &self.authority,
            height,
            block_id,
            &self.candidate_root,
            &self.state_root,
            &self.consensus_root,
            0,
            budget,
        )?;
        if proof.finalized_state_root() != Some(state_root) {
            return Err("finalized processing state root mismatch".into());
        }
        proof.verify_retirement(identity)
    }
    fn verify(
        &self,
        context: &ProcessingContext,
        timestamp: u64,
        admission: &WalletProcessingAdmission,
    ) -> Result<(), String> {
        ProcessingAdmissionAuthenticator::verify(
            &self.source(context, &self.scratch)?,
            context,
            timestamp,
            admission,
        )
    }
    fn verify_retained(
        &self,
        context: &ProcessingContext,
        timestamp: u64,
        admission: &WalletProcessingAdmission,
    ) -> Result<(), String> {
        // The store authenticated the immutable original source/request bytes
        // and checks its trusted hash before calling here.
        // New intake and open/recovery always use full native authentication.
        if *context != self.context_for_anchor(context.authority.target_height)?
            || timestamp
                != self
                    .authority
                    .consensus_timestamp_unix(context.authority.target_height)?
        {
            return Err("retained processing source differs from frozen native authority".into());
        }
        admission
            .request
            .validate_context(context)
            .map_err(|error| format!("{error:?}"))
    }
    fn verify_retained_progress(
        &self,
        context: &ProcessingContext,
        admission: &WalletProcessingAdmission,
        _: &ProcessingProgressEvidence,
        _: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        // Only exact hash-bound bytes from an already verified progress index
        // reach this method. Every incoming update still uses verify_progress.
        ProcessingAdmissionAuthenticator::verify_retained(
            self,
            context,
            self.authority
                .consensus_timestamp_unix(context.authority.target_height)?,
            admission,
        )
    }
    fn verify_progress(
        &self,
        context: &ProcessingContext,
        admission: &WalletProcessingAdmission,
        evidence: &ProcessingProgressEvidence,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        let source = self.source(context, budget)?;
        let parent = evidence
            .reveal_validation
            .as_ref()
            .map(|vc| parent_at(&self.candidate_root, vc, budget))
            .transpose()?;
        let parents = self.parents(&evidence.parents)?;
        NativeProcessingProgressRecovery {
            source: &source,
            reveal_parent: parent.as_ref(),
            dag_parents: &parents,
        }
        .verify_progress(context, admission, evidence, budget)
    }
    fn verify_completion(
        &self,
        context: &ProcessingContext,
        admission: &WalletProcessingAdmission,
        evidence: &ProcessingCompletionEvidence,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<(), String> {
        let source = self.source(context, budget)?;
        let parent = parent_at(&self.candidate_root, &evidence.reveal_validation, budget)?;
        let parents = self.parents(&evidence.parents)?;
        NativeProcessingRecovery {
            source: &source,
            reveal_parent: &parent,
            dag_parents: &parents,
        }
        .verify_completion(context, admission, evidence, budget)
    }
}
fn vertex(
    admission: &WalletProcessingAdmission,
    evidence: &ProcessingProgressEvidence,
) -> ProcessingVertex {
    ProcessingVertex {
        vertex_version: evidence.vertex_version,
        admission: admission.clone(),
        envelope_ref: evidence.envelope_ref.clone(),
        parents: evidence.parents.clone(),
        author_id: evidence.author_id.clone(),
        key_id: evidence.key_id.clone(),
        author_signature: evidence.author_signature.clone(),
    }
}
impl EtdagService {
    fn authored_processing_vertex(
        &self,
        admission: &WalletProcessingAdmission,
    ) -> Result<ProcessingVertex, ProcessingStoreError> {
        let r = &admission.request;
        let mut v = ProcessingVertex {
            vertex_version: 1,
            admission: admission.clone(),
            envelope_ref: CertifiedEnvelopeRef {
                tx_commitment: r.envelope.envelope_id.clone(),
                sender_id: r.sender_wallet.clone(),
                nonce_slot: r.sender_nonce,
                certified_dag_round: 0,
                gas_class_units: r.gas_class_units,
                ciphertext_bytes: r.envelope.ciphertext.len() as u64,
                fee_class: r.fee_class,
                protocol_dependencies: Vec::new(),
            },
            parents: Vec::new(),
            author_id: self.local_signer.validator_id.clone(),
            key_id: self.local_signer.key_id.as_str().into(),
            author_signature: Vec::new(),
        };
        v.author_signature = check(
            self.local_signer
                .signer
                .sign(
                    &self.local_signer.key_id,
                    &SigningContext {
                        domain: "SYNERGY-ETDAG-SIGNATURE-V1".into(),
                        chain_id: self.local_signer.chain_id,
                        epoch: Some(self.local_signer.epoch),
                        height: None,
                    },
                    &check(v.signing_bytes().map_err(|e| format!("{e:?}")))?,
                )
                .map(|s| s.bytes)
                .map_err(|e| e.to_string()),
        )?;
        Ok(v)
    }
    pub(super) fn initialize_pending_work(&mut self) -> Result<(), String> {
        let source = self
            .processing_transition
            .as_ref()
            .map(|transition| transition.finalized());
        let target = match source {
            Some(source) => self
                .authority
                .protected_parameters()?
                .protected_target_height(source.height)
                .map_err(|error| format!("{error:?}"))?,
            None => 3,
        };
        let context = ProcessingContext {
            context_version: 1,
            profile_id: synergy_etdag::PROCESSING_PROFILE_ID.into(),
            authority: self.authority.protected_target(source, target)?.0,
        };
        let scratch = self
            .ingress
            .world_budget()
            .reserve(256 * 1024)
            .map_err(|e| e.to_string())?
            .into_budget();
        let verifier = LiveVerifier {
            transition: self.processing_transition.clone(),
            authority: self.authority.clone(),
            genesis: self.initial_wallet_world.clone(),
            context: context.clone(),
            candidate_root: self.processing_candidate_root.clone(),
            state_root: self.finalized_state_root.clone(),
            consensus_root: self.processing_consensus_root.clone(),
            scratch,
            members: BTreeMap::new(),
            ingress: self.ingress.clone(),
        };
        verifier.source(&context, &verifier.scratch)?;
        let pending = PendingProcessingStore::open(
            &self.pipeline_root.join(if self.authority.epoch.epoch == 1 {
                "processing-v1".to_owned()
            } else {
                format!("processing-v1-epoch-{:020}", self.authority.epoch.epoch)
            }),
            processing_namespace(&self.authority, self.ingress.world_budget())?,
            ProcessingStoreLimits {
                slots: 4096,
                completion_bytes_per_item: 64 * 1024 * 1024,
            },
            self.ingress.world_budget(),
            &verifier,
        )
        .map_err(|e| e.to_string())?;
        let publish_genesis = self
            .ingress
            .latest_finality()?
            .is_none_or(|record| record.height == 0);
        self.processing
            .as_mut()
            .ok_or("processing owner absent")?
            .work = Some(ProcessingWork {
            pending,
            verifier,
            items: BTreeMap::new(),
            retry: None,
            cursor: 0,
            finalized_scan: 0,
            observed_finality: 0,
            finalized_store: None,
            finalized_retry: None,
            finalized_retry_cursor: 0,
            authorization_root: authorization_state_root(&self.initial_wallet_world),
            requested_source: None,
            context_published: publish_genesis,
        });
        if let Some(handle) = &self.wallet_admission {
            let response = if publish_genesis {
                Some(serde_json::json!({
                    "context": context, "profile_id": synergy_etdag::PROCESSING_PROFILE_ID,
                    "ingress_kem_registry": self.authority.protected_ingress_registry()?
                }))
            } else {
                None
            };
            handle.publish_processing_context(&self.authority, response)?;
        }
        Ok(())
    }
    fn with_processing_work<T>(
        &mut self,
        action: impl FnOnce(&mut Self, &mut ProcessingWork) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut work = self
            .processing
            .as_mut()
            .and_then(|owner| owner.work.take())
            .ok_or("durable processing owner unavailable")?;
        let result = action(self, &mut work);
        self.processing
            .as_mut()
            .expect("processing owner retained")
            .work = Some(work);
        result
    }
    fn processing_frame(
        &self,
        message: EtdagNetworkMessage,
        budget: &Arc<WorldResourceBudget>,
    ) -> Result<Frame, String> {
        let size = measure(&message)?;
        let permit = budget
            .reserve(
                size.checked_mul(32)
                    .and_then(|n| n.checked_add(128 * 1024))
                    .ok_or("processing frame reservation overflow")?,
            )
            .map_err(|e| e.to_string())?;
        let signed = self.local_signer.sign_message(message)?;
        let bytes = serde_json::to_vec(&signed).map_err(|e| e.to_string())?;
        if bytes.len() > synergy_network::protocol::DEFAULT_MAX_FRAME_BYTES {
            return Err("processing frame exceeds native transport limit".into());
        }
        Ok(Frame {
            bytes,
            _permit: permit,
        })
    }
    fn restore_processing_item(
        &mut self,
        work: &mut ProcessingWork,
        envelope: &EtdagDigest,
    ) -> Result<(), String> {
        if work.items.contains_key(envelope) {
            return Ok(());
        }
        let (item, new_progress) = work
            .pending
            .with_progress(envelope, &work.verifier, |admission, evidence, budget| {
                let permit = budget.reserve((self.members.len() + 1) * 1024 * 1024)?;
                // A crash after immutable intake but before the first author record
                // must retain actionable work. No vote/frame was emitted at that
                // boundary, so authenticate and persist a fresh local author proof.
                let generated;
                let new_progress = evidence.is_none();
                let evidence = match evidence {
                    Some(evidence) => evidence,
                    None => {
                        generated = ProcessingProgressEvidence::from_vertex(
                            &self.authored_processing_vertex(admission)?,
                        );
                        &generated
                    }
                };
                let context = check(
                    work.verifier
                        .context_for_anchor(admission.request.envelope.aad.authorization_height),
                )?;
                let source = check(work.verifier.source(&context, budget))?;
                let v = vertex(admission, evidence);
                let parents = check(work.verifier.parents(&evidence.parents))?;
                check(NativeProcessingVertex::verify_for_availability(
                    &source, &v, &parents, budget,
                ))?;
                let vertex_id = check(v.id().map_err(|e| format!("{e:?}")))?;
                let mut frames = BTreeMap::new();
                frames.insert(
                    0,
                    check(
                        self.processing_frame(EtdagNetworkMessage::ProcessingVertexV1(v), budget),
                    )?,
                );
                Ok((
                    LiveItem {
                        vertex_id,
                        context_root: admission.request.context_root.clone(),
                        evidence: evidence.clone(),
                        votes: BTreeMap::new(),
                        vertex_holders: BTreeMap::new(),
                        frames,
                        workspace: budget.clone(),
                        completed: false,
                        local_share_rejected: None,
                        _permit: permit,
                    },
                    new_progress,
                ))
            })
            .map_err(|e| e.to_string())?;
        if new_progress {
            {
                #[cfg(feature = "qualification-timing")]
                let _diagnostic = diagnostic_span(DiagnosticStage::ProgressWrite);
                work.pending
                    .update_progress(envelope, &item.evidence, &work.verifier)
                    .map_err(|e| e.to_string())?;
            }
        }
        work.items.insert(envelope.clone(), item);
        Ok(())
    }
    fn accept_processing_vertex(
        &mut self,
        work: &mut ProcessingWork,
        v: ProcessingVertex,
    ) -> Result<(), ProcessingStoreError> {
        #[cfg(feature = "qualification-timing")]
        let _diagnostic = diagnostic_span(
            if work
                .items
                .contains_key(&v.admission.request.envelope.envelope_id)
            {
                DiagnosticStage::VertexRetained
            } else {
                DiagnosticStage::VertexNew
            },
        );
        if let Some((_, world)) = check(self.ingress.processing_finalized_world())? {
            if world
                .accounts
                .get(&v.admission.request.sender_wallet)
                .map_or(0, |account| account.nonce)
                > v.admission.request.sender_nonce
            {
                return Err(ProcessingStoreError::Invalid(
                    "processing nonce already finalized".into(),
                ));
            }
        }
        // A live item was authenticated from its immutable durable original.
        // Exact peer retransmissions carry no new progress. Reuse that proof
        // only when the complete native vertex commitment AND the separately
        // signed author bytes match; changed inputs still take full validation.
        // Hash scratch comes from the original's retained worker reservation.
        if let Some(item) = work
            .items
            .get(&v.admission.request.envelope.envelope_id)
            .filter(|item| v.author_signature == item.evidence.author_signature)
        {
            let mut scratch = item.workspace.reserve(16 * 1024)?;
            let bytes = measure(&v).map_err(ProcessingStoreError::Verification)?;
            scratch.grow(
                bytes
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(64 * 1024))
                    .ok_or_else(|| {
                        ProcessingStoreError::Invalid("processing retry hash size overflow".into())
                    })?,
            )?;
            if check(v.id().map_err(|error| format!("{error:?}")))? == item.vertex_id {
                return Ok(());
            }
        }
        {
            #[cfg(feature = "qualification-timing")]
            let _diagnostic = diagnostic_span(DiagnosticStage::ProofInvalidation);
            check(self.ingress.invalidate_processing_proof_references())?;
        }
        let context = check(
            work.verifier
                .context_for_anchor(v.admission.request.envelope.aad.authorization_height),
        )?;
        let timestamp = check(
            self.authority
                .consensus_timestamp_unix(context.authority.target_height),
        )?;
        let source = check(work.verifier.source(&context, &work.verifier.scratch))?;
        // Incoming transport storage already owns the decode. Reserve native
        // proof scratch before verification; accepted work uses its child pool.
        let parents = check(work.verifier.parents(&v.parents))?;
        // New intake must leave the control/execution envelope available.
        // An existing original uses its already retained worker capacity, so
        // exact retries cannot be blocked by their own global reservation.
        let existing = work
            .pending
            .retirement_budget(&v.admission.request.envelope.envelope_id);
        let workspace = match existing {
            Some(workspace) => workspace,
            None => self
                .ingress
                .world_budget()
                .reserve_with_headroom(
                    measure(&v)
                        .map_err(ProcessingStoreError::Verification)?
                        .checked_mul(32)
                        .and_then(|n| n.checked_add(128 * 1024))
                        .ok_or_else(|| {
                            ProcessingStoreError::Invalid("processing intake size overflow".into())
                        })?,
                    PROCESSING_INTAKE_HEADROOM_BYTES,
                )?
                .into_budget(),
        };
        check(NativeProcessingVertex::verify_for_availability(
            &source, &v, &parents, &workspace,
        ))?;
        let _encode = workspace.reserve(
            measure(&v.admission).map_err(ProcessingStoreError::Verification)? * 2 + 64 * 1024,
        )?;
        let bytes = check(serde_json::to_vec(&v.admission).map_err(|e| e.to_string()))?;
        let identity = work
            .pending
            .admit(&context, timestamp, &bytes, &work.verifier)?;
        if work
            .pending
            .finalized_identities()
            .any(|(old, _, _)| old == &identity)
        {
            return Ok(());
        }
        let evidence = ProcessingProgressEvidence::from_vertex(&v);
        // Existing immutable author proof wins an exact request retransmission.
        let has_progress = {
            #[cfg(feature = "qualification-timing")]
            let _diagnostic = diagnostic_span(DiagnosticStage::VertexProgressRead);
            work.pending
                .with_progress(&identity.envelope_id, &work.verifier, |_, old, _| {
                    Ok(old.is_some())
                })?
        };
        if !has_progress {
            #[cfg(feature = "qualification-timing")]
            let _diagnostic = diagnostic_span(DiagnosticStage::ProgressWrite);
            work.pending
                .update_progress(&identity.envelope_id, &evidence, &work.verifier)?;
        }
        check(self.restore_processing_item(work, &identity.envelope_id))?;
        Ok(())
    }
    pub(in crate::services::etdag) fn processing_vertex(
        &mut self,
        v: ProcessingVertex,
    ) -> Result<(), String> {
        self.with_processing_work(
            |owner, work| match owner.accept_processing_vertex(work, v) {
                Ok(()) => Ok(()),
                Err(ProcessingStoreError::Storage(error)) => {
                    let reason = format!("durable processing storage failure: {error}");
                    owner.failure = Some(reason.clone());
                    Err(reason)
                }
                Err(error) => Err(error.to_string()),
            },
        )
    }
    pub(in crate::services::etdag) fn processing_availability_vote(
        &mut self,
        peer: &AuthenticatedPeer,
        vote: AvailabilityVote,
    ) -> Result<(), String> {
        self.with_processing_work(|owner, work| {
            if vote.validator_id != peer.node_address.as_str()
                || !owner.members.contains(&vote.validator_id)
                || !owner.ingress.is_current_session(peer)?
            {
                return Err(
                    "processing availability receipt differs from current member session".into(),
                );
            }
            let voter = vote.validator_id.clone();
            let vertex = vote.vertex_id.clone();
            // Native signature, processing source and durable local original
            // are checked before this advisory transport receipt is recorded.
            owner.accept_processing_vote(work, vote)?;
            if let Some(item) = work
                .items
                .values_mut()
                .find(|item| item.vertex_id == vertex)
            {
                item.vertex_holders.insert(voter, peer.clone());
            }
            Ok(())
        })
    }
    fn accept_processing_vote(
        &mut self,
        work: &mut ProcessingWork,
        vote: AvailabilityVote,
    ) -> Result<(), String> {
        vote.validate().map_err(|e| format!("{e:?}"))?;
        let bytes = canonical_signing_bytes(
            "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
            &(
                &vote.context_root,
                &vote.vertex_id,
                &vote.validator_id,
                &vote.key_id,
            ),
        )
        .map_err(|e| format!("{e:?}"))?;
        SignatureVerifier::verify(
            self.authority.as_ref(),
            &vote.validator_id,
            &vote.key_id,
            &bytes,
            &vote.signature,
        )
        .map_err(|e| format!("{e:?}"))?;
        let Some(item) = work
            .items
            .values_mut()
            .find(|item| item.vertex_id == vote.vertex_id)
        else {
            return Err("processing availability awaits durable vertex; retry".into());
        };
        if vote.context_root != item.context_root {
            return Err("availability vote has another processing source".into());
        }
        if item.evidence.availability.is_some() {
            return Ok(());
        }
        item.votes.entry(vote.validator_id.clone()).or_insert(vote);
        match AvailabilityCertificate::from_votes(
            item.context_root.clone(),
            item.vertex_id.clone(),
            item.votes.values().cloned().collect(),
            self.members.len(),
        ) {
            Ok(certificate) => self.accept_processing_certificate(work, certificate),
            Err(EtdagError::InsufficientAvailability { .. }) => Ok(()),
            Err(e) => Err(format!("{e:?}")),
        }
    }
    pub(in crate::services::etdag) fn processing_availability_certificate(
        &mut self,
        certificate: AvailabilityCertificate,
    ) -> Result<(), String> {
        self.with_processing_work(|owner, work| {
            owner.accept_processing_certificate(work, certificate)
        })
    }
    fn accept_processing_certificate(
        &mut self,
        work: &mut ProcessingWork,
        certificate: AvailabilityCertificate,
    ) -> Result<(), String> {
        let Some(envelope) = work
            .items
            .iter()
            .find(|(_, item)| item.vertex_id == certificate.vertex_id)
            .map(|(id, _)| id.clone())
        else {
            return Err("processing certificate awaits durable vertex; retry".into());
        };
        let item = work.items.get(&envelope).expect("located item");
        if item.evidence.availability.is_some() {
            return Ok(());
        }
        let mut evidence = item.evidence.clone();
        evidence.availability = Some(certificate);
        // Native recovery enforces count AND strict frozen voting weight.
        let progress_result = {
            #[cfg(feature = "qualification-timing")]
            let _diagnostic = diagnostic_span(DiagnosticStage::ProgressWrite);
            work.pending
                .update_progress(&envelope, &evidence, &work.verifier)
        };
        match progress_result {
            Ok(()) => {}
            Err(ProcessingStoreError::Verification(reason))
                if reason == "processing availability lacks strict weight quorum" =>
            {
                return Ok(())
            }
            Err(error) => return Err(error.to_string()),
        }
        work.items
            .get_mut(&envelope)
            .expect("located item")
            .evidence = evidence;
        if let Some(handle) = &self.wallet_admission {
            let item = work.items.get(&envelope).expect("located item");
            let certificate = item
                .evidence
                .availability
                .as_ref()
                .expect("availability persisted");
            handle.record_verified_stage(
                &envelope,
                "certified",
                serde_json::json!({
                    "vertex_id": item.vertex_id,
                    "context_root": certificate.context_root,
                    "verified_vote_count": certificate.votes.len(),
                    "finalized": false,
                }),
            )?;
        }
        self.publish_processing_member(work, &envelope)
    }
    fn publish_processing_member(
        &self,
        work: &mut ProcessingWork,
        envelope: &EtdagDigest,
    ) -> Result<(), String> {
        let item = work.items.get(envelope).ok_or("pending member absent")?;
        if work.verifier.members.contains_key(&item.vertex_id) {
            return Ok(());
        }
        let evidence = &item.evidence;
        let Some(certificate) = evidence.availability.as_ref() else {
            return Ok(());
        };
        let member = work
            .pending
            .with_worker(envelope, &work.verifier, |context, _, admission, budget| {
                let source = check(work.verifier.source(context, budget))?;
                let v = vertex(admission, evidence);
                let parents = check(work.verifier.parents(&evidence.parents))?;
                let verified = check(NativeProcessingVertex::verify(
                    &source,
                    &v,
                    certificate,
                    &parents,
                    budget,
                ))?;
                check(verified.retain_member(budget)).map(Arc::new)
            })
            .map_err(|e| e.to_string())?;
        self.ingress.publish_processing_member(member.clone())?;
        work.verifier.members.insert(item.vertex_id.clone(), member);
        let frame = self.processing_frame(
            EtdagNetworkMessage::ProcessingAvailabilityCertificateV1(certificate.clone()),
            &item.workspace,
        )?;
        work.items
            .get_mut(envelope)
            .expect("located item")
            .frames
            .insert(2, frame);
        Ok(())
    }
    pub(in crate::services::etdag) fn processing_reveal_share(
        &mut self,
        share: ProcessingDecryptShare,
    ) -> Result<(), String> {
        self.with_processing_work(|owner, work| owner.accept_processing_share(work, share))
    }
    fn accept_processing_share(
        &mut self,
        work: &mut ProcessingWork,
        share: ProcessingDecryptShare,
    ) -> Result<(), String> {
        let envelope = share.permission.envelope_id.clone();
        let Some(item) = work.items.get(&envelope) else {
            return Err("processing share awaits durable vertex; retry".into());
        };
        if item.completed {
            return Ok(());
        }
        if item.evidence.reveal_validation.is_none() {
            return Err("processing share awaits native reveal permission; retry".into());
        }
        let vc = item
            .evidence
            .reveal_validation
            .as_ref()
            .expect("checked VC");
        if !finalized_processing_order(
            vc,
            self.ingress.finalized_record(vc.context.height)?.as_ref(),
        )? {
            return Err("processing share awaits finalized encrypted order; retry".into());
        }
        if item
            .evidence
            .shares
            .iter()
            .any(|s| s.validator_id == share.validator_id)
        {
            return Ok(());
        }
        if item.evidence.shares.len() >= self.members.len() {
            return Err("processing share limit".into());
        }
        let mut evidence = item.evidence.clone();
        evidence.shares.push(share);
        evidence
            .shares
            .sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        {
            #[cfg(feature = "qualification-timing")]
            let _diagnostic = diagnostic_span(DiagnosticStage::ProgressWrite);
            work.pending
                .update_progress(&envelope, &evidence, &work.verifier)
                .map_err(|e| e.to_string())?;
        }
        work.items
            .get_mut(&envelope)
            .expect("located item")
            .evidence = evidence;
        Ok(())
    }
    pub(super) fn poll_pending_work(&mut self) -> Result<(), String> {
        self.with_processing_work(|owner, work| owner.poll_pending_work_inner(work))
    }
    fn refresh_processing_context(&self, work: &mut ProcessingWork) -> Result<(), String> {
        // Admission needs the source's canonical identity binding, not its
        // balances/nonce. Inclusion still verifies both against the real parent.
        // Refresh only on an authorization transition, avoiding per-height pins.
        if let Some((height, world)) = self.ingress.processing_finalized_world()? {
            let root = authorization_state_root(&world);
            if root == work.authorization_root
                && !work.context_published
                && work.requested_source.is_none()
            {
                if let Some(handle) = &self.wallet_admission {
                    handle.publish_processing_context(&self.authority, Some(serde_json::json!({
                        "context": work.verifier.context, "profile_id": synergy_etdag::PROCESSING_PROFILE_ID,
                        "ingress_kem_registry": self.authority.protected_ingress_registry()?
                    })))?;
                }
                work.context_published = true;
            }
            if root != work.authorization_root
                && work
                    .requested_source
                    .as_ref()
                    .is_none_or(|(_, pending)| pending != &root)
            {
                let source_height =
                    synergy_identity::registration::authorization_update_height(&world.protocol)?;
                if source_height == 0 || source_height > height {
                    return Err(
                        "changed canonical authorization lacks its exact finalized update height"
                            .into(),
                    );
                }
                let target = source_height
                    .checked_add(self.authority.protected_parameters()?.target_height_offset)
                    .ok_or("processing authorization anchor overflow")?;
                let context = work.verifier.context_for_anchor(target)?;
                work.requested_source = Some((context, root));
            }
        }
        let Some((context, root)) = &work.requested_source else {
            return Ok(());
        };
        let candidates = BudgetedCandidateStore::new_budgeted(
            &work.verifier.candidate_root,
            self.ingress.world_budget().clone(),
        )?;
        // The Execution owner creates/retires all sparse pins. Its existing
        // positive-reference reconciliation must finish before advertisement.
        if !candidates
            .pinned_descriptors()
            .iter()
            .any(|pin| pin.height == context.authority.source_finalized_height)
        {
            return Ok(());
        }
        if work
            .verifier
            .source(context, self.ingress.world_budget())?
            .authorization_root()
            != *root
        {
            return Err(
                "canonical authorization update height has a different source table".into(),
            );
        }
        if let Some(handle) = &self.wallet_admission {
            handle.publish_processing_context(
                &self.authority,
                Some(serde_json::json!({
                    "context": context, "profile_id": synergy_etdag::PROCESSING_PROFILE_ID,
                    "ingress_kem_registry": self.authority.protected_ingress_registry()?
                })),
            )?;
        }
        work.verifier.context = context.clone();
        work.authorization_root = root.clone();
        work.requested_source = None;
        work.context_published = true;
        Ok(())
    }
    fn poll_pending_work_inner(&mut self, work: &mut ProcessingWork) -> Result<(), String> {
        self.reconcile_finalized_processing(work)?;
        self.refresh_processing_context(work)?;
        self.retry_finalized_processing_shares(work)?;
        // Finish disseminating locally owned originals before introducing more
        // RPC work into the same bounded pool. Otherwise a single ingress can
        // fill it with separate, partially replicated items, none of which has
        // enough replicas to certify availability and release its reservation.
        // This is local intake backpressure only: peer intake, existing workers
        // and PoSy continue, and the next request need not await block finality.
        let availability_ready = work.pending.pending_identities().all(|identity| {
            work.items
                .get(&identity.envelope_id)
                .is_some_and(|item| item.evidence.availability.is_some())
        });
        if !self.ingress_paused && availability_ready {
            if let Some(handle) = self.wallet_admission.clone() {
                if let Some(request) = handle.take_processing()? {
                    let result = (|| {
                        let retained = work
                            .pending
                            .retirement_budget(&request.admission.request.envelope.envelope_id);
                        let charge = request.owned_byte_charge();
                        let _charge = match retained.as_ref() {
                            Some(workspace) => workspace.reserve(charge),
                            None => self
                                .ingress
                                .world_budget()
                                .reserve_with_headroom(charge, PROCESSING_INTAKE_HEADROOM_BYTES),
                        }
                        .map_err(ProcessingStoreError::Resource)?;
                        let v = self.authored_processing_vertex(&request.admission)?;
                        self.accept_processing_vertex(work, v)
                    })();
                    match result {
                        Ok(()) => handle.complete(&request.id, Ok(serde_json::json!({ "newly_admitted":true,
                            "envelope_id": request.admission.request.envelope.envelope_id, "durable_pending":true, "finalized":false })))?,
                        Err(ProcessingStoreError::Resource(WorldResourceError::Capacity { .. }) | ProcessingStoreError::Full) => handle.return_processing_pending(request)?,
                        Err(ProcessingStoreError::Storage(error)) => return Err(format!("processing intake storage failure: {error}")),
                        Err(error) => handle.complete(&request.id, Err(error.to_string()))?,
                    }
                }
            }
        }
        #[cfg(test)]
        if self.ingress.processing_work_held()? {
            return Ok(());
        }
        // The index is bounded and prepaid. One serial worker owns each item;
        // detached members/completions retain that item's parent reservation.
        let ids = work
            .pending
            .pending_identities()
            .map(|i| i.envelope_id.clone())
            .collect::<Vec<_>>();
        for envelope in &ids {
            self.restore_processing_item(work, envelope)?;
            let Some(item) = work.items.get(envelope) else {
                continue;
            };
            if !item.frames.contains_key(&1) {
                let vote = self
                    .local_signer
                    .sign_availability_vote(item.context_root.clone(), item.vertex_id.clone())?;
                let frame = self.processing_frame(
                    EtdagNetworkMessage::ProcessingAvailabilityVoteV1(vote.clone()),
                    &item.workspace,
                )?;
                work.items
                    .get_mut(envelope)
                    .expect("located item")
                    .frames
                    .insert(1, frame);
                self.accept_processing_vote(work, vote)?;
            }
            self.publish_processing_member(work, envelope)?;
            self.advance_processing_reveal(work, envelope)?;
        }
        let payloads = work
            .items
            .values()
            .flat_map(|item| item.frames.values().map(|frame| frame.bytes.as_slice()));
        deliver_processing_retry_slice(
            payloads,
            self.members
                .iter()
                .filter(|peer| *peer != &self.local_signer.validator_id)
                .map(String::as_str),
            &mut work.cursor,
            &mut work.retry,
            Instant::now(),
            |peer, bytes| {
                for item in work.items.values() {
                    if let Some(vertex) = item.frames.get(&0) {
                        if vertex_retry_has_current_receipt(
                            &self.ingress,
                            &item.vertex_holders,
                            peer,
                            &vertex.bytes,
                            bytes,
                        )? {
                            return Ok(true);
                        }
                    }
                }
                self.ingress.try_publish_outbound(OutboundFrame {
                    peer_id: peer.into(),
                    protocol: ProtocolKind::Etdag,
                    payload: bytes.to_vec(),
                })
            },
        )?;
        self.publish_pending_processing_references(work)?;
        Ok(())
    }

    fn reconcile_finalized_processing(&mut self, work: &mut ProcessingWork) -> Result<(), String> {
        let tip = self
            .ingress
            .processing_finalized_world()?
            .map_or(0, |(height, _)| height);
        if work
            .finalized_store
            .as_ref()
            .is_none_or(|store| store.current().map_or(0, |state| state.finalized_height) != tip)
        {
            work.finalized_store = Some(
                synergy_state::FinalizedStateStore::load_budgeted(
                    &work.verifier.state_root,
                    self.ingress.world_budget().clone(),
                )
                .map_err(|error| format!("processing finalized fence: {error:?}"))?,
            );
        }
        if tip > work.observed_finality {
            let candidates = BudgetedCandidateStore::new_budgeted(
                &work.verifier.candidate_root,
                self.ingress.world_budget().clone(),
            )?;
            let mut scan = Vec::with_capacity(4);
            for pin in candidates
                .pinned_descriptors()
                .iter()
                .filter(|pin| pin.height > work.finalized_scan && pin.height <= tip)
            {
                let position = scan
                    .binary_search_by_key(&pin.height, |(height, _): &(u64, String)| *height)
                    .unwrap_or_else(|index| index);
                if position < 4 {
                    scan.insert(position, (pin.height, pin.block_id.clone()));
                    scan.truncate(4);
                }
            }
            for (height, block_id) in scan {
                if work.pending.pending_identities().next().is_some()
                    && candidates
                        .commitment(height)?
                        .is_some_and(|commitment| commitment.transaction_count > 0)
                {
                    let workspace = work
                        .pending
                        .pending_identities()
                        .next()
                        .and_then(|identity| work.pending.retirement_budget(&identity.envelope_id));
                    let proof = NativeProcessingRetirement::recover_pending(
                        &self.authority,
                        height,
                        &block_id,
                        &work.verifier.candidate_root,
                        &work.verifier.state_root,
                        &work.verifier.consensus_root,
                        work.pending.pending_identities(),
                        workspace.as_ref().unwrap_or(self.ingress.world_budget()),
                    )?;
                    let Some(proof) = proof else {
                        work.finalized_scan = height;
                        continue;
                    };
                    for identity in proof.identities() {
                        if work
                            .pending
                            .pending_identities()
                            .any(|pending| pending == identity)
                        {
                            work.pending
                                .mark_finalized(&identity.envelope_id, height, &block_id, &proof)
                                .map_err(|error| error.to_string())?;
                            if let Some(handle) = &self.wallet_admission {
                                handle.record_verified_stage(
                                    &identity.envelope_id,
                                    "finalized",
                                    serde_json::json!({
                                        "finalized": true,
                                        "finalized_height": height,
                                        "finalized_block_id": block_id,
                                    }),
                                )?;
                            }
                        }
                    }
                    self.ingress.release_finalized_processing(&proof)?;
                }
                work.finalized_scan = height;
            }
            if !candidates
                .pinned_descriptors()
                .iter()
                .any(|pin| pin.height > work.finalized_scan && pin.height <= tip)
            {
                work.observed_finality = tip;
            }
        }
        let finalized = work
            .pending
            .finalized_identities()
            .map(|(identity, height, block)| {
                (identity.envelope_id.clone(), height, block.to_owned())
            })
            .collect::<Vec<_>>();
        for (envelope, height, _block) in finalized {
            if let Some(item) = work.items.remove(&envelope) {
                if !work
                    .items
                    .values()
                    .any(|other| other.evidence.parents.contains(&item.vertex_id))
                {
                    work.verifier.members.remove(&item.vertex_id);
                }
            }
            work.pending
                .try_quiesce_finalized(&envelope)
                .map_err(|error| error.to_string())?;
            if let Some(retain) = self.retention_blocks {
                if tip
                    >= height
                        .checked_add(retain)
                        .ok_or("processing retirement fence overflow")?
                {
                    work.pending
                        .retire_finalized(
                            &envelope,
                            work.finalized_store
                                .as_ref()
                                .expect("loaded finalized fence"),
                            retain,
                        )
                        .map_err(|error| error.to_string())?;
                }
            }
        }
        Ok(())
    }

    fn retry_finalized_processing_shares(&self, work: &mut ProcessingWork) -> Result<(), String> {
        let now = Instant::now();
        if work
            .finalized_retry
            .is_some_and(|last| now.duration_since(last) < Duration::from_millis(250))
        {
            return Ok(());
        }
        work.finalized_retry = Some(now);
        let count = work.pending.finalized_identities().count();
        if count == 0 {
            work.finalized_retry_cursor = 0;
            return Ok(());
        }
        let index = work.finalized_retry_cursor % count;
        let (identity, height, _) = work
            .pending
            .finalized_identities()
            .nth(index)
            .expect("bounded finalized cursor");
        let envelope = identity.envelope_id.clone();
        let mut peers = Vec::new();
        for peer in self
            .members
            .iter()
            .filter(|peer| *peer != &self.local_signer.validator_id)
        {
            // Consensus finality alone does not prove execution. Require a
            // later native candidate ECHO before suppressing this public share.
            if !self.ingress.processing_peer_replayed_after(peer, height)? {
                peers.push(peer);
            }
        }
        if peers.is_empty() {
            work.finalized_retry_cursor = (index + 1) % count;
            return Ok(());
        }
        let replayed = work
            .pending
            .with_finalized_progress(&envelope, |evidence, budget| {
                let Some(vc) = &evidence.reveal_validation else {
                    return Err(ProcessingStoreError::Invalid(
                        "finalized reveal lacks native permission".into(),
                    ));
                };
                if vc.context.height > height {
                    return Err(ProcessingStoreError::Invalid(
                        "retained reveal follows its finalized consumption".into(),
                    ));
                }
                // These exact native-signed shares were public before consumption
                // finalized. This repeats their bytes; it neither decrypts a new
                // capsule nor grants a new reveal permission. Recipients retain
                // their ordinary finality and native share-verification fences.
                let Some(share) = evidence
                    .shares
                    .iter()
                    .find(|share| share.validator_id == self.local_signer.validator_id)
                    .or_else(|| evidence.shares.first())
                else {
                    return Ok(false);
                };
                let frame = check(self.processing_frame(
                    EtdagNetworkMessage::ProcessingDecryptShareV1(share.clone()),
                    budget,
                ))?;
                for peer in &peers {
                    if !check(self.ingress.try_publish_outbound(OutboundFrame {
                        peer_id: (*peer).clone(),
                        protocol: ProtocolKind::Etdag,
                        payload: frame.bytes.clone(),
                    }))? {
                        return Ok(false);
                    }
                }
                Ok(true)
            });
        match replayed {
            Ok(Some(false))
            | Err(ProcessingStoreError::Resource(WorldResourceError::Capacity { .. })) => {}
            Ok(_) => work.finalized_retry_cursor = (index + 1) % count,
            Err(error) => return Err(error.to_string()),
        }
        Ok(())
    }
    fn publish_pending_processing_references(&self, work: &ProcessingWork) -> Result<(), String> {
        let Some(parent) = self.ingress.processing_certified_parent()? else {
            return Ok(());
        };
        let tip = self
            .ingress
            .processing_finalized_world()?
            .map_or(0, |(height, _)| height);
        if work.observed_finality < tip {
            return self.ingress.invalidate_processing_proof_references();
        }
        let count = work.pending.identities().count();
        let _scratch = match self.ingress.world_budget().reserve(count * 256 + 4096) {
            Ok(permit) => permit,
            Err(WorldResourceError::Capacity { .. }) => {
                return self.ingress.invalidate_processing_proof_references()
            }
            Err(error) => return Err(error.to_string()),
        };
        let mut heights = std::collections::BTreeSet::new();
        heights.extend(work.pending.source_heights().filter(|height| *height > 0));
        if work.verifier.context.authority.source_finalized_height > 0 {
            heights.insert(work.verifier.context.authority.source_finalized_height);
        }
        if let Some((context, _)) = &work.requested_source {
            heights.insert(context.authority.source_finalized_height);
        }
        for (_, height, _) in work.pending.finalized_identities() {
            heights.insert(height);
            heights.insert(
                height
                    .checked_sub(1)
                    .ok_or("processing finalized parent underflow")?,
            );
        }
        let Some(namespace) =
            try_processing_namespace(&self.authority, self.ingress.world_budget())?
        else {
            return self.ingress.invalidate_processing_proof_references();
        };
        let candidates = BudgetedCandidateStore::new_budgeted(
            &work.verifier.candidate_root,
            self.ingress.world_budget().clone(),
        )?;
        for identity in work.pending.pending_identities() {
            if let Some(vc) = work
                .items
                .get(&identity.envelope_id)
                .and_then(|item| item.evidence.reveal_validation.as_ref())
            {
                heights.insert(vc.context.height);
                continue;
            }
            let Some(claim) = synergy_execution::processing_member_claim_optional(
                &parent.state,
                &identity.sender_wallet,
                identity.sender_nonce,
            )
            .map_err(|error| error.to_string())?
            else {
                if parent
                    .state
                    .accounts
                    .get(&identity.sender_wallet)
                    .map_or(0, |account| account.nonce)
                    > identity.sender_nonce
                {
                    return self.ingress.invalidate_processing_proof_references();
                }
                continue;
            };
            let group = synergy_execution::processing_group_state(
                &parent.state,
                &namespace,
                claim.group_number,
            )
            .map_err(|error| error.to_string())?;
            if let Some(successor) = group.closed_by_successor {
                let Some(store) = self.ingress.processing_proposal_store()? else {
                    return self.ingress.invalidate_processing_proof_references();
                };
                let records = match store
                    .lock()
                    .map_err(|_| "processing proposal journal lock poisoned")?
                    .try_group_candidates(&successor)
                {
                    Ok(records) => records,
                    Err(error) if error.is_capacity() => {
                        return self.ingress.invalidate_processing_proof_references()
                    }
                    Err(error) => return Err(error.to_string()),
                };
                let mut found = false;
                for (height, id) in records {
                    if candidates
                        .commitment(height)?
                        .is_some_and(|candidate| candidate.block_id == id)
                    {
                        heights.insert(height);
                        found = true;
                        break;
                    }
                }
                if !found {
                    return self.ingress.invalidate_processing_proof_references();
                }
            }
        }
        self.ingress
            .publish_processing_proof_references(&parent.block_id, &heights)?;
        Ok(())
    }

    fn advance_processing_reveal(
        &mut self,
        work: &mut ProcessingWork,
        envelope: &EtdagDigest,
    ) -> Result<(), String> {
        #[cfg(feature = "qualification-timing")]
        let _diagnostic = diagnostic_span(DiagnosticStage::RevealAdvance);
        let Some(item) = work.items.get(envelope) else {
            return Ok(());
        };
        if item.evidence.availability.is_none() || item.completed {
            return Ok(());
        }
        if item.evidence.reveal_validation.is_none() {
            // Unfinished order finality is an ordinary async wait. Do not
            // repeatedly read/verify certified journals that cannot satisfy it.
            // The exact height/block/root fence below still authorizes reveal.
            let Some(finalized) = self.ingress.latest_finality()? else {
                return Ok(());
            };
            let Some(latest) = self.ingress.processing_certified_parent()? else {
                return Ok(());
            };
            let namespace = processing_namespace(&self.authority, &item.workspace)?;
            let Some(claim) = synergy_execution::processing_member_claim_optional(
                latest.state.as_ref(),
                &item.evidence.envelope_ref.sender_id,
                item.evidence.envelope_ref.nonce_slot,
            )
            .map_err(|e| e.to_string())?
            else {
                return Ok(());
            };
            let group = synergy_execution::processing_group_state(
                latest.state.as_ref(),
                &namespace,
                claim.group_number,
            )
            .map_err(|e| e.to_string())?;
            let Some(successor) = group.closed_by_successor else {
                return Ok(());
            };
            let Some(stages) = self.ingress.processing_proposal_store()? else {
                return Ok(());
            };
            let matches = match stages
                .lock()
                .map_err(|_| "processing proposal journal lock poisoned")?
                .try_group_candidates_at_or_below(&successor, finalized.height)
            {
                Ok(records) => records,
                Err(error) if error.is_retryable() => return Ok(()),
                Err(error) => return Err(error.to_string()),
            };
            let store = BudgetedCandidateStore::new_budgeted(
                &work.verifier.candidate_root,
                item.workspace.clone(),
            )?;
            let mut validation = None;
            for (height, id) in matches {
                let Some(candidate) = store.get_budgeted(height).map_err(|e| e.to_string())? else {
                    continue;
                };
                if candidate.block_id == id {
                    let vc = match stages
                        .lock()
                        .map_err(|_| "processing proposal journal lock poisoned")?
                        .try_with_validation(&id, |vc| Ok(vc.clone()))
                    {
                        Ok(value) => value,
                        Err(error) if error.is_retryable() => return Ok(()),
                        Err(error) => return Err(error.to_string()),
                    };
                    if !finalized_processing_order(
                        &vc,
                        self.ingress.finalized_record(height)?.as_ref(),
                    )? {
                        continue;
                    }
                    validation = Some(vc);
                    break;
                }
            }
            let Some(vc) = validation else { return Ok(()) };
            let reveal_proof = serde_json::json!({
                "proposal_height": vc.context.height,
                "proposal_block_id": vc.candidate.block_id,
                "finalized": false,
            });
            let mut evidence = item.evidence.clone();
            evidence.reveal_validation = Some(vc);
            {
                #[cfg(feature = "qualification-timing")]
                let _diagnostic = diagnostic_span(DiagnosticStage::ProgressWrite);
                work.pending
                    .update_progress(envelope, &evidence, &work.verifier)
                    .map_err(|e| e.to_string())?;
            }
            work.items.get_mut(envelope).expect("located item").evidence = evidence;
            if let Some(handle) = &self.wallet_admission {
                handle.record_verified_stage(envelope, "reveal_authorized", reveal_proof)?;
            }
        }
        let item = work.items.get(envelope).expect("located item");
        // Apply the same fence to recovered progress/completions. Restart may
        // restore a valid VC before the local verified finality cache is warm.
        let vc = item
            .evidence
            .reveal_validation
            .as_ref()
            .expect("checked VC");
        if !finalized_processing_order(
            vc,
            self.ingress.finalized_record(vc.context.height)?.as_ref(),
        )? {
            return Ok(());
        }
        if !item.frames.contains_key(&3) && item.local_share_rejected.is_none() {
            let mut rejected = None;
            let evidence = &item.evidence;
            let historical_pending = work
                .pending
                .allows_historical_kem_recovery(envelope)
                .map_err(|e| e.to_string())?;
            let message = work
                .pending
                .with_worker(envelope, &work.verifier, |context, _, admission, budget| {
                    let source = check(work.verifier.source(context, budget))?;
                    let v = vertex(admission, evidence);
                    let parents = check(work.verifier.parents(&evidence.parents))?;
                    let native = check(NativeProcessingVertex::verify(
                        &source,
                        &v,
                        evidence.availability.as_ref().expect("checked VAC"),
                        &parents,
                        budget,
                    ))?;
                    let candidate = check(parent_at(
                        &work.verifier.candidate_root,
                        evidence.reveal_validation.as_ref().expect("checked VC"),
                        budget,
                    ))?;
                    let parent = check(NativeProcessingParent::verify(
                        &candidate,
                        evidence.reveal_validation.as_ref().expect("checked VC"),
                        &self.authority,
                    ))?;
                    let permission = check(parent.reveal_permission(&native))?;
                    let capsule = admission
                        .request
                        .envelope
                        .share_capsules
                        .iter()
                        .find(|c| c.validator_id == self.local_signer.validator_id)
                        .ok_or_else(|| {
                            ProcessingStoreError::Invalid(
                                "local original capsule unavailable".into(),
                            )
                        })?;
                    let key = check(
                        synergy_etdag::crypto::active_key_for_validator(
                            self.authority
                                .protected_ingress_registry()
                                .map_err(ProcessingStoreError::Verification)?,
                            &self.local_signer.validator_id,
                            context.authority.target_height,
                        )
                        .map_err(|e| format!("{e:?}")),
                    )?;
                    let result = match self.ingress_custody.kem.as_ref() {
                        Some(kem) => {
                            synergy_etdag::crypto::decrypt_share_capsule_with_kem_diagnostic(
                                &admission.request.envelope,
                                capsule,
                                key,
                                &self.ingress_custody.secret,
                                historical_pending,
                                kem.as_ref(),
                            )
                        }
                        None => {
                            let decrypt = if historical_pending {
                                synergy_etdag::crypto::decrypt_historical_share_capsule_diagnostic
                            } else {
                                synergy_etdag::crypto::decrypt_share_capsule_diagnostic
                            };
                            decrypt(
                                &admission.request.envelope,
                                capsule,
                                key,
                                &self.ingress_custody.secret,
                            )
                        }
                    };
                    let mut secret = match result {
                        Ok(share) => share,
                        Err(failure) => {
                            rejected = Some(check(classify_local_capsule_failure(failure.stage))?);
                            return Ok(None);
                        }
                    };
                    let bytes = secret
                        .canonical_bytes()
                        .map_err(|e| ProcessingStoreError::Verification(format!("{e:?}")));
                    secret.value.fill(0);
                    let mut message = ProcessingDecryptShare {
                        share_version: 1,
                        permission,
                        validator_id: self.local_signer.validator_id.clone(),
                        key_id: self.local_signer.key_id.as_str().into(),
                        ingress_kem_key_id: capsule.ingress_kem_key_id.clone(),
                        share_index: capsule.share_index,
                        share_commitment: capsule.share_commitment.clone(),
                        share_bytes: bytes?,
                        signature: Vec::new(),
                    };
                    message.signature = check(
                        self.local_signer
                            .signer
                            .sign(
                                &self.local_signer.key_id,
                                &SigningContext {
                                    domain: "SYNERGY-ETDAG-SIGNATURE-V1".into(),
                                    chain_id: self.local_signer.chain_id,
                                    epoch: Some(self.local_signer.epoch),
                                    height: None,
                                },
                                &check(message.signing_bytes().map_err(|e| format!("{e:?}")))?,
                            )
                            .map(|s| s.bytes)
                            .map_err(|e| e.to_string()),
                    )?;
                    Ok(Some(message))
                })
                .map_err(|e| e.to_string())?;
            if let Some(stage) = rejected {
                work.items
                    .get_mut(envelope)
                    .expect("located item")
                    .local_share_rejected = Some(stage);
                eprintln!("ETDAG_LOCAL_CAPSULE_REJECTED envelope={} stage={stage:?} pending_preserved=true", envelope.0);
            }
            if let Some(message) = message {
                self.accept_processing_share(work, message.clone())?;
                let item = work.items.get_mut(envelope).expect("located item");
                item.frames.insert(
                    3,
                    self.processing_frame(
                        EtdagNetworkMessage::ProcessingDecryptShareV1(message),
                        &item.workspace,
                    )?,
                );
            }
        }
        let item = work.items.get(envelope).expect("located item");
        let threshold = synergy_etdag::crypto::governed_reveal_threshold(
            self.members.len(),
            self.members.len().saturating_sub(1),
        )
        .map_err(|e| format!("{e:?}"))?;
        if !work.pending.has_completion(envelope) && item.evidence.shares.len() < threshold {
            return Ok(());
        }
        let evidence = &item.evidence;
        #[cfg(feature = "qualification-timing")]
        let completion_diagnostic = diagnostic_span(DiagnosticStage::CompletionBuild);
        let (completion, witness) = work
            .pending
            .with_worker(envelope, &work.verifier, |context, _, admission, budget| {
                let source = check(work.verifier.source(context, budget))?;
                let v = vertex(admission, evidence);
                let parents = check(work.verifier.parents(&evidence.parents))?;
                let native = check(NativeProcessingVertex::verify(
                    &source,
                    &v,
                    evidence.availability.as_ref().expect("checked VAC"),
                    &parents,
                    budget,
                ))?;
                let vc = evidence.reveal_validation.as_ref().expect("checked VC");
                let candidate = check(parent_at(&work.verifier.candidate_root, vc, budget))?;
                let parent = check(NativeProcessingParent::verify(
                    &candidate,
                    vc,
                    &self.authority,
                ))?;
                let completion = check(NativeProcessingCompletion::decrypt_in(
                    &parent,
                    &native,
                    &evidence.shares,
                    budget,
                ))?;
                let witness = ProcessingCompletionEvidence::from_inputs(
                    &v,
                    evidence.availability.as_ref().expect("checked VAC"),
                    vc,
                    &evidence.shares,
                    &completion.record,
                );
                Ok((Arc::new(completion), witness))
            })
            .map_err(|e| e.to_string())?;
        #[cfg(feature = "qualification-timing")]
        drop(completion_diagnostic);
        {
            #[cfg(feature = "qualification-timing")]
            let _diagnostic = diagnostic_span(DiagnosticStage::CompletionDurable);
            work.pending
                .complete(envelope, &witness, &work.verifier)
                .map_err(|e| e.to_string())?;
        }
        if let Some(handle) = &self.wallet_admission {
            // Completion is durable local processing output.  It is not a
            // PoSy-finality claim; the separate finalized stage is recorded
            // only after authenticated retirement proof below.
            handle.record_verified_stage(
                envelope,
                "execution_completed",
                serde_json::json!({"finalized": false}),
            )?;
        }
        self.ingress.publish_processing_completion(completion)?;
        work.items
            .get_mut(envelope)
            .expect("located item")
            .completed = true;
        Ok(())
    }
}

#[cfg(test)]
mod paced_retry_tests {
    use super::deliver_processing_retry_slice;
    use std::time::{Duration, Instant};

    #[test]
    fn capsule_input_rejection_is_local_but_custody_failure_remains_fatal() {
        use synergy_etdag::crypto::CapsuleVerificationStage as Stage;
        for stage in [
            Stage::Envelope,
            Stage::CapsuleBinding,
            Stage::KemCiphertext,
            Stage::CapsuleContext,
            Stage::CapsuleAead,
            Stage::ShareEncoding,
            Stage::ShareCommitment,
        ] {
            assert_eq!(super::classify_local_capsule_failure(stage).unwrap(), stage);
        }
        for stage in [
            Stage::Provider,
            Stage::RegistryKey,
            Stage::SecretKey,
            Stage::KeyPossession,
        ] {
            assert!(super::classify_local_capsule_failure(stage).is_err());
        }
    }

    #[test]
    fn vertex_vote_receipt_skips_only_exact_original_on_current_session() {
        use super::{vertex_retry_has_current_receipt, AuthenticatedIngress, AuthenticatedPeer};
        use std::collections::BTreeMap;
        use synergy_protocol_types::SessionId;
        let ingress = AuthenticatedIngress::default();
        let peer = "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn";
        let original = b"native encrypted vertex".to_vec();
        let equal_other_allocation = original.clone();
        let vote = b"availability vote";
        let mut holders = BTreeMap::new();
        ingress.admit_session(peer.into(), SessionId(1)).unwrap();
        assert!(
            !vertex_retry_has_current_receipt(&ingress, &holders, peer, &original, &original)
                .unwrap()
        );
        holders.insert(
            peer.into(),
            AuthenticatedPeer::new(peer, SessionId(1), vec![]).unwrap(),
        );
        assert!(
            vertex_retry_has_current_receipt(&ingress, &holders, peer, &original, &original)
                .unwrap()
        );
        assert!(!vertex_retry_has_current_receipt(
            &ingress,
            &holders,
            "other-peer",
            &original,
            &original
        )
        .unwrap());
        assert!(
            !vertex_retry_has_current_receipt(&ingress, &holders, peer, &original, vote).unwrap()
        );
        assert!(!vertex_retry_has_current_receipt(
            &ingress,
            &holders,
            peer,
            &original,
            &equal_other_allocation
        )
        .unwrap());
        ingress.admit_session(peer.into(), SessionId(2)).unwrap();
        assert!(
            !vertex_retry_has_current_receipt(&ingress, &holders, peer, &original, &original)
                .unwrap()
        );
        holders.insert(
            peer.into(),
            AuthenticatedPeer::new(peer, SessionId(2), vec![]).unwrap(),
        );
        ingress.discard_session(peer, SessionId(1)).unwrap();
        assert!(
            vertex_retry_has_current_receipt(&ingress, &holders, peer, &original, &original)
                .unwrap()
        );
        ingress.discard_session(peer, SessionId(2)).unwrap();
        assert!(
            !vertex_retry_has_current_receipt(&ingress, &holders, peer, &original, &original)
                .unwrap()
        );
    }

    #[test]
    fn reveal_waits_for_exact_existing_posy_finality() {
        use synergy_posy::{
            CertifiedCandidateSubject, ConsensusObjectContext, FinalizedBlockRecord,
            ProposalValidationCertificate, SimplifiedFinalityParent,
        };
        let context = ConsensusObjectContext {
            schema_version: 1,
            chain_id: 1266,
            network_id: "isolated".into(),
            protocol_version: "test".into(),
            epoch: 1,
            height: 19,
            round: 0,
            epoch_context_root: "a".repeat(64),
            consensus_parameter_root: "b".repeat(64),
            active_validator_set_root: "c".repeat(64),
            validator_consensus_key_root: "d".repeat(64),
            frozen_voting_weight_root: "e".repeat(64),
        };
        // This test isolates the finality fence. Native VC authentication is
        // separately exercised by the genuine five-validator lifecycle test.
        let vc = ProposalValidationCertificate {
            context: context.clone(),
            candidate: CertifiedCandidateSubject {
                context,
                block_id: "1".repeat(64),
                parent_block_id: "2".repeat(64),
                parent: SimplifiedFinalityParent::QuorumCertificate {
                    height: 18,
                    block_id: "2".repeat(64),
                    qc_id: "7".repeat(64),
                },
                protected_execution_root: "3".repeat(64),
            },
            echoes: vec![],
        };
        assert!(!super::finalized_processing_order(&vc, None).unwrap());
        let record = FinalizedBlockRecord {
            height: 19,
            block_id: vc.candidate.block_id.clone(),
            protected_execution_root: vc.candidate.protected_execution_root.clone(),
            finality_certificate_id: "4".repeat(64),
        };
        assert!(super::finalized_processing_order(&vc, Some(&record)).unwrap());
        let mut wrong = record.clone();
        wrong.height += 1;
        assert!(super::finalized_processing_order(&vc, Some(&wrong)).is_err());
        let mut wrong = record.clone();
        wrong.block_id = "5".repeat(64);
        assert!(super::finalized_processing_order(&vc, Some(&wrong)).is_err());
        let mut wrong = record;
        wrong.protected_execution_root = "6".repeat(64);
        assert!(super::finalized_processing_order(&vc, Some(&wrong)).is_err());
    }

    #[test]
    fn partial_queue_progress_is_paced_and_eventually_covers_every_pair() {
        let payloads = (0u8..20).map(|id| [id]).collect::<Vec<_>>();
        let peers = ["a", "b", "c", "d"];
        let start = Instant::now();
        let mut last = None;
        let mut cursor = 0;
        let mut accepted = Vec::new();
        let mut attempts = Vec::new();
        for millis in 0..=1000u64 {
            let mut queued = 0;
            let mut attempted = false;
            deliver_processing_retry_slice(
                payloads.iter().map(|payload| payload.as_slice()),
                peers.iter().copied(),
                &mut cursor,
                &mut last,
                start + Duration::from_millis(millis),
                |peer, payload| {
                    attempted = true;
                    if queued == 16 {
                        return Ok(false);
                    }
                    queued += 1;
                    accepted.push((payload[0], peer.to_owned()));
                    Ok(true)
                },
            )
            .unwrap();
            if attempted {
                attempts.push(millis);
            }
        }
        assert_eq!(attempts, [0, 250, 500, 750, 1000]);
        assert_eq!(cursor, 0);
        assert_eq!(
            accepted,
            (0u8..20)
                .flat_map(|id| peers.iter().map(move |peer| (id, (*peer).to_owned())))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn full_queue_retains_exact_pair_without_busy_retry_and_errors_propagate() {
        let start = Instant::now();
        let mut last = None;
        let mut cursor = 1;
        deliver_processing_retry_slice(
            [b"work".as_slice()].into_iter(),
            ["a", "b"].into_iter(),
            &mut cursor,
            &mut last,
            start,
            |_, _| Ok(false),
        )
        .unwrap();
        assert_eq!(cursor, 1);
        assert_eq!(last, Some(start));
        deliver_processing_retry_slice(
            [b"work".as_slice()].into_iter(),
            ["a", "b"].into_iter(),
            &mut cursor,
            &mut last,
            start + Duration::from_millis(249),
            |_, _| panic!("full queue must not cause an immediate retry"),
        )
        .unwrap();
        let mut accepted = Vec::new();
        deliver_processing_retry_slice(
            [b"work".as_slice()].into_iter(),
            ["a", "b"].into_iter(),
            &mut cursor,
            &mut last,
            start + Duration::from_millis(250),
            |peer, bytes| {
                accepted.push((peer.to_owned(), bytes.to_vec()));
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(
            accepted,
            [
                ("b".into(), b"work".to_vec()),
                ("a".into(), b"work".to_vec())
            ]
        );
        assert_eq!(cursor, 1);
        let error = deliver_processing_retry_slice(
            [b"work".as_slice()].into_iter(),
            ["a", "b"].into_iter(),
            &mut cursor,
            &mut last,
            start + Duration::from_millis(500),
            |_, _| Err("queue unavailable".into()),
        )
        .unwrap_err();
        assert_eq!(error, "queue unavailable");
        assert_eq!(cursor, 1);
    }
}
