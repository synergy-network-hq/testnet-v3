//! Shared bounded ingress from authenticated networking to owner services.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use synergy_etdag::execution::PreparedProtectedBatch;
type ExecutionCandidate = Arc<synergy_execution::BudgetedExecutionCandidate>;
use synergy_network::protocol::InboundFrame;
use synergy_posy::FinalizedBlockRecord;
use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind, SessionId};
use synergy_state::world_resources::{BudgetedWorld, WorldResourcePermit};
type ProcessingProofReferences = (Arc<BTreeSet<u64>>, Arc<WorldResourcePermit>);
use synergy_sync::{FinalizedCandidateRequest, HeadClaim, SnapshotChunkRequest, VerifiedHead};
use synergy_transport_registry::VerifiedSnapshot;

/// Response metadata and its World stay charged while queued or deferred.
#[derive(Debug)]
pub(crate) struct FinalizedCandidateResponse {
    pub response: synergy_sync::BudgetedFinalizedCandidateResponse,
    pub _metadata: Arc<WorldResourcePermit>,
}
#[cfg(test)]
impl FinalizedCandidateResponse {
    pub(super) fn decode_test<T: serde::Serialize>(
        value: &T,
        ingress: &AuthenticatedIngress,
    ) -> Self {
        let bytes = serde_json::to_vec(value).unwrap();
        let (response, metadata) =
            synergy_sync::decode_budgeted_candidate_response(&bytes, ingress.world_budget())
                .unwrap()
                .into_parts();
        Self {
            response,
            _metadata: Arc::new(metadata),
        }
    }
}
#[cfg(test)]
impl PartialEq for FinalizedCandidateResponse {
    fn eq(&self, other: &Self) -> bool {
        self.response == other.response
    }
}
#[cfg(test)]
impl serde::Serialize for FinalizedCandidateResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.response.serialize(serializer)
    }
}
#[cfg(test)]
impl Clone for FinalizedCandidateResponse {
    fn clone(&self) -> Self {
        let bytes = serde_json::to_vec(&self.response).unwrap();
        let (response, metadata) =
            synergy_sync::decode_budgeted_candidate_response(&bytes, self.candidate.state.budget())
                .unwrap()
                .into_parts();
        Self {
            response,
            _metadata: Arc::new(metadata),
        }
    }
}
impl std::ops::Deref for FinalizedCandidateResponse {
    type Target = synergy_sync::BudgetedFinalizedCandidateResponse;
    fn deref(&self) -> &Self::Target {
        &self.response
    }
}

const MAX_PER_PROTOCOL: usize = 64;
const MAX_PENDING_CUT_RECOVERY_BYTES: usize = 8 * 1024 * 1024;

fn cut_recovery_resource_bytes(g: &synergy_etdag::persistence::CutRecoveryGeneration) -> usize {
    std::mem::size_of_val(g)
        .saturating_add(g.original_cutoff_context_root.0.capacity())
        .saturating_add(g.previous_cutoff_context_root.0.capacity())
        .saturating_add(g.cutoff_context_root.0.capacity())
        .saturating_add(g.timeout_id.capacity())
        .saturating_add(g.authorization.capacity())
        .saturating_add(512) // map node and spare queue slots
}

// The sum is 64. Fixed service poll order cannot let one protocol consume
// another owner's entire retry budget.
fn outbound_limit(protocol: ProtocolKind) -> usize {
    match protocol {
        ProtocolKind::Posy | ProtocolKind::Etdag => 16,
        ProtocolKind::Sync => 8,
        ProtocolKind::Status
        | ProtocolKind::Discovery
        | ProtocolKind::Transaction
        | ProtocolKind::Snapshot
        | ProtocolKind::Observer
        | ProtocolKind::Sxcp => 4,
    }
}

#[derive(Default)]
struct Queues {
    frames: BTreeMap<ProtocolKind, VecDeque<InboundFrame>>,
    authenticated_sessions: BTreeMap<String, SessionId>,
    apqe_sessions: BTreeMap<String, SessionId>,
    verified_peer_heights: BTreeMap<String, (SessionId, u64)>,
    // Transport hint from an already admitted native ECHO, never voting authority.
    processing_input_echoes: BTreeMap<String, (SessionId, u64, u64, String)>,
    verified_overlay: Option<VerifiedSnapshot>,
    dials: VecDeque<DialRequest>,
    outbound: VecDeque<OutboundFrame>,
    peer_controls: VecDeque<PeerControlRequest>,
    sync_controls: VecDeque<SyncControlRequest>,
    etdag_controls: VecDeque<EtdagControlRequest>,
    head_claims: VecDeque<(AuthenticatedPeer, HeadClaim)>,
    verified_heads: VecDeque<VerifiedHead>,
    sync_candidate_requests: VecDeque<(AuthenticatedPeer, FinalizedCandidateRequest, bool)>,
    sync_candidate_responses: VecDeque<(AuthenticatedPeer, FinalizedCandidateResponse)>,
    snapshot_chunk_requests: VecDeque<(AuthenticatedPeer, SnapshotChunkRequest)>,
    finalized_execution_commits: VecDeque<FinalizedExecutionCommit>,
    snapshot_restore_handoffs: VecDeque<SnapshotRestoreHandoff>,
    snapshot_restore_receipts: VecDeque<SnapshotRestoreReceipt>,
    verified_sync_candidates: VecDeque<(ExecutionCandidate, FinalizedBlockRecord)>,
    protected_batches: VecDeque<PreparedProtectedBatch>,
    local_protected_vertices: VecDeque<LocalProtectedVertexRequest>,
    local_protected_vertex_bytes: usize,
    execution_candidates: VecDeque<ExecutionCandidate>,
    processing_build_request: Option<Arc<ProcessingBuildRequest>>,
    processing_slot_pool: Option<Arc<synergy_state::world_resources::WorldResourceBudget>>,
    processing_candidates: VecDeque<ProcessingCandidateHandoff>,
    processing_input_frames: VecDeque<ProcessingInputFrame>,
    processing_announcements: VecDeque<ProcessingInputFrame>,
    processing_local_validator: Option<String>,
    processing_certified_parent: Option<ExecutionCandidate>,
    #[cfg(test)]
    processing_work_held: bool,
    #[cfg(test)]
    processing_handoff_held: Option<(u64, u64)>,
    #[cfg(test)]
    processing_stale_handoffs: usize,
    processing_proposal_store:
        Option<Arc<Mutex<super::processing_proposals::ProcessingProposalStore>>>,
    processing_members: BTreeMap<
        synergy_etdag::EtdagDigest,
        Arc<super::processing_pipeline::NativeProcessingMember>,
    >,
    processing_completions: BTreeMap<
        synergy_etdag::EtdagDigest,
        Arc<super::processing_pipeline::NativeProcessingCompletion>,
    >,
    processing_proof_refs: Option<(String, Arc<BTreeSet<u64>>, Arc<WorldResourcePermit>)>,
    processing_finalized_world: Option<(u64, Arc<BudgetedWorld>)>,
    finality: VecDeque<FinalizedBlockRecord>,
    latest_finality: Option<FinalizedBlockRecord>,
    latest_finality_witness: Option<Vec<u8>>,
    observations: ChainObservations,
    finalized_records: BTreeMap<u64, FinalizedBlockRecord>,
    finality_history: Option<FinalityHistory>,
    protected_commitments: BTreeMap<
        u64,
        (
            synergy_etdag::DeterministicProtectedBatch,
            synergy_etdag::EtdagDigest,
        ),
    >,
    protected_materials: BTreeMap<u64, synergy_etdag::execution::ProtectedProposalMaterial>,
    proposal_validations: BTreeMap<u64, synergy_posy::ProposalValidationCertificate>,
    cut_recovery_states: BTreeMap<u64, CutRecoveryState>,
    cut_recovery_generations: BTreeMap<u64, Vec<synergy_etdag::persistence::CutRecoveryGeneration>>,
}

/// Immutable assembly instruction exported by the existing PoSy control plane.
/// No wire decoder, worker completion or diagnostic JSON can construct it.
/// The execution owner may assemble only for this slot and exact parent.
pub(crate) struct ProcessingBuildRequest {
    pub context: synergy_posy::ConsensusObjectContext,
    pub parent: synergy_posy::SimplifiedFinalityParent,
    pub proposer: String,
    pub takeover: Option<synergy_posy::AcceptedTimeoutSummary>,
    pub mandatory_carry: Option<synergy_posy::CertifiedCandidateSubject>,
    _permit: WorldResourcePermit,
}

pub(crate) struct ProcessingCandidateHandoff {
    pub request: Arc<ProcessingBuildRequest>,
    pub candidate: ExecutionCandidate,
}

pub(super) struct ProcessingInputFrame {
    pub sender: String,
    pub payload: Vec<u8>,
    _permit: WorldResourcePermit,
}

pub(super) struct ProcessingSnapshot {
    pub members: Vec<Arc<super::processing_pipeline::NativeProcessingMember>>,
    pub completions: Vec<Arc<super::processing_pipeline::NativeProcessingCompletion>>,
    _permit: WorldResourcePermit,
}

#[derive(Debug, Clone)]
pub(super) struct CutRecoveryState {
    pub cutoff: synergy_etdag::EtdagDigest,
    pub last_timeout_id: Option<String>,
    pub committed: bool,
}

pub(super) struct LocalProtectedVertexRequest {
    pub vertex: synergy_etdag::TransactionVertex,
    pub response: mpsc::Sender<Result<(), String>>,
    encoded_bytes: usize,
}

#[derive(Clone)]
struct FinalityHistory {
    root: std::path::PathBuf,
    authority: Arc<super::authority::VerifiedAuthority>,
    transition: Option<Arc<super::authority::VerifiedTransitionContext>>,
}

impl FinalityHistory {
    fn verified_qc(
        &self,
        store: &synergy_posy::VerifiedQuorumCertificateStore,
        height: u64,
    ) -> Result<Option<synergy_posy::SimplifiedQuorumCertificate>, String> {
        // Select only by signed epoch ranges, then retain the store's complete
        // canonical-record and signature verification under that exact epoch.
        let selected = if (self.authority.epoch.epoch_start_height
            ..=self.authority.epoch.epoch_end_height)
            .contains(&height)
        {
            &self.authority
        } else if let Some(transition) = &self.transition {
            transition.verify_current(&self.authority)?;
            let previous = transition.previous_authority();
            if !(previous.epoch.epoch_start_height..=previous.epoch.epoch_end_height)
                .contains(&height)
            {
                return Err("historical QC lies outside authenticated epoch lineage".into());
            }
            previous
        } else {
            return Err("historical QC requires its authenticated epoch transition".into());
        };
        // RPC/source workers must not share the supervisor's nonblocking engine.
        let authority = super::authority::VerifiedAuthority::worker_context(selected)?;
        store
            .get_verified(height, &authority.epoch, &authority.registry, authority.as_ref())
            .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct DialRequest {
    pub peer_id: String,
    pub address: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct OutboundFrame {
    pub peer_id: String,
    pub protocol: ProtocolKind,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerControlAction {
    Disconnect { peer_id: String },
    Quarantine { peer_id: String, until: u64 },
    Ban { peer_id: String, until: Option<u64> },
    Unban { peer_id: String },
}

impl PeerControlAction {
    pub fn peer_id(&self) -> &str {
        match self {
            Self::Disconnect { peer_id }
            | Self::Quarantine { peer_id, .. }
            | Self::Ban { peer_id, .. }
            | Self::Unban { peer_id } => peer_id,
        }
    }
}

pub struct PeerControlRequest {
    pub action: PeerControlAction,
    pub response: mpsc::SyncSender<Result<(), String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncControlAction {
    Pause,
    Resume,
    RetrySource { peer_id: String },
}

pub struct SyncControlRequest {
    pub action: SyncControlAction,
    pub response: mpsc::SyncSender<Result<(), String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtdagControlAction {
    PauseIngress,
    ResumeIngress,
}

pub struct EtdagControlRequest {
    pub action: EtdagControlAction,
    pub response: mpsc::SyncSender<Result<(), String>>,
}

#[derive(Debug, Clone)]
pub struct FinalizedExecutionCommit {
    pub epoch: u64,
    pub finality: FinalizedBlockRecord,
    pub application_state_root: String,
}

#[derive(Debug, Clone)]
pub struct SnapshotRestoreHandoff {
    pub epoch: u64,
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub finality_evidence_id: String,
    pub application_state_root: String,
    pub state: Arc<BudgetedWorld>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRestoreReceipt {
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub application_state_root: String,
}

#[derive(Default)]
struct ChainObservations {
    consensus: Option<serde_json::Value>,
    candidate: Option<serde_json::Value>,
    executed_height: Option<u64>,
    finalized_execution_height: Option<u64>,
    executed_total: u64,
    finalized_total: u64,
    counts: BTreeMap<u64, usize>,
    finalized_last_at: Option<std::time::Instant>,
    finalized_intervals_ms: VecDeque<f64>,
    maximum_finalized_gap_ms: Option<f64>,
}

fn observation_unix_ms() -> Result<u64, String> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis(),
    )
    .map_err(|e| e.to_string())
}

pub(super) enum CandidateResponseHandoff {
    Queued,
    StaleSession,
    Full(Box<(AuthenticatedPeer, FinalizedCandidateResponse)>),
}

#[derive(Clone)]
pub struct AuthenticatedIngress(
    Arc<Mutex<Queues>>,
    Arc<synergy_state::world_resources::WorldResourceBudget>,
);
#[cfg(test)]
impl Default for AuthenticatedIngress {
    fn default() -> Self {
        Self::with_world_budget(synergy_state::world_resources::WorldResourceBudget::new(
            synergy_config::default_world_memory_budget_bytes(),
        ))
    }
}

impl AuthenticatedIngress {
    pub fn with_world_budget(
        budget: Arc<synergy_state::world_resources::WorldResourceBudget>,
    ) -> Self {
        Self(Arc::new(Mutex::new(Queues::default())), budget)
    }
    pub fn world_budget(&self) -> &Arc<synergy_state::world_resources::WorldResourceBudget> {
        &self.1
    }

    /// Unsigned diagnostic snapshot; this never confers consensus authority.
    pub fn publish_consensus_observation(
        &self,
        height: u64,
        round: u64,
        epoch_context_root: String,
    ) -> Result<(), String> {
        if !synergy_posy::is_hash(&epoch_context_root) {
            return Err("consensus observation requires canonical epoch root".into());
        }
        let value = serde_json::json!({"height":height,"round":round,"epoch_context_root":epoch_context_root,
            "observed_at_unix_ms":observation_unix_ms()?,"authority":false});
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?
            .observations
            .consensus = Some(value);
        Ok(())
    }

    pub fn consensus_observation(&self) -> Result<Option<serde_json::Value>, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?
            .observations
            .consensus
            .clone())
    }

    /// Call only after native durable execution, and set finalized only after
    /// its finalized block/state/receipt commit has been acknowledged.
    pub fn record_execution_observation(
        &self,
        height: u64,
        transaction_count: usize,
        finalized: bool,
    ) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        let obs = &mut queues.observations;
        if let Some(count) = obs.counts.get(&height) {
            if *count != transaction_count {
                return Err("execution observation count conflicts at retained height".into());
            }
        }
        if obs.executed_height.is_none_or(|h| height > h) {
            obs.executed_total = obs.executed_total.saturating_add(transaction_count as u64);
            obs.executed_height = Some(height);
            obs.counts.insert(height, transaction_count);
            obs.counts.retain(|h, _| *h >= height.saturating_sub(127));
        }
        if finalized && obs.finalized_execution_height.is_none_or(|h| height > h) {
            obs.finalized_total = obs.finalized_total.saturating_add(transaction_count as u64);
            obs.finalized_execution_height = Some(height);
            let now = std::time::Instant::now();
            if let Some(previous) = obs.finalized_last_at {
                let interval = now.duration_since(previous).as_secs_f64() * 1000.0;
                obs.maximum_finalized_gap_ms = Some(
                    obs.maximum_finalized_gap_ms
                        .unwrap_or(interval)
                        .max(interval),
                );
                if obs.finalized_intervals_ms.len() == 128 {
                    obs.finalized_intervals_ms.pop_front();
                }
                obs.finalized_intervals_ms.push_back(interval);
            }
            obs.finalized_last_at = Some(now);
        }
        Ok(())
    }

    /// Unsigned, bounded owner state for the immediate canary diagnosis.
    pub(super) fn observe_candidate_stage(
        &self,
        height: u64,
        round: u64,
        candidate_height: Option<u64>,
        candidate_round: Option<u64>,
        stage: &'static str,
    ) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        queues.observations.candidate = Some(serde_json::json!({
            "height":height,"round":round,"candidate_height":candidate_height,
            "candidate_round":candidate_round,"stage":stage,"authority":false,
            "observed_at_unix_ms":observation_unix_ms()?
        }));
        Ok(())
    }

    pub fn chain_observations(&self) -> Result<serde_json::Value, String> {
        let observed_at = observation_unix_ms()?;
        let queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        let obs = &queues.observations;
        let mut intervals = obs
            .finalized_intervals_ms
            .iter()
            .copied()
            .collect::<Vec<_>>();
        intervals.sort_by(f64::total_cmp);
        let percentile = |p: f64| -> Option<f64> {
            if intervals.is_empty() {
                None
            } else {
                Some(
                    intervals[((intervals.len() as f64 * p).ceil() as usize)
                        .saturating_sub(1)
                        .min(intervals.len() - 1)],
                )
            }
        };
        Ok(
            serde_json::json!({"observed_at_unix_ms":observed_at,"scope":"process_lifetime",
            "consensus":obs.consensus,
            "pipeline":{"authority":false,"candidate":obs.candidate,
                "inbound":queues.frames.iter().map(|(protocol,frames)|
                    (format!("{protocol:?}"),frames.len())).collect::<BTreeMap<_,_>>(),
                "outbound_count":queues.outbound.len(),"head_claim_count":queues.head_claims.len(),
                "verified_peer_heights":queues.verified_peer_heights.iter().map(|(peer,(_,height))|
                    (peer.clone(),*height)).collect::<BTreeMap<_,_>>(),
                "processing_build":queues.processing_build_request.as_ref().map(|r|serde_json::json!({
                    "height":r.context.height,"round":r.context.round,"parent_height":r.parent.height(),
                    "proposer":r.proposer,"mandatory_carry":r.mandatory_carry.is_some()})),
                "native_replayed_prefix":queues.processing_certified_parent.as_ref().map(|p|p.height),
                "processing_finalized_world_height":queues.processing_finalized_world.as_ref().map(|(h,_)|h),
                "processing_candidate_count":queues.processing_candidates.len(),
                "processing_input_count":queues.processing_input_frames.len(),
                "processing_announcement_count":queues.processing_announcements.len(),
                "processing_member_count":queues.processing_members.len(),
                "processing_completion_count":queues.processing_completions.len()},
            "executed_height":obs.executed_height,
            "finalized_execution_height":obs.finalized_execution_height,
            "executed_total":obs.executed_height.map(|_|obs.executed_total),
            "finalized_total":obs.finalized_execution_height.map(|_|obs.finalized_total),
            "cadence":{"basis":"durable finalized execution observation intervals", "samples":intervals.len(),
                "p50_ms":percentile(0.5),"p95_ms":percentile(0.95),"p99_ms":percentile(0.99),
                "maximum_gap_ms":obs.maximum_finalized_gap_ms,
                "current_gap_ms":obs.finalized_last_at.map(|at|at.elapsed().as_secs_f64()*1000.0)},
            "finality_latency_ms":null,"finality_latency_reason":"requires correlated admission and finalized-commit timestamps"}),
        )
    }

    pub fn install_verified_overlay(&self, snapshot: VerifiedSnapshot) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "network control lock poisoned".to_string())?;
        queues.verified_overlay = Some(snapshot);
        Ok(())
    }

    /// For inbound sockets the remote source port is ephemeral; the verified
    /// overlay IP and authenticated identity must match. Outbound dials also
    /// require the exact signed listening address.
    pub fn permit_overlay_peer(
        &self,
        peer_id: &str,
        observed: SocketAddr,
        inbound: bool,
        required: bool,
    ) -> Result<(), String> {
        if !required {
            return Ok(());
        }
        let queues = self
            .0
            .lock()
            .map_err(|_| "network control lock poisoned".to_string())?;
        let snapshot = queues
            .verified_overlay
            .as_ref()
            .ok_or("verified transport overlay is not installed")?;
        let route = snapshot
            .registry()
            .route_for(peer_id)
            .ok_or("authenticated identity is absent from verified overlay")?;
        let expected: SocketAddr = route
            .dial_address
            .parse()
            .map_err(|_| "verified overlay route is malformed".to_string())?;
        if observed.ip() != expected.ip() || (!inbound && observed != expected) {
            return Err("observed overlay address differs from signed identity route".into());
        }
        Ok(())
    }

    pub fn admit_session(&self, peer_id: String, session_id: SessionId) -> Result<(), String> {
        if peer_id.trim().is_empty() {
            return Err("authenticated peer id is empty".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "authenticated ingress lock poisoned".to_string())?;
        queues.apqe_sessions.remove(&peer_id);
        if let Some(previous) = queues
            .authenticated_sessions
            .insert(peer_id.clone(), session_id)
        {
            if previous != session_id {
                discard_queued_session(&mut queues, &peer_id, previous);
            }
        }
        Ok(())
    }

    pub(super) fn mark_apqe_session(&self, peer: &str, session: SessionId) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "authenticated ingress lock poisoned")?;
        if queues.authenticated_sessions.get(peer) != Some(&session) {
            return Err("APQE session displaced before observation".into());
        }
        queues.apqe_sessions.insert(peer.to_owned(), session);
        Ok(())
    }
    pub fn transport_observations(&self) -> Result<serde_json::Value, String> {
        let queues = self
            .0
            .lock()
            .map_err(|_| "authenticated ingress lock poisoned")?;
        let peers = queues
            .authenticated_sessions
            .iter()
            .map(|(peer, session)| {
                let apqe = queues.apqe_sessions.get(peer) == Some(session);
                serde_json::json!({"peer_id":peer,"session_id":session.0,
                "profile":if apqe { Some("PQ-VSESSION-01-candidate-v1") } else {None},
                "engineering_only":apqe})
            })
            .collect::<Vec<_>>();
        Ok(
            serde_json::json!({"authenticated_peer_count":peers.len(),"apqe_session_count":queues.apqe_sessions.len(),"peers":peers,"production_qualified":false}),
        )
    }

    pub fn authenticated_peers(&self) -> Result<Vec<String>, String> {
        self.0
            .lock()
            .map_err(|_| "authenticated ingress lock poisoned".to_string())
            .map(|queues| queues.authenticated_sessions.keys().cloned().collect())
    }

    /// Snapshot session identity and only the progress verified in that session.
    /// Sync must not reuse proof-delivery hints after an authenticated reconnect.
    pub(super) fn authenticated_peer_progress(
        &self,
    ) -> Result<BTreeMap<String, (SessionId, Option<u64>)>, String> {
        let queues = self
            .0
            .lock()
            .map_err(|_| "authenticated ingress lock poisoned")?;
        Ok(queues
            .authenticated_sessions
            .iter()
            .map(|(peer, session)| {
                let height = queues
                    .verified_peer_heights
                    .get(peer)
                    .filter(|(verified_session, _)| verified_session == session)
                    .map(|(_, height)| *height);
                (peer.clone(), (*session, height))
            })
            .collect())
    }

    pub fn is_current_session(&self, peer: &AuthenticatedPeer) -> Result<bool, String> {
        self.0
            .lock()
            .map_err(|_| "authenticated ingress lock poisoned".to_string())
            .map(|queues| {
                queues
                    .authenticated_sessions
                    .get(peer.node_address.as_str())
                    == Some(&peer.session_id)
            })
    }

    pub fn request_dial(&self, request: DialRequest) -> Result<(), String> {
        if request.peer_id.trim().is_empty() || request.address.port() == 0 {
            return Err("invalid authenticated dial request".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "network control lock poisoned".to_string())?;
        if queues.dials.len() >= MAX_PER_PROTOCOL {
            return Err("outbound dial queue is full".into());
        }
        if !queues
            .dials
            .iter()
            .any(|entry| entry.peer_id == request.peer_id)
        {
            queues.dials.push_back(request);
        }
        Ok(())
    }

    pub fn take_dial(&self) -> Result<Option<DialRequest>, String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "network control lock poisoned".to_string())?;
        Ok(queues.dials.pop_front())
    }

    pub fn publish_outbound(&self, frame: OutboundFrame) -> Result<(), String> {
        if self.try_publish_outbound(frame)? {
            Ok(())
        } else {
            Err("outbound frame queue is full".into())
        }
    }

    /// Queue saturation is backpressure, not a local integrity failure.
    /// Retry-owning callers retain their original authenticated frame.
    pub fn try_publish_outbound(&self, frame: OutboundFrame) -> Result<bool, String> {
        if frame.peer_id.trim().is_empty() || frame.payload.is_empty() {
            return Err("invalid outbound authenticated frame".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "network control lock poisoned".to_string())?;
        if queues.outbound.len() >= MAX_PER_PROTOCOL
            || queues
                .outbound
                .iter()
                .filter(|queued| queued.protocol == frame.protocol)
                .count()
                >= outbound_limit(frame.protocol)
        {
            return Ok(false);
        }
        queues.outbound.push_back(frame);
        Ok(true)
    }

    #[cfg(test)]
    pub fn take_outbound(&self) -> Result<Option<OutboundFrame>, String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "network control lock poisoned".to_string())?;
        Ok(queues.outbound.pop_front())
    }

    /// Dispatch each queued frame at most once per poll. A full peer sender
    /// returns the exact frame for retention; other peers still get a turn.
    /// Holding the short queue lock around nonblocking dispatch preserves the
    /// reserved slot while a frame is temporarily outside the deque.
    pub fn dispatch_outbound(
        &self,
        mut dispatch: impl FnMut(OutboundFrame) -> Option<OutboundFrame>,
    ) -> Result<(), String> {
        let mut queues = self.0.lock().map_err(|_| "network control lock poisoned")?;
        let attempts = queues.outbound.len();
        for _ in 0..attempts {
            let Some(frame) = queues.outbound.pop_front() else {
                break;
            };
            if let Some(retained) = dispatch(frame) {
                queues.outbound.push_back(retained);
            }
        }
        Ok(())
    }

    pub fn request_peer_control(
        &self,
        action: PeerControlAction,
        timeout: Duration,
    ) -> Result<(), String> {
        if action.peer_id().trim().is_empty() {
            return Err("peer control requires a canonical peer identity".into());
        }
        let (response, receiver) = mpsc::sync_channel(1);
        {
            let mut queues = self
                .0
                .lock()
                .map_err(|_| "network control lock poisoned".to_string())?;
            if queues.peer_controls.len() >= MAX_PER_PROTOCOL {
                return Err("peer control queue is full".into());
            }
            queues
                .peer_controls
                .push_back(PeerControlRequest { action, response });
        }
        receiver
            .recv_timeout(timeout)
            .map_err(|error| format!("peer control did not complete: {error}"))?
    }

    pub fn take_peer_control(&self) -> Result<Option<PeerControlRequest>, String> {
        self.0
            .lock()
            .map_err(|_| "network control lock poisoned".to_string())
            .map(|mut queues| queues.peer_controls.pop_front())
    }

    pub fn request_sync_control(
        &self,
        action: SyncControlAction,
        timeout: Duration,
    ) -> Result<(), String> {
        if matches!(
            &action,
            SyncControlAction::RetrySource { peer_id } if peer_id.trim().is_empty()
        ) {
            return Err("Sync source retry requires a canonical peer identity".into());
        }
        let (response, receiver) = mpsc::sync_channel(1);
        {
            let mut queues = self
                .0
                .lock()
                .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
            if queues.sync_controls.len() >= MAX_PER_PROTOCOL {
                return Err("Sync control queue is full".into());
            }
            queues
                .sync_controls
                .push_back(SyncControlRequest { action, response });
        }
        receiver
            .recv_timeout(timeout)
            .map_err(|error| format!("Sync control did not complete: {error}"))?
    }

    pub fn take_sync_control(&self) -> Result<Option<SyncControlRequest>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.sync_controls.pop_front())
    }
    pub fn request_etdag_control(
        &self,
        action: EtdagControlAction,
        timeout: Duration,
    ) -> Result<(), String> {
        let (response, receiver) = mpsc::sync_channel(1);
        {
            let mut queues = self
                .0
                .lock()
                .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
            if queues.etdag_controls.len() >= MAX_PER_PROTOCOL {
                return Err("ETDAG control queue is full".into());
            }
            queues
                .etdag_controls
                .push_back(EtdagControlRequest { action, response });
        }
        receiver
            .recv_timeout(timeout)
            .map_err(|error| format!("ETDAG control did not complete: {error}"))?
    }

    pub fn take_etdag_control(&self) -> Result<Option<EtdagControlRequest>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.etdag_controls.pop_front())
    }

    pub fn submit_head_claim(
        &self,
        peer: AuthenticatedPeer,
        claim: HeadClaim,
    ) -> Result<(), String> {
        if peer.node_address.as_str() != claim.peer_id.as_str() {
            return Err("sync head claim differs from authenticated peer".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        if queues
            .authenticated_sessions
            .get(peer.node_address.as_str())
            != Some(&peer.session_id)
        {
            return Ok(());
        }
        bounded_push(&mut queues.head_claims, (peer, claim), "sync head claim")
    }

    pub fn take_head_claim(&self) -> Result<Option<(AuthenticatedPeer, HeadClaim)>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.head_claims.pop_front())
    }

    pub fn submit_verified_head(
        &self,
        head: VerifiedHead,
        session_id: SessionId,
    ) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        if queues.authenticated_sessions.get(&head.peer_id) != Some(&session_id) {
            return Ok(());
        }
        queues
            .verified_peer_heights
            .entry(head.peer_id.clone())
            .and_modify(|(current_session, height)| {
                if *current_session == session_id {
                    *height = (*height).max(head.finalized_height);
                } else {
                    *current_session = session_id;
                    *height = head.finalized_height;
                }
            })
            .or_insert((session_id, head.finalized_height));
        bounded_push(&mut queues.verified_heads, head, "verified sync head")
    }

    /// Return only verified progress reported by each peer's current authenticated session.
    pub fn verified_peer_heights(&self) -> Result<BTreeMap<String, u64>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|queues| {
                queues
                    .verified_peer_heights
                    .iter()
                    .filter(|(peer_id, (session_id, _))| {
                        queues.authenticated_sessions.get(*peer_id) == Some(session_id)
                    })
                    .map(|(peer_id, (_, height))| (peer_id.clone(), *height))
                    .collect()
            })
    }

    pub fn take_verified_head(&self) -> Result<Option<VerifiedHead>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.verified_heads.pop_front())
    }

    /// Caller is the PoSy delivery owner, after native signature/slot admission.
    /// Retain only one small hint per current authenticated peer. Reconnection
    /// restores normal replay retries; no durable proof or transaction is retired.
    pub(super) fn record_processing_input_echo(
        &self,
        peer: &str,
        height: u64,
        round: u64,
        block_id: &str,
    ) -> Result<(), String> {
        let mut q = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        let Some(session) = q.authenticated_sessions.get(peer).copied() else {
            return Ok(());
        };
        if q.processing_input_echoes
            .get(peer)
            .is_some_and(|(_, h, r, _)| (*h, *r) > (height, round))
        {
            return Ok(());
        }
        if !q.processing_input_echoes.contains_key(peer)
            && q.processing_input_echoes.len() >= MAX_PER_PROTOCOL
        {
            return Ok(()); // A missing hint always keeps retransmission enabled.
        }
        q.processing_input_echoes.insert(
            peer.to_owned(),
            (session, height, round, block_id.to_owned()),
        );
        Ok(())
    }

    pub(super) fn processing_input_was_echoed(
        &self,
        peer: &str,
        height: u64,
        round: u64,
        block_id: &str,
    ) -> Result<bool, String> {
        let q = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        Ok(q.processing_input_echoes
            .get(peer)
            .is_some_and(|(s, h, r, id)| {
                q.authenticated_sessions.get(peer) == Some(s)
                    && (*h, *r, id.as_str()) == (height, round, block_id)
            }))
    }

    /// An honest peer's native ECHO at H requires replay of its QC-selected
    /// parent H-1. This is a session-scoped retry hint, never execution finality.
    pub(super) fn processing_peer_replayed_after(
        &self,
        peer: &str,
        height: u64,
    ) -> Result<bool, String> {
        let q = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        Ok(q.processing_input_echoes
            .get(peer)
            .is_some_and(|(session, echoed, _, _)| {
                q.authenticated_sessions.get(peer) == Some(session) && *echoed > height
            }))
    }

    pub fn submit_sync_candidate_request(
        &self,
        peer: AuthenticatedPeer,
        request: FinalizedCandidateRequest,
    ) -> Result<(), String> {
        self.submit_sync_candidate_request_version(peer, request, false)
    }

    pub fn submit_sync_candidate_request_version(
        &self,
        peer: AuthenticatedPeer,
        request: FinalizedCandidateRequest,
        chunks: bool,
    ) -> Result<(), String> {
        if !request.validate() || request.expected_parent_id.len() > 256 {
            return Err("invalid finalized candidate request".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        if queues
            .authenticated_sessions
            .get(peer.node_address.as_str())
            != Some(&peer.session_id)
        {
            return Ok(());
        }
        if queues.sync_candidate_requests.iter().any(
            |(queued_peer, queued_request, queued_chunks)| {
                queued_peer.node_address == peer.node_address
                    && queued_peer.session_id == peer.session_id
                    && queued_request == &request
                    && queued_chunks == &chunks
            },
        ) {
            return Ok(());
        }
        if queues.sync_candidate_requests.len() >= MAX_PER_PROTOCOL {
            // Requesters retain their bounded request and retry. A historical
            // response stream must not turn request congestion into node death.
            return Ok(());
        }
        queues
            .sync_candidate_requests
            .push_back((peer, request, chunks));
        Ok(())
    }

    pub fn take_sync_candidate_request(
        &self,
    ) -> Result<Option<(AuthenticatedPeer, FinalizedCandidateRequest, bool)>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.sync_candidate_requests.pop_front())
    }

    #[cfg(test)]
    pub fn submit_sync_candidate_response(
        &self,
        peer: AuthenticatedPeer,
        response: FinalizedCandidateResponse,
    ) -> Result<(), String> {
        self.try_submit_sync_candidate_response(peer, response)
            .map(|_| ())
    }

    pub(super) fn try_submit_sync_candidate_response(
        &self,
        peer: AuthenticatedPeer,
        response: FinalizedCandidateResponse,
    ) -> Result<CandidateResponseHandoff, String> {
        response.candidate.validate()?;
        if !response.request.validate()
            || response.candidate.height != response.request.height
            || response.candidate.parent_block_id != response.request.expected_parent_id
            || response.finality_witness.is_empty()
            || response.finality_witness.len() > synergy_sync::MAX_CANDIDATE_WITNESS_BYTES
        {
            return Err("invalid finalized candidate response".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        if queues
            .authenticated_sessions
            .get(peer.node_address.as_str())
            != Some(&peer.session_id)
        {
            return Ok(CandidateResponseHandoff::StaleSession);
        }
        // Only four requests can be in flight. Bound the decoded handoff as
        // well as transport assembly. Saturation returns ownership to the
        // Sync owner, which retains and retries without dropping the response.
        let bytes = candidate_response_memory(&response)?;
        let queued =
            queues
                .sync_candidate_responses
                .iter()
                .try_fold(0usize, |sum, (_, value)| {
                    candidate_response_memory(value).map(|bytes| sum.saturating_add(bytes))
                })?;
        if queues.sync_candidate_responses.len() >= 4
            || bytes > synergy_sync::MAX_CANDIDATE_RESPONSE_BYTES.saturating_sub(queued)
        {
            return Ok(CandidateResponseHandoff::Full(Box::new((peer, response))));
        }
        queues.sync_candidate_responses.push_back((peer, response));
        Ok(CandidateResponseHandoff::Queued)
    }

    pub fn take_sync_candidate_response(
        &self,
    ) -> Result<Option<(AuthenticatedPeer, FinalizedCandidateResponse)>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.sync_candidate_responses.pop_front())
    }

    pub fn submit_snapshot_chunk_request(
        &self,
        peer: AuthenticatedPeer,
        request: SnapshotChunkRequest,
    ) -> Result<(), String> {
        if !request.validate() {
            return Err("invalid snapshot chunk request".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        if queues
            .authenticated_sessions
            .get(peer.node_address.as_str())
            != Some(&peer.session_id)
        {
            return Ok(());
        }
        bounded_push(
            &mut queues.snapshot_chunk_requests,
            (peer, request),
            "snapshot chunk request",
        )
    }

    pub fn take_snapshot_chunk_request(
        &self,
    ) -> Result<Option<(AuthenticatedPeer, SnapshotChunkRequest)>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.snapshot_chunk_requests.pop_front())
    }

    /// Execution is the sole producer. Check before its durable commit; the
    /// Sync consumer can only free capacity between this check and publication.
    pub fn finalized_execution_commit_has_capacity(&self) -> Result<bool, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|queues| queues.finalized_execution_commits.len() < MAX_PER_PROTOCOL)
    }

    pub fn submit_finalized_execution_commit(
        &self,
        publication: FinalizedExecutionCommit,
    ) -> Result<(), String> {
        if publication.epoch == 0
            || publication.finality.height == 0
            || publication.finality.block_id.trim().is_empty()
            || publication
                .finality
                .finality_certificate_id
                .trim()
                .is_empty()
            || publication.application_state_root.trim().is_empty()
        {
            return Err("invalid finalized execution commitment".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        bounded_push(
            &mut queues.finalized_execution_commits,
            publication,
            "finalized execution commitment",
        )
    }

    pub fn take_finalized_execution_commit(
        &self,
    ) -> Result<Option<FinalizedExecutionCommit>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.finalized_execution_commits.pop_front())
    }

    /// Bounded, read-only diagnostic view; never acknowledges or imports work.
    #[cfg(any(test, feature = "qualification-timing"))]
    pub(super) fn sync_progress_diagnostic(&self) -> Result<serde_json::Value, String> {
        let q = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        Ok(serde_json::json!({
            "execution_ack_count": q.finalized_execution_commits.len(),
            "execution_ack_first": q.finalized_execution_commits.front().map(|p| p.finality.height),
            "execution_ack_last": q.finalized_execution_commits.back().map(|p| p.finality.height),
            "local_posy_finality": q.latest_finality.as_ref().map(|p| p.height),
            "native_replayed_prefix": q.processing_certified_parent.as_ref().map(|p| p.height),
            "outbound_count": q.outbound.len(),
            "verified_peer_heights": q.verified_peer_heights.iter().map(|(peer, (_, height))|
                (peer.clone(), *height)).collect::<BTreeMap<_, _>>(),
        }))
    }

    pub fn submit_snapshot_restore_handoff(
        &self,
        handoff: SnapshotRestoreHandoff,
    ) -> Result<(), String> {
        if handoff.epoch == 0
            || handoff.finalized_height == 0
            || handoff.finalized_block_id.trim().is_empty()
            || handoff.finality_evidence_id.trim().is_empty()
            || synergy_state::state_root(&handoff.state)
                .map_err(|error| format!("root snapshot restore state: {error:?}"))?
                != handoff.application_state_root
        {
            return Err("invalid verified snapshot restore handoff".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        bounded_push(
            &mut queues.snapshot_restore_handoffs,
            handoff,
            "verified snapshot restore handoff",
        )
    }

    pub fn take_snapshot_restore_handoff(&self) -> Result<Option<SnapshotRestoreHandoff>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.snapshot_restore_handoffs.pop_front())
    }

    pub fn submit_snapshot_restore_receipt(
        &self,
        receipt: SnapshotRestoreReceipt,
    ) -> Result<(), String> {
        if receipt.finalized_height == 0
            || receipt.finalized_block_id.trim().is_empty()
            || receipt.application_state_root.trim().is_empty()
        {
            return Err("invalid snapshot restore receipt".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        bounded_push(
            &mut queues.snapshot_restore_receipts,
            receipt,
            "snapshot restore receipt",
        )
    }

    pub fn take_snapshot_restore_receipt(&self) -> Result<Option<SnapshotRestoreReceipt>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.snapshot_restore_receipts.pop_front())
    }

    pub fn submit_verified_sync_candidate(
        &self,
        candidate: ExecutionCandidate,
        record: FinalizedBlockRecord,
    ) -> Result<(), String> {
        if self.enqueue_verified_sync_candidate(candidate, record, MAX_PER_PROTOCOL)? {
            Ok(())
        } else {
            Err("verified Sync candidate queue is full".into())
        }
    }

    pub(super) fn try_submit_verified_sync_candidate(
        &self,
        candidate: ExecutionCandidate,
        record: FinalizedBlockRecord,
    ) -> Result<bool, String> {
        // Only Execution consumes this queue, one item at a time. Reserve one
        // slot within the existing bound so its in-flight item can always be
        // returned during native dependency/resource pressure, even if PoSy
        // concurrently publishes more verified work.
        self.enqueue_verified_sync_candidate(candidate, record, MAX_PER_PROTOCOL - 1)
    }

    fn enqueue_verified_sync_candidate(
        &self,
        candidate: ExecutionCandidate,
        record: FinalizedBlockRecord,
        limit: usize,
    ) -> Result<bool, String> {
        candidate.validate()?;
        if candidate.height != record.height
            || candidate.block_id != record.block_id
            || candidate.protected_execution_root != record.protected_execution_root
        {
            return Err("verified Sync candidate differs from PoSy finality".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        for (existing, finalized) in &queues.verified_sync_candidates {
            if existing.height == candidate.height {
                if existing.as_ref() != candidate.as_ref() || finalized != &record {
                    return Err("conflicting verified Sync execution candidate".into());
                }
                // Retransmission cannot fill the bounded queue with copies of
                // the same authenticated candidate and exact finality record.
                return Ok(true);
            }
        }
        if queues.verified_sync_candidates.len() >= limit {
            return Ok(false);
        }
        queues
            .verified_sync_candidates
            .push_back((candidate, record));
        Ok(true)
    }

    pub fn take_verified_sync_candidate(
        &self,
    ) -> Result<Option<(ExecutionCandidate, FinalizedBlockRecord)>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.verified_sync_candidates.pop_front())
    }

    pub fn submit_protected_batch(&self, batch: PreparedProtectedBatch) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        bounded_push(
            &mut queues.protected_batches,
            batch,
            "ETDAG execution handoff",
        )
    }

    /// Enqueues a complete signed validator-authored vertex. Queue admission
    /// grants no protocol authority; the ETDAG owner returns durable validation.
    #[allow(
        dead_code,
        reason = "typed local admission boundary; external submission owner is not wired yet"
    )]
    pub fn submit_local_protected_vertex(
        &self,
        vertex: synergy_etdag::TransactionVertex,
    ) -> Result<mpsc::Receiver<Result<(), String>>, String> {
        const MAX_LOCAL_VERTICES: usize = 16;
        const MAX_LOCAL_VERTEX_BYTES: usize = 8 * 1024 * 1024;
        vertex
            .validate()
            .map_err(|e| format!("invalid local protected vertex: {e:?}"))?;
        synergy_etdag::dag::validate_vertex_identity(&vertex)
            .map_err(|e| format!("invalid local protected vertex identity: {e:?}"))?;
        let encoded_bytes = serde_json::to_vec(&vertex)
            .map_err(|e| format!("encode local protected vertex: {e}"))?
            .len();
        if encoded_bytes > synergy_network::protocol::DEFAULT_MAX_FRAME_BYTES {
            return Err("local protected vertex exceeds authenticated frame bound".into());
        }
        let (response, receipt) = mpsc::channel();
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        if queues.local_protected_vertices.len() >= MAX_LOCAL_VERTICES
            || encoded_bytes
                > MAX_LOCAL_VERTEX_BYTES.saturating_sub(queues.local_protected_vertex_bytes)
        {
            return Err("local protected vertex queue is full".into());
        }
        queues.local_protected_vertex_bytes += encoded_bytes;
        queues
            .local_protected_vertices
            .push_back(LocalProtectedVertexRequest {
                vertex,
                response,
                encoded_bytes,
            });
        Ok(receipt)
    }

    pub(super) fn take_local_protected_vertex(
        &self,
    ) -> Result<Option<LocalProtectedVertexRequest>, String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        let request = queues.local_protected_vertices.pop_front();
        if let Some(request) = &request {
            queues.local_protected_vertex_bytes -= request.encoded_bytes;
        }
        Ok(request)
    }

    pub fn take_protected_batch(&self) -> Result<Option<PreparedProtectedBatch>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.protected_batches.pop_front())
    }

    pub fn submit_execution_candidate(&self, candidate: ExecutionCandidate) -> Result<(), String> {
        candidate.validate()?;
        if candidate.height == 0
            || candidate.block_id.trim().is_empty()
            || candidate.parent_block_id.trim().is_empty()
            || candidate.protected_execution_root.trim().is_empty()
            || candidate.state_root.trim().is_empty()
            || candidate.transactions.len() != candidate.receipts.len()
        {
            return Err("invalid execution candidate".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        bounded_push(
            &mut queues.execution_candidates,
            candidate,
            "execution candidate",
        )
    }

    pub fn take_execution_candidate(&self) -> Result<Option<ExecutionCandidate>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.execution_candidates.pop_front())
    }

    pub(crate) fn publish_processing_build_request(
        &self,
        machine: &synergy_posy::SimplifiedConsensusStateMachine,
    ) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        if machine.epoch_complete() {
            queues.processing_build_request = None;
            return Ok(());
        }
        let (height, round) = machine.active_slot();
        if queues
            .processing_build_request
            .as_ref()
            .is_some_and(|request| {
                request.context.height == height
                    && request.context.round == round
                    && request.context.validate_against(machine.epoch()).is_ok()
                    && request.parent == *machine.highest_parent()
                    && request.takeover.as_ref().map(|tc| tc.id())
                        == machine.active_takeover_tc_id()
                    && request.mandatory_carry.as_ref() == machine.active_mandatory_carry()
            })
        {
            return Ok(());
        }
        let takeover = match machine.active_takeover_tc_id() {
            Some(id) => Some(
                machine
                    .accepted_timeout_certificate(id)
                    .ok_or("processing slot lacks admitted takeover authority")?,
            ),
            None => None,
        };
        let lease = machine
            .epoch()
            .lease_index(height)
            .map_err(|e| e.to_string())?;
        if (round == 0) != takeover.is_none()
            || machine.highest_parent().height().checked_add(1) != Some(height)
            || takeover.is_some_and(|tc| {
                tc.context().height > height
                    || tc.lease_index() != lease
                    || tc.context().round.checked_add(1) != Some(round)
                    || (tc.context().height == height
                        && tc.highest_parent() != machine.highest_parent())
            })
        {
            return Err("processing assembly request differs from native PoSy slot".into());
        }
        // The control-plane metadata pool is prepaid before processing intake.
        // Pending transaction work cannot consume its assembly handoff capacity.
        let pool = queues
            .processing_slot_pool
            .as_ref()
            .ok_or("processing assembly pool was not initialized")?;
        // Reserve before cloning the native metadata. TC summaries contain
        // bounded digests, never historical signature vectors or Worlds.
        let mut permit = match pool.reserve(16 * 1024) {
            Ok(permit) => permit,
            Err(_) => return Ok(()), // Existing consumers release their old slot on retry.
        };
        struct Counter(usize);
        impl std::io::Write for Counter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_add(bytes.len())
                    .filter(|n| *n <= 256 * 1024)
                    .ok_or_else(|| {
                        std::io::Error::other("processing slot metadata exceeds bound")
                    })?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let context =
            synergy_posy::ConsensusObjectContext::for_height(machine.epoch(), height, round)
                .map_err(|e| e.to_string())?;
        let mut count = Counter(0);
        serde_json::to_writer(
            &mut count,
            &(
                &context,
                machine.highest_parent(),
                takeover,
                machine.active_mandatory_carry(),
            ),
        )
        .map_err(|e| e.to_string())?;
        if permit
            .grow(
                count
                    .0
                    .checked_mul(16)
                    .ok_or("processing slot size overflow")?,
            )
            .is_err()
        {
            return Ok(());
        }
        queues.processing_build_request = Some(Arc::new(ProcessingBuildRequest {
            context,
            parent: machine.highest_parent().clone(),
            proposer: machine
                .epoch()
                .authorized_proposer(height, round)
                .map_err(|e| e.to_string())?
                .to_owned(),
            takeover: takeover.cloned(),
            mandatory_carry: machine.active_mandatory_carry().cloned(),
            _permit: permit,
        }));
        Ok(())
    }

    pub(crate) fn initialize_processing_build_requests(&self) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        if queues.processing_slot_pool.is_none() {
            queues.processing_slot_pool = Some(
                self.1
                    .reserve(8 * 1024 * 1024 + 64 * 1024)
                    .map_err(|e| format!("provision processing slot handoff: {e}"))?
                    .into_budget(),
            );
        }
        Ok(())
    }

    pub(crate) fn install_processing_proposal_store(
        &self,
        store: Arc<Mutex<super::processing_proposals::ProcessingProposalStore>>,
    ) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        if queues.processing_proposal_store.is_some() {
            return Err("processing proposal owner already installed".into());
        }
        queues.processing_proposal_store = Some(store);
        Ok(())
    }
    pub(crate) fn processing_proposal_store(
        &self,
    ) -> Result<Option<Arc<Mutex<super::processing_proposals::ProcessingProposalStore>>>, String>
    {
        Ok(self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?
            .processing_proposal_store
            .clone())
    }
    pub(super) fn publish_processing_member(
        &self,
        member: Arc<super::processing_pipeline::NativeProcessingMember>,
    ) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        let id = &member.member().envelope.tx_commitment;
        if let Some(previous) = queues.processing_members.get(id) {
            return if previous.member() == member.member()
                && previous.vertex_id() == member.vertex_id()
            {
                Ok(())
            } else {
                Err("conflicting native processing member".into())
            };
        }
        if queues.processing_members.len() >= 4096 {
            return Err("processing member index full".into());
        }
        queues.processing_members.insert(id.clone(), member);
        Ok(())
    }
    pub(super) fn publish_processing_completion(
        &self,
        completion: Arc<super::processing_pipeline::NativeProcessingCompletion>,
    ) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        let id = &completion.record.item.envelope_id;
        if let Some(previous) = queues.processing_completions.get(id) {
            return if previous.record == completion.record {
                Ok(())
            } else {
                Err("conflicting native processing completion".into())
            };
        }
        if queues.processing_completions.len() >= 4096 {
            return Err("processing completion index full".into());
        }
        queues.processing_completions.insert(id.clone(), completion);
        Ok(())
    }
    pub(super) fn processing_snapshot(&self) -> Result<Option<ProcessingSnapshot>, String> {
        let queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        let reservation = self.1.reserve(
            (queues.processing_members.len() + queues.processing_completions.len())
                .checked_mul(256)
                .and_then(|n| n.checked_add(4096))
                .ok_or("processing snapshot size overflow")?,
        );
        let permit = match reservation {
            Ok(permit) => permit,
            Err(synergy_state::world_resources::WorldResourceError::Capacity { .. }) => {
                return Ok(None)
            }
            Err(error) => return Err(error.to_string()),
        };
        Ok(Some(ProcessingSnapshot {
            members: queues.processing_members.values().cloned().collect(),
            completions: queues.processing_completions.values().cloned().collect(),
            _permit: permit,
        }))
    }

    pub(super) fn release_finalized_processing(
        &self,
        proof: &super::processing_pipeline::NativeProcessingRetirement,
    ) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        for identity in proof.identities() {
            queues.processing_members.remove(&identity.envelope_id);
            queues.processing_completions.remove(&identity.envelope_id);
        }
        Ok(())
    }

    pub(super) fn publish_processing_certified_parent(
        &self,
        candidate: ExecutionCandidate,
        qc: &synergy_posy::SimplifiedQuorumCertificate,
        authority: &super::authority::VerifiedAuthority,
    ) -> Result<(), String> {
        if !authority.processing_profile_enabled()
            || !Arc::ptr_eq(candidate.state.budget(), self.world_budget())
        {
            return Err("processing certified parent has another owner/profile".into());
        }
        qc.verify(&authority.epoch, &authority.registry, authority)
            .map_err(|e| e.to_string())?;
        candidate.validate()?;
        if candidate.height != qc.context.height
            || candidate.block_id != qc.block_id
            || candidate.parent_block_id != qc.parent_block_id
            || candidate.protected_execution_root != qc.protected_execution_root
        {
            return Err("processing parent handoff differs from exact native QC".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        if let Some(old) = &queues.processing_certified_parent {
            if candidate.height < old.height {
                return Ok(());
            }
            if candidate.height == old.height {
                return if candidate.block_id == old.block_id {
                    Ok(())
                } else {
                    Err("conflicting certified processing parent".into())
                };
            }
        }
        queues.processing_proof_refs = None;
        queues.processing_certified_parent = Some(candidate);
        Ok(())
    }
    pub(super) fn processing_certified_parent(&self) -> Result<Option<ExecutionCandidate>, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?
            .processing_certified_parent
            .clone())
    }
    pub(super) fn invalidate_processing_proof_references(&self) -> Result<(), String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?
            .processing_proof_refs = None;
        Ok(())
    }
    pub(super) fn publish_processing_proof_references(
        &self,
        parent_id: &str,
        heights: &BTreeSet<u64>,
    ) -> Result<bool, String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        if queues
            .processing_certified_parent
            .as_ref()
            .map(|parent| parent.block_id.as_str())
            != Some(parent_id)
        {
            return Ok(false);
        }
        if queues
            .processing_proof_refs
            .as_ref()
            .is_some_and(|(id, old, _)| id == parent_id && old.as_ref() == heights)
        {
            return Ok(true);
        }
        queues.processing_proof_refs = None;
        let permit = match self.1.reserve(
            heights
                .len()
                .checked_mul(64)
                .and_then(|size| size.checked_add(4096))
                .ok_or("processing reference size overflow")?,
        ) {
            Ok(permit) => permit,
            Err(synergy_state::world_resources::WorldResourceError::Capacity { .. }) => {
                return Ok(false)
            }
            Err(error) => return Err(error.to_string()),
        };
        queues.processing_proof_refs = Some((
            parent_id.into(),
            Arc::new(heights.clone()),
            Arc::new(permit),
        ));
        Ok(true)
    }
    pub(super) fn processing_proof_references(
        &self,
    ) -> Result<Option<ProcessingProofReferences>, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?
            .processing_proof_refs
            .as_ref()
            .map(|(_, heights, permit)| (heights.clone(), permit.clone())))
    }
    #[cfg(test)]
    pub(super) fn hold_processing_work(&self, held: bool) -> Result<(), String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?
            .processing_work_held = held;
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn processing_work_held(&self) -> Result<bool, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?
            .processing_work_held)
    }
    #[cfg(test)]
    pub(super) fn hold_processing_handoff(&self, slot: Option<(u64, u64)>) -> Result<(), String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?
            .processing_handoff_held = slot;
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn stale_processing_handoffs(&self) -> Result<usize, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?
            .processing_stale_handoffs)
    }

    pub(super) fn set_processing_local_validator(&self, id: &str) -> Result<(), String> {
        let mut q = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        if q.processing_local_validator
            .as_deref()
            .is_some_and(|old| old != id)
        {
            return Err("processing validator identity changed".into());
        }
        q.processing_local_validator = Some(id.to_owned());
        Ok(())
    }
    pub(super) fn processing_local_validator(&self) -> Result<Option<String>, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?
            .processing_local_validator
            .clone())
    }
    // The ETDAG owner supplies sender only after native envelope verification.
    // Decode scratch is prepaid here and retained through execution replay.
    pub(super) fn queue_processing_inputs(
        &self,
        sender: &str,
        bytes: &[u8],
        outgoing: bool,
    ) -> Result<bool, String> {
        if bytes.is_empty() || bytes.len() > 8 * 1024 * 1024 || sender.len() > 256 {
            return Err("processing proposal transport exceeds bound".into());
        }
        let mut q = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        let queue = if outgoing {
            &mut q.processing_announcements
        } else {
            &mut q.processing_input_frames
        };
        if queue
            .iter()
            .any(|v| v.sender == sender && v.payload == bytes)
        {
            return Ok(true);
        }
        if queue.len() >= 2 {
            return Ok(false);
        }
        let charge = bytes
            .len()
            .checked_mul(32)
            .and_then(|n| n.checked_add(64 * 1024))
            .ok_or("processing transport size overflow")?;
        let permit = match self.1.reserve(charge) {
            Ok(permit) => permit,
            Err(synergy_state::world_resources::WorldResourceError::Capacity { .. }) => {
                return Ok(false)
            }
            Err(error) => return Err(error.to_string()),
        };
        queue.push_back(ProcessingInputFrame {
            sender: sender.to_owned(),
            payload: bytes.to_vec(),
            _permit: permit,
        });
        Ok(true)
    }
    pub(super) fn take_processing_inputs(
        &self,
        outgoing: bool,
    ) -> Result<Option<ProcessingInputFrame>, String> {
        let mut q = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        Ok(if outgoing {
            q.processing_announcements.pop_front()
        } else {
            q.processing_input_frames.pop_front()
        })
    }

    pub(super) fn detach_processing_execution(&self) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        queues.processing_proposal_store = None;
        queues.processing_certified_parent = None;
        queues.processing_finalized_world = None;
        queues.processing_proof_refs = None;
        queues.processing_members.clear();
        queues.processing_completions.clear();
        queues.processing_input_frames.clear();
        queues.processing_announcements.clear();
        Ok(())
    }

    pub(crate) fn clear_processing_build_requests(&self) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        queues.processing_build_request = None;
        queues.processing_candidates.clear();
        queues.processing_slot_pool = None;
        Ok(())
    }

    pub(crate) fn processing_build_request(
        &self,
    ) -> Result<Option<Arc<ProcessingBuildRequest>>, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?
            .processing_build_request
            .clone())
    }

    /// The native execution owner stages replay inputs durably before this
    /// handoff. The slot capability prevents a late worker result from becoming
    /// a candidate for a different round or parent.
    pub(crate) fn submit_processing_candidate(
        &self,
        durable: super::processing_proposals::DurableProcessingCandidate,
    ) -> Result<(), String> {
        let (request, candidate) = durable.into_parts();
        candidate.validate()?;
        if candidate.height != request.context.height
            || !Arc::ptr_eq(candidate.state.budget(), self.world_budget())
            || candidate.parent_block_id != request.parent.block_id()
            || !matches!(
                candidate.protected_material,
                synergy_etdag::execution::CandidateProtectedMaterial::Processing(_)
            )
        {
            return Err("processing candidate differs from native assembly instruction".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        let Some(current) = queues.processing_build_request.as_ref() else {
            return Ok(());
        };
        if !Arc::ptr_eq(current, &request) {
            return Ok(());
        }
        if queues.processing_candidates.iter().any(|entry| {
            Arc::ptr_eq(&entry.request, &request) && entry.candidate.block_id == candidate.block_id
        }) {
            return Ok(());
        }
        if queues.processing_candidates.len() >= 2 {
            return Err("processing candidate handoff is full".into());
        }
        #[cfg(feature = "qualification-timing")]
        super::qualification_timing::processing_boundary(
            "candidate_ready",
            request.context.height,
            request.context.round,
            &candidate.block_id,
            &request.proposer,
        );
        queues
            .processing_candidates
            .push_back(ProcessingCandidateHandoff { request, candidate });
        Ok(())
    }

    pub(crate) fn take_processing_candidate(
        &self,
    ) -> Result<Option<ProcessingCandidateHandoff>, String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        #[cfg(test)]
        {
            let current = queues
                .processing_build_request
                .as_ref()
                .map(|request| (request.context.height, request.context.round));
            if current.is_some() && queues.processing_handoff_held == current {
                return Ok(None);
            }
            if queues.processing_candidates.front().is_some_and(|handoff| {
                Some((
                    handoff.request.context.height,
                    handoff.request.context.round,
                )) != current
            }) {
                queues.processing_stale_handoffs += 1;
            }
        }
        Ok(queues.processing_candidates.pop_front())
    }

    pub fn submit_finality(
        &self,
        record: FinalizedBlockRecord,
        witness: Vec<u8>,
    ) -> Result<(), String> {
        if witness.is_empty() || witness.len() > 1024 * 1024 {
            return Err("PoSy finality witness exceeds the Sync bound".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        if queues.latest_finality.as_ref().is_some_and(|current| {
            record.height < current.height
                || (record.height == current.height && record != *current)
        }) {
            return Err("PoSy finality regressed or conflicted".into());
        }
        // Repeated publication of the same verified tip is idempotent, even
        // when execution is waiting for its next authenticated payload.
        if queues.latest_finality.as_ref() == Some(&record) {
            return Ok(());
        }
        let history_root = queues
            .finality_history
            .as_ref()
            .map(|history| history.root.clone());
        enqueue_finality(&mut queues.finality, &record, history_root.as_deref())?;
        queues
            .finalized_records
            .insert(record.height, record.clone());
        let retain_from = record.height.saturating_sub(MAX_PER_PROTOCOL as u64);
        queues
            .finalized_records
            .retain(|height, _| *height >= retain_from);
        // Reserve headroom for the five-height pipeline. Retaining a full
        // 64 finalized heights in a 64-entry cache would stall at H65.
        // Historical material is recovered from QC-bound candidate records.
        prune_protected_caches(&mut queues, record.height);
        #[cfg(feature = "qualification-timing")]
        let observed_height = record.height;
        queues.latest_finality = Some(record);
        queues.latest_finality_witness = Some(witness);
        #[cfg(feature = "qualification-timing")]
        {
            drop(queues);
            use super::qualification_timing::{self as timing, Classification, Kind, Phase, Role};
            timing::emit_once(
                Kind::Window,
                Phase::Finalized,
                observed_height,
                0,
                0,
                Role::Participant,
                Classification::Observed,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Execution calls this only after committing the exact verified block and
    /// world state. Sync can repopulate historical material while the consensus
    /// tip is unchanged, so its cache lifecycle must also follow executed state.
    pub fn execution_committed(&self, height: u64) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        prune_protected_caches(&mut queues, height);
        Ok(())
    }

    pub(super) fn publish_processing_finalized_world(
        &self,
        height: u64,
        world: Arc<BudgetedWorld>,
    ) -> Result<(), String> {
        if !Arc::ptr_eq(world.budget(), self.world_budget()) {
            return Err("processing finalized World has another budget".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        if queues
            .processing_finalized_world
            .as_ref()
            .is_none_or(|(old, _)| height > *old)
        {
            queues.processing_proof_refs = None;
            queues.processing_finalized_world = Some((height, world));
        }
        Ok(())
    }
    pub(super) fn processing_finalized_world(
        &self,
    ) -> Result<Option<(u64, Arc<BudgetedWorld>)>, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?
            .processing_finalized_world
            .clone())
    }
    #[cfg(test)]
    pub(super) fn processing_certified_measurement(
        &self,
        after: u64,
    ) -> Result<Option<(u64, String, String, usize)>, String> {
        let queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        Ok(queues
            .processing_certified_parent
            .as_ref()
            .filter(|parent| parent.height > after)
            .map(|parent| {
                (
                    parent.height,
                    parent.block_id.clone(),
                    parent.state_root.clone(),
                    parent.transactions.len(),
                )
            }))
    }
    pub fn install_finality_history(
        &self,
        root: std::path::PathBuf,
        authority: Arc<super::authority::VerifiedAuthority>,
    ) -> Result<(), String> {
        self.install_finality_history_with_transition(root, authority, None)
    }

    pub(super) fn install_finality_history_with_transition(
        &self,
        root: std::path::PathBuf,
        authority: Arc<super::authority::VerifiedAuthority>,
        transition: Option<super::authority::VerifiedTransitionContext>,
    ) -> Result<(), String> {
        if let Some(transition) = &transition {
            transition.verify_current(&authority)?;
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        queues.finality_history = Some(FinalityHistory {
            root,
            authority,
            transition: transition.map(Arc::new),
        });
        Ok(())
    }

    /// Historical target admission reuses verified durable three-QC evidence,
    /// never a peer height or an unauthenticated cached record after restart.
    pub fn finalized_record(&self, height: u64) -> Result<Option<FinalizedBlockRecord>, String> {
        let history = {
            let queues = self
                .0
                .lock()
                .map_err(|_| "runtime pipeline lock poisoned")?;
            if let Some(record) = queues.finalized_records.get(&height) {
                return Ok(Some(record.clone()));
            }
            queues.finality_history.clone()
        };
        let Some(history) = history else {
            return Ok(None);
        };
        let store = synergy_posy::persistence::FinalityStore::new(&history.root)
            .map_err(|e| e.to_string())?;
        let Some(record) = store.get(height).map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        // History is callable from RPC/source workers concurrently with PoSy.
        // Consume it using this thread's independent authenticated provider,
        // never the supervisor's nonblocking consensus engine.
        let qcs = synergy_posy::VerifiedQuorumCertificateStore::new(&history.root)
            .map_err(|e| e.to_string())?;
        let end = height
            .checked_add(2)
            .ok_or("historical finality height overflow")?;
        let mut finality = synergy_posy::ThreeQcFinality::default();
        for certified_height in height..=end {
            let Some(qc) = history.verified_qc(&qcs, certified_height)?
            else {
                return Err("historical finality lacks verified three-QC witness".into());
            };
            finality.accept(qc).map_err(|e| e.to_string())?;
        }
        if finality.last_finalized() != Some(&record) {
            return Err("historical finality record differs from verified witness".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        if queues.finalized_records.len() < MAX_PER_PROTOCOL {
            queues.finalized_records.insert(height, record.clone());
        }
        Ok(Some(record))
    }

    /// Reads the exact durable record and its authenticated three-QC witness.
    /// The shared queue lock only snapshots immutable history configuration;
    /// disk reads and signature verification never run under that lock.
    pub fn finalized_record_with_witness(
        &self,
        height: u64,
    ) -> Result<
        Option<(
            FinalizedBlockRecord,
            [synergy_posy::SimplifiedQuorumCertificate; 3],
        )>,
        String,
    > {
        let history = {
            self.0
                .lock()
                .map_err(|_| "runtime pipeline lock poisoned")?
                .finality_history
                .clone()
        };
        let Some(history) = history else {
            return Ok(None);
        };
        let store = synergy_posy::persistence::FinalityStore::new(&history.root)
            .map_err(|e| e.to_string())?;
        let Some(record) = store.get(height).map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        // History is callable from RPC/source workers concurrently with PoSy.
        // Consume it using this thread's independent authenticated provider,
        // never the supervisor's nonblocking consensus engine.
        let qcs = synergy_posy::VerifiedQuorumCertificateStore::new(&history.root)
            .map_err(|e| e.to_string())?;
        let mut witness = Vec::with_capacity(3);
        let mut finality = synergy_posy::ThreeQcFinality::default();
        let end = height
            .checked_add(2)
            .ok_or("source witness height overflow")?;
        for certified_height in height..=end {
            let qc = history.verified_qc(&qcs, certified_height)?
                .ok_or("source finality lacks durable verified QC")?;
            finality.accept(qc.clone()).map_err(|e| e.to_string())?;
            witness.push(qc);
        }
        if finality.last_finalized() != Some(&record) {
            return Err("source record disagrees with authenticated three-QC witness".into());
        }
        let witness = witness
            .try_into()
            .map_err(|_| "source witness must contain exactly three QCs")?;
        Ok(Some((record, witness)))
    }

    pub fn submit_proposal_validation(
        &self,
        certificate: synergy_posy::ProposalValidationCertificate,
    ) -> Result<(), String> {
        self.submit_validation(certificate, None, false)
    }

    pub(crate) fn submit_processing_proposal_validation(
        &self,
        certificate: synergy_posy::ProposalValidationCertificate,
        takeover: Option<&synergy_posy::AcceptedTimeoutSummary>,
    ) -> Result<(), String> {
        self.submit_validation(certificate, takeover, true)
    }

    fn submit_validation(
        &self,
        certificate: synergy_posy::ProposalValidationCertificate,
        takeover: Option<&synergy_posy::AcceptedTimeoutSummary>,
        processing: bool,
    ) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        let height = certificate.context.height;
        if let Some(existing) = queues.proposal_validations.get(&height) {
            if existing.id().map_err(|e| e.to_string())?
                != certificate.id().map_err(|e| e.to_string())?
            {
                if !processing {
                    return Err("conflicting locally verified proposal validation".into());
                }
                synergy_posy::verify_processing_validation_replacement(
                    existing,
                    &certificate,
                    takeover,
                )
                .map_err(|e| e.to_string())?;
            } else {
                return Ok(());
            }
        }
        if queues.proposal_validations.len() >= MAX_PER_PROTOCOL {
            let oldest = queues
                .proposal_validations
                .keys()
                .next()
                .copied()
                .ok_or("empty validation cache")?;
            if height <= oldest {
                return Ok(());
            }
            queues.proposal_validations.remove(&oldest);
        }
        queues.proposal_validations.insert(height, certificate);
        // Record the authoritative VC event, not the later ETDAG acknowledgement.
        #[cfg(feature = "qualification-timing")]
        drop(queues);
        #[cfg(feature = "qualification-timing")]
        if let Some(target) = height.checked_add(2) {
            use super::qualification_timing::{self as timing, Classification, Kind, Phase, Role};
            timing::emit_once(
                Kind::Window,
                Phase::CutoffClose,
                target,
                0,
                0,
                Role::Participant,
                Classification::Observed,
                None,
                None,
            );
        }
        Ok(())
    }

    pub fn proposal_validation(
        &self,
        height: u64,
    ) -> Result<Option<synergy_posy::ProposalValidationCertificate>, String> {
        let queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        Ok(queues.proposal_validations.get(&height).cloned())
    }

    pub(super) fn report_cut_recovery_state(
        &self,
        target: u64,
        state: CutRecoveryState,
    ) -> Result<(), String> {
        let mut q = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        if let Some(finalized) = q.latest_finality.as_ref().map(|f| f.height) {
            q.cut_recovery_states
                .retain(|height, _| *height > finalized);
            q.cut_recovery_generations
                .retain(|height, _| *height > finalized);
        }
        if !q.cut_recovery_states.contains_key(&target)
            && q.cut_recovery_states.len() >= MAX_PER_PROTOCOL
        {
            return Err("R3 target state cache full".into());
        }
        // The pending queue is bounded independently of retained disk history.
        // Remove only authorizations the ETDAG owner has durably acknowledged.
        if let Some(id) = state.last_timeout_id.as_ref() {
            if let Some(generations) = q.cut_recovery_generations.get_mut(&target) {
                if let Some(index) = generations.iter().position(|g| &g.timeout_id == id) {
                    generations.drain(..=index);
                }
            }
        }
        q.cut_recovery_states.insert(target, state);
        Ok(())
    }
    pub(super) fn cut_recovery_state(
        &self,
        target: u64,
    ) -> Result<Option<CutRecoveryState>, String> {
        let q = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        let mut state = q.cut_recovery_states.get(&target).cloned();
        if let (Some(state), Some(generations)) =
            (&mut state, q.cut_recovery_generations.get(&target))
        {
            if let Some(last) = generations.last() {
                state.cutoff = last.cutoff_context_root.clone();
                state.last_timeout_id = Some(last.timeout_id.clone());
            }
        }
        Ok(state)
    }
    /// Called only by the PoSy owner after verifying all runtime exclusions.
    pub(super) fn try_submit_cut_recovery_generation(
        &self,
        target: u64,
        generation: synergy_etdag::persistence::CutRecoveryGeneration,
    ) -> Result<bool, String> {
        let mut q = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        if q.protected_commitments.contains_key(&target)
            || target.checked_sub(1).is_some_and(|h| {
                q.proposal_validations.contains_key(&h) || q.protected_materials.contains_key(&h)
            })
            || q.latest_finality
                .as_ref()
                .is_some_and(|f| f.height >= target)
        {
            return Err("R3 cannot replace bound protected material".into());
        }
        if q.cut_recovery_generations
            .get(&target)
            .and_then(|generations| generations.last())
            .is_some_and(|g| g.timeout_id == generation.timeout_id)
        {
            return Ok(true);
        }
        let retained = q
            .cut_recovery_generations
            .values()
            .flatten()
            .fold(0usize, |sum, g| {
                sum.saturating_add(cut_recovery_resource_bytes(g))
            });
        if cut_recovery_resource_bytes(&generation)
            > MAX_PENDING_CUT_RECOVERY_BYTES.saturating_sub(retained)
            || q.cut_recovery_generations
                .get(&target)
                .is_some_and(|g| g.len() >= MAX_PER_PROTOCOL)
            || (!q.cut_recovery_generations.contains_key(&target)
                && q.cut_recovery_generations.len() >= MAX_PER_PROTOCOL)
        {
            // PoSy retains its authenticated durable timeout path and retries
            // derivation after ETDAG acknowledges the pending prefix.
            return Ok(false);
        }
        q.cut_recovery_generations
            .entry(target)
            .or_default()
            .push(generation);
        Ok(true)
    }
    pub(super) fn cut_recovery_generations(
        &self,
        target: u64,
    ) -> Result<Vec<synergy_etdag::persistence::CutRecoveryGeneration>, String> {
        let q = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        Ok(q.cut_recovery_generations
            .get(&target)
            .cloned()
            .unwrap_or_default())
    }

    pub fn protected_cutoff_authority(
        &self,
        target: u64,
    ) -> Result<Option<synergy_etdag::EtdagDigest>, String> {
        let height = target.checked_sub(2).ok_or("invalid cutoff target")?;
        self.proposal_validation(height)?
            .map(|certificate| {
                let id = certificate.id().map_err(|e| e.to_string())?;
                Ok(synergy_etdag::EtdagDigest::from_domain_bytes(
                    "SYNERGY_ETDAG_CUTOFF_VC_V1",
                    id.as_bytes(),
                ))
            })
            .transpose()
    }

    pub fn submit_protected_commitments(
        &self,
        target: u64,
        batch: synergy_etdag::DeterministicProtectedBatch,
        cutoff: synergy_etdag::EtdagDigest,
    ) -> Result<(), String> {
        batch
            .validate()
            .map_err(|e| format!("invalid protected commitment: {e:?}"))?;
        cutoff
            .validate()
            .map_err(|e| format!("invalid cutoff commitment: {e:?}"))?;
        if batch.target_height != target {
            return Err("protected commitment target mismatch".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        if let Some(existing) = queues.protected_commitments.get(&target) {
            return if existing == &(batch, cutoff) {
                Ok(())
            } else {
                Err("conflicting protected commitments".into())
            };
        }
        if queues.protected_commitments.len() >= MAX_PER_PROTOCOL {
            return Err("protected commitment cache full".into());
        }
        queues.protected_commitments.insert(target, (batch, cutoff));
        Ok(())
    }

    pub fn protected_commitments(
        &self,
        target: u64,
    ) -> Result<
        Option<(
            synergy_etdag::DeterministicProtectedBatch,
            synergy_etdag::EtdagDigest,
        )>,
        String,
    > {
        let queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        Ok(queues.protected_commitments.get(&target).cloned())
    }

    pub fn submit_protected_material(
        &self,
        material: synergy_etdag::execution::ProtectedProposalMaterial,
    ) -> Result<(), String> {
        material
            .validate()
            .map_err(|e| format!("invalid protected material: {e:?}"))?;
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        if let Some(existing) = queues.protected_materials.get(&material.height) {
            return if existing == &material {
                Ok(())
            } else {
                Err("conflicting protected proposal material".into())
            };
        }
        if queues.protected_materials.len() >= MAX_PER_PROTOCOL {
            return Err("protected material cache full".into());
        }
        queues.protected_materials.insert(material.height, material);
        Ok(())
    }

    pub fn accepted_protected_parent(
        &self,
        target: u64,
    ) -> Result<
        Option<(
            synergy_etdag::ProtectedRevealAuthorization,
            synergy_etdag::execution::ParentProposalRevealEvidence,
        )>,
        String,
    > {
        let parent = target
            .checked_sub(1)
            .ok_or("invalid protected reveal target")?;
        let queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned")?;
        let Some(certificate) = queues.proposal_validations.get(&parent) else {
            return Ok(None);
        };
        let Some(material) = queues.protected_materials.get(&parent) else {
            return Ok(None);
        };
        let Some((batch, _)) = queues.protected_commitments.get(&target) else {
            return Ok(None);
        };
        let root = synergy_block::hash_block_bytes(
            &material
                .commitment_bytes()
                .map_err(|e| format!("protected material: {e:?}"))?,
        );
        if certificate.candidate.protected_execution_root != root
            || material.next_batch_root != batch.protected_batch_root
        {
            return Err("accepted parent VC differs from protected material".into());
        }
        let mut authorization = synergy_etdag::ProtectedRevealAuthorization {
            authorization_version: 1,
            context_root: batch.context_root.clone(),
            target_height: target,
            protected_batch_root: batch.protected_batch_root.clone(),
            finality_reference: batch.protected_batch_root.clone(),
        };
        authorization.finality_reference = synergy_etdag::reveal::parent_reveal_reference(
            &certificate.candidate.block_id,
            &certificate.id().map_err(|e| e.to_string())?,
            &authorization,
        )
        .map_err(|e| format!("reveal reference: {e:?}"))?;
        Ok(Some((
            authorization,
            synergy_etdag::execution::ParentProposalRevealEvidence {
                material: material.clone(),
                next_batch: batch.clone(),
                validation_proof: serde_json::to_vec(certificate).map_err(|e| e.to_string())?,
            },
        )))
    }

    pub fn latest_finality_with_witness(
        &self,
    ) -> Result<Option<(FinalizedBlockRecord, Vec<u8>)>, String> {
        let queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        Ok(queues
            .latest_finality
            .clone()
            .zip(queues.latest_finality_witness.clone()))
    }

    pub fn latest_finality(&self) -> Result<Option<FinalizedBlockRecord>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|queues| queues.latest_finality.clone())
    }

    /// Execution inspects the verified front without discarding finality while
    /// its canonical candidate is still being fetched/re-executed by Sync.
    pub fn pending_finality(&self) -> Result<Option<FinalizedBlockRecord>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|queues| queues.finality.front().cloned())
    }

    pub fn take_finality(&self) -> Result<Option<FinalizedBlockRecord>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.finality.pop_front())
    }

    pub fn publish(&self, frame: InboundFrame) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "authenticated ingress lock poisoned".to_string())?;
        if queues
            .authenticated_sessions
            .get(frame.peer.node_address.as_str())
            != Some(&frame.peer.session_id)
        {
            return Ok(());
        }
        let queue = queues.frames.entry(frame.protocol).or_default();
        if queue.len() >= MAX_PER_PROTOCOL {
            // Authenticated transport remains best effort under a bounded
            // burst. Protocol retry owners recover omitted frames; one full
            // protocol cannot terminate the shared networking service.
            return Ok(());
        }
        queue.push_back(frame);
        Ok(())
    }

    pub fn take(&self, protocol: ProtocolKind) -> Result<Option<InboundFrame>, String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "authenticated ingress lock poisoned".to_string())?;
        Ok(queues
            .frames
            .get_mut(&protocol)
            .and_then(VecDeque::pop_front))
    }

    pub fn discard_session(&self, peer_id: &str, session_id: SessionId) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "authenticated ingress lock poisoned".to_string())?;
        discard_queued_session(&mut queues, peer_id, session_id);
        if queues.authenticated_sessions.get(peer_id) == Some(&session_id) {
            queues.authenticated_sessions.remove(peer_id);
            queues.apqe_sessions.remove(peer_id);
            queues.verified_heads.retain(|head| head.peer_id != peer_id);
        }
        if queues
            .verified_peer_heights
            .get(peer_id)
            .is_some_and(|(current_session, _)| *current_session == session_id)
        {
            queues.verified_peer_heights.remove(peer_id);
        }
        Ok(())
    }

    pub fn clear(&self, protocol: ProtocolKind) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "authenticated ingress lock poisoned".to_string())?;
        queues.frames.remove(&protocol);
        Ok(())
    }
}

fn discard_queued_session(queues: &mut Queues, peer_id: &str, session_id: SessionId) {
    if queues
        .processing_input_echoes
        .get(peer_id)
        .is_some_and(|(s, _, _, _)| *s == session_id)
    {
        queues.processing_input_echoes.remove(peer_id);
    }
    if queues
        .verified_peer_heights
        .get(peer_id)
        .is_some_and(|(current_session, _)| *current_session == session_id)
    {
        queues.verified_peer_heights.remove(peer_id);
    }
    for queue in queues.frames.values_mut() {
        queue.retain(|frame| {
            frame.peer.node_address.as_str() != peer_id || frame.peer.session_id != session_id
        });
    }
    queues
        .head_claims
        .retain(|(peer, _)| peer.node_address.as_str() != peer_id || peer.session_id != session_id);
    queues.sync_candidate_requests.retain(|(peer, _, _)| {
        peer.node_address.as_str() != peer_id || peer.session_id != session_id
    });
    queues
        .sync_candidate_responses
        .retain(|(peer, _)| peer.node_address.as_str() != peer_id || peer.session_id != session_id);
    queues
        .snapshot_chunk_requests
        .retain(|(peer, _)| peer.node_address.as_str() != peer_id || peer.session_id != session_id);
}

pub(super) fn candidate_response_memory(
    response: &FinalizedCandidateResponse,
) -> Result<usize, String> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(
        response
            .finality_witness
            .len()
            .saturating_add(response.processing_replay.as_ref().map_or(0, Vec::len)),
    );
    serde_json::to_writer(&mut counter, &response.candidate).map_err(|e| e.to_string())?;
    Ok(counter.0)
}

fn bounded_push<T>(queue: &mut VecDeque<T>, value: T, label: &str) -> Result<(), String> {
    if queue.len() >= MAX_PER_PROTOCOL {
        return Err(format!("{label} queue is full"));
    }
    queue.push_back(value);
    Ok(())
}

// Finality notifications are scheduling hints, not the durable authority.
// Under execution backpressure, retain the newest hint only after proving every
// omitted record remains exactly available in the canonical finality store.
// Execution still verifies each intermediate three-QC proof and executes every
// candidate in order; this never authorizes a skipped state transition.
fn enqueue_finality(
    pending: &mut VecDeque<FinalizedBlockRecord>,
    record: &FinalizedBlockRecord,
    history_root: Option<&std::path::Path>,
) -> Result<(), String> {
    if pending.len() >= MAX_PER_PROTOCOL {
        let root = history_root.ok_or("PoSy finality queue is full without durable history")?;
        let store = synergy_posy::persistence::FinalityStore::new(root)
            .map_err(|error| format!("open finality notification history: {error}"))?;
        for retained in pending.iter().chain(std::iter::once(record)) {
            if store
                .get(retained.height)
                .map_err(|error| error.to_string())?
                .as_ref()
                != Some(retained)
            {
                return Err("finality notification lacks exact durable backing".into());
            }
        }
        pending.clear();
    }
    pending.push_back(record.clone());
    Ok(())
}

fn prune_protected_caches(queues: &mut Queues, finalized_height: u64) {
    let retain_from = finalized_height.saturating_sub(8);
    queues
        .protected_commitments
        .retain(|height, _| *height >= retain_from);
    queues
        .protected_materials
        .retain(|height, _| *height >= retain_from);
    queues
        .proposal_validations
        .retain(|height, _| *height >= retain_from);
}

#[cfg(test)]
mod outbound_tests {
    use super::*;

    fn frame(protocol: ProtocolKind, sequence: u8) -> OutboundFrame {
        OutboundFrame {
            peer_id: "verified-peer".into(),
            protocol,
            payload: vec![sequence],
        }
    }

    #[test]
    fn verified_sync_handoff_coalesces_retries_and_reserves_consumer_return() {
        let ingress = AuthenticatedIngress::default();
        let candidate = |height: u64| {
            let world = synergy_state::WorldState::default();
            let material = synergy_etdag::execution::ProtectedProposalMaterial {
                material_version: 2,
                height,
                execution_root: synergy_etdag::EtdagDigest::from_domain_bytes(
                    "handoff-test",
                    b"execution",
                ),
                next_batch_root: synergy_etdag::EtdagDigest::from_domain_bytes(
                    "handoff-test",
                    b"batch",
                ),
                cutoff_boundary_root: synergy_etdag::EtdagDigest::from_domain_bytes(
                    "handoff-test",
                    b"cutoff",
                ),
            };
            let mut candidate = synergy_execution::BudgetedExecutionCandidate {
                resource_permit: None,
                height,
                block_id: String::new(),
                parent_block_id: "a".repeat(64),
                protected_execution_root: synergy_block::hash_block_bytes(
                    &material.commitment_bytes().unwrap(),
                ),
                protected_material: material.into(),
                state_root: synergy_state::state_root(&world).unwrap(),
                transactions: vec![],
                receipts: vec![],
                state: Arc::new(
                    BudgetedWorld::try_clone_world(&world, ingress.world_budget()).unwrap(),
                ),
            };
            candidate.block_id = candidate.commitment_id().unwrap();
            let record = FinalizedBlockRecord {
                height,
                block_id: candidate.block_id.clone(),
                finality_certificate_id: format!("{height:064x}"),
                protected_execution_root: candidate.protected_execution_root.clone(),
            };
            (Arc::new(candidate), record)
        };
        let (first, first_record) = candidate(1);
        for _ in 0..MAX_PER_PROTOCOL * 2 {
            assert!(ingress
                .try_submit_verified_sync_candidate(Arc::clone(&first), first_record.clone())
                .unwrap());
        }
        assert_eq!(ingress.0.lock().unwrap().verified_sync_candidates.len(), 1);
        let mut conflict = first_record.clone();
        conflict.finality_certificate_id = "f".repeat(64);
        assert!(ingress
            .try_submit_verified_sync_candidate(Arc::clone(&first), conflict)
            .unwrap_err()
            .contains("conflicting"));
        for height in 2..MAX_PER_PROTOCOL as u64 {
            let (item, record) = candidate(height);
            assert!(ingress
                .try_submit_verified_sync_candidate(item, record)
                .unwrap());
        }
        let retained = candidate(MAX_PER_PROTOCOL as u64);
        let retained_bytes = serde_json::to_vec(retained.0.as_ref()).unwrap();
        assert!(!ingress
            .try_submit_verified_sync_candidate(Arc::clone(&retained.0), retained.1.clone())
            .unwrap());
        // Execution pops one item. A concurrent producer consumes the newly
        // available producer slot, while the reserved slot still admits return
        // of the exact in-flight item under native dependency backpressure.
        let in_flight = ingress.take_verified_sync_candidate().unwrap().unwrap();
        assert!(ingress
            .try_submit_verified_sync_candidate(Arc::clone(&retained.0), retained.1.clone())
            .unwrap());
        ingress
            .submit_verified_sync_candidate(Arc::clone(&in_flight.0), in_flight.1.clone())
            .unwrap();
        assert_eq!(
            ingress.0.lock().unwrap().verified_sync_candidates.len(),
            MAX_PER_PROTOCOL
        );
        let next_retained = candidate(MAX_PER_PROTOCOL as u64 + 1);
        assert!(!ingress
            .try_submit_verified_sync_candidate(
                Arc::clone(&next_retained.0),
                next_retained.1.clone()
            )
            .unwrap());
        assert_eq!(
            serde_json::to_vec(retained.0.as_ref()).unwrap(),
            retained_bytes
        );
        let mut delivered = BTreeSet::new();
        while let Some((item, record)) = ingress.take_verified_sync_candidate().unwrap() {
            assert_eq!(item.height, record.height);
            assert!(delivered.insert(item.height));
        }
        assert_eq!(delivered.len(), MAX_PER_PROTOCOL);
        assert!(ingress
            .try_submit_verified_sync_candidate(
                Arc::clone(&next_retained.0),
                next_retained.1.clone()
            )
            .unwrap());
        let delivered = ingress.take_verified_sync_candidate().unwrap().unwrap();
        assert!(Arc::ptr_eq(&delivered.0, &next_retained.0));
        assert_eq!(delivered.1, next_retained.1);
    }

    #[test]
    fn cut_recovery_shared_byte_budget_preserves_unacknowledged_originals() {
        let ingress = AuthenticatedIngress::default();
        let root = synergy_etdag::EtdagDigest::from_domain_bytes("handoff-test", b"root");
        let generation = |index: usize| synergy_etdag::persistence::CutRecoveryGeneration {
            original_cutoff_context_root: root.clone(),
            previous_cutoff_context_root: root.clone(),
            cutoff_context_root: root.clone(),
            timeout_id: format!("{index:064x}"),
            timeout_round: index as u64,
            authorization: vec![1; 1024 * 1024],
        };
        let mut accepted = Vec::new();
        for index in 0..64 {
            let target = 5 + index as u64 % 2;
            if !ingress
                .try_submit_cut_recovery_generation(target, generation(index))
                .unwrap()
            {
                break;
            }
            accepted.push((target, index));
        }
        assert!(!accepted.is_empty() && accepted.len() < 8);
        let before: Vec<_> = [5, 6]
            .into_iter()
            .map(|height| ingress.cut_recovery_generations(height).unwrap())
            .collect();
        let mut inflated = generation(100);
        inflated.authorization.reserve_exact(8 * 1024 * 1024);
        assert!(!ingress
            .try_submit_cut_recovery_generation(5, inflated)
            .unwrap());
        for (i, height) in [5, 6].into_iter().enumerate() {
            assert_eq!(ingress.cut_recovery_generations(height).unwrap(), before[i]);
        }
        // Only a durable owner acknowledgement frees a prefix. The other target
        // and later original proofs remain byte-identical through backpressure.
        ingress
            .report_cut_recovery_state(
                5,
                CutRecoveryState {
                    cutoff: root.clone(),
                    last_timeout_id: Some(format!("{:064x}", accepted[0].1)),
                    committed: false,
                },
            )
            .unwrap();
        assert_eq!(ingress.cut_recovery_generations(6).unwrap(), before[1]);
        assert_eq!(ingress.cut_recovery_generations(5).unwrap(), before[0][1..]);
        assert!(ingress
            .try_submit_cut_recovery_generation(5, generation(100))
            .unwrap());
        let q = ingress.0.lock().unwrap();
        assert!(
            q.cut_recovery_generations
                .values()
                .flatten()
                .map(cut_recovery_resource_bytes)
                .sum::<usize>()
                <= MAX_PENDING_CUT_RECOVERY_BYTES
        );
    }

    #[test]
    fn busy_etdag_cannot_starve_posy_and_full_peer_frames_are_retained_exactly() {
        let ingress = AuthenticatedIngress::default();
        for sequence in 0..64 {
            assert_eq!(
                ingress
                    .try_publish_outbound(frame(ProtocolKind::Etdag, sequence))
                    .unwrap(),
                sequence < 16
            );
        }
        for sequence in 0..16 {
            assert!(ingress
                .try_publish_outbound(frame(ProtocolKind::Posy, sequence))
                .unwrap());
        }
        for sequence in 0..8 {
            assert!(ingress
                .try_publish_outbound(frame(ProtocolKind::Sync, sequence))
                .unwrap());
        }
        for protocol in [
            ProtocolKind::Status,
            ProtocolKind::Discovery,
            ProtocolKind::Transaction,
            ProtocolKind::Snapshot,
            ProtocolKind::Observer,
            ProtocolKind::Sxcp,
        ] {
            for sequence in 0..4 {
                assert!(ingress
                    .try_publish_outbound(frame(protocol, sequence))
                    .unwrap());
            }
            assert!(!ingress.try_publish_outbound(frame(protocol, 4)).unwrap());
        }
        assert_eq!(ingress.0.lock().unwrap().outbound.len(), 64);
        let mut delivered_posy = Vec::new();
        let mut attempts = 0;
        ingress
            .dispatch_outbound(|frame| {
                attempts += 1;
                if frame.protocol == ProtocolKind::Etdag {
                    return Some(frame);
                }
                if frame.protocol == ProtocolKind::Posy {
                    delivered_posy.push(frame.payload);
                }
                None
            })
            .unwrap();
        assert_eq!(attempts, 64);
        assert_eq!(
            delivered_posy,
            (0..16).map(|sequence| vec![sequence]).collect::<Vec<_>>()
        );
        assert_eq!(ingress.0.lock().unwrap().outbound.len(), 16);
        let mut recovered = Vec::new();
        ingress
            .dispatch_outbound(|frame| {
                recovered.push(frame);
                None
            })
            .unwrap();
        assert_eq!(recovered.len(), 16);
        for (sequence, retained) in recovered.iter().enumerate() {
            assert_eq!(retained.peer_id, "verified-peer");
            assert_eq!(retained.protocol, ProtocolKind::Etdag);
            assert_eq!(retained.payload, vec![sequence as u8]);
        }
        assert!(ingress.take_outbound().unwrap().is_none());
    }

    #[test]
    fn inbound_burst_is_bounded_and_does_not_stop_another_protocol() {
        let ingress = AuthenticatedIngress::default();
        let peer = AuthenticatedPeer::new(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            SessionId(1),
            vec![],
        )
        .unwrap();
        ingress
            .admit_session(peer.node_address.to_string(), peer.session_id)
            .unwrap();
        for _ in 0..128 {
            ingress
                .publish(InboundFrame::new(peer.clone(), ProtocolKind::Etdag, vec![1], 8).unwrap())
                .unwrap();
        }
        ingress
            .publish(InboundFrame::new(peer, ProtocolKind::Posy, vec![2], 8).unwrap())
            .unwrap();
        assert_eq!(
            ingress.take(ProtocolKind::Posy).unwrap().unwrap().payload,
            vec![2]
        );
        let mut admitted = 0;
        while ingress.take(ProtocolKind::Etdag).unwrap().is_some() {
            admitted += 1;
        }
        assert_eq!(admitted, 64);
    }

    #[test]
    fn verified_peer_progress_is_monotonic_and_scoped_to_current_session() {
        let ingress = AuthenticatedIngress::default();
        ingress
            .admit_session("validator-peer".into(), SessionId(1))
            .unwrap();
        let head = |height| VerifiedHead {
            peer_id: "validator-peer".into(),
            finalized_height: height,
            finalized_hash: format!("block-{height}"),
            finality_evidence_id: format!("finality-{height}"),
        };

        ingress
            .submit_verified_head(head(12), SessionId(1))
            .unwrap();
        ingress
            .submit_verified_head(head(10), SessionId(1))
            .unwrap();
        assert_eq!(
            ingress.verified_peer_heights().unwrap()["validator-peer"],
            12
        );

        ingress
            .admit_session("validator-peer".into(), SessionId(2))
            .unwrap();
        assert!(ingress.verified_peer_heights().unwrap().is_empty());
        ingress
            .submit_verified_head(head(99), SessionId(1))
            .unwrap();
        assert!(ingress.verified_peer_heights().unwrap().is_empty());
        ingress
            .submit_verified_head(head(13), SessionId(2))
            .unwrap();
        assert_eq!(
            ingress.verified_peer_heights().unwrap()["validator-peer"],
            13
        );
    }

    #[test]
    fn processing_echo_transport_hint_is_exact_and_resets_on_reconnect() {
        let ingress = AuthenticatedIngress::default();
        let peer = "validator-peer";
        ingress
            .record_processing_input_echo(peer, 10, 0, "candidate-a")
            .unwrap();
        assert!(!ingress
            .processing_input_was_echoed(peer, 10, 0, "candidate-a")
            .unwrap());
        ingress.admit_session(peer.into(), SessionId(1)).unwrap();
        ingress
            .record_processing_input_echo(peer, 10, 0, "candidate-a")
            .unwrap();
        assert!(ingress
            .processing_input_was_echoed(peer, 10, 0, "candidate-a")
            .unwrap());
        assert!(ingress.processing_peer_replayed_after(peer, 9).unwrap());
        assert!(!ingress.processing_peer_replayed_after(peer, 10).unwrap());
        for (h, r, id) in [
            (11, 0, "candidate-a"),
            (10, 1, "candidate-a"),
            (10, 0, "candidate-b"),
        ] {
            assert!(!ingress.processing_input_was_echoed(peer, h, r, id).unwrap());
        }
        assert!(!ingress
            .processing_input_was_echoed("other-peer", 10, 0, "candidate-a")
            .unwrap());
        ingress
            .record_processing_input_echo(peer, 10, 1, "candidate-b")
            .unwrap();
        ingress
            .record_processing_input_echo(peer, 10, 0, "candidate-a")
            .unwrap();
        assert!(ingress
            .processing_input_was_echoed(peer, 10, 1, "candidate-b")
            .unwrap());
        ingress.admit_session(peer.into(), SessionId(2)).unwrap();
        assert!(!ingress
            .processing_input_was_echoed(peer, 10, 1, "candidate-b")
            .unwrap());
        assert!(!ingress.processing_peer_replayed_after(peer, 9).unwrap());
        ingress
            .record_processing_input_echo(peer, 10, 1, "candidate-b")
            .unwrap();
        ingress.discard_session(peer, SessionId(1)).unwrap();
        assert!(ingress
            .processing_input_was_echoed(peer, 10, 1, "candidate-b")
            .unwrap());
        ingress.discard_session(peer, SessionId(2)).unwrap();
        assert!(!ingress
            .processing_input_was_echoed(peer, 10, 1, "candidate-b")
            .unwrap());
    }

    #[test]
    fn processing_echo_transport_hints_are_bounded_without_losing_retry_fallback() {
        let ingress = AuthenticatedIngress::default();
        for n in 0..=MAX_PER_PROTOCOL {
            let peer = format!("peer-{n}");
            ingress.admit_session(peer.clone(), SessionId(1)).unwrap();
            ingress
                .record_processing_input_echo(&peer, 10, 0, "candidate-a")
                .unwrap();
        }
        assert_eq!(
            ingress.0.lock().unwrap().processing_input_echoes.len(),
            MAX_PER_PROTOCOL
        );
        assert!(!ingress
            .processing_input_was_echoed(&format!("peer-{MAX_PER_PROTOCOL}"), 10, 0, "candidate-a")
            .unwrap());
        ingress
            .record_processing_input_echo("peer-0", 11, 0, "candidate-b")
            .unwrap();
        assert!(ingress
            .processing_input_was_echoed("peer-0", 11, 0, "candidate-b")
            .unwrap());
    }
    fn structural_finality(height: u64) -> FinalizedBlockRecord {
        // Queue/storage lifecycle fixture only, never a substitute for the
        // genuine authenticated three-QC execution-gap recovery regression.
        FinalizedBlockRecord {
            height,
            block_id: format!("backpressure-{height}"),
            finality_certificate_id: "a".repeat(64),
            protected_execution_root: "b".repeat(64),
        }
    }

    #[test]
    fn finality_backpressure_coalesces_only_exact_durable_notifications() {
        let root = std::env::temp_dir().join(format!(
            "synergy-finality-backpressure-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = synergy_posy::persistence::FinalityStore::new(&root).unwrap();
        let mut pending = VecDeque::new();
        let mut previous = None;
        // The execution owner consumes nothing while its candidate is absent.
        // More than two full queue windows must remain bounded without loss of
        // any authoritative durable record.
        for height in 1..=200 {
            let record = structural_finality(height);
            if pending.len() == MAX_PER_PROTOCOL {
                let before = pending.clone();
                assert!(enqueue_finality(&mut pending, &record, None).is_err());
                assert_eq!(pending, before);
                assert!(enqueue_finality(&mut pending, &record, Some(&root)).is_err());
                assert_eq!(pending, before);
            }
            store
                .commit_exactly_once(&record, previous.as_ref())
                .unwrap();
            if pending.len() == MAX_PER_PROTOCOL {
                let before = pending.clone();
                let mut conflict = record.clone();
                conflict.block_id.push_str("-conflict");
                assert!(enqueue_finality(&mut pending, &conflict, Some(&root)).is_err());
                assert_eq!(pending, before);
            }
            enqueue_finality(&mut pending, &record, Some(&root)).unwrap();
            assert!(pending.len() <= MAX_PER_PROTOCOL);
            assert_eq!(pending.back(), Some(&record));
            previous = Some(record);
        }
        for height in 1..=200 {
            assert_eq!(
                store.get(height).unwrap(),
                Some(structural_finality(height))
            );
        }
        assert_eq!(pending.front().unwrap().height, 193);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn execution_commit_prunes_catchup_material_while_consensus_tip_is_unchanged() {
        let ingress = AuthenticatedIngress::default();
        ingress
            .submit_finality(structural_finality(1_000), vec![1])
            .unwrap();
        let root = synergy_etdag::EtdagDigest::from_domain_bytes("cache-test", b"root");
        let material = |height| synergy_etdag::execution::ProtectedProposalMaterial {
            material_version: 2,
            height,
            execution_root: root.clone(),
            next_batch_root: root.clone(),
            cutoff_boundary_root: root.clone(),
        };
        ingress.submit_protected_material(material(1_001)).unwrap();
        for height in 1..=200 {
            ingress.submit_protected_material(material(height)).unwrap();
            ingress.execution_committed(height).unwrap();
            let queues = ingress.0.lock().unwrap();
            assert!(queues.protected_materials.contains_key(&height));
            assert!(queues.protected_materials.contains_key(&1_001));
            assert!(queues.protected_materials.len() <= 10);
            assert_eq!(queues.latest_finality.as_ref().unwrap().height, 1_000);
        }
        // Repeated identical publication cannot fill the pending queue either.
        for _ in 0..200 {
            ingress
                .submit_finality(structural_finality(1_000), vec![1])
                .unwrap();
        }
        assert_eq!(ingress.0.lock().unwrap().finality.len(), 1);
    }

    #[test]
    fn protected_cache_retains_pipeline_headroom_past_h65() {
        // Cache lifecycle only: this does not fabricate finality authority.
        // The ingress finality publisher is exercised with structural records.
        let ingress = AuthenticatedIngress::default();
        let root = synergy_etdag::EtdagDigest::from_domain_bytes("cache-test", b"root");
        for height in 1..=200 {
            ingress
                .submit_protected_material(synergy_etdag::execution::ProtectedProposalMaterial {
                    material_version: 2,
                    height,
                    execution_root: root.clone(),
                    next_batch_root: root.clone(),
                    cutoff_boundary_root: root.clone(),
                })
                .unwrap();
            if height > 2 {
                let finalized = height - 2;
                ingress
                    .submit_finality(
                        FinalizedBlockRecord {
                            height: finalized,
                            block_id: format!("cache-{finalized}"),
                            finality_certificate_id: "structural-only".into(),
                            protected_execution_root: "structural-only".into(),
                        },
                        vec![1],
                    )
                    .unwrap();
                ingress.take_finality().unwrap();
                let queues = ingress.0.lock().unwrap();
                assert!(queues.protected_materials.contains_key(&height));
                assert!(queues.protected_materials.contains_key(&(height - 1)));
                assert!(queues.protected_materials.len() <= 11);
            }
        }
    }
}

#[cfg(test)]
mod chain_observation_tests {
    use super::*;

    #[test]
    fn missing_execution_hooks_are_unknown_and_replay_does_not_inflate_tps() {
        let ingress = AuthenticatedIngress::default();
        assert!(ingress.chain_observations().unwrap()["executed_total"].is_null());
        assert!(ingress.chain_observations().unwrap()["finalized_total"].is_null());
        ingress.record_execution_observation(1, 3, false).unwrap();
        assert_eq!(ingress.chain_observations().unwrap()["executed_total"], 3);
        assert!(ingress.chain_observations().unwrap()["finalized_total"].is_null());
        ingress.record_execution_observation(1, 3, true).unwrap();
        ingress.record_execution_observation(1, 3, true).unwrap();
        assert_eq!(ingress.chain_observations().unwrap()["finalized_total"], 3);
        for height in 2..=140 {
            ingress
                .record_execution_observation(height, 0, true)
                .unwrap();
        }
        ingress.record_execution_observation(1, 3, true).unwrap();
        assert_eq!(ingress.chain_observations().unwrap()["executed_total"], 3);
        assert_eq!(ingress.chain_observations().unwrap()["finalized_total"], 3);
        let queues = ingress.0.lock().unwrap();
        assert!(queues.observations.counts.len() <= 129);
        assert!(queues.observations.finalized_intervals_ms.len() <= 128);
    }

    #[test]
    fn conflicting_retained_execution_count_and_invalid_slot_root_are_rejected() {
        let ingress = AuthenticatedIngress::default();
        ingress.record_execution_observation(1, 3, true).unwrap();
        assert!(ingress.record_execution_observation(1, 4, true).is_err());
        assert!(ingress
            .publish_consensus_observation(3, 0, "invalid".into())
            .is_err());
        assert!(ingress.consensus_observation().unwrap().is_none());
        assert!(ingress
            .publish_consensus_observation(3, 2, "a".repeat(128))
            .is_err());
        let epoch_root = synergy_posy::canonical_hash(
            "SYNERGY_POSY_OBSERVATION_TEST_V1",
            &serde_json::json!({"epoch": 1}),
        )
        .unwrap();
        ingress
            .publish_consensus_observation(3, 2, epoch_root.clone())
            .unwrap();
        let slot = ingress.consensus_observation().unwrap().unwrap();
        assert_eq!(slot["height"], 3);
        assert_eq!(slot["round"], 2);
        assert_eq!(slot["epoch_context_root"], epoch_root);
        assert_eq!(slot["authority"], false);
    }
}

#[cfg(test)]
mod secure_transport_observation_tests {
    use super::*;
    #[test]
    fn profile_requires_actual_secure_admission_and_tracks_exact_session_retirement() {
        let ingress = AuthenticatedIngress::default();
        ingress.admit_session("peer".into(), SessionId(1)).unwrap();
        assert_eq!(
            ingress.transport_observations().unwrap()["apqe_session_count"],
            0
        );
        assert!(ingress.mark_apqe_session("peer", SessionId(2)).is_err());
        ingress.mark_apqe_session("peer", SessionId(1)).unwrap();
        let observed = ingress.transport_observations().unwrap();
        assert_eq!(observed["authenticated_peer_count"], 1);
        assert_eq!(observed["apqe_session_count"], 1);
        assert_eq!(
            observed["peers"][0]["profile"],
            "PQ-VSESSION-01-candidate-v1"
        );
        ingress.admit_session("peer".into(), SessionId(2)).unwrap();
        assert_eq!(
            ingress.transport_observations().unwrap()["apqe_session_count"],
            0
        );
        ingress.mark_apqe_session("peer", SessionId(2)).unwrap();
        ingress.discard_session("peer", SessionId(1)).unwrap();
        assert_eq!(
            ingress.transport_observations().unwrap()["apqe_session_count"],
            1
        );
        ingress.discard_session("peer", SessionId(2)).unwrap();
        assert_eq!(
            ingress.transport_observations().unwrap()["authenticated_peer_count"],
            0
        );
        assert_eq!(
            ingress.transport_observations().unwrap()["apqe_session_count"],
            0
        );
    }
}
