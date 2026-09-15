//! Shared bounded ingress from authenticated networking to owner services.
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use synergy_etdag::execution::PreparedProtectedBatch;
use synergy_execution::ExecutionCandidate;
use synergy_network::protocol::InboundFrame;
use synergy_posy::{ConsensusEvent, FinalizedBlockRecord};
use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind, SessionId};
use synergy_state::WorldState;
use synergy_sync::{
    FinalizedCandidateRequest, FinalizedCandidateResponse, HeadClaim, SnapshotChunkRequest,
    SnapshotChunkResponse, VerifiedHead,
};
use synergy_transport_registry::VerifiedSnapshot;

const MAX_PER_PROTOCOL: usize = 64;

#[derive(Default)]
struct Queues {
    frames: BTreeMap<ProtocolKind, VecDeque<InboundFrame>>,
    authenticated_sessions: BTreeMap<String, SessionId>,
    verified_overlay: Option<VerifiedSnapshot>,
    dials: VecDeque<DialRequest>,
    outbound: VecDeque<OutboundFrame>,
    head_claims: VecDeque<(AuthenticatedPeer, HeadClaim)>,
    verified_heads: VecDeque<VerifiedHead>,
    sync_candidate_requests: VecDeque<(AuthenticatedPeer, FinalizedCandidateRequest)>,
    sync_candidate_responses: VecDeque<(AuthenticatedPeer, FinalizedCandidateResponse)>,
    snapshot_chunk_requests: VecDeque<(AuthenticatedPeer, SnapshotChunkRequest)>,
    snapshot_chunk_responses: VecDeque<(AuthenticatedPeer, SnapshotChunkResponse)>,
    snapshot_publications: VecDeque<SnapshotPublication>,
    snapshot_restore_handoffs: VecDeque<SnapshotRestoreHandoff>,
    snapshot_restore_receipts: VecDeque<SnapshotRestoreReceipt>,
    verified_sync_candidates: VecDeque<(ExecutionCandidate, FinalizedBlockRecord)>,
    protected_batches: VecDeque<PreparedProtectedBatch>,
    consensus_events: VecDeque<(AuthenticatedPeer, ConsensusEvent)>,
    execution_candidates: VecDeque<ExecutionCandidate>,
    finality: VecDeque<FinalizedBlockRecord>,
    latest_finality: Option<FinalizedBlockRecord>,
    latest_finality_witness: Option<Vec<u8>>,
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

#[derive(Debug, Clone)]
pub struct SnapshotPublication {
    pub epoch: u64,
    pub finality: FinalizedBlockRecord,
    pub application_state_root: String,
    pub state: WorldState,
}

#[derive(Debug, Clone)]
pub struct SnapshotRestoreHandoff {
    pub epoch: u64,
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub finality_evidence_id: String,
    pub application_state_root: String,
    pub state: WorldState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRestoreReceipt {
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub application_state_root: String,
}

#[derive(Clone, Default)]
pub struct AuthenticatedIngress(Arc<Mutex<Queues>>);

impl AuthenticatedIngress {
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

    pub fn authenticated_peers(&self) -> Result<Vec<String>, String> {
        self.0
            .lock()
            .map_err(|_| "authenticated ingress lock poisoned".to_string())
            .map(|queues| queues.authenticated_sessions.keys().cloned().collect())
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
        if frame.peer_id.trim().is_empty() || frame.payload.is_empty() {
            return Err("invalid outbound authenticated frame".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "network control lock poisoned".to_string())?;
        if queues.outbound.len() >= MAX_PER_PROTOCOL {
            return Err("outbound frame queue is full".into());
        }
        queues.outbound.push_back(frame);
        Ok(())
    }

    pub fn take_outbound(&self) -> Result<Option<OutboundFrame>, String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "network control lock poisoned".to_string())?;
        Ok(queues.outbound.pop_front())
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

    pub fn submit_verified_head(&self, head: VerifiedHead) -> Result<(), String> {
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        if !queues.authenticated_sessions.contains_key(&head.peer_id) {
            return Ok(());
        }
        bounded_push(&mut queues.verified_heads, head, "verified sync head")
    }

    pub fn take_verified_head(&self) -> Result<Option<VerifiedHead>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.verified_heads.pop_front())
    }

    pub fn submit_sync_candidate_request(
        &self,
        peer: AuthenticatedPeer,
        request: FinalizedCandidateRequest,
    ) -> Result<(), String> {
        if !request.validate() {
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
        bounded_push(
            &mut queues.sync_candidate_requests,
            (peer, request),
            "Sync candidate request",
        )
    }

    pub fn take_sync_candidate_request(
        &self,
    ) -> Result<Option<(AuthenticatedPeer, FinalizedCandidateRequest)>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.sync_candidate_requests.pop_front())
    }

    pub fn submit_sync_candidate_response(
        &self,
        peer: AuthenticatedPeer,
        response: FinalizedCandidateResponse,
    ) -> Result<(), String> {
        response.candidate.validate()?;
        if !response.request.validate()
            || response.candidate.height != response.request.height
            || response.candidate.parent_block_id != response.request.expected_parent_id
            || response.finality_witness.is_empty()
            || response.finality_witness.len() > 1024 * 1024
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
            return Ok(());
        }
        bounded_push(
            &mut queues.sync_candidate_responses,
            (peer, response),
            "Sync candidate response",
        )
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

    pub fn submit_snapshot_chunk_response(
        &self,
        peer: AuthenticatedPeer,
        response: SnapshotChunkResponse,
    ) -> Result<(), String> {
        response.validate()?;
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
            &mut queues.snapshot_chunk_responses,
            (peer, response),
            "snapshot chunk response",
        )
    }

    pub fn take_snapshot_chunk_response(
        &self,
    ) -> Result<Option<(AuthenticatedPeer, SnapshotChunkResponse)>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.snapshot_chunk_responses.pop_front())
    }

    pub fn submit_snapshot_publication(
        &self,
        publication: SnapshotPublication,
    ) -> Result<(), String> {
        if publication.epoch == 0
            || publication.finality.height == 0
            || publication.finality.block_id.trim().is_empty()
            || publication
                .finality
                .finality_certificate_id
                .trim()
                .is_empty()
            || synergy_state::state_root(&publication.state)
                .map_err(|error| format!("root snapshot publication state: {error:?}"))?
                != publication.application_state_root
        {
            return Err("invalid finalized snapshot publication".into());
        }
        let mut queues = self
            .0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())?;
        bounded_push(
            &mut queues.snapshot_publications,
            publication,
            "finalized snapshot publication",
        )
    }

    pub fn take_snapshot_publication(&self) -> Result<Option<SnapshotPublication>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.snapshot_publications.pop_front())
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
        bounded_push(
            &mut queues.verified_sync_candidates,
            (candidate, record),
            "verified Sync candidate",
        )
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

    pub fn take_protected_batch(&self) -> Result<Option<PreparedProtectedBatch>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.protected_batches.pop_front())
    }

    pub fn submit_consensus_event(
        &self,
        peer: AuthenticatedPeer,
        event: ConsensusEvent,
    ) -> Result<(), String> {
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
        bounded_push(&mut queues.consensus_events, (peer, event), "PoSy event")
    }

    pub fn take_consensus_event(
        &self,
    ) -> Result<Option<(AuthenticatedPeer, ConsensusEvent)>, String> {
        self.0
            .lock()
            .map_err(|_| "runtime pipeline lock poisoned".to_string())
            .map(|mut queues| queues.consensus_events.pop_front())
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
        if queues.finality.len() >= MAX_PER_PROTOCOL {
            return Err("PoSy finality queue is full".into());
        }
        queues.finality.push_back(record.clone());
        queues.latest_finality = Some(record);
        queues.latest_finality_witness = Some(witness);
        Ok(())
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
            return Err("authenticated protocol ingress is full".into());
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
            queues.verified_heads.retain(|head| head.peer_id != peer_id);
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
    for queue in queues.frames.values_mut() {
        queue.retain(|frame| {
            frame.peer.node_address.as_str() != peer_id || frame.peer.session_id != session_id
        });
    }
    queues
        .head_claims
        .retain(|(peer, _)| peer.node_address.as_str() != peer_id || peer.session_id != session_id);
    queues
        .consensus_events
        .retain(|(peer, _)| peer.node_address.as_str() != peer_id || peer.session_id != session_id);
    queues
        .sync_candidate_requests
        .retain(|(peer, _)| peer.node_address.as_str() != peer_id || peer.session_id != session_id);
    queues
        .sync_candidate_responses
        .retain(|(peer, _)| peer.node_address.as_str() != peer_id || peer.session_id != session_id);
    queues
        .snapshot_chunk_requests
        .retain(|(peer, _)| peer.node_address.as_str() != peer_id || peer.session_id != session_id);
    queues
        .snapshot_chunk_responses
        .retain(|(peer, _)| peer.node_address.as_str() != peer_id || peer.session_id != session_id);
}

fn bounded_push<T>(queue: &mut VecDeque<T>, value: T, label: &str) -> Result<(), String> {
    if queue.len() >= MAX_PER_PROTOCOL {
        return Err(format!("{label} queue is full"));
    }
    queue.push_back(value);
    Ok(())
}
