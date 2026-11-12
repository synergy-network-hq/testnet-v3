use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use synergy_aegis::{
    AegisPolicy, AegisSha3_256, AegisSigner, AegisVerifier, KeyId, PqvmSigner, Signature,
    SignatureAlgorithm, SigningContext,
};
use synergy_config::NodeConfiguration;
use synergy_data_availability::ProofVerifier;
use synergy_identity::PublicNodeIdentity;
use synergy_manifest::NetworkManifest;
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};
use synergy_p2p_protocols::{AdapterEnvelope, SyncAdapter, SyncMessageSink};
use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind, SessionId};
use synergy_snapshot::{
    build_snapshot, restore_verified_snapshot, verify_snapshot_manifest, SnapshotChunk,
    SnapshotManifest, SnapshotRestoreSink, SnapshotSigningProvider, SnapshotVerificationProvider,
};
use synergy_storage::{AtomicStore, NodeStorageLayout};
use synergy_sync::{
    BlockRequest, BudgetedSyncWireMessage as SyncWireMessage, EpochAuthorityRequest,
    EpochAuthorityResponse, FinalizedCandidateRequest, HeadClaim, HeadCollectionError,
    SnapshotChunkRequest, SnapshotChunkResponse, SyncManager, SyncMetrics, SyncPeerCandidate,
    SyncPhase, SyncStatus, VerifiedHead, VerifiedHeadCollector,
};

use super::authority::{self, AuthorityTransitionSignal, VerifiedAuthority};
use super::preparation;
use synergy_sync::{
    CandidateResponseAssembly, CandidateResponseChunk, MAX_CANDIDATE_WITNESS_BYTES,
};

use super::ingress::{
    AuthenticatedIngress, FinalizedCandidateResponse, OutboundFrame, SnapshotRestoreHandoff,
    SnapshotRestoreReceipt, SyncControlAction,
};

const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_MESSAGES_PER_POLL: usize = 64;
const MAX_CANDIDATE_WINDOW: usize = 4;
const MAX_CANDIDATE_SOLICITATIONS: usize = 8;
const SNAPSHOT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const CANDIDATE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const AUTHORITY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Retains exact request/response bytes across local outbound congestion.
/// Polling stops consuming new work while retained delivery is blocked.
#[derive(Default)]
struct SyncOutbox(RefCell<VecDeque<OutboundFrame>>);
impl SyncOutbox {
    fn publish(&self, ingress: &AuthenticatedIngress, frame: OutboundFrame) -> Result<(), String> {
        let mut pending = self.0.borrow_mut();
        if pending.iter().any(|old| {
            old.peer_id == frame.peer_id
                && old.protocol == frame.protocol
                && old.payload == frame.payload
        }) {
            return Ok(());
        }
        if pending.is_empty() && ingress.try_publish_outbound(frame.clone())? {
            return Ok(());
        }
        if pending.len() >= MAX_MESSAGES_PER_POLL {
            return Err("bounded retained Sync outbox is full".into());
        }
        pending.push_back(frame);
        Ok(())
    }
    fn has_pending(&self) -> bool {
        !self.0.borrow().is_empty()
    }
    fn flush(&self, ingress: &AuthenticatedIngress) -> Result<bool, String> {
        let mut pending = self.0.borrow_mut();
        while let Some(frame) = pending.front() {
            if !ingress.try_publish_outbound(frame.clone())? {
                return Ok(false);
            }
            pending.pop_front();
        }
        Ok(true)
    }
}

fn candidate_retry_source(
    sources: &[VerifiedHead],
    attempted: &BTreeSet<String>,
) -> Option<(String, bool)> {
    sources
        .iter()
        .find(|source| !attempted.contains(&source.peer_id))
        .map(|source| (source.peer_id.clone(), false))
        .or_else(|| sources.first().map(|source| (source.peer_id.clone(), true)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedCandidateRequest {
    request: FinalizedCandidateRequest,
    peer_id: String,
    attempted: BTreeSet<String>,
}

fn candidate_response_matches(
    expected: &FinalizedCandidateRequest,
    expected_peer: &str,
    peer: &AuthenticatedPeer,
    session_is_current: bool,
    received: &FinalizedCandidateRequest,
    candidate_height: u64,
    candidate_parent: &str,
) -> bool {
    session_is_current
        && expected_peer == peer.node_address.as_str()
        && expected == received
        && candidate_height == expected.height
        && candidate_parent == expected.expected_parent_id
}

// Receipt is advisory: a reconnect can discard an ingress response before
// verification. Only durable Execution progress acknowledges it. Reopen a
// missing height after session replacement or bounded verification/commit wait.
fn retain_candidate_commits(
    awaiting: &mut BTreeMap<u64, (AuthenticatedPeer, Instant)>,
    committed: u64,
    now: Instant,
    ingress: &AuthenticatedIngress,
) -> Result<(), String> {
    let mut expired = Vec::new();
    for (height, (peer, received_at)) in awaiting.iter() {
        if *height <= committed
            || now.saturating_duration_since(*received_at) >= CANDIDATE_RESPONSE_TIMEOUT
            || !ingress.is_current_session(peer)?
        {
            expired.push(*height);
        }
    }
    for height in expired {
        awaiting.remove(&height);
    }
    Ok(())
}

fn resumable_candidate_request(
    request: &PersistedCandidateRequest,
    committed: u64,
    parent: &str,
) -> bool {
    committed.checked_add(1) == Some(request.request.height)
        && request.request.expected_parent_id == parent
}

/// The async execution owner publishes this contiguous prefix only after native
/// QC verification and local replay/storage. Give its ordinary finality commit
/// the existing response interval before fetching the same payload from Sync.
/// This is only a fetch hint: it never acknowledges execution or advances Sync.
/// A stalled commit still reopens recovery, even if the certified tip advances.
fn native_candidate_prefix_wait(
    waiting: &mut Option<(u64, Instant)>,
    committed: u64,
    certified: Option<u64>,
    now: Instant,
) -> Option<u64> {
    let Some(certified) = certified.filter(|height| *height > committed) else {
        *waiting = None;
        return None;
    };
    if waiting
        .as_ref()
        .is_none_or(|(height, _)| *height != committed)
    {
        *waiting = Some((committed, now));
    }
    let (_, since) = waiting.as_ref()?;
    (now.saturating_duration_since(*since) < CANDIDATE_RESPONSE_TIMEOUT).then_some(certified)
}

fn next_candidate_prefetch(
    committed: u64,
    committed_parent: &str,
    target: u64,
    occupied: &BTreeSet<u64>,
    mut verified_parent: impl FnMut(u64) -> Result<Option<String>, String>,
) -> Result<Option<FinalizedCandidateRequest>, String> {
    if occupied.len() >= MAX_CANDIDATE_WINDOW {
        return Ok(None);
    }
    let next = committed.checked_add(1).ok_or("Sync height overflow")?;
    let end = committed
        .saturating_add(MAX_CANDIDATE_WINDOW as u64)
        .min(target);
    for height in next..=end {
        if occupied.contains(&height) {
            continue;
        }
        let parent = if height == next {
            committed_parent.to_owned()
        } else {
            let Some(parent) = verified_parent(height - 1)? else {
                return Ok(None);
            };
            parent
        };
        return Ok(Some(FinalizedCandidateRequest {
            height,
            expected_parent_id: parent,
        }));
    }
    Ok(None)
}

struct SyncRequestStore {
    store: AtomicStore,
}

impl SyncRequestStore {
    fn new(root: impl AsRef<std::path::Path>) -> Result<Self, String> {
        Ok(Self {
            store: AtomicStore::new(root.as_ref(), 64 * 1024)
                .map_err(|error| format!("open Sync request store: {error}"))?,
        })
    }

    fn load(&self) -> Result<Option<PersistedCandidateRequest>, String> {
        const PATH: &str = "active-candidate-request.json";
        if !self.store.exists(PATH).map_err(|error| error.to_string())? {
            return Ok(None);
        }
        let bytes = self
            .store
            .read_bounded(PATH)
            .map_err(|error| format!("read persisted Sync request: {error}"))?;
        let request = serde_json::from_slice::<Option<PersistedCandidateRequest>>(&bytes)
            .map_err(|error| format!("decode persisted Sync request: {error}"))?;
        Ok(request)
    }

    fn save(&self, request: &PersistedCandidateRequest) -> Result<(), String> {
        let bytes = serde_json::to_vec(request)
            .map_err(|error| format!("encode persisted Sync request: {error}"))?;
        self.store
            .write_atomic("active-candidate-request.json", &bytes)
            .map_err(|error| format!("persist Sync request: {error}"))
    }

    fn clear(&self) -> Result<(), String> {
        self.store
            .write_atomic("active-candidate-request.json", b"null")
            .map_err(|error| format!("clear persisted Sync request: {error}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedSnapshotAcquisition {
    epoch: u64,
    height: u64,
    finalized_block_id: String,
    finality_evidence_id: String,
    peer_id: String,
    attempted: BTreeSet<String>,
    manifest: Option<SnapshotManifest>,
    received: BTreeSet<u64>,
    requested_index: u64,
}

impl PersistedSnapshotAcquisition {
    fn request(&self) -> SnapshotChunkRequest {
        SnapshotChunkRequest {
            epoch: self.epoch,
            height: self.height,
            finalized_block_id: self.finalized_block_id.clone(),
            finality_evidence_id: self.finality_evidence_id.clone(),
            expected_snapshot_root: self.manifest.as_ref().map(|manifest| manifest.state_root),
            index: self.requested_index,
        }
    }

    fn verified_head(&self) -> VerifiedHead {
        VerifiedHead {
            peer_id: self.peer_id.clone(),
            finalized_height: self.height,
            finalized_hash: self.finalized_block_id.clone(),
            finality_evidence_id: self.finality_evidence_id.clone(),
        }
    }
}

struct ActiveSnapshotAcquisition {
    persisted: PersistedSnapshotAcquisition,
    sent_at: Instant,
    handoff_sent: bool,
}

struct LocalSnapshotSigner {
    key_id: KeyId,
    signer: PqvmSigner,
}

impl AegisSigner for LocalSnapshotSigner {
    fn sign(
        &self,
        key_id: &KeyId,
        context: &SigningContext,
        message: &[u8],
    ) -> Result<Signature, synergy_aegis::SigningError> {
        self.signer.sign(key_id, context, message)
    }
}

impl SnapshotSigningProvider for LocalSnapshotSigner {
    fn snapshot_key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn snapshot_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::MlDsa65
    }
}

#[path = "sync_snapshot_cache.rs"]
mod snapshot_cache;
use snapshot_cache::SnapshotChunkStore;

fn state_root_hex(root: &synergy_crypto::Hash32) -> String {
    root.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn same_snapshot_content(a: &SnapshotManifest, b: &SnapshotManifest) -> bool {
    a.format_version == b.format_version
        && a.chain_id == b.chain_id
        && a.network_id == b.network_id
        && a.epoch == b.epoch
        && a.height == b.height
        && a.finalized_block_id == b.finalized_block_id
        && a.finality_evidence_id == b.finality_evidence_id
        && a.application_state_root == b.application_state_root
        && a.state_root == b.state_root
        && a.chunk_size == b.chunk_size
        && a.chunk_hashes == b.chunk_hashes
}

impl SnapshotVerificationProvider for VerifiedAuthority {
    fn governed_public_key(&self, key_id: &KeyId) -> Result<Vec<u8>, String> {
        ProofVerifier::governed_public_key(self, key_id)
    }
}

struct IngressSnapshotRestoreSink<'a> {
    ingress: &'a AuthenticatedIngress,
    manifest: &'a SnapshotManifest,
    staged: Option<synergy_state::world_resources::BudgetedWorld>,
    resource_blocked: bool,
}

impl SnapshotRestoreSink for IngressSnapshotRestoreSink<'_> {
    fn stage(&mut self, height: u64, state: &[u8]) -> Result<(), String> {
        self.resource_blocked = false;
        if height != self.manifest.height {
            return Err("snapshot restore height differs from verified manifest".into());
        }
        let world_state = match synergy_state::world_resources::decode_budgeted_world(
            state,
            self.ingress.world_budget(),
        ) {
            Ok(state) => state,
            Err(error @ synergy_state::world_resources::WorldResourceError::Capacity { .. }) => {
                self.resource_blocked = true;
                return Err(format!("defer verified snapshot world state: {error}"));
            }
            Err(error) => return Err(format!("decode verified snapshot world state: {error}")),
        };
        let state_root = synergy_state::state_root(&world_state)
            .map_err(|error| format!("root verified snapshot world state: {error:?}"))?;
        if state_root != self.manifest.application_state_root {
            return Err("verified snapshot application state root mismatch".into());
        }
        self.staged = Some(world_state);
        Ok(())
    }

    fn commit(&mut self, height: u64) -> Result<(), String> {
        if height != self.manifest.height {
            return Err("snapshot commit height differs from verified manifest".into());
        }
        let state = self
            .staged
            .take()
            .ok_or("snapshot commit attempted before state staging")?;
        self.ingress
            .submit_snapshot_restore_handoff(SnapshotRestoreHandoff {
                epoch: self.manifest.epoch,
                finalized_height: self.manifest.height,
                finalized_block_id: self.manifest.finalized_block_id.clone(),
                finality_evidence_id: self.manifest.finality_evidence_id.clone(),
                application_state_root: self.manifest.application_state_root.clone(),
                state: Arc::new(state),
            })
    }
}

fn validate_persisted_snapshot(
    persisted: &PersistedSnapshotAcquisition,
    manifest: &NetworkManifest,
    authority: &VerifiedAuthority,
) -> Result<(), String> {
    if persisted.height == 0
        || persisted.epoch != authority.epoch.epoch
        || persisted.finalized_block_id.trim().is_empty()
        || persisted.finality_evidence_id.trim().is_empty()
        || persisted.peer_id.trim().is_empty()
        || persisted.manifest.as_ref().is_some_and(|snapshot| {
            snapshot.chain_id != manifest.chain_id
                || snapshot.network_id != manifest.network_id
                || snapshot.epoch != persisted.epoch
                || snapshot.height != persisted.height
                || snapshot.finalized_block_id != persisted.finalized_block_id
                || snapshot.finality_evidence_id != persisted.finality_evidence_id
                || persisted.requested_index >= snapshot.chunk_hashes.len() as u64
                || persisted
                    .received
                    .iter()
                    .any(|index| *index >= snapshot.chunk_hashes.len() as u64)
        })
    {
        return Err("persisted snapshot acquisition is not bound to current authority".into());
    }
    Ok(())
}

pub fn registration_with_preparation(
    configuration: &NodeConfiguration,
    authority: Option<Arc<VerifiedAuthority>>,
    authority_transition: AuthorityTransitionSignal,
    ingress: AuthenticatedIngress,
    preparation: Option<preparation::Handle>,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    let (spec, service) = construct_sync(
        configuration,
        authority,
        authority_transition,
        ingress,
        preparation,
    )?;
    Ok((
        spec,
        super::owned_service::production(Box::new(service), "sync"),
    ))
}

fn construct_sync(
    configuration: &NodeConfiguration,
    authority: Option<Arc<VerifiedAuthority>>,
    authority_transition: AuthorityTransitionSignal,
    ingress: AuthenticatedIngress,
    preparation: Option<preparation::Handle>,
) -> Result<(ServiceSpec, SyncService), String> {
    let authority = authority
        .as_ref()
        .map(VerifiedAuthority::owner_context)
        .transpose()?;
    let manifest = load_manifest(configuration)?;
    let local_peer_id = load_local_peer_id(configuration)?;
    let mut local_parent_id = authority
        .as_ref()
        .map(|authority| authority.anchor_parent.block_id().to_string())
        .unwrap_or_else(|| manifest.genesis_hash.clone());
    let manager = SyncManager::new(manifest.genesis_hash.clone());
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    // Requests must follow durable Execution commits, not an ahead-of-state
    // PoSy certificate or a remotely advertised snapshot height.
    let committed = synergy_state::FinalizedStateStore::load_budgeted(
        layout.state().join("execution"),
        Arc::clone(ingress.world_budget()),
    )
    .map_err(|error| format!("load durable Sync execution cursor: {error:?}"))?;
    let local_height = committed
        .current()
        .map(|state| state.finalized_height)
        .unwrap_or(0);
    if let Some(state) = committed.current() {
        local_parent_id = state.finalized_block_id.clone();
    }
    let request_store = SyncRequestStore::new(layout.metadata().join("sync"))?;
    let snapshot_store = SnapshotChunkStore::new(layout.state().join("snapshots"))?;
    // Prefetch is advisory. After restart only the exact durable execution
    // successor is resumed; other requests are reconstructed from verified
    // history. The existing single-request journal remains compatible.
    let active_requests = request_store
        .load()?
        .filter(|persisted| resumable_candidate_request(persisted, local_height, &local_parent_id))
        .map(|persisted| {
            (
                persisted.request.height,
                ActiveCandidateRequest {
                    request: persisted.request,
                    peer_id: persisted.peer_id,
                    attempted: persisted.attempted,
                    solicited: VecDeque::new(),
                    sent_at: Instant::now(),
                    requested_at: Instant::now(),
                    diagnostic_at: Instant::now(),
                    observed_chunks: 0,
                    observed_bytes: 0,
                    last_rx_session: None,
                    last_boundary: "resumed-request",
                    last_rejection: None,
                },
            )
        })
        .into_iter()
        .collect();
    let snapshot_signer = load_snapshot_signer(configuration, authority.as_deref())?;
    let mut snapshot_unavailable_height = None;
    let active_snapshot = match snapshot_store.load_active()? {
        Some(persisted) => {
            let verifier = authority
                .as_ref()
                .ok_or("persisted snapshot acquisition requires frozen authority")?;
            validate_persisted_snapshot(&persisted, &manifest, verifier)?;
            if let Some(snapshot) = persisted.manifest.as_ref() {
                verify_snapshot_manifest(verifier.as_ref(), snapshot)?;
            }
            if persisted
                .manifest
                .as_ref()
                .is_some_and(|snapshot| !SnapshotChunkStore::supports(snapshot))
            {
                snapshot_unavailable_height = Some(persisted.height);
                snapshot_store.clear_active()?;
                None
            } else {
                Some(ActiveSnapshotAcquisition {
                    persisted,
                    sent_at: Instant::now()
                        .checked_sub(SNAPSHOT_RESPONSE_TIMEOUT)
                        .unwrap_or_else(Instant::now),
                    handoff_sent: false,
                })
            }
        }
        None => None,
    };
    let preparation = match (preparation, authority.as_ref()) {
        (Some(handle), Some(authority)) => Some(
            handle.owner(preparation::AuthorityTag {
                incarnation: authority.epoch.network_id.clone(),
                epoch: authority.epoch.epoch,
                authority_digest: synergy_etdag::EtdagDigest::from_domain_bytes(
                    "SYNERGY_PREPARATION_AUTHORITY_V1",
                    authority.binding_bytes(),
                )
                .0,
            })?,
        ),
        _ => None,
    };
    Ok((
        ServiceSpec {
            id: ServiceId::new("sync")?,
            dependencies: vec![ServiceId::new("network")?, ServiceId::new("storage")?],
            criticality: Criticality::Critical,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        SyncService {
            configuration: configuration.clone(),
            preparation,
            manager,
            manifest,
            local_peer_id,
            ingress,
            outbox: SyncOutbox::default(),
            request_store,
            snapshot_store,
            authority,
            authority_transition,
            active_authority_request: None,
            snapshot_signer,
            local_parent_id,
            candidates: BTreeMap::new(),
            heads: VerifiedHeadCollector::new(),
            advertised: BTreeMap::new(),
            active_requests,
            candidate_assemblies: BTreeMap::new(),
            completed_candidates: BTreeMap::new(),
            resource_pending: VecDeque::new(),
            preparation_pending: 0,
            deferred_wire: None,
            awaiting_candidate_commits: BTreeMap::new(),
            native_candidate_wait: None,
            active_snapshot,
            snapshot_unavailable_height,
            status: SyncStatus::collecting(local_height),
            #[cfg(any(test, feature = "qualification-timing"))]
            diagnostic: SyncPollDiagnostic::new(),
            metrics: SyncMetrics::default(),
            started: false,
            paused: false,
            failure: None,
        },
    ))
}

fn load_snapshot_signer(
    configuration: &NodeConfiguration,
    authority: Option<&VerifiedAuthority>,
) -> Result<Option<LocalSnapshotSigner>, String> {
    let Some(authority) = authority else {
        return Ok(None);
    };
    let Some(path) = configuration.consensus.signing_key_path.as_ref() else {
        return Ok(None);
    };
    let identity = load_local_peer_id(configuration)?;
    let (key_id_text, public_key) = authority.consensus_binding(&identity)?;
    let key_id = KeyId::new(key_id_text.to_owned()).map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect snapshot signing key: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > 8 * 1024
    {
        return Err("snapshot signing key must be a bounded regular file".into());
    }
    let secret = fs::read(path).map_err(|error| format!("read snapshot signing key: {error}"))?;
    let policy = AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: 64 * 1024,
        maximum_signature_bytes: 16 * 1024,
    };
    let signer = super::apqe_provider::signer(
        configuration,
        policy.clone(),
        key_id.clone(),
        public_key,
        secret,
    )
    .map_err(|error| format!("load snapshot PQVM signer: {error}"))?;
    let verifier = super::apqe_provider::verifier(configuration, policy)?;
    let context = SigningContext {
        domain: "SYNERGY-SNAPSHOT-KEY-CHECK-V1".into(),
        chain_id: configuration.chain_id,
        epoch: Some(authority.epoch.epoch),
        height: None,
    };
    let proof = b"SYNERGY-SNAPSHOT-KEY-CHECK-V1";
    let signature = signer
        .sign(&key_id, &context, proof)
        .map_err(|error| format!("prove snapshot signing key possession: {error}"))?;
    verifier
        .verify(&context, proof, &signature, public_key)
        .map_err(|_| "snapshot signing key does not match frozen authority".to_string())?;
    Ok(Some(LocalSnapshotSigner { key_id, signer }))
}

fn load_local_peer_id(configuration: &NodeConfiguration) -> Result<String, String> {
    let metadata = fs::symlink_metadata(&configuration.public_identity_path)
        .map_err(|error| format!("inspect public identity: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err("public identity must be a bounded regular file".into());
    }
    let bytes = fs::read(&configuration.public_identity_path)
        .map_err(|error| format!("read public identity: {error}"))?;
    serde_json::from_slice::<PublicNodeIdentity>(&bytes)
        .map_err(|error| format!("decode public identity: {error}"))?
        .validate()
        .map(|identity| identity.node_address.to_string())
        .map_err(|error| format!("validate public identity: {error:?}"))
}

fn load_manifest(configuration: &NodeConfiguration) -> Result<NetworkManifest, String> {
    let metadata = fs::symlink_metadata(&configuration.manifest_path).map_err(|error| {
        format!(
            "inspect network manifest {}: {error}",
            configuration.manifest_path.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err("network manifest must be a bounded regular file".into());
    }
    let bytes = fs::read(&configuration.manifest_path).map_err(|error| {
        format!(
            "read network manifest {}: {error}",
            configuration.manifest_path.display()
        )
    })?;
    let manifest: NetworkManifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode network manifest: {error}"))?;
    if manifest.chain_id != configuration.chain_id
        || manifest.network_id != configuration.network_id
        || manifest.genesis_hash.trim().is_empty()
        || manifest.protocol_version.trim().is_empty()
    {
        return Err("network manifest does not bind this canonical node configuration".into());
    }
    manifest
        .validate_against(&manifest)
        .map_err(|error| format!("validate network manifest: {error:?}"))?;
    Ok(manifest)
}

struct ActiveAuthorityRequest {
    request: EpochAuthorityRequest,
    peer_id: String,
    attempted: BTreeSet<String>,
    sent_at: Instant,
}

#[cfg(any(test, feature = "qualification-timing"))]
struct SyncPollDiagnostic {
    enabled: bool,
    started: Instant,
    previous_start: Instant,
    last_report: Instant,
    reports: usize,
    boundary: &'static str,
    previous_phase: SyncPhase,
    pending_since: Option<Instant>,
    maximum_pending: Duration,
    stage_started: Instant,
    stages: Vec<(&'static str, u128)>,
}
#[cfg(any(test, feature = "qualification-timing"))]
impl SyncPollDiagnostic {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            enabled: std::env::var_os("SYNERGY_SYNC_POLL_DIAGNOSTIC").is_some_and(|v| v == "1"),
            started: now,
            previous_start: now,
            last_report: now,
            reports: 0,
            boundary: "constructed",
            previous_phase: SyncPhase::CollectingHeads,
            pending_since: None,
            maximum_pending: Duration::ZERO,
            stage_started: now,
            stages: Vec::with_capacity(24),
        }
    }
}

struct SyncService {
    preparation: Option<preparation::Owner<PreparedSync>>,
    configuration: NodeConfiguration,
    manager: SyncManager,
    manifest: NetworkManifest,
    local_peer_id: String,
    ingress: AuthenticatedIngress,
    outbox: SyncOutbox,
    request_store: SyncRequestStore,
    snapshot_store: SnapshotChunkStore,
    authority: Option<Arc<VerifiedAuthority>>,
    authority_transition: AuthorityTransitionSignal,
    active_authority_request: Option<ActiveAuthorityRequest>,
    snapshot_signer: Option<LocalSnapshotSigner>,
    local_parent_id: String,
    candidates: BTreeMap<String, SyncPeerCandidate>,
    heads: VerifiedHeadCollector,
    advertised: BTreeMap<String, (SessionId, u64)>,
    active_requests: BTreeMap<u64, ActiveCandidateRequest>,
    candidate_assemblies: BTreeMap<u64, IncomingCandidate>,
    completed_candidates: BTreeMap<u64, CompletedCandidate>,
    // Oldest resource-blocked frame gates all later preparation completions.
    resource_pending: VecDeque<Arc<(AuthenticatedPeer, Vec<u8>)>>,
    // Existing bounded worker mailboxes retain all admitted predecessors.
    preparation_pending: usize,
    // At most one owner fallback; intake stops until its predecessors drain.
    deferred_wire: Option<(AuthenticatedPeer, Vec<u8>)>,
    awaiting_candidate_commits: BTreeMap<u64, (AuthenticatedPeer, Instant)>,
    native_candidate_wait: Option<(u64, Instant)>,
    active_snapshot: Option<ActiveSnapshotAcquisition>,
    snapshot_unavailable_height: Option<u64>,
    status: SyncStatus,
    #[cfg(any(test, feature = "qualification-timing"))]
    diagnostic: SyncPollDiagnostic,
    metrics: SyncMetrics,
    started: bool,
    failure: Option<String>,
    paused: bool,
}

// Charge includes input and decoded output retained until completion consumption.
// Larger native messages retain the independent Sync-owner path, without any
// claim that its catch-up rate is qualified or expansion of the worker budget.
const BACKGROUND_MAILBOX_BYTES: usize = 8 * 1024 * 1024;
fn preparation_charge(bytes: &[u8], capacity: usize) -> Option<usize> {
    capacity
        .checked_add(bytes.len().checked_mul(16)?)?
        .checked_add(64 * 1024)
        .filter(|charge| *charge <= BACKGROUND_MAILBOX_BYTES)
}
enum PreparedSync {
    Wire {
        peer: AuthenticatedPeer,
        message: Box<synergy_sync::DecodedBudgetedSync<SyncWireMessage>>,
        snapshot_verified: bool,
    },
    ResourceBlocked(Arc<(AuthenticatedPeer, Vec<u8>)>),
}
/// Submit exact authenticated bytes without losing ownership when the shared
/// background mailbox is full. The existing owner decoder is the fallback;
/// native proof verification remains in the normal message-specific path.
fn prepare_sync_wire(
    owner: &preparation::Owner<PreparedSync>,
    height: u64,
    peer: AuthenticatedPeer,
    payload: Vec<u8>,
    authority: Arc<VerifiedAuthority>,
    budget: Arc<synergy_state::world_resources::WorldResourceBudget>,
) -> Result<Option<(AuthenticatedPeer, Vec<u8>)>, String> {
    let Some(charge) = preparation_charge(&payload, payload.capacity()) else {
        return Ok(Some((peer, payload)));
    };
    let digest =
        synergy_etdag::EtdagDigest::from_canonical("SYNERGY_SYNC_PREPARATION_V1", &payload)
            .map_err(|e| format!("Sync preparation digest: {e:?}"))?
            .0;
    let retained = Arc::new((peer, payload));
    let worker = Arc::clone(&retained);
    match owner.submit(
        preparation::Lane::Background,
        height,
        0,
        height,
        digest,
        charge,
        move || {
            let authority = VerifiedAuthority::worker_context(&authority)?;
            let message = match synergy_sync::decode_budgeted_sync_wire(&worker.1, &budget) {
                Ok(message) => message,
                Err(error) if sync_resource_pressure(&error) => {
                    return Ok(PreparedSync::ResourceBlocked(worker));
                }
                Err(error) => return Err(error.to_string()),
            };
            let snapshot_verified =
                if let SyncWireMessage::SnapshotChunkResponse(response) = &*message {
                    verify_snapshot_preparation(authority.as_ref(), response)?;
                    true
                } else {
                    false
                };
            Ok(PreparedSync::Wire {
                peer: worker.0.clone(),
                message: Box::new(message),
                snapshot_verified,
            })
        },
    ) {
        Ok(_) => Ok(None),
        Err(error) if error == "preparation backpressure" => Arc::try_unwrap(retained)
            .map(Some)
            .map_err(|_| "rejected Sync preparation retained worker ownership".into()),
        Err(error) => Err(error),
    }
}

fn sync_resource_pressure(error: &synergy_sync::SyncResourceError) -> bool {
    matches!(
        error,
        synergy_sync::SyncResourceError::Resource(
            synergy_state::world_resources::WorldResourceError::Capacity { .. }
        )
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn retain_sync_wire_on_backpressure<T: Send + 'static>(
    owner: &preparation::Owner<T>,
    height: u64,
    peer: AuthenticatedPeer,
    payload: Vec<u8>,
    digest: String,
    charge: usize,
    decode: impl FnOnce(AuthenticatedPeer, &[u8]) -> Result<T, String> + Send + 'static,
) -> Result<Option<(AuthenticatedPeer, Vec<u8>)>, String> {
    // Arc shares ownership, not a copied frame. Failed submit destroys its
    // closure before returning, leaving this original as the sole owner.
    let retained = Arc::new((peer, payload));
    let worker = Arc::clone(&retained);
    match owner.submit(
        preparation::Lane::Background,
        height,
        0,
        height,
        digest,
        charge,
        move || decode(worker.0.clone(), &worker.1),
    ) {
        Ok(_) => Ok(None),
        Err(error) if error == "preparation backpressure" => Arc::try_unwrap(retained)
            .map(Some)
            .map_err(|_| "rejected Sync preparation retained unexpected worker ownership".into()),
        Err(error) => Err(error),
    }
}

fn verify_snapshot_preparation(
    authority: &VerifiedAuthority,
    response: &SnapshotChunkResponse,
) -> Result<(), String> {
    response.validate()?;
    verify_snapshot_manifest(authority, &response.manifest)?;
    response.chunk.verify(
        &AegisSha3_256,
        &synergy_crypto::CryptoDomain {
            chain_id: response.manifest.chain_id,
            network_id: response.manifest.network_id.clone(),
            purpose: "snapshot-chunk-v1".into(),
            epoch: Some(response.manifest.epoch),
            height: Some(response.manifest.height),
        },
    )
}
/// Transport-complete bytes stay in this owner's existing bounded window.
/// The next owner poll decodes them before ordinary background wire work.
struct CompletedCandidate {
    peer: AuthenticatedPeer,
    request: FinalizedCandidateRequest,
    digest: [u8; 32],
    payload: CompletedCandidatePayload,
}

enum CompletedCandidatePayload {
    Raw(Vec<u8>),
    Decoded(Box<FinalizedCandidateResponse>, usize),
}

impl CompletedCandidate {
    fn bytes(&self) -> usize {
        match &self.payload {
            CompletedCandidatePayload::Raw(bytes) => bytes.len(),
            CompletedCandidatePayload::Decoded(_, charge) => *charge,
        }
    }

    fn try_into_response(
        self,
        active: Option<&ActiveCandidateRequest>,
        ingress: &AuthenticatedIngress,
    ) -> Result<Result<Option<(AuthenticatedPeer, FinalizedCandidateResponse)>, Self>, String> {
        if !active.is_some_and(|active| {
            active.request == self.request && active.peer_id == self.peer.node_address.as_str()
        }) || !ingress.is_current_session(&self.peer)?
        {
            return Ok(Ok(None));
        }
        let response = match self.payload {
            CompletedCandidatePayload::Raw(bytes) => {
                match synergy_sync::decode_budgeted_candidate_response(
                    &bytes,
                    ingress.world_budget(),
                ) {
                    Ok(decoded) => {
                        let (response, metadata) = decoded.into_parts();
                        FinalizedCandidateResponse {
                            response,
                            _metadata: Arc::new(metadata),
                        }
                    }
                    Err(error) if sync_resource_pressure(&error) => {
                        return Ok(Err(Self {
                            payload: CompletedCandidatePayload::Raw(bytes),
                            ..self
                        }));
                    }
                    Err(_) => return Ok(Ok(None)),
                }
            }
            CompletedCandidatePayload::Decoded(response, _) => *response,
        };
        if response.request != self.request
            || response.finality_witness.len() > MAX_CANDIDATE_WITNESS_BYTES
        {
            return Ok(Ok(None));
        }
        Ok(Ok(Some((self.peer, response))))
    }
}

fn candidate_window_has_capacity(
    assemblies: &BTreeMap<u64, IncomingCandidate>,
    completed: &BTreeMap<u64, CompletedCandidate>,
    height: u64,
    bytes: usize,
) -> bool {
    if assemblies.contains_key(&height) || completed.contains_key(&height) {
        return true;
    }
    let used = assemblies
        .values()
        .map(|active| active.total_bytes)
        .chain(completed.values().map(CompletedCandidate::bytes))
        .fold(0usize, usize::saturating_add);
    assemblies.len() + completed.len() < MAX_CANDIDATE_WINDOW
        && bytes <= synergy_sync::MAX_CANDIDATE_RESPONSE_BYTES.saturating_sub(used)
}

struct IncomingCandidate {
    peer: AuthenticatedPeer,
    request: FinalizedCandidateRequest,
    assembly: CandidateResponseAssembly,
    total_bytes: usize,
    started: Instant,
    progressed: Instant,
}

struct ActiveCandidateRequest {
    request: FinalizedCandidateRequest,
    peer_id: String,
    attempted: BTreeSet<String>,
    sent_at: Instant,
    solicited: VecDeque<(String, SessionId)>,
    // Observation only: retries never reset the original request age.
    requested_at: Instant,
    diagnostic_at: Instant,
    observed_chunks: u64,
    observed_bytes: u64,
    last_rx_session: Option<synergy_protocol_types::SessionId>,
    last_boundary: &'static str,
    last_rejection: Option<&'static str>,
}

impl ActiveCandidateRequest {
    fn record_solicitation(&mut self, peer_id: &str, session: Option<SessionId>) {
        self.solicited.retain(|(peer, _)| peer != peer_id);
        if let Some(session) = session {
            if self.solicited.len() == MAX_CANDIDATE_SOLICITATIONS {
                self.solicited.pop_front();
            }
            self.solicited.push_back((peer_id.to_owned(), session));
        }
    }

    fn permits_chunk(&self, peer: &AuthenticatedPeer, request: &FinalizedCandidateRequest) -> bool {
        self.request == *request
            && self.solicited.iter().any(|(id, session)| {
                id == peer.node_address.as_str() && *session == peer.session_id
            })
    }
}

// Transport-only assembly: authenticated request eligibility is checked by the
// caller; complete bytes still pass normal PoSy witness and execution checks.
// Four prefetched heights share the existing 64-MiB aggregate allocation cap.
fn push_candidate_chunk(
    assemblies: &mut BTreeMap<u64, IncomingCandidate>,
    peer: &AuthenticatedPeer,
    chunk: CandidateResponseChunk,
) -> Result<(bool, Option<Vec<u8>>), String> {
    chunk.validate()?;
    let height = chunk.request.height;
    if let Some(active) = assemblies.get(&height) {
        if active.peer.node_address != peer.node_address
            || active.peer.session_id != peer.session_id
            || active.request != chunk.request
        {
            return Err("candidate chunk differs from authenticated assembly request".into());
        }
    } else {
        // A tail from an earlier retry cannot capture the sole assembly slot
        // and exclude a complete competing stream. Sender chunks start at zero;
        // initial decoder reordering is recoverable by the existing retry.
        // Once started, this assembly still accepts out-of-order later chunks.
        if chunk.offset != 0 {
            return Err("candidate assembly awaits initial chunk".into());
        }
        let used = assemblies
            .values()
            .map(|active| active.total_bytes)
            .sum::<usize>();
        if assemblies.len() >= MAX_CANDIDATE_WINDOW
            || chunk.total_bytes > synergy_sync::MAX_CANDIDATE_RESPONSE_BYTES.saturating_sub(used)
        {
            return Err("candidate assembly window capacity reached".into());
        }
        let assembly = CandidateResponseAssembly::new(&chunk)?;
        assemblies.insert(
            height,
            IncomingCandidate {
                peer: peer.clone(),
                request: chunk.request.clone(),
                assembly,
                total_bytes: chunk.total_bytes,
                started: Instant::now(),
                progressed: Instant::now(),
            },
        );
    }
    let active = assemblies
        .get_mut(&height)
        .ok_or("candidate assembly disappeared")?;
    let progressed = match active.assembly.push(chunk) {
        Ok(progressed) => progressed,
        Err(error) => {
            assemblies.remove(&height);
            return Err(error);
        }
    };
    if progressed {
        active.progressed = Instant::now();
    }
    if active.assembly.is_complete() {
        let active = assemblies
            .remove(&height)
            .ok_or("candidate assembly disappeared")?;
        return Ok((progressed, Some(active.assembly.finish()?)));
    }
    Ok((progressed, None))
}

// The collector rejects every regression without changing its high-water mark.
// These are asynchronous, already PoSy-verified observations: an older delivery
// is rejected locally, not a request to roll back finality or fail the service.
fn record_posy_verified_head(
    heads: &mut VerifiedHeadCollector,
    metrics: &SyncMetrics,
    head: VerifiedHead,
) -> Result<(), String> {
    match heads.record(head) {
        Ok(_) => metrics.record_verified_blocks(1),
        Err(HeadCollectionError::Regression { .. }) => metrics.record_rejection(),
        Err(error) => return Err(format!("record PoSy-verified Sync head: {error:?}")),
    }
    Ok(())
}

impl SyncService {
    fn advertise_head(&mut self) -> Result<(), String> {
        let Some(tip) = self.ingress.latest_finality()? else {
            return Ok(());
        };
        if tip.height < self.status.local_finalized_height {
            return Ok(());
        }
        let peers = self.ingress.authenticated_peer_progress()?;
        self.advertised.retain(|peer, (session, _)| {
            peers
                .get(peer)
                .is_some_and(|(current, _)| current == session)
        });
        let needs_head = |peer: &String, session: SessionId, height: u64| {
            !self
                .advertised
                .get(peer)
                .is_some_and(|(sent_session, sent_height)| {
                    *sent_session == session && *sent_height >= height
                })
        };
        let recipients: Vec<_> = peers
            .into_iter()
            .filter(|(peer, (session, _))| needs_head(peer, *session, tip.height))
            .collect();
        if recipients.is_empty() {
            return Ok(());
        }
        // Knowing the receiver's consensus tip does not mean that receiver
        // knows this peer is an available recovery source. Announce once per
        // session/tip even when its proof is already known, using the existing
        // witness-free head schema. Unknown peers still receive the full proof.
        let needs_proof = recipients
            .iter()
            .any(|(_, (_, known))| !known.is_some_and(|height| height >= tip.height));
        let (finalized, witness) = if needs_proof {
            let Some((finalized, witness)) = self.ingress.latest_finality_with_witness()? else {
                return Ok(());
            };
            (finalized, Some(witness))
        } else {
            (tip, None)
        };
        let mut claim = HeadClaim {
            peer_id: self.local_peer_id.clone(),
            chain_id: self.manifest.chain_id,
            genesis_hash: self.manifest.genesis_hash.clone(),
            finalized_height: finalized.height,
            finalized_hash: finalized.block_id.clone(),
            finality_evidence_id: finalized.finality_certificate_id.clone(),
            finality_witness: witness,
        };
        let proof_payload = if claim.finality_witness.is_some() {
            Some(
                serde_json::to_vec(&SyncWireMessage::Head(claim.clone()))
                    .map_err(|error| format!("encode Sync head proof: {error}"))?,
            )
        } else {
            None
        };
        claim.finality_witness = None;
        let compact_payload = serde_json::to_vec(&SyncWireMessage::Head(claim))
            .map_err(|error| format!("encode Sync head claim: {error}"))?;
        for (peer_id, (session, known)) in recipients {
            let payload = if known.is_some_and(|height| height >= finalized.height) {
                &compact_payload
            } else {
                proof_payload
                    .as_ref()
                    .ok_or("unknown Sync peer requires finality proof")?
            };
            self.outbox.publish(
                &self.ingress,
                OutboundFrame {
                    peer_id: peer_id.clone(),
                    protocol: ProtocolKind::Sync,
                    payload: payload.clone(),
                },
            )?;
            self.advertised.insert(peer_id, (session, finalized.height));
            if self.outbox.has_pending() {
                break;
            }
        }
        Ok(())
    }

    fn note_candidate_boundary(
        &mut self,
        height: u64,
        peer: &AuthenticatedPeer,
        code: &'static str,
        rejected: bool,
        chunk_bytes: Option<usize>,
    ) {
        if let Some(active) = self.active_requests.get_mut(&height) {
            active.last_boundary = code;
            active.last_rx_session = Some(peer.session_id);
            if rejected {
                active.last_rejection = Some(code);
            }
            if let Some(bytes) = chunk_bytes {
                active.observed_chunks = active.observed_chunks.saturating_add(1);
                active.observed_bytes = active.observed_bytes.saturating_add(bytes as u64);
            }
        }
    }

    fn report_candidate_waits(&mut self) {
        let pending_outbound = self.outbox.has_pending();
        for (height, active) in &mut self.active_requests {
            if active.requested_at.elapsed() < Duration::from_secs(10)
                || active.diagnostic_at.elapsed() < Duration::from_secs(10)
            {
                continue;
            }
            active.diagnostic_at = Instant::now();
            let assembly = self.candidate_assemblies.get(height);
            eprintln!(
                "SYNC_CANDIDATE_WAIT node={} height={} peer={} last_rx_session={:?} age_ms={} send_age_ms={} attempts={} boundary={} rejection={:?} rx_chunks={} rx_bytes={} assembly_bytes={} assembly_age_ms={} progress_age_ms={} outbox_pending={}",
                self.configuration.node_name, height, active.peer_id, active.last_rx_session,
                active.requested_at.elapsed().as_millis(), active.sent_at.elapsed().as_millis(),
                active.attempted.len(), active.last_boundary, active.last_rejection,
                active.observed_chunks, active.observed_bytes,
                assembly.map_or(0, |assembly| assembly.total_bytes),
                assembly.map_or(0, |assembly| assembly.started.elapsed().as_millis()),
                assembly.map_or(0, |assembly| assembly.progressed.elapsed().as_millis()),
                pending_outbound,
            );
        }
    }

    fn apply_sync_control(&mut self, action: SyncControlAction) -> Result<(), String> {
        match action {
            SyncControlAction::Pause => {
                self.paused = true;
                Ok(())
            }
            SyncControlAction::Resume => {
                self.paused = false;
                Ok(())
            }
            SyncControlAction::RetrySource { peer_id } => {
                if self.paused {
                    return Err("Sync source retry is unavailable while Sync is paused".into());
                }
                let authenticated = self
                    .ingress
                    .authenticated_peers()?
                    .into_iter()
                    .collect::<BTreeSet<_>>();
                if !authenticated.contains(&peer_id) {
                    return Err("requested Sync source is not an authenticated peer".into());
                }
                let candidates: Vec<_> = self.candidates.values().cloned().collect();
                let heads: Vec<_> = self.heads.heads().cloned().collect();
                let plan = self
                    .manager
                    .plan(&candidates, &heads)
                    .map_err(|error| format!("select verified Sync retry source: {error:?}"))?;
                let source = plan
                    .sources
                    .iter()
                    .find(|source| source.peer_id == peer_id)
                    .ok_or("requested peer is not a verified Sync source")?;

                if let Some(active) = self.active_snapshot.as_ref() {
                    if active.handoff_sent {
                        return Err("snapshot restore is already awaiting durable admission".into());
                    }
                    let expected = active.persisted.verified_head();
                    if source.finalized_height != expected.finalized_height
                        || source.finalized_hash != expected.finalized_hash
                        || source.finality_evidence_id != expected.finality_evidence_id
                    {
                        return Err(
                            "requested Sync source does not advertise the active snapshot".into(),
                        );
                    }
                    let request = {
                        let active = self
                            .active_snapshot
                            .as_mut()
                            .ok_or("active snapshot acquisition disappeared")?;
                        active.persisted.peer_id = peer_id.clone();
                        active.persisted.attempted.insert(peer_id.clone());
                        active.sent_at = Instant::now();
                        active.persisted.request()
                    };
                    self.snapshot_store.save_active(
                        &self
                            .active_snapshot
                            .as_ref()
                            .ok_or("active snapshot acquisition disappeared")?
                            .persisted,
                    )?;
                    return self.send_snapshot_request(&peer_id, &request);
                }
                if let Some((&height, active)) = self.active_requests.iter().next() {
                    let request = active.request.clone();
                    let session = self.send_candidate_request(&peer_id, &request)?;
                    let active = self
                        .active_requests
                        .get_mut(&height)
                        .ok_or("Sync request disappeared")?;
                    active.record_solicitation(&peer_id, session);
                    active.peer_id = peer_id.clone();
                    active.attempted.insert(peer_id.clone());
                    active.sent_at = Instant::now();
                    self.request_store.save(&PersistedCandidateRequest {
                        request: active.request.clone(),
                        peer_id: active.peer_id.clone(),
                        attempted: active.attempted.clone(),
                    })?;
                    return Ok(());
                }
                if let Some(active) = self.active_authority_request.as_mut() {
                    let request = active.request.clone();
                    active.peer_id = peer_id.clone();
                    active.attempted.insert(peer_id.clone());
                    active.sent_at = Instant::now();
                    return self.send_authority_request(&peer_id, &request);
                }
                Err("Sync has no active request to retry".into())
            }
        }
    }

    fn send_authority_request(
        &self,
        peer_id: &str,
        request: &EpochAuthorityRequest,
    ) -> Result<(), String> {
        self.outbox.publish(
            &self.ingress,
            OutboundFrame {
                peer_id: peer_id.to_owned(),
                protocol: ProtocolKind::Sync,
                payload: serde_json::to_vec(&SyncWireMessage::EpochAuthorityRequest(
                    request.clone(),
                ))
                .map_err(|error| format!("encode epoch authority request: {error}"))?,
            },
        )
    }

    fn accept_authority_request(
        &self,
        peer: AuthenticatedPeer,
        request: EpochAuthorityRequest,
    ) -> Result<(), String> {
        if !request.validate() {
            return Err("invalid epoch authority request".into());
        }
        let authority = self
            .authority
            .as_ref()
            .ok_or("epoch authority response requires frozen PoSy authority")?;
        // At an epoch boundary every validator can be waiting for the same
        // signed successor. Having nothing to serve is not a supervisor error.
        if authority.epoch.epoch <= request.current_epoch {
            return Ok(());
        }
        if request.current_epoch.checked_add(1) != Some(authority.epoch.epoch) {
            return Err("requested authority is not the local successor epoch".into());
        }
        match &authority.anchor_parent {
            synergy_posy::SimplifiedFinalityParent::QuorumCertificate {
                height,
                block_id,
                qc_id,
            } if *height == request.finalized_height.saturating_add(2)
                && !block_id.trim().is_empty()
                && qc_id == &request.finality_evidence_id => {}
            _ => {
                return Err(
                    "local successor authority is not anchored to the requested finality".into(),
                )
            }
        }
        let response = EpochAuthorityResponse {
            request,
            next_authority_binding: authority.binding_bytes().to_vec(),
        };
        self.outbox.publish(
            &self.ingress,
            OutboundFrame {
                peer_id: peer.node_address.to_string(),
                protocol: ProtocolKind::Sync,
                payload: serde_json::to_vec(&SyncWireMessage::EpochAuthorityResponse(response))
                    .map_err(|error| format!("encode epoch authority response: {error}"))?,
            },
        )
    }

    fn accept_authority_response(
        &mut self,
        peer: AuthenticatedPeer,
        response: EpochAuthorityResponse,
    ) -> Result<(), String> {
        if !response.validate() {
            return Err("invalid epoch authority response".into());
        }
        let active = self
            .active_authority_request
            .as_ref()
            .filter(|active| {
                active.peer_id == peer.node_address.as_str() && active.request == response.request
            })
            .ok_or("unsolicited epoch authority response")?;
        let _ = active;
        let authority = self
            .authority
            .as_ref()
            .ok_or("epoch authority transition requires current frozen authority")?;
        if response.request.current_epoch_context_root
            != authority.epoch.root().map_err(|error| error.to_string())?
        {
            return Err("epoch authority response differs from current frozen context".into());
        }
        let (finalized, witness) = self
            .ingress
            .latest_finality_with_witness()?
            .ok_or("epoch authority transition requires verified PoSy finality")?;
        if finalized.height != response.request.finalized_height
            || finalized.block_id != response.request.finalized_block_id
            || finalized.finality_certificate_id != response.request.finality_evidence_id
        {
            return Err("epoch authority response differs from local verified finality".into());
        }
        if !self.execution_ready_for_authority(&finalized)? {
            return Err("epoch authority response precedes durable execution boundary".into());
        }
        authority::verify_and_persist_transition(
            &self.configuration,
            authority.as_ref(),
            &finalized,
            &witness,
            response.next_authority_binding,
            &self.authority_transition,
        )?;
        Ok(())
    }

    fn execution_ready_for_authority(
        &self,
        finalized: &synergy_posy::FinalizedBlockRecord,
    ) -> Result<bool, String> {
        // This cursor starts at recovered durable Execution state and advances
        // only through its contiguous commit acknowledgements. PoSy may know
        // the terminal certificate while Execution is still replaying history.
        if self.status.local_finalized_height < finalized.height {
            return Ok(false);
        }
        if self.status.local_finalized_height != finalized.height
            || self.local_parent_id != finalized.block_id
        {
            return Err("durable execution differs from epoch authority finality boundary".into());
        }
        Ok(true)
    }

    fn drive_authority_transition(
        &mut self,
        authenticated: &BTreeSet<String>,
    ) -> Result<bool, String> {
        let Some(authority) = self.authority.as_ref() else {
            return Ok(false);
        };
        let Some((finalized, witness)) = self.ingress.latest_finality_with_witness()? else {
            return Ok(false);
        };
        let boundary_height = finalized
            .height
            .checked_add(2)
            .ok_or("epoch boundary height overflow")?;
        if boundary_height < authority.epoch.epoch_end_height {
            return Ok(false);
        }
        if boundary_height != authority.epoch.epoch_end_height || witness.is_empty() {
            return Err("local PoSy finality advanced beyond frozen epoch authority".into());
        }
        if !self.execution_ready_for_authority(&finalized)? {
            // Do not starve candidate retry/prefetch behind an ahead-of-state
            // boundary certificate. Authority activation must wait for replay.
            return Ok(false);
        }
        if let Some(active) = self.active_authority_request.as_ref() {
            if active.sent_at.elapsed() < AUTHORITY_RESPONSE_TIMEOUT {
                return Ok(true);
            }
            let next_peer = authenticated
                .iter()
                .find(|peer| !active.attempted.contains(*peer))
                .cloned();
            if let Some(next_peer) = next_peer {
                let request = active.request.clone();
                self.send_authority_request(&next_peer, &request)?;
                let active = self
                    .active_authority_request
                    .as_mut()
                    .ok_or("active authority request disappeared")?;
                active.peer_id = next_peer.clone();
                active.attempted.insert(next_peer);
                active.sent_at = Instant::now();
            } else {
                self.active_authority_request = None;
            }
            return Ok(true);
        }
        let Some(peer_id) = authenticated.iter().next().cloned() else {
            return Ok(true);
        };
        let request = EpochAuthorityRequest {
            current_epoch: authority.epoch.epoch,
            current_epoch_context_root: authority
                .epoch
                .root()
                .map_err(|error| error.to_string())?,
            finalized_height: finalized.height,
            finalized_block_id: finalized.block_id,
            finality_evidence_id: finalized.finality_certificate_id,
        };
        if !request.validate() {
            return Err("local finalized authority transition request is malformed".into());
        }
        self.send_authority_request(&peer_id, &request)?;
        self.active_authority_request = Some(ActiveAuthorityRequest {
            request,
            peer_id: peer_id.clone(),
            attempted: BTreeSet::from([peer_id]),
            sent_at: Instant::now(),
        });
        Ok(true)
    }

    fn send_candidate_request(
        &self,
        peer_id: &str,
        request: &FinalizedCandidateRequest,
    ) -> Result<Option<SessionId>, String> {
        // A reconnect must not inherit authority for a request sent to its
        // predecessor. Resolicit it normally if a session changes in transit.
        let session = self
            .ingress
            .authenticated_peer_progress()?
            .get(peer_id)
            .map(|(id, _)| *id);
        self.outbox.publish(
            &self.ingress,
            OutboundFrame {
                peer_id: peer_id.to_string(),
                protocol: ProtocolKind::Sync,
                payload: serde_json::to_vec(&SyncWireMessage::FinalizedCandidateRequestV2(
                    request.clone(),
                ))
                .map_err(|error| format!("encode Sync candidate request: {error}"))?,
            },
        )?;
        Ok(session)
    }

    /// Snapshot creation is demand-driven. Finalized acknowledgements never
    /// carry a world state or perform snapshot serialization on the healthy path.
    fn snapshot_response(
        &self,
        request: &SnapshotChunkRequest,
    ) -> Result<Option<SnapshotChunkResponse>, String> {
        if let Some(response) = self.snapshot_store.get(request)? {
            return Ok(Some(response));
        }
        if !self.snapshot_store.can_materialize(request)? {
            return Ok(None);
        }
        let (Some(signer), Some(authority)) =
            (self.snapshot_signer.as_ref(), self.authority.as_ref())
        else {
            return Ok(None);
        };
        if request.epoch != authority.epoch.epoch
            || !authority.epoch.contains_height(request.height)
            || request.height > self.status.local_finalized_height
        {
            return Ok(None);
        }
        let Some(finality) = self.ingress.finalized_record(request.height)? else {
            return Ok(None);
        };
        if finality.block_id != request.finalized_block_id
            || finality.finality_certificate_id != request.finality_evidence_id
        {
            return Ok(None);
        }
        let layout = NodeStorageLayout::new(self.configuration.storage.data_directory.clone())
            .map_err(|error| format!("construct snapshot state layout: {error}"))?;
        let committed = synergy_state::FinalizedStateStore::load_budgeted(
            layout.state().join("execution"),
            Arc::clone(self.ingress.world_budget()),
        )
        .map_err(|error| format!("load snapshot execution commitment: {error:?}"))?;
        let Some(commitment) = committed
            .history_at(request.height)
            .map_err(|error| format!("read snapshot execution commitment: {error:?}"))?
        else {
            return Ok(None);
        };
        if commitment.finalized_block_id != finality.block_id {
            return Err("snapshot execution commitment differs from verified PoSy finality".into());
        }
        let state_bytes = match committed
            .world_state_at_budgeted(request.height, self.ingress.world_budget())
        {
            Ok(Some(state)) => state,
            Ok(None) | Err(synergy_state::StateError::ResourcePressure { .. }) => return Ok(None),
            Err(error) => return Err(format!("read verified snapshot world: {error:?}")),
        };
        let _snapshot_scratch = match synergy_state::world_resources::reserve_world_write(
            &state_bytes,
            Some(&state_bytes),
            self.ingress.world_budget(),
        ) {
            Ok(permit) => permit,
            Err(synergy_state::world_resources::WorldResourceError::Capacity { .. }) => {
                return Ok(None)
            }
            Err(error) => return Err(format!("reserve snapshot serialization: {error}")),
        };
        let state_bytes =
            serde_json::to_vec(&state_bytes).map_err(|e| format!("encode snapshot world: {e}"))?;
        let (manifest, chunks) = build_snapshot(
            &AegisSha3_256,
            signer,
            self.manifest.chain_id,
            &self.manifest.network_id,
            request.epoch,
            request.height,
            &finality.block_id,
            &finality.finality_certificate_id,
            &commitment.state_root,
            1024 * 1024,
            &state_bytes,
        )?;
        if request.index >= chunks.len() as u64
            || request
                .expected_snapshot_root
                .is_some_and(|root| root != manifest.state_root)
        {
            return Ok(None);
        }
        for chunk in chunks {
            let chunk_request = SnapshotChunkRequest {
                epoch: manifest.epoch,
                height: manifest.height,
                finalized_block_id: manifest.finalized_block_id.clone(),
                finality_evidence_id: manifest.finality_evidence_id.clone(),
                expected_snapshot_root: Some(manifest.state_root),
                index: chunk.index,
            };
            if !self.snapshot_store.put(&SnapshotChunkResponse {
                request: chunk_request,
                manifest: manifest.clone(),
                chunk,
            })? {
                return Ok(None);
            }
        }
        self.snapshot_store.get(request)
    }

    fn send_snapshot_request(
        &self,
        peer_id: &str,
        request: &SnapshotChunkRequest,
    ) -> Result<(), String> {
        self.outbox.publish(
            &self.ingress,
            OutboundFrame {
                peer_id: peer_id.to_string(),
                protocol: ProtocolKind::Sync,
                payload: serde_json::to_vec(&SyncWireMessage::SnapshotChunkRequest(
                    request.clone(),
                ))
                .map_err(|error| format!("encode snapshot chunk request: {error}"))?,
            },
        )
    }

    fn begin_snapshot_acquisition(&mut self, head: &VerifiedHead) -> Result<(), String> {
        let authority = self
            .authority
            .as_ref()
            .ok_or("snapshot acquisition requires frozen PoSy authority")?;
        if head.finalized_height < authority.epoch.epoch_start_height
            || head.finalized_height > authority.epoch.epoch_end_height
        {
            return Err("verified Sync head is outside the loaded snapshot authority epoch".into());
        }
        let persisted = PersistedSnapshotAcquisition {
            epoch: authority.epoch.epoch,
            height: head.finalized_height,
            finalized_block_id: head.finalized_hash.clone(),
            finality_evidence_id: head.finality_evidence_id.clone(),
            peer_id: head.peer_id.clone(),
            attempted: BTreeSet::from([head.peer_id.clone()]),
            manifest: None,
            received: BTreeSet::new(),
            requested_index: 0,
        };
        self.send_snapshot_request(&persisted.peer_id, &persisted.request())?;
        self.snapshot_store.save_active(&persisted)?;
        self.active_snapshot = Some(ActiveSnapshotAcquisition {
            persisted,
            sent_at: Instant::now(),
            handoff_sent: false,
        });
        Ok(())
    }

    fn accept_snapshot_response_prepared(
        &mut self,
        peer: AuthenticatedPeer,
        response: SnapshotChunkResponse,
        verified: bool,
    ) -> Result<(), String> {
        let Some(expected) = self.active_snapshot.as_ref().filter(|active| {
            active.persisted.peer_id == peer.node_address.as_str() && !active.handoff_sent
        }) else {
            self.metrics.record_rejection();
            return Ok(());
        };
        if response.request != expected.persisted.request() {
            self.metrics.record_rejection();
            return Ok(());
        }
        let authority = self
            .authority
            .as_ref()
            .ok_or("snapshot verification requires frozen PoSy authority")?;
        response.validate()?;
        if response.manifest.chain_id != self.manifest.chain_id
            || response.manifest.network_id != self.manifest.network_id
            || response.manifest.epoch != authority.epoch.epoch
            || response.manifest.height < authority.epoch.epoch_start_height
            || response.manifest.height > authority.epoch.epoch_end_height
            || response.manifest.finalized_block_id != expected.persisted.finalized_block_id
            || response.manifest.finality_evidence_id != expected.persisted.finality_evidence_id
        {
            self.metrics.record_rejection();
            return Err("snapshot manifest differs from verified PoSy head authority".into());
        }
        if !verified {
            verify_snapshot_preparation(authority.as_ref(), &response)?;
        }
        if expected
            .persisted
            .manifest
            .as_ref()
            .is_some_and(|manifest| !same_snapshot_content(manifest, &response.manifest))
        {
            return Err("snapshot source changed manifest during acquisition".into());
        }
        if !SnapshotChunkStore::supports(&response.manifest) {
            // Unsupported local resource profile falls back to canonical replay.
            // This follows signature/context verification and grants no finality.
            self.metrics.record_rejection();
            self.snapshot_unavailable_height = Some(response.manifest.height);
            self.snapshot_store.clear_active()?;
            self.active_snapshot = None;
            return Ok(());
        }
        if !self.snapshot_store.put(&response)? {
            // Cache pressure is retryable; do not advance durable acquisition.
            return Ok(());
        }

        let mut next_request = None;
        let complete = {
            let active = self
                .active_snapshot
                .as_mut()
                .ok_or("active snapshot acquisition disappeared")?;
            if active.persisted.manifest.is_none() {
                active.persisted.manifest = Some(response.manifest.clone());
            }
            active.persisted.received.insert(response.chunk.index);
            let manifest = active
                .persisted
                .manifest
                .as_ref()
                .ok_or("snapshot manifest disappeared")?;
            if let Some(index) = (0..manifest.chunk_hashes.len() as u64)
                .find(|index| !active.persisted.received.contains(index))
            {
                active.persisted.requested_index = index;
                active.sent_at = Instant::now();
                next_request = Some((active.persisted.peer_id.clone(), active.persisted.request()));
                false
            } else {
                true
            }
        };
        self.snapshot_store.save_active(
            &self
                .active_snapshot
                .as_ref()
                .ok_or("active snapshot acquisition disappeared")?
                .persisted,
        )?;
        if let Some((peer_id, request)) = next_request {
            self.send_snapshot_request(&peer_id, &request)?;
        }
        if complete {
            self.restore_completed_snapshot()?;
        }
        Ok(())
    }

    fn restore_completed_snapshot(&mut self) -> Result<(), String> {
        let active = self
            .active_snapshot
            .as_ref()
            .ok_or("snapshot restore has no active acquisition")?;
        if active.handoff_sent {
            return Ok(());
        }
        let manifest = active
            .persisted
            .manifest
            .as_ref()
            .ok_or("snapshot restore has no verified manifest")?
            .clone();
        // A head witness establishes remote finality; it does not install the
        // intervening local PoSy QC prefix. Replay canonical candidates first.
        if self.status.local_finalized_height < manifest.height {
            return Ok(());
        }
        let local = self
            .ingress
            .finalized_record(manifest.height)?
            .ok_or("snapshot restore lacks the local canonical finalized prefix")?;
        if local.block_id != manifest.finalized_block_id
            || local.finality_certificate_id != manifest.finality_evidence_id
        {
            return Err("snapshot restore conflicts with local canonical finality".into());
        }
        if self.status.local_finalized_height > manifest.height {
            // The durable contiguous replay already passed this verified
            // snapshot. Its cached chunks may retire; never regress state.
            self.active_snapshot = None;
            self.snapshot_store.clear_active()?;
            return Ok(());
        }
        let chunks = self
            .snapshot_store
            .chunks(&manifest)?
            .ok_or("snapshot restore is missing a persisted chunk")?;
        let authority = self
            .authority
            .as_ref()
            .ok_or("snapshot restore requires frozen PoSy authority")?;
        let mut sink = IngressSnapshotRestoreSink {
            ingress: &self.ingress,
            manifest: &manifest,
            staged: None,
            resource_blocked: false,
        };
        let result = restore_verified_snapshot(
            &AegisSha3_256,
            authority.as_ref(),
            &manifest,
            &chunks,
            &mut sink,
        );
        if sink.resource_blocked {
            // Keep the verified manifest and durable chunks. The completed
            // acquisition is retried without requesting or trusting new bytes.
            return Ok(());
        }
        result?;
        self.active_snapshot
            .as_mut()
            .ok_or("active snapshot acquisition disappeared")?
            .handoff_sent = true;
        Ok(())
    }

    fn accept_snapshot_restore_receipt(
        &mut self,
        receipt: SnapshotRestoreReceipt,
    ) -> Result<(), String> {
        let active = self
            .active_snapshot
            .as_ref()
            .filter(|active| active.handoff_sent)
            .ok_or("unsolicited snapshot restore receipt")?;
        let manifest = active
            .persisted
            .manifest
            .as_ref()
            .ok_or("snapshot restore receipt has no manifest")?;
        if receipt.finalized_height != manifest.height
            || receipt.finalized_block_id != manifest.finalized_block_id
            || receipt.application_state_root != manifest.application_state_root
        {
            return Err("snapshot restore receipt differs from verified manifest".into());
        }
        if receipt.finalized_height >= self.status.local_finalized_height {
            self.status.complete(receipt.finalized_height);
            self.local_parent_id = receipt.finalized_block_id;
        }
        self.snapshot_unavailable_height = None;
        self.active_snapshot = None;
        self.snapshot_store.clear_active()
    }

    fn drive_snapshot_acquisition(
        &mut self,
        plan: &synergy_sync::SyncPlan,
    ) -> Result<bool, String> {
        if let Some(active) = self.active_snapshot.as_ref() {
            if active.handoff_sent {
                return Ok(true);
            }
            if active.persisted.manifest.as_ref().is_some_and(|manifest| {
                active.persisted.received.len() == manifest.chunk_hashes.len()
            }) {
                self.restore_completed_snapshot()?;
                return Ok(self
                    .active_snapshot
                    .as_ref()
                    .is_some_and(|active| active.handoff_sent));
            }
            if active.sent_at.elapsed() < SNAPSHOT_RESPONSE_TIMEOUT {
                return Ok(false);
            }
            let expected = active.persisted.verified_head();
            let next = plan.sources.iter().find(|source| {
                source.finalized_height == expected.finalized_height
                    && source.finalized_hash == expected.finalized_hash
                    && source.finality_evidence_id == expected.finality_evidence_id
                    && !active.persisted.attempted.contains(&source.peer_id)
            });
            let Some(next) = next else {
                self.snapshot_unavailable_height = Some(active.persisted.height);
                self.active_snapshot = None;
                self.snapshot_store.clear_active()?;
                return Ok(false);
            };
            let (peer_id, request) = {
                let active = self
                    .active_snapshot
                    .as_mut()
                    .ok_or("active snapshot acquisition disappeared")?;
                active.persisted.peer_id = next.peer_id.clone();
                active.persisted.attempted.insert(next.peer_id.clone());
                active.sent_at = Instant::now();
                (active.persisted.peer_id.clone(), active.persisted.request())
            };
            self.snapshot_store.save_active(
                &self
                    .active_snapshot
                    .as_ref()
                    .ok_or("active snapshot acquisition disappeared")?
                    .persisted,
            )?;
            self.send_snapshot_request(&peer_id, &request)?;
            return Ok(false);
        }
        if plan.target_height > self.status.local_finalized_height.saturating_add(1)
            && self.snapshot_unavailable_height != Some(plan.target_height)
        {
            let source = plan
                .sources
                .first()
                .ok_or("verified Sync plan has no snapshot source")?;
            self.begin_snapshot_acquisition(source)?;
            return Ok(false);
        }
        Ok(false)
    }

    fn accept_head(&mut self, peer: AuthenticatedPeer, claim: HeadClaim) -> Result<(), String> {
        if claim.peer_id != peer.node_address.as_str()
            || claim.chain_id != self.manifest.chain_id
            || claim.genesis_hash != self.manifest.genesis_hash
            || claim
                .finality_witness
                .as_ref()
                .is_some_and(|witness| witness.is_empty() || witness.len() > 1024 * 1024)
        {
            self.metrics.record_rejection();
            return Err("Sync head claim is not bound to the authenticated peer and chain".into());
        }
        self.candidates.insert(
            peer.node_address.to_string(),
            SyncPeerCandidate {
                peer_id: peer.node_address.to_string(),
                authenticated: true,
                protocol_compatible: true,
                genesis_hash: self.manifest.genesis_hash.clone(),
                quarantined: false,
                consensus_duties_disabled: true,
                designated_support: false,
                advertised_height: claim.finalized_height,
            },
        );
        self.ingress.submit_head_claim(peer, claim)
    }

    fn persist_oldest_candidate_request(&self) -> Result<(), String> {
        if let Some(active) = self.active_requests.values().next() {
            self.request_store.save(&PersistedCandidateRequest {
                request: active.request.clone(),
                peer_id: active.peer_id.clone(),
                attempted: active.attempted.clone(),
            })
        } else {
            self.request_store.clear()
        }
    }

    fn drive_candidate_window(
        &mut self,
        sources: &[VerifiedHead],
        target: u64,
    ) -> Result<(), String> {
        let native_prefix = native_candidate_prefix_wait(
            &mut self.native_candidate_wait,
            self.status.local_finalized_height,
            self.ingress
                .processing_certified_parent()?
                .map(|parent| parent.height),
            Instant::now(),
        );
        let expired = self
            .active_requests
            .iter()
            .filter(|(height, active)| {
                !self.completed_candidates.contains_key(height)
                    && !native_prefix.is_some_and(|prefix| **height <= prefix)
                    && active.sent_at.elapsed() >= CANDIDATE_RESPONSE_TIMEOUT
            })
            .map(|(height, _)| *height)
            .collect::<Vec<_>>();
        for height in expired {
            let active = self
                .active_requests
                .get(&height)
                .ok_or("Sync request disappeared")?;
            let eligible = sources
                .iter()
                .filter(|source| source.finalized_height >= height)
                .cloned()
                .collect::<Vec<_>>();
            let Some((peer_id, revisit)) = candidate_retry_source(&eligible, &active.attempted)
            else {
                continue;
            };
            let request = active.request.clone();
            let session = self.send_candidate_request(&peer_id, &request)?;
            let active = self
                .active_requests
                .get_mut(&height)
                .ok_or("Sync request disappeared")?;
            active.record_solicitation(&peer_id, session);
            active.peer_id = peer_id.clone();
            if revisit {
                active.attempted.clear();
            }
            active.attempted.insert(peer_id);
            active.sent_at = Instant::now();
            active.last_boundary = "request-retried";
            self.persist_oldest_candidate_request()?;
            if self.outbox.has_pending() {
                return Ok(());
            }
        }
        let mut added = false;
        while self.active_requests.len() + self.awaiting_candidate_commits.len()
            < MAX_CANDIDATE_WINDOW
        {
            let mut occupied: BTreeSet<u64> = self
                .active_requests
                .keys()
                .copied()
                .chain(self.awaiting_candidate_commits.keys().copied())
                .collect();
            if let Some(prefix) = native_prefix {
                let end = prefix.min(
                    self.status
                        .local_finalized_height
                        .saturating_add(MAX_CANDIDATE_WINDOW as u64),
                );
                occupied.extend(self.status.local_finalized_height.saturating_add(1)..=end);
            }
            let Some(request) = next_candidate_prefetch(
                self.status.local_finalized_height,
                &self.local_parent_id,
                target,
                &occupied,
                |height| {
                    Ok(self
                        .ingress
                        .finalized_record(height)?
                        .map(|record| record.block_id))
                },
            )?
            else {
                break;
            };
            let Some(source) = sources
                .iter()
                .find(|source| source.finalized_height >= request.height)
            else {
                break;
            };
            let session = self.send_candidate_request(&source.peer_id, &request)?;
            self.status.begin_block_request(&BlockRequest {
                from_height: request.height,
                through_height: request.height,
                expected_parent_id: request.expected_parent_id.clone(),
            });
            let height = request.height;
            let mut active = ActiveCandidateRequest {
                request,
                peer_id: source.peer_id.clone(),
                attempted: BTreeSet::from([source.peer_id.clone()]),
                solicited: VecDeque::new(),
                sent_at: Instant::now(),
                requested_at: Instant::now(),
                diagnostic_at: Instant::now(),
                observed_chunks: 0,
                observed_bytes: 0,
                last_rx_session: None,
                last_boundary: "request-sent",
                last_rejection: None,
            };
            active.record_solicitation(&source.peer_id, session);
            self.active_requests.insert(height, active);
            added = true;
            if self.outbox.has_pending() {
                break;
            }
        }
        if added {
            self.persist_oldest_candidate_request()?;
        }
        Ok(())
    }

    fn prune_candidate_assembly(&mut self) -> Result<(), String> {
        let mut expired = Vec::new();
        for (height, active) in &self.candidate_assemblies {
            let request_matches = self.active_requests.get(height).is_some_and(|r| {
                r.request == active.request && r.peer_id == active.peer.node_address.as_str()
            });
            let reason = if !request_matches {
                Some("assembly-request-source-changed")
            } else if !self.ingress.is_current_session(&active.peer)? {
                Some("assembly-stale-session")
            } else if active.started.elapsed() >= Duration::from_secs(120) {
                Some("assembly-total-age-expired")
            } else if active.progressed.elapsed() >= CANDIDATE_RESPONSE_TIMEOUT {
                Some("assembly-progress-timeout")
            } else {
                None
            };
            if let Some(reason) = reason {
                expired.push((*height, reason));
            }
        }
        for (height, reason) in expired {
            let expired = self.candidate_assemblies.remove(&height);
            if let Some(request) = self.active_requests.get_mut(&height) {
                if let Some(expired) = expired {
                    // A stalled stream cannot win the empty slot again without
                    // a new request. Keep other solicited sessions eligible.
                    request.solicited.retain(|(id, session)| {
                        id != expired.peer.node_address.as_str()
                            || *session != expired.peer.session_id
                    });
                }
                request.last_boundary = "assembly-reset";
                request.last_rejection = Some(reason);
            }
        }
        Ok(())
    }

    fn accept_candidate_chunk(
        &mut self,
        peer: AuthenticatedPeer,
        chunk: CandidateResponseChunk,
    ) -> Result<(), String> {
        self.prune_candidate_assembly()?;
        let height = chunk.request.height;
        let reason = if !self.ingress.is_current_session(&peer)? {
            Some("chunk-stale-session")
        } else if chunk.validate().is_err() {
            Some("chunk-invalid-bounds")
        } else if !self
            .active_requests
            .get(&height)
            .is_some_and(|active| active.permits_chunk(&peer, &chunk.request))
        {
            Some("chunk-request-or-peer-mismatch")
        } else if !self.candidate_assemblies.contains_key(&height) && chunk.offset != 0 {
            Some("chunk-awaits-initial-offset")
        } else if self
            .candidate_assemblies
            .get(&height)
            .is_some_and(|assembly| {
                assembly.peer.node_address != peer.node_address
                    || assembly.peer.session_id != peer.session_id
            })
        {
            Some("chunk-competing-assembly")
        } else {
            None
        };
        self.note_candidate_boundary(
            height,
            &peer,
            reason.unwrap_or("chunk-received"),
            reason.is_some(),
            Some(chunk.bytes.len()),
        );
        if reason.is_some() {
            self.metrics.record_rejection();
            return Ok(());
        }
        if let Some(completed) = self.completed_candidates.get(&height) {
            if completed.peer.node_address != peer.node_address
                || completed.peer.session_id != peer.session_id
                || completed.request != chunk.request
                || completed.digest != chunk.digest
            {
                self.metrics.record_rejection();
            }
            return Ok(());
        }
        if !candidate_window_has_capacity(
            &self.candidate_assemblies,
            &self.completed_candidates,
            height,
            chunk.total_bytes,
        ) {
            self.note_candidate_boundary(
                height,
                &peer,
                "completed-window-backpressure",
                true,
                None,
            );
            self.metrics.record_rejection();
            return Ok(());
        }
        let request = chunk.request.clone();
        let digest = chunk.digest;
        let (progressed, complete) =
            match push_candidate_chunk(&mut self.candidate_assemblies, &peer, chunk) {
                Ok(result) => result,
                Err(_) => {
                    self.note_candidate_boundary(
                        height,
                        &peer,
                        "chunk-assembly-rejected",
                        true,
                        None,
                    );
                    self.metrics.record_rejection();
                    return Ok(());
                }
            };
        if progressed {
            if let Some(active) = self.active_requests.get_mut(&request.height) {
                // Progress pins this request to the winning session's peer,
                // including the completed-response handoff and its retries.
                active.peer_id = peer.node_address.to_string();
                active.sent_at = Instant::now();
            }
        }
        if let Some(bytes) = complete {
            self.note_candidate_boundary(
                height,
                &peer,
                "assembly-retained-for-owner-decode",
                false,
                None,
            );
            self.completed_candidates.insert(
                height,
                CompletedCandidate {
                    peer,
                    request,
                    digest,
                    payload: CompletedCandidatePayload::Raw(bytes),
                },
            );
        }
        Ok(())
    }

    fn drain_completed_candidate(&mut self) -> Result<(), String> {
        // Only JSON/request decoding moves to the already supported Sync-owner
        // fallback. PoSy still verifies the native witness before any authority.
        // One completed height per poll bounds work and cannot starve behind
        // unrelated head claims competing for the shared background mailbox.
        let Some(height) = self.completed_candidates.keys().next().copied() else {
            return Ok(());
        };
        let completed = self
            .completed_candidates
            .remove(&height)
            .ok_or("completed Sync candidate disappeared")?;
        let peer = completed.peer.clone();
        match completed.try_into_response(self.active_requests.get(&height), &self.ingress)? {
            Ok(Some((peer, response))) => self.accept_candidate_response(peer, response),
            Err(retained) => {
                self.completed_candidates.insert(height, retained);
                if let Some(active) = self.active_requests.get_mut(&height) {
                    active.sent_at = Instant::now();
                    active.last_boundary = "world-resource-backpressure-retained";
                }
                Ok(())
            }
            Ok(None) => {
                self.note_candidate_boundary(
                    height,
                    &peer,
                    "completed-request-session-or-json-rejected",
                    true,
                    None,
                );
                self.metrics.record_rejection();
                Ok(())
            }
        }
    }

    fn accept_candidate_response(
        &mut self,
        peer: AuthenticatedPeer,
        response: FinalizedCandidateResponse,
    ) -> Result<(), String> {
        let Some(expected) = self
            .active_requests
            .get(&response.request.height)
            .filter(|active| active.peer_id == peer.node_address.as_str())
        else {
            // Retries and source failover can deliver an authenticated response
            // after its request has committed or moved to another source.
            self.note_candidate_boundary(
                response.request.height,
                &peer,
                "response-unsolicited-or-old-source",
                true,
                None,
            );
            self.metrics.record_rejection();
            return Ok(());
        };
        if !candidate_response_matches(
            &expected.request,
            &expected.peer_id,
            &peer,
            self.ingress.is_current_session(&peer)?,
            &response.request,
            response.candidate.height,
            &response.candidate.parent_block_id,
        ) {
            self.note_candidate_boundary(
                response.request.height,
                &peer,
                "response-request-peer-session-or-parent-mismatch",
                true,
                None,
            );
            self.metrics.record_rejection();
            return Ok(());
        }
        let height = response.candidate.height;
        match self
            .ingress
            .try_submit_sync_candidate_response(peer.clone(), response)?
        {
            super::ingress::CandidateResponseHandoff::Queued => {}
            super::ingress::CandidateResponseHandoff::StaleSession => {
                self.metrics.record_rejection();
                return Ok(());
            }
            super::ingress::CandidateResponseHandoff::Full(retained) => {
                let (peer, response) = *retained;
                let charge = super::ingress::candidate_response_memory(&response)?;
                if !candidate_window_has_capacity(
                    &self.candidate_assemblies,
                    &self.completed_candidates,
                    height,
                    charge,
                ) {
                    return Err("bounded completed candidate handoff accounting exceeded".into());
                }
                self.completed_candidates.insert(
                    height,
                    CompletedCandidate {
                        peer,
                        request: response.request.clone(),
                        digest: [0; 32],
                        payload: CompletedCandidatePayload::Decoded(Box::new(response), charge),
                    },
                );
                if let Some(active) = self.active_requests.get_mut(&height) {
                    active.last_boundary = "candidate-handoff-backpressure-retained";
                }
                return Ok(());
            }
        }
        self.note_candidate_boundary(height, &peer, "candidate-forwarded-to-posy", false, None);
        self.awaiting_candidate_commits
            .insert(height, (peer, Instant::now()));
        self.active_requests.remove(&height);
        self.persist_oldest_candidate_request()?;
        Ok(())
    }
}

impl SyncService {
    fn apply_prepared_message(
        &mut self,
        peer: AuthenticatedPeer,
        message: synergy_sync::DecodedBudgetedSync<SyncWireMessage>,
        snapshot_verified: bool,
    ) -> Result<(), String> {
        if !self.ingress.is_current_session(&peer)? {
            self.metrics.record_rejection();
            return Ok(());
        }
        let (message, metadata) = message.into_parts();
        let metadata = Arc::new(metadata);
        match message {
            SyncWireMessage::Head(claim) => self.accept_head(peer, claim),
            SyncWireMessage::FinalizedCandidateRequest(request) => {
                self.ingress.submit_sync_candidate_request(peer, request)
            }
            SyncWireMessage::FinalizedCandidateRequestV2(request) => self
                .ingress
                .submit_sync_candidate_request_version(peer, request, true),
            SyncWireMessage::FinalizedCandidateChunk(chunk) => {
                self.accept_candidate_chunk(peer, chunk)
            }
            SyncWireMessage::FinalizedCandidateResponse(response) => self
                .accept_candidate_response(
                    peer,
                    FinalizedCandidateResponse {
                        response,
                        _metadata: metadata,
                    },
                ),
            SyncWireMessage::SnapshotChunkRequest(request) => {
                self.ingress.submit_snapshot_chunk_request(peer, request)
            }
            SyncWireMessage::SnapshotChunkResponse(response) => {
                self.accept_snapshot_response_prepared(peer, response, snapshot_verified)
            }
            SyncWireMessage::EpochAuthorityRequest(request) => {
                self.accept_authority_request(peer, request)
            }
            SyncWireMessage::EpochAuthorityResponse(response) => {
                self.accept_authority_response(peer, response)
            }
        }
    }
    fn drain_preparation(&mut self) -> Result<(), String> {
        for _ in 0..MAX_MESSAGES_PER_POLL {
            if !self.resource_pending.is_empty() {
                break;
            }
            let Some(owner) = self.preparation.as_ref() else {
                break;
            };
            let Some(completion) = owner.take()? else {
                break;
            };
            self.preparation_pending = self
                .preparation_pending
                .checked_sub(1)
                .ok_or("Sync preparation completion has no admitted predecessor")?;
            match completion.result {
                Ok(PreparedSync::Wire {
                    peer,
                    message,
                    snapshot_verified,
                }) => self.apply_prepared_message(peer, *message, snapshot_verified)?,
                Ok(PreparedSync::ResourceBlocked(input)) => {
                    self.resource_pending.push_back(input);
                    break;
                }
                Err(_) => self.metrics.record_rejection(),
            }
        }
        Ok(())
    }
}
impl SyncMessageSink for SyncService {
    fn receive_sync(&mut self, peer: AuthenticatedPeer, payload: Vec<u8>) -> Result<(), String> {
        if !self.ingress.is_current_session(&peer)? {
            self.metrics.record_rejection();
            return Ok(());
        }
        let (peer, payload) = if let (Some(owner), Some(authority)) =
            (self.preparation.as_ref(), self.authority.clone())
        {
            match prepare_sync_wire(
                owner,
                self.status.local_finalized_height,
                peer,
                payload,
                authority,
                Arc::clone(self.ingress.world_budget()),
            )? {
                None => {
                    self.preparation_pending += 1;
                    return Ok(());
                }
                Some(retained) => retained,
            }
        } else {
            (peer, payload)
        };
        if self.preparation_pending != 0 || !self.resource_pending.is_empty() {
            if self.deferred_wire.is_some() {
                return Err("Sync intake passed its ordered fallback barrier".into());
            }
            self.deferred_wire = Some((peer, payload));
            return Ok(());
        }
        self.apply_raw_sync(peer, payload)
    }
}
impl SyncService {
    fn drain_ordered_wire(&mut self) -> Result<(), String> {
        self.drain_preparation()?;
        if let Some(input) = self.resource_pending.pop_front() {
            if self.ingress.is_current_session(&input.0)? {
                match synergy_sync::decode_budgeted_sync_wire(&input.1, self.ingress.world_budget())
                {
                    Ok(message) => self.apply_prepared_message(input.0.clone(), message, false)?,
                    Err(error) if sync_resource_pressure(&error) => {
                        self.resource_pending.push_front(input)
                    }
                    Err(_) => self.metrics.record_rejection(),
                }
            }
        }
        if self.preparation_pending == 0 && self.resource_pending.is_empty() {
            if let Some((peer, payload)) = self.deferred_wire.take() {
                self.apply_raw_sync(peer, payload)?;
            }
        }
        Ok(())
    }
    fn apply_raw_sync(&mut self, peer: AuthenticatedPeer, payload: Vec<u8>) -> Result<(), String> {
        if !self.ingress.is_current_session(&peer)? {
            self.metrics.record_rejection();
            return Ok(());
        }
        let message =
            match synergy_sync::decode_budgeted_sync_wire(&payload, self.ingress.world_budget()) {
                Ok(message) => message,
                Err(error) if sync_resource_pressure(&error) => {
                    self.resource_pending.push_back(Arc::new((peer, payload)));
                    return Ok(());
                }
                Err(error) => {
                    self.metrics.record_rejection();
                    return Err(format!("decode bounded Sync message: {error}"));
                }
            };
        self.apply_prepared_message(peer, message, false)
    }
}
impl SyncService {
    fn diagnostic_boundary(&mut self, boundary: &'static str) {
        #[cfg(any(test, feature = "qualification-timing"))]
        {
            if self.diagnostic.enabled {
                let now = Instant::now();
                if self.diagnostic.stages.len() < 32 {
                    self.diagnostic.stages.push((
                        self.diagnostic.boundary,
                        now.duration_since(self.diagnostic.stage_started)
                            .as_micros(),
                    ));
                }
                self.diagnostic.stage_started = now;
            }
            self.diagnostic.boundary = boundary;
        }
        #[cfg(not(any(test, feature = "qualification-timing")))]
        let _ = boundary;
    }

    #[cfg(any(test, feature = "qualification-timing"))]
    fn report_poll_diagnostic(&mut self, started: Instant, result: &Result<(), String>) {
        let now = Instant::now();
        let gap = started.saturating_duration_since(self.diagnostic.previous_start);
        self.diagnostic.previous_start = started;
        if !self.diagnostic.enabled {
            return;
        }
        let phase_changed = self.status.phase != self.diagnostic.previous_phase;
        self.diagnostic.previous_phase = self.status.phase;
        let pending = if self.status.phase == SyncPhase::Complete {
            self.diagnostic
                .pending_since
                .take()
                .map(|t| now.duration_since(t))
                .unwrap_or_default()
        } else {
            let since = self.diagnostic.pending_since.get_or_insert(now);
            now.duration_since(*since)
        };
        self.diagnostic.maximum_pending = self.diagnostic.maximum_pending.max(pending);
        // Opt-in, bounded to 30 minutes and 7,200 small rows per owner. No payloads/keys.
        if !self.diagnostic.enabled
            || self.diagnostic.reports >= 7200
            || now.duration_since(self.diagnostic.started) > Duration::from_secs(1800)
            || (!phase_changed
                && now.duration_since(self.diagnostic.last_report) < Duration::from_millis(250))
        {
            return;
        }
        self.diagnostic.last_report = now;
        self.diagnostic.reports += 1;
        eprintln!(
            "SYNC_POLL_DIAGNOSTIC {}",
            serde_json::json!({
                "node": self.configuration.node_name,
                "elapsed_us": now.duration_since(self.diagnostic.started).as_micros(),
                "poll_us": now.duration_since(started).as_micros(),
                "stages_us": self.diagnostic.stages,
                "tail_us": now.duration_since(self.diagnostic.stage_started).as_micros(),
                "native_wait_cursor": self.native_candidate_wait.as_ref().map(|(h, _)| *h),
                "native_wait_us": self.native_candidate_wait.as_ref().map(|(_, t)| now.duration_since(*t).as_micros()),
                "start_gap_us": gap.as_micros(), "boundary": self.diagnostic.boundary,
                "phase": format!("{:?}", self.status.phase),
                "pending_us": pending.as_micros(),
                "maximum_pending_us": self.diagnostic.maximum_pending.as_micros(),
                "ack_cursor": self.status.local_finalized_height,
                "target": self.status.verified_target_height,
                "selected_heads": self.heads.heads().map(|h| (&h.peer_id, h.finalized_height)).collect::<BTreeMap<_, _>>(),
                "retained_outbox": self.outbox.0.borrow().len(),
                "active_candidates": self.active_requests.len(),
                "awaiting_candidate_commits": self.awaiting_candidate_commits.len(),
                "snapshot_target": self.active_snapshot.as_ref().map(|a| a.persisted.height),
                "snapshot_handoff": self.active_snapshot.as_ref().map(|a| a.handoff_sent),
                "resource_pending": self.resource_pending.len(),
                "ingress": self.ingress.sync_progress_diagnostic().ok(),
                "error": result.as_ref().err(),
            })
        );
    }
    fn poll_sync(&mut self) -> Result<(), String> {
        if !self.started {
            return Err("sync service is not started".into());
        }
        // Execution has already verified and durably committed these records.
        // Consume its bounded contiguous acknowledgements before network output:
        // an unsent head/response must not freeze the local recovery cursor.
        self.diagnostic_boundary("execution-acknowledgements");
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(publication) = self.ingress.take_finalized_execution_commit()? else {
                break;
            };
            let finalized = publication.finality;
            if finalized.height > self.status.local_finalized_height {
                if finalized.height != self.status.local_finalized_height.saturating_add(1) {
                    return Err(
                        "Sync execution acknowledgement skipped a finalized transition".into(),
                    );
                }
                self.status.local_finalized_height = finalized.height;
                if self
                    .status
                    .verified_target_height
                    .is_none_or(|target| finalized.height >= target)
                {
                    self.status.complete(finalized.height);
                }
                self.local_parent_id = finalized.block_id;
            }
        }
        self.diagnostic_boundary("snapshot-maintenance");
        self.snapshot_store.maintain()?;
        self.diagnostic_boundary("preparation-completions");
        self.drain_ordered_wire()?;
        self.diagnostic_boundary("candidate-completions");
        self.drain_completed_candidate()?;
        self.report_candidate_waits();
        self.prune_candidate_assembly()?;
        self.diagnostic_boundary("outbox-flush");
        if self.outbox.has_pending() {
            let flushed = self.outbox.flush(&self.ingress)?;
            let now = Instant::now();
            // Local queue wait is not a timeout or a failed remote source.
            for active in self.active_requests.values_mut() {
                active.sent_at = now;
            }
            if let Some(active) = self.active_snapshot.as_mut() {
                active.sent_at = now;
            }
            if let Some(active) = self.active_authority_request.as_mut() {
                active.sent_at = now;
            }
            if !flushed {
                return Ok(());
            }
        }
        self.diagnostic_boundary("sync-control");
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(request) = self.ingress.take_sync_control()? else {
                break;
            };
            let result = self.apply_sync_control(request.action);
            let _ = request.response.send(result);
            if self.outbox.has_pending() {
                break;
            }
        }
        if self.outbox.has_pending() {
            return Ok(());
        }
        self.diagnostic_boundary("advertise-head");
        self.advertise_head()?;
        if self.outbox.has_pending() {
            return Ok(());
        }
        self.diagnostic_boundary("network-intake");
        for _ in 0..MAX_MESSAGES_PER_POLL {
            if !self.resource_pending.is_empty() || self.deferred_wire.is_some() {
                break;
            }
            let Some(frame) = self.ingress.take(ProtocolKind::Sync)? else {
                break;
            };
            SyncAdapter
                .deliver(AdapterEnvelope::from(frame), self)
                .map_err(|error| format!("route authenticated Sync frame: {error:?}"))?;
            if self.outbox.has_pending()
                || !self.resource_pending.is_empty()
                || self.deferred_wire.is_some()
            {
                break;
            }
        }
        if self.outbox.has_pending() {
            return Ok(());
        }
        // A cache miss can materialize one bounded world. Never multiply that
        // work by the general network-message batch on the sole Sync owner.
        self.diagnostic_boundary("snapshot-response");
        for _ in 0..1 {
            let Some((peer, request)) = self.ingress.take_snapshot_chunk_request()? else {
                break;
            };
            if let Some(response) = self.snapshot_response(&request)? {
                self.outbox.publish(
                    &self.ingress,
                    OutboundFrame {
                        peer_id: peer.node_address.to_string(),
                        protocol: ProtocolKind::Sync,
                        payload: serde_json::to_vec(&SyncWireMessage::SnapshotChunkResponse(
                            response,
                        ))
                        .map_err(|error| format!("encode snapshot chunk response: {error}"))?,
                    },
                )?;
                if self.outbox.has_pending() {
                    break;
                }
            }
        }
        if self.outbox.has_pending() {
            return Ok(());
        }
        self.diagnostic_boundary("snapshot-receipts");
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(receipt) = self.ingress.take_snapshot_restore_receipt()? else {
                break;
            };
            self.accept_snapshot_restore_receipt(receipt)?;
        }
        self.diagnostic_boundary("verified-peer-heads");
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(head) = self.ingress.take_verified_head()? else {
                break;
            };
            record_posy_verified_head(&mut self.heads, &self.metrics, head)?;
        }
        let authenticated = self
            .ingress
            .authenticated_peers()?
            .into_iter()
            .collect::<BTreeSet<_>>();
        if self.paused {
            return Ok(());
        }
        self.candidates
            .retain(|peer_id, _| authenticated.contains(peer_id));
        self.heads.retain_authenticated(&authenticated);
        self.advertised
            .retain(|peer_id, _| authenticated.contains(peer_id));
        self.diagnostic_boundary("authority-transition");
        if self.drive_authority_transition(&authenticated)? {
            return Ok(());
        }
        let active_before = self.active_requests.len();
        self.active_requests
            .retain(|height, _| *height > self.status.local_finalized_height);
        retain_candidate_commits(
            &mut self.awaiting_candidate_commits,
            self.status.local_finalized_height,
            Instant::now(),
            &self.ingress,
        )?;
        if active_before != self.active_requests.len() {
            self.persist_oldest_candidate_request()?;
        }
        // Keep a persisted request across a peer disconnect so the next
        // authenticated source can be selected after the bounded timeout.
        let candidates: Vec<_> = self.candidates.values().cloned().collect();
        let heads: Vec<_> = self.heads.heads().cloned().collect();
        self.diagnostic_boundary("target-selection");
        if !heads.is_empty() {
            let plan = self
                .manager
                .plan(&candidates, &heads)
                .map_err(|error| format!("select verified Sync source: {error:?}"))?;
            self.status.select_target(plan.target_height);
            self.diagnostic_boundary("snapshot-acquisition");
            if self.drive_snapshot_acquisition(&plan)? {
                // A handed-off exact-prefix snapshot waits for durable receipt;
                // acquisition alone never blocks canonical candidate replay.
            } else if self.status.local_finalized_height >= plan.target_height {
                self.status.complete(self.status.local_finalized_height);
            } else {
                self.diagnostic_boundary("candidate-window");
                self.drive_candidate_window(&plan.sources, plan.target_height)?;
            }
        }
        self.diagnostic_boundary("poll-complete");
        if self.manager.may_determine_finality() || self.status.may_determine_finality() {
            return Err("Sync must never determine PoSy finality".into());
        }
        Ok(())
    }
}

impl ManagedService for SyncService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("sync service start was cancelled".into());
        }
        self.status.complete(self.status.local_finalized_height);
        self.failure = None;
        self.started = true;
        Ok(())
    }

    fn poll(&mut self) -> Result<(), String> {
        #[cfg(any(test, feature = "qualification-timing"))]
        let started = Instant::now();
        #[cfg(any(test, feature = "qualification-timing"))]
        {
            self.diagnostic.stages.clear();
            self.diagnostic.stage_started = started;
            self.diagnostic.boundary = "poll-start";
        }
        let result = self.poll_sync();
        #[cfg(any(test, feature = "qualification-timing"))]
        self.report_poll_diagnostic(started, &result);
        result
    }

    fn stop(&mut self) -> Result<(), String> {
        if let Some(owner) = self.preparation.take() {
            owner.cancel();
        }
        self.ingress.clear(ProtocolKind::Sync)?;
        self.outbox.0.borrow_mut().clear();
        self.advertised.clear();
        self.active_requests.clear();
        self.candidate_assemblies.clear();
        self.completed_candidates.clear();
        self.resource_pending.clear();
        self.preparation_pending = 0;
        self.deferred_wire = None;
        self.awaiting_candidate_commits.clear();
        self.native_candidate_wait = None;
        self.active_authority_request = None;
        self.started = false;
        self.paused = false;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        if !self.started {
            return ServiceHealth::Unhealthy {
                reason: "sync service is stopped".into(),
            };
        }
        if let Some(reason) = &self.failure {
            return ServiceHealth::Unhealthy {
                reason: reason.clone(),
            };
        }
        if self.status.phase == SyncPhase::Failed {
            return ServiceHealth::Unhealthy {
                reason: self
                    .status
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "Sync failed".into()),
            };
        }
        ServiceHealth::Healthy
    }

    fn readiness(&self) -> ServiceReadiness {
        if !self.started {
            return ServiceReadiness::Blocked {
                reason: "Sync service is stopped".into(),
            };
        }
        match self.status.phase {
            SyncPhase::Complete => ServiceReadiness::Ready,
            SyncPhase::Failed => ServiceReadiness::Blocked {
                reason: self
                    .status
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "Sync failed".into()),
            },
            _ => ServiceReadiness::Pending {
                reason: "verified synchronization remains in progress".into(),
            },
        }
    }
}

#[cfg(test)]
#[path = "sync_ordering_qualification.rs"]
mod ordering_qualification;

#[cfg(test)]
mod congestion_tests {
    use super::*;

    fn poll_fixture() -> (std::path::PathBuf, SyncService) {
        let (root, configuration) =
            super::super::socket_qualification::sync_poll_test_configuration();
        let (_, mut service) = construct_sync(
            &configuration,
            None,
            AuthorityTransitionSignal::default(),
            AuthenticatedIngress::default(),
            None,
        )
        .unwrap();
        service.start(&CancellationToken::default()).unwrap();
        (root, service)
    }

    #[test]
    #[ignore = "requires authenticated native APQE provider fixtures"]
    fn epoch_boundary_peer_without_successor_stays_online_and_sends_no_authority() {
        let (root, configuration) =
            super::super::socket_qualification::sync_poll_native_test_configuration();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root);
        let authority = authority::load(&configuration).unwrap().unwrap();
        let (_, mut service) = construct_sync(
            &configuration,
            None,
            AuthorityTransitionSignal::default(),
            AuthenticatedIngress::default(),
            None,
        )
        .unwrap();
        service.start(&CancellationToken::default()).unwrap();
        let request = EpochAuthorityRequest {
            current_epoch: authority.epoch.epoch,
            current_epoch_context_root: authority.epoch.root().unwrap(),
            finalized_height: authority.epoch.epoch_end_height - 2,
            finalized_block_id: "boundary-block".into(),
            finality_evidence_id: "b".repeat(64),
        };
        service.authority = Some(authority);
        let peer = AuthenticatedPeer::new(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            SessionId(1),
            vec![],
        )
        .unwrap();
        service
            .ingress
            .admit_session(peer.node_address.to_string(), peer.session_id)
            .unwrap();
        let frame = serde_json::to_vec(&SyncWireMessage::EpochAuthorityRequest(request)).unwrap();
        service.apply_raw_sync(peer, frame).unwrap();
        assert!(!service.outbox.has_pending());
        assert!(service.ingress.take_outbound().unwrap().is_none());
        assert!(service.authority_transition.take().unwrap().is_none());
        service.stop().unwrap();
    }

    #[test]
    #[ignore = "requires authenticated native APQE provider fixtures"]
    fn epoch_boundary_finality_does_not_starve_restarted_execution_replay() {
        let (root, configuration) =
            super::super::socket_qualification::sync_poll_native_test_configuration();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root);
        let authority = authority::load(&configuration).unwrap().unwrap();
        let boundary = authority.epoch.epoch_end_height - 2;
        let lagging = boundary - 17;
        let epoch = authority.epoch.epoch;
        let finalized = |height: u64| synergy_posy::FinalizedBlockRecord {
            height,
            block_id: format!("block-{height}"),
            finality_certificate_id: format!("{height:064x}"),
            protected_execution_root: "protected-root".into(),
        };
        let expected_transition = EpochAuthorityRequest {
            current_epoch: epoch,
            current_epoch_context_root: authority.epoch.root().unwrap(),
            finalized_height: boundary,
            finalized_block_id: finalized(boundary).block_id,
            finality_evidence_id: finalized(boundary).finality_certificate_id,
        };
        assert!(
            expected_transition.validate(),
            "boundary fixture must use canonical wire identities"
        );
        let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone()).unwrap();
        // The scheduler consumes trusted Execution/PoSy owner publications;
        // cryptographic boundary validation remains in native recovery tests.
        // Seed the real durable store, then resume its exact persisted request.
        let world = synergy_state::WorldState::default();
        synergy_state::FinalizedStateStore::load(layout.state().join("execution"))
            .unwrap()
            .commit_verified_snapshot(
                synergy_state::FinalizedState {
                    finalized_height: lagging,
                    finalized_block_id: format!("block-{lagging}"),
                    state_root: synergy_state::state_root(&world).unwrap(),
                },
                &world,
            )
            .unwrap();
        let local = load_local_peer_id(&configuration).unwrap();
        let peers: Vec<_> = authority
            .registry
            .quorum_validators()
            .into_iter()
            .map(|validator| validator.validator_id)
            .filter(|peer| peer != &local)
            .collect();
        assert_eq!(peers.len(), 4);
        let request = FinalizedCandidateRequest {
            height: lagging + 1,
            expected_parent_id: format!("block-{lagging}"),
        };
        SyncRequestStore::new(layout.metadata().join("sync"))
            .unwrap()
            .save(&PersistedCandidateRequest {
                request: request.clone(),
                peer_id: peers[0].clone(),
                attempted: BTreeSet::from([peers[0].clone()]),
            })
            .unwrap();
        let (_, mut service) = construct_sync(
            &configuration,
            None,
            AuthorityTransitionSignal::default(),
            AuthenticatedIngress::default(),
            None,
        )
        .unwrap();
        service.authority = Some(authority);
        service.start(&CancellationToken::default()).unwrap();
        assert_eq!(service.status.local_finalized_height, lagging);
        let resumed = service.active_requests.get_mut(&request.height).unwrap();
        assert_eq!(resumed.last_boundary, "resumed-request");
        assert!(resumed.solicited.is_empty());
        resumed.sent_at = Instant::now() - CANDIDATE_RESPONSE_TIMEOUT;
        service
            .ingress
            .submit_finality(finalized(boundary), vec![173; 146_079])
            .unwrap();
        for (index, peer) in peers.iter().enumerate() {
            let session = SessionId(index as u64 + 101);
            service
                .ingress
                .admit_session(peer.clone(), session)
                .unwrap();
            service.candidates.insert(
                peer.clone(),
                SyncPeerCandidate {
                    peer_id: peer.clone(),
                    authenticated: true,
                    protocol_compatible: true,
                    genesis_hash: service.manifest.genesis_hash.clone(),
                    quarantined: false,
                    consensus_duties_disabled: true,
                    designated_support: false,
                    advertised_height: boundary,
                },
            );
            service
                .ingress
                .submit_verified_head(
                    VerifiedHead {
                        peer_id: peer.clone(),
                        finalized_height: boundary,
                        finalized_hash: finalized(boundary).block_id,
                        finality_evidence_id: finalized(boundary).finality_certificate_id,
                    },
                    session,
                )
                .unwrap();
        }
        // Isolate candidate replay from optional snapshot acquisition.
        service.snapshot_unavailable_height = Some(boundary);
        service.poll().unwrap();
        assert!(service.active_authority_request.is_none());
        let retried = service.active_requests.get(&request.height).unwrap();
        assert_eq!(retried.request, request);
        assert_eq!(retried.last_boundary, "request-retried");
        assert!(!retried.solicited.is_empty());
        assert!(retried.solicited.iter().all(|(peer, session)| {
            service
                .ingress
                .authenticated_peer_progress()
                .unwrap()
                .get(peer)
                .is_some_and(|(current, _)| *current == *session)
        }));
        let mut saw_retry = false;
        while let Some(frame) = service.ingress.take_outbound().unwrap() {
            if let synergy_sync::SyncWireMessage::FinalizedCandidateRequestV2(sent) =
                serde_json::from_slice::<synergy_sync::SyncWireMessage<synergy_state::WorldState>>(
                    &frame.payload,
                )
                .unwrap()
            {
                saw_retry |= sent == request;
            }
        }
        assert!(
            saw_retry,
            "resumed exact request must actually enter the transport outbox"
        );
        // Every subsequent durable commit must continue ordinary scheduling;
        // knowing terminal finality cannot strand the next missing height.
        for height in lagging + 1..=boundary {
            service
                .ingress
                .submit_finalized_execution_commit(
                    super::super::ingress::FinalizedExecutionCommit {
                        epoch,
                        finality: finalized(height),
                        application_state_root: "state-root".into(),
                    },
                )
                .unwrap();
            service.poll().unwrap();
            if height < boundary {
                assert!(service.active_authority_request.is_none());
                assert!(service.active_requests.contains_key(&(height + 1)));
            }
            while service.ingress.take_outbound().unwrap().is_some() {}
        }
        let transition = service.active_authority_request.as_ref().unwrap();
        assert_eq!(transition.request, expected_transition);
        let finalized = service.ingress.latest_finality().unwrap().unwrap();
        assert!(service.execution_ready_for_authority(&finalized).unwrap());
        service.local_parent_id = "conflicting-durable-parent".into();
        assert!(service.execution_ready_for_authority(&finalized).is_err());
        service.local_parent_id = finalized.block_id.clone();
        service.status.local_finalized_height += 1;
        assert!(service.execution_ready_for_authority(&finalized).is_err());
        service.stop().unwrap();
    }

    fn publish_test_execution(service: &SyncService, height: u64) {
        // This exercises the already-trusted owner acknowledgement boundary,
        // not cryptographic/finality qualification (covered by live fixtures).
        service
            .ingress
            .submit_finalized_execution_commit(super::super::ingress::FinalizedExecutionCommit {
                epoch: 1,
                finality: synergy_posy::FinalizedBlockRecord {
                    height,
                    block_id: format!("block-{height}"),
                    finality_certificate_id: format!("finality-{height}"),
                    protected_execution_root: "protected-root".into(),
                },
                application_state_root: "state-root".into(),
            })
            .unwrap();
    }

    fn publish_test_consensus_tip(service: &SyncService, height: u64, witness: Vec<u8>) {
        service
            .ingress
            .submit_finality(
                synergy_posy::FinalizedBlockRecord {
                    height,
                    block_id: format!("block-{height}"),
                    finality_certificate_id: format!("finality-{height}"),
                    protected_execution_root: "protected-root".into(),
                },
                witness,
            )
            .unwrap();
    }

    fn verify_test_peer(service: &SyncService, peer: &str, session: SessionId, height: u64) {
        service
            .ingress
            .submit_verified_head(
                VerifiedHead {
                    peer_id: peer.into(),
                    finalized_height: height,
                    finalized_hash: format!("block-{height}"),
                    finality_evidence_id: format!("finality-{height}"),
                },
                session,
            )
            .unwrap();
    }

    fn native_poll_fixture() -> (std::path::PathBuf, SyncService) {
        let (root, configuration) =
            super::super::socket_qualification::sync_poll_native_test_configuration();
        let (_, mut service) = construct_sync(
            &configuration,
            None,
            AuthorityTransitionSignal::default(),
            AuthenticatedIngress::default(),
            None,
        )
        .unwrap();
        service.start(&CancellationToken::default()).unwrap();
        (root, service)
    }

    #[test]
    #[ignore = "requires authenticated native APQE provider fixtures"]
    fn reciprocal_known_tip_head_announces_source_once_without_repeating_proof() {
        let (root, mut donor) = native_poll_fixture();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let authority = authority::load(&donor.configuration).unwrap().unwrap();
        let receiver_id = authority
            .registry
            .quorum_validators()
            .into_iter()
            .map(|validator| validator.validator_id)
            .find(|id| id != &donor.local_peer_id)
            .unwrap();
        let session = SessionId(301);
        let terminal = synergy_posy::FinalizedBlockRecord {
            height: 18,
            block_id: "block-18".into(),
            finality_certificate_id: "a".repeat(64),
            protected_execution_root: "protected-root".into(),
        };
        // Publications cross the existing trusted PoSy owner boundary. Actual
        // native witness/session qualification remains in socket integration.
        donor
            .ingress
            .submit_finality(terminal.clone(), vec![173; 146_079])
            .unwrap();
        donor
            .ingress
            .admit_session(receiver_id.clone(), session)
            .unwrap();
        donor
            .ingress
            .submit_verified_head(
                VerifiedHead {
                    peer_id: receiver_id.clone(),
                    finalized_height: 18,
                    finalized_hash: terminal.block_id.clone(),
                    finality_evidence_id: terminal.finality_certificate_id.clone(),
                },
                session,
            )
            .unwrap();
        assert!(donor.advertised.is_empty());
        donor.advertise_head().unwrap();
        let reciprocal = donor.ingress.take_outbound().unwrap().unwrap();
        assert_eq!(reciprocal.peer_id, receiver_id);
        assert!(reciprocal.payload.len() < 1024);
        let value: serde_json::Value = serde_json::from_slice(&reciprocal.payload).unwrap();
        let claim: HeadClaim = serde_json::from_value(value["body"].clone()).unwrap();
        assert!(claim.finality_witness.is_none());
        assert_eq!(claim.finalized_height, 18);
        assert_eq!(claim.finality_evidence_id, terminal.finality_certificate_id);
        donor.advertise_head().unwrap();
        assert!(donor.ingress.take_outbound().unwrap().is_none());
        let mut receiver_config = donor.configuration.clone();
        receiver_config.storage.data_directory = root.join("receiver");
        let layout = NodeStorageLayout::new(&receiver_config.storage.data_directory).unwrap();
        let world = synergy_state::WorldState::default();
        synergy_state::FinalizedStateStore::load(layout.state().join("execution"))
            .unwrap()
            .commit_verified_snapshot(
                synergy_state::FinalizedState {
                    finalized_height: 1,
                    finalized_block_id: "block-1".into(),
                    state_root: synergy_state::state_root(&world).unwrap(),
                },
                &world,
            )
            .unwrap();
        let (_, mut receiver) = construct_sync(
            &receiver_config,
            None,
            AuthorityTransitionSignal::default(),
            AuthenticatedIngress::default(),
            None,
        )
        .unwrap();
        receiver.local_peer_id = receiver_id;
        receiver.start(&CancellationToken::default()).unwrap();
        receiver
            .ingress
            .submit_finality(terminal.clone(), vec![173; 146_079])
            .unwrap();
        receiver
            .ingress
            .admit_session(donor.local_peer_id.clone(), session)
            .unwrap();
        let peer = AuthenticatedPeer::new(&donor.local_peer_id, session, vec![]).unwrap();
        receiver
            .apply_raw_sync(peer.clone(), reciprocal.payload)
            .unwrap();
        assert_eq!(
            receiver.heads.len(),
            0,
            "unverified compact claim grants no source authority"
        );
        let (claimed_peer, pending) = receiver.ingress.take_head_claim().unwrap().unwrap();
        assert_eq!(claimed_peer, peer);
        assert_eq!(pending, claim);
        // PoSy must establish exact local finality identity before publishing
        // source eligibility; compact transport alone never bypasses this gate.
        receiver
            .ingress
            .submit_verified_head(
                VerifiedHead {
                    peer_id: donor.local_peer_id.clone(),
                    finalized_height: terminal.height,
                    finalized_hash: terminal.block_id,
                    finality_evidence_id: terminal.finality_certificate_id,
                },
                session,
            )
            .unwrap();
        receiver.snapshot_unavailable_height = Some(18);
        receiver.poll().unwrap();
        assert_eq!(receiver.status.local_finalized_height, 1);
        assert_eq!(receiver.heads.len(), 1);
        let request = receiver.request_store.load().unwrap().unwrap();
        assert_eq!(request.request.height, 2);
        assert_eq!(request.request.expected_parent_id, "block-1");
        assert_eq!(request.peer_id, donor.local_peer_id);
        // A new authenticated session gets one fresh claim; the old session's
        // known-proof hint cannot suppress source discovery after restart.
        donor
            .ingress
            .admit_session(receiver.local_peer_id.clone(), SessionId(302))
            .unwrap();
        donor.advertise_head().unwrap();
        let refreshed = donor.ingress.take_outbound().unwrap().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&refreshed.payload).unwrap();
        let refreshed: HeadClaim = serde_json::from_value(value["body"].clone()).unwrap();
        assert!(refreshed.finality_witness.is_some());
        donor.stop().unwrap();
        receiver.stop().unwrap();
    }

    #[test]
    #[ignore = "requires authenticated native APQE provider fixtures"]
    fn verified_current_peer_heads_leave_writer_capacity_for_posy() {
        let (root, mut service) = native_poll_fixture();
        // A native-sized proof at the existing trusted PoSy publication boundary.
        // Native socket fixtures separately verify real three-QC signatures.
        publish_test_consensus_tip(&service, 20, vec![173; 146_079]);
        for peer in ["peer-a", "peer-b", "peer-c", "peer-d"] {
            service
                .ingress
                .admit_session(peer.into(), SessionId(1))
                .unwrap();
            verify_test_peer(&service, peer, SessionId(1), 20);
        }
        service.advertise_head().unwrap();
        let mut compact_heads = 0;
        while let Some(frame) = service.ingress.take_outbound().unwrap() {
            let value: serde_json::Value = serde_json::from_slice(&frame.payload).unwrap();
            let claim: HeadClaim = serde_json::from_value(value["body"].clone()).unwrap();
            assert!(claim.finality_witness.is_none());
            assert!(frame.payload.len() < 1024);
            compact_heads += 1;
        }
        assert_eq!(compact_heads, 4);
        let filler = || OutboundFrame {
            peer_id: "peer-a".into(),
            protocol: ProtocolKind::Discovery,
            payload: vec![0],
        };
        let consensus = || OutboundFrame {
            peer_id: "peer-a".into(),
            protocol: ProtocolKind::Posy,
            payload: vec![4],
        };
        // The real nonblocking dispatcher feeds one 16-frame ordered writer per
        // peer. Hold its reader, leaving one free slot after earlier traffic.
        let (writer, reader) = std::sync::mpsc::sync_channel::<OutboundFrame>(16);
        let dispatch = |frame| match writer.try_send(frame) {
            Ok(()) => None,
            Err(std::sync::mpsc::TrySendError::Full(frame)) => Some(frame),
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => panic!("writer disconnected"),
        };
        for _ in 0..15 {
            writer.try_send(filler()).unwrap();
        }
        let legacy_payload = serde_json::to_vec(&SyncWireMessage::Head(HeadClaim {
            peer_id: service.local_peer_id.clone(),
            chain_id: service.manifest.chain_id,
            genesis_hash: service.manifest.genesis_hash.clone(),
            finalized_height: 20,
            finalized_hash: "block-20".into(),
            finality_evidence_id: "finality-20".into(),
            finality_witness: Some(vec![173; 146_079]),
        }))
        .unwrap();
        let legacy_bytes = legacy_payload.len();
        // Before: unconditional full-proof advertising occupies the last writer
        // slot. PoSy remains retained despite its separate ingress reservation.
        assert!(service
            .ingress
            .try_publish_outbound(OutboundFrame {
                peer_id: "peer-a".into(),
                protocol: ProtocolKind::Sync,
                payload: legacy_payload,
            })
            .unwrap());
        assert!(service.ingress.try_publish_outbound(consensus()).unwrap());
        service.ingress.dispatch_outbound(dispatch).unwrap();
        assert_eq!(
            service.ingress.take_outbound().unwrap().unwrap().protocol,
            ProtocolKind::Posy
        );
        let before: Vec<_> = reader.try_iter().collect();
        assert_eq!(before.len(), 16);
        assert_eq!(before.last().unwrap().protocol, ProtocolKind::Sync);
        for _ in 0..15 {
            writer.try_send(filler()).unwrap();
        }
        // After: verified-current proof suppression leaves the same slot free.
        service.advertise_head().unwrap();
        assert!(!service.outbox.has_pending());
        assert!(
            service.advertised.len() == 4,
            "one compact source announcement is retained per current session"
        );
        assert!(service.ingress.try_publish_outbound(consensus()).unwrap());
        service.ingress.dispatch_outbound(dispatch).unwrap();
        assert!(service.ingress.take_outbound().unwrap().is_none());
        let after: Vec<_> = reader.try_iter().collect();
        assert_eq!(after.len(), 16);
        assert_eq!(after.last().unwrap().protocol, ProtocolKind::Posy);
        assert!(after
            .iter()
            .all(|frame| frame.protocol != ProtocolKind::Sync));
        eprintln!("SYNC_KNOWN_PROOF_WRITER_REGRESSION before_redundant_bytes={legacy_bytes} after_redundant_bytes=0 before_posy_retained=1 after_posy_dispatched=1 writer_capacity=16");
        // The next height still requires a full proof; no safety material is removed.
        publish_test_consensus_tip(&service, 21, vec![174; 146_079]);
        service.advertise_head().unwrap();
        let mut delivered = 0;
        while let Some(frame) = service.ingress.take_outbound().unwrap() {
            let value: serde_json::Value = serde_json::from_slice(&frame.payload).unwrap();
            assert_eq!(value["kind"], "head");
            let claim: HeadClaim = serde_json::from_value(value["body"].clone()).unwrap();
            assert_eq!(claim.finalized_height, 21);
            assert_eq!(claim.finality_witness.unwrap(), vec![174; 146_079]);
            delivered += 1;
        }
        assert_eq!(delivered, 4);
        service.stop().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires authenticated native APQE provider fixtures"]
    fn sync_head_delivery_preserves_wire_and_reconnect_under_backpressure() {
        let (root, mut service) = native_poll_fixture();
        let witness = vec![173; 146_079];
        publish_test_consensus_tip(&service, 20, witness.clone());
        for peer in ["known", "ahead", "lagging", "unknown"] {
            service
                .ingress
                .admit_session(peer.into(), SessionId(1))
                .unwrap();
        }
        verify_test_peer(&service, "known", SessionId(1), 20);
        verify_test_peer(&service, "ahead", SessionId(1), 21);
        verify_test_peer(&service, "lagging", SessionId(1), 19);
        let expected = serde_json::to_vec(&SyncWireMessage::Head(HeadClaim {
            peer_id: service.local_peer_id.clone(),
            chain_id: service.manifest.chain_id,
            genesis_hash: service.manifest.genesis_hash.clone(),
            finalized_height: 20,
            finalized_hash: "block-20".into(),
            finality_evidence_id: "finality-20".into(),
            finality_witness: Some(witness),
        }))
        .unwrap();
        service.advertise_head().unwrap();
        let mut compact = BTreeSet::new();
        let mut full = BTreeSet::new();
        while let Some(frame) = service.ingress.take_outbound().unwrap() {
            if frame.peer_id == "known" || frame.peer_id == "ahead" {
                let value: serde_json::Value = serde_json::from_slice(&frame.payload).unwrap();
                let claim: HeadClaim = serde_json::from_value(value["body"].clone()).unwrap();
                assert!(claim.finality_witness.is_none());
                compact.insert(frame.peer_id);
            } else {
                assert_eq!(frame.payload, expected);
                full.insert(frame.peer_id);
            }
        }
        assert_eq!(compact, BTreeSet::from(["ahead".into(), "known".into()]));
        assert_eq!(full, BTreeSet::from(["lagging".into(), "unknown".into()]));
        service.advertise_head().unwrap();
        assert!(service.ingress.take_outbound().unwrap().is_none());
        // Reconnect without an intervening disconnected poll invalidates both hints.
        service
            .ingress
            .admit_session("lagging".into(), SessionId(2))
            .unwrap();
        verify_test_peer(&service, "lagging", SessionId(1), 99); // stale session is ignored
        service.advertise_head().unwrap();
        let resent = service.ingress.take_outbound().unwrap().unwrap();
        assert_eq!(resent.peer_id, "lagging");
        assert_eq!(resent.payload, expected);
        let filler = || OutboundFrame {
            peer_id: "unknown".into(),
            protocol: ProtocolKind::Sync,
            payload: vec![0],
        };
        while service.ingress.try_publish_outbound(filler()).unwrap() {}
        service
            .ingress
            .admit_session("unknown".into(), SessionId(2))
            .unwrap();
        service.advertise_head().unwrap();
        assert_eq!(service.outbox.0.borrow().len(), 1);
        assert_eq!(service.outbox.0.borrow().front().unwrap().payload, expected);
        verify_test_peer(&service, "unknown", SessionId(2), 20);
        assert!(!service.outbox.flush(&service.ingress).unwrap());
        assert_eq!(
            service.outbox.0.borrow().len(),
            1,
            "accepted unsent bytes remain retained"
        );
        while service.ingress.take_outbound().unwrap().is_some() {}
        assert!(service.outbox.flush(&service.ingress).unwrap());
        let retained = service.ingress.take_outbound().unwrap().unwrap();
        assert_eq!(retained.peer_id, "unknown");
        assert_eq!(retained.payload, expected);
        service.stop().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durable_execution_acknowledgement_progresses_while_sync_outbox_is_blocked() {
        let (root, mut service) = poll_fixture();
        service.status.select_target(1);
        let frame = |sequence: u64| OutboundFrame {
            peer_id: "blocked-peer".into(),
            protocol: ProtocolKind::Sync,
            payload: sequence.to_le_bytes().to_vec(),
        };
        let mut accepted = 0;
        while service
            .ingress
            .try_publish_outbound(frame(accepted))
            .unwrap()
        {
            accepted += 1;
        }
        service
            .outbox
            .publish(&service.ingress, frame(accepted))
            .unwrap();
        publish_test_execution(&service, 1);
        service.poll().unwrap();
        eprintln!(
            "SYNC_ACK_REGRESSION cursor={} phase={:?} retained_outbox={} ingress={}",
            service.status.local_finalized_height,
            service.status.phase,
            service.outbox.0.borrow().len(),
            service.ingress.sync_progress_diagnostic().unwrap()
        );
        assert_eq!(
            service.status.local_finalized_height, 1,
            "network backpressure must not starve an already durable Execution acknowledgement"
        );
        assert!(
            service.outbox.has_pending(),
            "repair must retain exact unsent bytes"
        );
        let held = Instant::now();
        while held.elapsed() < Duration::from_millis(5100) {
            service.poll().unwrap();
            assert_eq!(service.status.local_finalized_height, 1);
            assert_eq!(service.readiness(), ServiceReadiness::Ready);
            assert_eq!(service.outbox.0.borrow().len(), 1);
            std::thread::sleep(Duration::from_millis(5));
        }
        eprintln!(
            "SYNC_ACK_SUSTAINED held_ms={} cursor=1 ready=true retained_outbox=1",
            held.elapsed().as_millis()
        );
        assert_eq!(service.readiness(), ServiceReadiness::Ready);
        service.stop().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durable_execution_acknowledgement_does_not_complete_below_verified_target() {
        let (root, mut service) = poll_fixture();
        service.status.select_target(2);
        let frame = || OutboundFrame {
            peer_id: "blocked-peer".into(),
            protocol: ProtocolKind::Sync,
            payload: vec![1],
        };
        while service.ingress.try_publish_outbound(frame()).unwrap() {}
        service.outbox.publish(&service.ingress, frame()).unwrap();
        publish_test_execution(&service, 1);
        service.poll().unwrap();
        assert_eq!(service.status.local_finalized_height, 1);
        assert_eq!(service.status.verified_target_height, Some(2));
        assert!(matches!(
            service.readiness(),
            ServiceReadiness::Pending { .. }
        ));
        assert!(service.outbox.has_pending());
        publish_test_execution(&service, 2);
        service.poll().unwrap();
        assert_eq!(service.status.local_finalized_height, 2);
        assert_eq!(service.readiness(), ServiceReadiness::Ready);
        assert!(service.outbox.has_pending());
        service.stop().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durable_execution_acknowledgements_still_reject_noncontiguous_progress() {
        let (root, mut service) = poll_fixture();
        publish_test_execution(&service, 2);
        assert!(service
            .poll()
            .unwrap_err()
            .contains("skipped a finalized transition"));
        assert_eq!(service.status.local_finalized_height, 0);
        service.stop().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn snapshot_restore_pressure_preserves_input_and_retries_without_accepting_corruption() {
        let ingress = AuthenticatedIngress::default();
        let world = synergy_state::WorldState::default();
        let raw = serde_json::to_vec(&world).unwrap();
        let original = raw.clone();
        // This unit exercises the post-authentication staging boundary. The
        // full socket fixture separately verifies manifest signatures/finality.
        let manifest = SnapshotManifest {
            format_version: 1,
            chain_id: 1266,
            network_id: "pressure-test".into(),
            epoch: 1,
            height: 1,
            finalized_block_id: "block-1".into(),
            finality_evidence_id: "finality-1".into(),
            application_state_root: synergy_state::state_root(&world).unwrap(),
            state_root: synergy_crypto::Hash32([0; 32]),
            chunk_size: 1024,
            chunk_hashes: vec![],
            signing_key_id: "unit-staging".into(),
            signature_algorithm: SignatureAlgorithm::MlDsa65,
            signature: vec![],
        };
        let pressure = ingress
            .world_budget()
            .reserve(ingress.world_budget().available())
            .unwrap();
        let mut sink = IngressSnapshotRestoreSink {
            ingress: &ingress,
            manifest: &manifest,
            staged: None,
            resource_blocked: false,
        };
        assert!(sink.stage(1, &raw).is_err());
        assert!(sink.resource_blocked);
        assert!(sink.staged.is_none());
        assert!(ingress.take_snapshot_restore_handoff().unwrap().is_none());
        assert_eq!(raw, original);
        drop(pressure);
        assert!(sink.stage(1, b"{broken").is_err());
        assert!(
            !sink.resource_blocked,
            "corruption must remain a verification failure"
        );
        sink.stage(1, &raw).unwrap();
        assert!(!sink.resource_blocked);
        sink.commit(1).unwrap();
        let handoff = ingress.take_snapshot_restore_handoff().unwrap().unwrap();
        assert_eq!(handoff.state.as_ref().as_ref(), &world);
        assert!(ingress.world_budget().used() > 0);
        drop(handoff);
        assert_eq!(ingress.world_budget().used(), 0);
    }

    #[test]
    fn posy_verified_head_notifications_ignore_stale_delivery_but_preserve_monotonic_head() {
        let mut heads = VerifiedHeadCollector::new();
        let metrics = SyncMetrics::default();
        let head = |height| VerifiedHead {
            peer_id: "verified-peer".into(),
            finalized_height: height,
            finalized_hash: format!("block-{height}"),
            finality_evidence_id: format!("finality-{height}"),
        };
        record_posy_verified_head(&mut heads, &metrics, head(13)).unwrap();
        let before = heads.heads().cloned().collect::<Vec<_>>();
        record_posy_verified_head(&mut heads, &metrics, head(12)).unwrap();
        assert_eq!(heads.heads().cloned().collect::<Vec<_>>(), before);
        assert_eq!(metrics.snapshot().verified_blocks, 1);
        assert_eq!(metrics.snapshot().rejected_responses, 1);
        // The collector itself still fails closed on actual regression calls.
        assert!(matches!(
            heads.record(head(12)),
            Err(HeadCollectionError::Regression {
                current: 13,
                received: 12
            })
        ));
        record_posy_verified_head(&mut heads, &metrics, head(14)).unwrap();
        assert_eq!(heads.heads().next(), Some(&head(14)));
        assert_eq!(metrics.snapshot().verified_blocks, 2);
        assert_eq!(heads.len(), 1);
    }

    #[test]
    fn posy_verified_head_notifications_reject_conflicting_block_without_mutation() {
        let mut heads = VerifiedHeadCollector::new();
        let metrics = SyncMetrics::default();
        let first = VerifiedHead {
            peer_id: "verified-peer".into(),
            finalized_height: 13,
            finalized_hash: "block-13".into(),
            finality_evidence_id: "finality-13".into(),
        };
        record_posy_verified_head(&mut heads, &metrics, first.clone()).unwrap();
        let conflicting = VerifiedHead {
            finalized_hash: "conflicting-block-13".into(),
            ..first.clone()
        };
        let error = record_posy_verified_head(&mut heads, &metrics, conflicting).unwrap_err();
        assert!(error.contains("ConflictingBlock"));
        assert_eq!(heads.heads().next(), Some(&first));
        assert_eq!(metrics.snapshot().verified_blocks, 1);
        assert_eq!(metrics.snapshot().rejected_responses, 0);
        let empty = VerifiedHead {
            peer_id: String::new(),
            ..first
        };
        assert!(record_posy_verified_head(&mut heads, &metrics, empty)
            .unwrap_err()
            .contains("EmptyPeer"));
    }

    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn ordered_sync_fallback_and_resource_blocked_predecessors_complete_exact_bytes() {
        for resource_blocked in [false, true] {
            let (root, configuration) =
                super::super::socket_qualification::sync_poll_native_test_configuration();
            struct Cleanup(std::path::PathBuf);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    let _ = fs::remove_dir_all(&self.0);
                }
            }
            let _cleanup = Cleanup(root.clone());
            let (_, mut service) = construct_sync(
                &configuration,
                None,
                AuthorityTransitionSignal::default(),
                AuthenticatedIngress::default(),
                None,
            )
            .unwrap();
            service.start(&CancellationToken::default()).unwrap();
            let engine = synergy_aegis::load_authenticated_native_engine(
                std::path::Path::new(&std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap()),
                &std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap(),
            )
            .unwrap();
            let authority = authority::qualification_authority_with_provider(
                (0..synergy_posy::POSY_MIN_VALIDATOR_COUNT)
                    .map(|i| {
                        (
                            synergy_posy::ValidatorRecord {
                                validator_id: format!("ordering-{i}"),
                                consensus_key_id: format!("key-{i}"),
                                frozen_voting_weight: 1,
                                status: synergy_posy::ValidatorStatus::Active,
                            },
                            vec![0; 1952],
                        )
                    })
                    .collect(),
                Some(engine),
            );
            let mut pool = preparation::Pool::new().unwrap();
            let tag = preparation::AuthorityTag {
                incarnation: "ordered-sync".into(),
                epoch: 1,
                authority_digest: "fixed".into(),
            };
            let blocker = pool.handle().owner::<()>(tag.clone()).unwrap();
            service.preparation = Some(pool.handle().owner::<PreparedSync>(tag).unwrap());
            service.authority = Some(authority);
            let peer = AuthenticatedPeer::new(
                "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
                SessionId(1),
                vec![],
            )
            .unwrap();
            service
                .ingress
                .admit_session(peer.node_address.to_string(), peer.session_id)
                .unwrap();
            let request = FinalizedCandidateRequest {
                height: 11,
                expected_parent_id: "parent".into(),
            };
            let mut active = ActiveCandidateRequest {
                request: request.clone(),
                peer_id: peer.node_address.to_string(),
                attempted: BTreeSet::new(),
                solicited: VecDeque::new(),
                sent_at: Instant::now(),
                requested_at: Instant::now(),
                diagnostic_at: Instant::now(),
                observed_chunks: 0,
                observed_bytes: 0,
                last_rx_session: None,
                last_boundary: "test",
                last_rejection: None,
            };
            active.record_solicitation(peer.node_address.as_str(), Some(peer.session_id));
            service.active_requests.insert(11, active);
            let bytes = vec![255; synergy_sync::CANDIDATE_CHUNK_BYTES + 1];
            let wire = |offset| {
                serde_json::to_vec(&SyncWireMessage::FinalizedCandidateChunk(
                    CandidateResponseChunk {
                        request: request.clone(),
                        total_bytes: bytes.len(),
                        digest: synergy_sync::candidate_response_digest(&bytes),
                        offset,
                        bytes: bytes[offset
                            ..(offset + synergy_sync::CANDIDATE_CHUNK_BYTES).min(bytes.len())]
                            .to_vec(),
                    },
                ))
                .unwrap()
            };
            let first = wire(0);
            let tail = wire(synergy_sync::CANDIDATE_CHUNK_BYTES);
            let budget = Arc::clone(service.ingress.world_budget());
            let (release, wait) = std::sync::mpsc::channel();
            let mut pressure = None;
            if resource_blocked {
                // A later already-decoded completion must remain in its existing
                // mailbox while the oldest raw input cannot acquire its budget.
                let decoded_tail = synergy_sync::decode_budgeted_sync_wire(&tail, &budget).unwrap();
                pressure = Some(budget.reserve(budget.limit() - budget.used()).unwrap());
                service.receive_sync(peer.clone(), first).unwrap();
                let owner = service.preparation.as_ref().unwrap();
                let tail_peer = peer.clone();
                owner
                    .submit(
                        preparation::Lane::Background,
                        10,
                        0,
                        10,
                        "tail".into(),
                        65536,
                        move || {
                            Ok(PreparedSync::Wire {
                                peer: tail_peer,
                                message: Box::new(decoded_tail),
                                snapshot_verified: false,
                            })
                        },
                    )
                    .unwrap();
                service.preparation_pending += 1;
            } else {
                let charge = preparation_charge(&first, first.capacity()).unwrap();
                blocker
                    .submit(
                        preparation::Lane::Background,
                        10,
                        0,
                        10,
                        "blocker".into(),
                        BACKGROUND_MAILBOX_BYTES - charge - 1,
                        move || {
                            wait.recv_timeout(Duration::from_secs(5))
                                .map_err(|e| e.to_string())
                        },
                    )
                    .unwrap();
                service.receive_sync(peer.clone(), first).unwrap();
                service.receive_sync(peer.clone(), tail).unwrap();
                assert!(service.deferred_wire.is_some());
                service.drain_ordered_wire().unwrap();
                assert!(service.candidate_assemblies.is_empty());
                release.send(()).unwrap();
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            if resource_blocked {
                while service.resource_pending.is_empty() {
                    service.drain_preparation().unwrap();
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(1));
                }
                service.drain_ordered_wire().unwrap();
                assert_eq!(service.preparation_pending, 1);
                assert!(service.candidate_assemblies.is_empty());
                drop(pressure.take());
            }
            while !service.completed_candidates.contains_key(&11) {
                service.drain_ordered_wire().unwrap();
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
            let completed = service.completed_candidates.remove(&11).unwrap();
            let CompletedCandidatePayload::Raw(actual) = completed.payload else {
                panic!("expected exact raw response")
            };
            assert_eq!(actual, bytes);
            assert_eq!(service.preparation_pending, 0);
            assert!(service.deferred_wire.is_none());
            assert!(service.resource_pending.is_empty());
            assert!(service.candidate_assemblies.is_empty());
            service.stop().unwrap();
            pool.shutdown().unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn raw_candidate_chunks_survive_background_pressure_without_copy_or_loss() {
        let mut pool = preparation::Pool::new().unwrap();
        let tag = preparation::AuthorityTag {
            incarnation: "raw-sync-pressure".into(),
            epoch: 1,
            authority_digest: "authority".into(),
        };
        let heads = pool.handle().owner::<()>(tag.clone()).unwrap();
        let wire = pool
            .handle()
            .owner::<synergy_sync::SyncWireMessage<synergy_state::WorldState>>(tag)
            .unwrap();
        let (release, wait) = std::sync::mpsc::channel();
        heads
            .submit(
                preparation::Lane::Background,
                10870,
                0,
                10870,
                "heads".into(),
                BACKGROUND_MAILBOX_BYTES,
                move || {
                    wait.recv_timeout(Duration::from_secs(10))
                        .map_err(|e| e.to_string())
                },
            )
            .unwrap();
        let ingress = AuthenticatedIngress::default();
        let peer = AuthenticatedPeer::new(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            synergy_protocol_types::SessionId(1),
            vec![],
        )
        .unwrap();
        ingress
            .admit_session(peer.node_address.to_string(), peer.session_id)
            .unwrap();
        let bytes = vec![7; 474383];
        let request = FinalizedCandidateRequest {
            height: 10871,
            expected_parent_id: "committed-10870".into(),
        };
        let mut assemblies = BTreeMap::new();
        let mut completed = None;
        let mut received = 0;
        for (index, part) in bytes
            .chunks(synergy_sync::CANDIDATE_CHUNK_BYTES)
            .enumerate()
        {
            let chunk = CandidateResponseChunk {
                request: request.clone(),
                total_bytes: bytes.len(),
                digest: synergy_sync::candidate_response_digest(&bytes),
                offset: index * synergy_sync::CANDIDATE_CHUNK_BYTES,
                bytes: part.to_vec(),
            };
            let payload = serde_json::to_vec(&synergy_sync::SyncWireMessage::<
                synergy_state::WorldState,
            >::FinalizedCandidateChunk(chunk))
            .unwrap();
            let address = payload.as_ptr();
            let charge = preparation_charge(&payload, payload.capacity()).unwrap();
            let (retained_peer, retained) = retain_sync_wire_on_backpressure(
                &wire,
                10870,
                peer.clone(),
                payload,
                "chunk".into(),
                charge,
                |_, bytes| serde_json::from_slice(bytes).map_err(|e| e.to_string()),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                retained.as_ptr(),
                address,
                "backpressure must retain the original allocation"
            );
            assert!(ingress.is_current_session(&retained_peer).unwrap());
            let synergy_sync::SyncWireMessage::<synergy_state::WorldState>::FinalizedCandidateChunk(
                chunk,
            ) = serde_json::from_slice(&retained).unwrap()
            else {
                panic!("wrong frame");
            };
            let (_, ready) = push_candidate_chunk(&mut assemblies, &retained_peer, chunk).unwrap();
            if ready.is_some() {
                assert!(completed.is_none());
                completed = ready;
            }
            received += 1;
        }
        assert_eq!(received, 8);
        assert_eq!(completed, Some(bytes));
        assert!(assemblies.is_empty());
        assert!(wire.take().unwrap().is_none());
        // A returned raw frame still has to pass the normal current-session
        // check; worker pressure cannot give an old peer generation authority.
        let payload =
            serde_json::to_vec(&synergy_sync::SyncWireMessage::<synergy_state::WorldState>::FinalizedCandidateRequestV2(request)).unwrap();
        let charge = preparation_charge(&payload, payload.capacity()).unwrap();
        let (retained_peer, _) = retain_sync_wire_on_backpressure(
            &wire,
            10870,
            peer.clone(),
            payload,
            "old-session".into(),
            charge,
            |_, bytes| serde_json::from_slice(bytes).map_err(|e| e.to_string()),
        )
        .unwrap()
        .unwrap();
        ingress
            .admit_session(
                peer.node_address.to_string(),
                synergy_protocol_types::SessionId(2),
            )
            .unwrap();
        assert!(!ingress.is_current_session(&retained_peer).unwrap());
        release.send(()).unwrap();
        pool.shutdown().unwrap();
    }

    #[test]
    fn completed_474383_byte_candidate_survives_competing_head_claims_and_forwards_once() {
        let ingress = AuthenticatedIngress::default();
        let peer = AuthenticatedPeer::new(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            synergy_protocol_types::SessionId(1),
            vec![],
        )
        .unwrap();
        ingress
            .admit_session(peer.node_address.to_string(), peer.session_id)
            .unwrap();
        let request = FinalizedCandidateRequest {
            height: 10871,
            expected_parent_id: "committed-10870".into(),
        };
        let material = synergy_etdag::execution::ProtectedProposalMaterial {
            material_version: 2,
            height: request.height,
            execution_root: synergy_etdag::EtdagDigest::from_domain_bytes(
                "test-execution",
                b"execution",
            ),
            next_batch_root: synergy_etdag::EtdagDigest::from_domain_bytes("test-next", b"next"),
            cutoff_boundary_root: synergy_etdag::EtdagDigest::from_domain_bytes("test-cut", b"cut"),
        };
        let state = synergy_state::WorldState::default();
        let mut candidate = synergy_execution::ExecutionCandidate {
            resource_permit: None,
            height: request.height,
            block_id: String::new(),
            parent_block_id: request.expected_parent_id.clone(),
            protected_execution_root: synergy_block::hash_block_bytes(
                &material.commitment_bytes().unwrap(),
            ),
            protected_material: material.into(),
            state_root: synergy_state::state_root(&state).unwrap(),
            transactions: vec![],
            receipts: vec![],
            state: std::sync::Arc::new(state),
        };
        candidate.block_id = candidate.commitment_id().unwrap();
        candidate.validate().unwrap();
        // The transport test forwards an unverified witness; only the PoSy
        // owner can authenticate it and grant finality in separate qualifications.
        let response = FinalizedCandidateResponse::decode_test(
            &synergy_sync::FinalizedCandidateResponse {
                request: request.clone(),
                candidate,
                finality_witness: vec![1],
                processing_replay: None,
            },
            &ingress,
        );
        let mut bytes = serde_json::to_vec(&response).unwrap();
        bytes.resize(474383, b' ');
        let charge = preparation_charge(&bytes, bytes.capacity()).unwrap();
        assert!(charge <= BACKGROUND_MAILBOX_BYTES);
        let mut pool = preparation::Pool::new().unwrap();
        let head_owner = pool
            .handle()
            .owner::<()>(preparation::AuthorityTag {
                incarnation: "test-sync-pressure".into(),
                epoch: 1,
                authority_digest: "test-authority".into(),
            })
            .unwrap();
        let (release, wait) = std::sync::mpsc::channel();
        head_owner
            .submit(
                preparation::Lane::Background,
                10870,
                0,
                10870,
                "head-claim".into(),
                BACKGROUND_MAILBOX_BYTES - charge + 1,
                move || {
                    wait.recv_timeout(Duration::from_secs(10))
                        .map_err(|e| e.to_string())
                },
            )
            .unwrap();
        assert_eq!(
            head_owner
                .submit(
                    preparation::Lane::Background,
                    10871,
                    0,
                    10871,
                    "completed-candidate".into(),
                    charge,
                    || Ok(()),
                )
                .unwrap_err(),
            "preparation backpressure",
        );
        let active = ActiveCandidateRequest {
            request: request.clone(),
            peer_id: peer.node_address.to_string(),
            attempted: BTreeSet::from([peer.node_address.to_string()]),
            solicited: VecDeque::new(),
            sent_at: Instant::now(),
            requested_at: Instant::now(),
            diagnostic_at: Instant::now(),
            observed_chunks: 0,
            observed_bytes: 0,
            last_rx_session: None,
            last_boundary: "test-request",
            last_rejection: None,
        };
        let digest = synergy_sync::candidate_response_digest(&bytes);
        let mut assemblies = BTreeMap::new();
        let mut completed = BTreeMap::new();
        for (index, part) in bytes
            .chunks(synergy_sync::CANDIDATE_CHUNK_BYTES)
            .enumerate()
        {
            let chunk = CandidateResponseChunk {
                request: request.clone(),
                total_bytes: bytes.len(),
                digest,
                offset: index * synergy_sync::CANDIDATE_CHUNK_BYTES,
                bytes: part.to_vec(),
            };
            assert!(candidate_window_has_capacity(
                &assemblies,
                &completed,
                request.height,
                bytes.len()
            ));
            if let Some(bytes) = push_candidate_chunk(&mut assemblies, &peer, chunk)
                .unwrap()
                .1
            {
                completed.insert(
                    request.height,
                    CompletedCandidate {
                        peer: peer.clone(),
                        request: request.clone(),
                        digest,
                        payload: CompletedCandidatePayload::Raw(bytes),
                    },
                );
            }
        }
        assert!(assemblies.is_empty());
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[&request.height].bytes(), 474383);
        assert!(!candidate_window_has_capacity(
            &assemblies,
            &completed,
            request.height + 1,
            synergy_sync::MAX_CANDIDATE_RESPONSE_BYTES,
        ));
        let raw = completed.remove(&request.height).unwrap();
        let used = ingress.world_budget().used();
        let pressure = ingress
            .world_budget()
            .reserve(ingress.world_budget().available())
            .unwrap();
        let raw = match raw.try_into_response(Some(&active), &ingress).unwrap() {
            Err(retained) => retained,
            Ok(_) => panic!("local pressure must retain the raw candidate"),
        };
        assert_eq!(raw.bytes(), 474383);
        let CompletedCandidatePayload::Raw(ref original) = raw.payload else {
            panic!("raw bytes lost");
        };
        assert_eq!(synergy_sync::candidate_response_digest(original), digest);
        assert_eq!(ingress.world_budget().used(), used + pressure.bytes());
        drop(pressure);
        assert_eq!(ingress.world_budget().used(), used);
        let ready = raw
            .try_into_response(Some(&active), &ingress)
            .unwrap()
            .ok()
            .expect("capacity release must unblock the same bytes")
            .unwrap();
        ingress
            .submit_sync_candidate_response(ready.0, ready.1)
            .unwrap();
        assert_eq!(
            ingress.take_sync_candidate_response().unwrap().unwrap().1,
            response
        );
        assert!(ingress.take_sync_candidate_response().unwrap().is_none());
        assert!(completed.remove(&request.height).is_none());

        for _ in 0..4 {
            assert!(matches!(
                ingress
                    .try_submit_sync_candidate_response(peer.clone(), response.clone())
                    .unwrap(),
                super::super::ingress::CandidateResponseHandoff::Queued,
            ));
        }
        let full = ingress
            .try_submit_sync_candidate_response(peer.clone(), response.clone())
            .unwrap();
        let (retained_peer, retained_response) = match full {
            super::super::ingress::CandidateResponseHandoff::Full(retained) => *retained,
            _ => panic!("full handoff must return the owned response"),
        };
        let charge = super::super::ingress::candidate_response_memory(&retained_response).unwrap();
        completed.insert(
            request.height,
            CompletedCandidate {
                peer: retained_peer,
                request: request.clone(),
                digest,
                payload: CompletedCandidatePayload::Decoded(Box::new(retained_response), charge),
            },
        );
        assert_eq!(completed[&request.height].bytes(), charge);
        assert!(matches!(
            &completed[&request.height].payload,
            CompletedCandidatePayload::Decoded(_, _)
        ));
        ingress.take_sync_candidate_response().unwrap().unwrap();
        let pending = completed
            .remove(&request.height)
            .unwrap()
            .try_into_response(Some(&active), &ingress)
            .unwrap()
            .ok()
            .expect("sufficient World capacity")
            .unwrap();
        assert!(matches!(
            ingress
                .try_submit_sync_candidate_response(pending.0, pending.1)
                .unwrap(),
            super::super::ingress::CandidateResponseHandoff::Queued,
        ));
        for _ in 0..4 {
            assert_eq!(
                ingress.take_sync_candidate_response().unwrap().unwrap().1,
                response
            );
        }
        assert!(ingress.take_sync_candidate_response().unwrap().is_none());
        assert!(completed.is_empty());

        let stale = CompletedCandidate {
            peer: peer.clone(),
            request: request.clone(),
            digest,
            payload: CompletedCandidatePayload::Raw(bytes.clone()),
        };
        ingress
            .admit_session(
                peer.node_address.to_string(),
                synergy_protocol_types::SessionId(2),
            )
            .unwrap();
        assert!(stale
            .try_into_response(Some(&active), &ingress)
            .unwrap()
            .ok()
            .expect("sufficient World capacity")
            .is_none());
        assert!(ingress.take_sync_candidate_response().unwrap().is_none());
        for height in request.height..request.height + MAX_CANDIDATE_WINDOW as u64 {
            completed.insert(
                height,
                CompletedCandidate {
                    peer: peer.clone(),
                    request: FinalizedCandidateRequest {
                        height,
                        ..request.clone()
                    },
                    digest,
                    payload: CompletedCandidatePayload::Raw(bytes.clone()),
                },
            );
        }
        assert!(!candidate_window_has_capacity(
            &assemblies,
            &completed,
            request.height + MAX_CANDIDATE_WINDOW as u64,
            bytes.len(),
        ));
        release.send(()).unwrap();
        pool.shutdown().unwrap();
    }

    #[test]
    fn interleaved_candidate_chunks_preserve_prefetch_and_session_bounds() {
        let peer = AuthenticatedPeer::new(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            synergy_protocol_types::SessionId(1),
            vec![],
        )
        .unwrap();
        let bytes = vec![7; synergy_sync::CANDIDATE_CHUNK_BYTES + 9];
        let part = |height, offset| CandidateResponseChunk {
            request: FinalizedCandidateRequest {
                height,
                expected_parent_id: format!("parent-{height}"),
            },
            total_bytes: bytes.len(),
            digest: synergy_sync::candidate_response_digest(&bytes),
            offset,
            bytes: bytes[offset..(offset + synergy_sync::CANDIDATE_CHUNK_BYTES).min(bytes.len())]
                .to_vec(),
        };
        // The old single assembly cannot accept the second height's first
        // chunk, so its last chunk cannot complete that response.
        let mut old = CandidateResponseAssembly::new(&part(10, 0)).unwrap();
        old.push(part(10, 0)).unwrap();
        assert!(old.push(part(11, 0)).is_err());
        let mut window = BTreeMap::new();
        for height in 10..14 {
            assert!(push_candidate_chunk(&mut window, &peer, part(height, 0))
                .unwrap()
                .1
                .is_none());
        }
        assert_eq!(window.len(), MAX_CANDIDATE_WINDOW);
        assert!(push_candidate_chunk(&mut window, &peer, part(14, 0)).is_err());
        let mut replaced = peer.clone();
        replaced.session_id = synergy_protocol_types::SessionId(2);
        assert!(push_candidate_chunk(
            &mut window,
            &replaced,
            part(10, synergy_sync::CANDIDATE_CHUNK_BYTES)
        )
        .is_err());
        assert_eq!(window.len(), MAX_CANDIDATE_WINDOW);
        for height in (10..14).rev() {
            assert_eq!(
                push_candidate_chunk(
                    &mut window,
                    &peer,
                    part(height, synergy_sync::CANDIDATE_CHUNK_BYTES)
                )
                .unwrap()
                .1,
                Some(bytes.clone())
            );
        }
        assert!(window.is_empty());
        let mut huge = part(10, 0);
        huge.total_bytes = synergy_sync::MAX_CANDIDATE_RESPONSE_BYTES;
        push_candidate_chunk(&mut window, &peer, huge).unwrap();
        assert!(push_candidate_chunk(&mut window, &peer, part(11, 0)).is_err());
        assert_eq!(window.len(), 1);
    }

    #[test]
    fn candidate_chunk_frame_remains_below_network_limit_at_maximum_raw_chunk() {
        let chunk = CandidateResponseChunk {
            request: FinalizedCandidateRequest {
                height: u64::MAX,
                expected_parent_id: "x".repeat(256),
            },
            total_bytes: synergy_sync::MAX_CANDIDATE_RESPONSE_BYTES,
            digest: [255; 32],
            offset: 0,
            bytes: vec![255; synergy_sync::CANDIDATE_CHUNK_BYTES],
        };
        chunk.validate().unwrap();
        let bytes = serde_json::to_vec(
            &synergy_sync::SyncWireMessage::<synergy_state::WorldState>::FinalizedCandidateChunk(
                chunk.clone(),
            ),
        )
        .unwrap();
        assert!(bytes.len() < synergy_network::protocol::DEFAULT_MAX_FRAME_BYTES);
        assert_eq!(
            serde_json::from_slice::<synergy_sync::SyncWireMessage<synergy_state::WorldState>>(
                &bytes
            )
            .unwrap(),
            synergy_sync::SyncWireMessage::<synergy_state::WorldState>::FinalizedCandidateChunk(
                chunk
            )
        );
        let legacy =
            synergy_sync::SyncWireMessage::<synergy_state::WorldState>::FinalizedCandidateRequest(
                FinalizedCandidateRequest {
                    height: 7,
                    expected_parent_id: "six".into(),
                },
            );
        let v2 =
            synergy_sync::SyncWireMessage::<synergy_state::WorldState>::FinalizedCandidateRequestV2(
                FinalizedCandidateRequest {
                    height: 7,
                    expected_parent_id: "six".into(),
                },
            );
        assert_ne!(
            serde_json::to_vec(&legacy).unwrap(),
            serde_json::to_vec(&v2).unwrap()
        );
    }

    #[test]
    fn native_candidate_wait_preserves_missing_payload_and_bounded_recovery_fallback() {
        let now = Instant::now();
        let mut waiting = None;
        assert_eq!(
            native_candidate_prefix_wait(&mut waiting, 10, None, now),
            None
        );
        assert!(waiting.is_none());
        assert_eq!(
            native_candidate_prefix_wait(&mut waiting, 10, Some(10), now),
            None
        );
        assert_eq!(
            native_candidate_prefix_wait(&mut waiting, 10, Some(12), now),
            Some(12)
        );
        // A moving certified tip cannot indefinitely defer a stuck durable commit.
        assert_eq!(
            native_candidate_prefix_wait(
                &mut waiting,
                10,
                Some(15),
                now + CANDIDATE_RESPONSE_TIMEOUT
            ),
            None
        );
        assert_eq!(
            native_candidate_prefix_wait(
                &mut waiting,
                10,
                Some(16),
                now + CANDIDATE_RESPONSE_TIMEOUT + Duration::from_secs(1)
            ),
            None
        );
        // Only durable progress starts a new bounded wait for the new successor.
        assert_eq!(
            native_candidate_prefix_wait(
                &mut waiting,
                11,
                Some(16),
                now + CANDIDATE_RESPONSE_TIMEOUT
            ),
            Some(16)
        );
        assert_eq!(
            native_candidate_prefix_wait(&mut waiting, 11, None, now + CANDIDATE_RESPONSE_TIMEOUT),
            None
        );
        assert!(waiting.is_none());
        // Restart has no retained hint and missing payload recovery is immediate.
        let mut restarted = None;
        assert_eq!(
            native_candidate_prefix_wait(&mut restarted, 11, None, now),
            None
        );
    }

    #[test]
    fn native_candidate_wait_skips_only_locally_replayed_bounded_prefix() {
        let now = Instant::now();
        let mut waiting = None;
        let prefix = native_candidate_prefix_wait(&mut waiting, 10, Some(12), now).unwrap();
        let occupied = (11..=prefix).collect();
        let next = next_candidate_prefetch(10, "committed-10", 20, &occupied, |height| {
            Ok(Some(format!("verified-{height}")))
        })
        .unwrap()
        .unwrap();
        assert_eq!(next.height, 13);
        assert_eq!(next.expected_parent_id, "verified-12");
        assert!(
            next_candidate_prefetch(10, "committed-10", 12, &occupied, |_| panic!(
                "locally replayed prefix needs no fetch"
            ))
            .unwrap()
            .is_none()
        );
        // Fallback requests the exact durable successor, not a skipped height.
        assert!(native_candidate_prefix_wait(
            &mut waiting,
            10,
            Some(12),
            now + CANDIDATE_RESPONSE_TIMEOUT
        )
        .is_none());
        let fallback = next_candidate_prefetch(10, "committed-10", 20, &BTreeSet::new(), |_| {
            panic!("strict successor uses durable parent")
        })
        .unwrap()
        .unwrap();
        assert_eq!(fallback.height, 11);
        assert_eq!(fallback.expected_parent_id, "committed-10");
    }

    #[test]
    fn candidate_prefetch_is_bounded_and_requires_verified_parent_for_every_future_height() {
        let mut occupied = BTreeSet::new();
        let first = next_candidate_prefetch(10, "committed-10", 100, &occupied, |_| {
            panic!("strict-next request must use durable execution parent")
        })
        .unwrap()
        .unwrap();
        assert_eq!(first.height, 11);
        assert_eq!(first.expected_parent_id, "committed-10");
        occupied.insert(first.height);
        assert!(
            next_candidate_prefetch(10, "committed-10", 100, &occupied, |_| Ok(None))
                .unwrap()
                .is_none()
        );
        for expected_height in 12..=14 {
            let request = next_candidate_prefetch(10, "committed-10", 100, &occupied, |parent| {
                Ok(Some(format!("verified-{parent}")))
            })
            .unwrap()
            .unwrap();
            assert_eq!(request.height, expected_height);
            assert_eq!(
                request.expected_parent_id,
                format!("verified-{}", expected_height - 1)
            );
            occupied.insert(request.height);
        }
        assert!(
            next_candidate_prefetch(10, "committed-10", 100, &occupied, |_| panic!(
                "full window"
            ))
            .unwrap()
            .is_none()
        );
        // Response receipt alone still occupies its height until durable commit.
        assert_eq!(occupied.len(), MAX_CANDIDATE_WINDOW);
        occupied.remove(&11);
        let next = next_candidate_prefetch(11, "committed-11", 15, &occupied, |parent| {
            assert_eq!(parent, 14);
            Ok(Some("verified-14".into()))
        })
        .unwrap()
        .unwrap();
        assert_eq!(next.height, 15);
        assert!(
            next_candidate_prefetch(11, "committed-11", 14, &occupied, |_| panic!(
                "target reached"
            ))
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn late_candidate_chunks_use_only_solicited_current_sessions_without_splicing() {
        let ingress = AuthenticatedIngress::default();
        let peer = |seed: u8, session| {
            AuthenticatedPeer::new(
                synergy_address::generate_class_based_address(&[seed; 1793], 1).unwrap(),
                SessionId(session),
                vec![],
            )
            .unwrap()
        };
        let a = peer(1, 1);
        let b = peer(2, 2);
        let unsolicited = peer(3, 3);
        for peer in [&a, &b, &unsolicited] {
            ingress
                .admit_session(peer.node_address.to_string(), peer.session_id)
                .unwrap();
        }
        let request = FinalizedCandidateRequest {
            height: 11,
            expected_parent_id: "committed-10".into(),
        };
        let mut active = ActiveCandidateRequest {
            request: request.clone(),
            peer_id: a.node_address.to_string(),
            attempted: BTreeSet::from([a.node_address.to_string()]),
            solicited: VecDeque::new(),
            sent_at: Instant::now() - CANDIDATE_RESPONSE_TIMEOUT,
            requested_at: Instant::now(),
            diagnostic_at: Instant::now(),
            observed_chunks: 0,
            observed_bytes: 0,
            last_rx_session: None,
            last_boundary: "test-request",
            last_rejection: None,
        };
        active.record_solicitation(a.node_address.as_str(), Some(a.session_id));
        active.peer_id = b.node_address.to_string();
        active.record_solicitation(b.node_address.as_str(), Some(b.session_id));
        let size = synergy_sync::CANDIDATE_CHUNK_BYTES;
        let bytes = vec![7; size + 1];
        let chunk = |offset| CandidateResponseChunk {
            request: request.clone(),
            total_bytes: bytes.len(),
            digest: synergy_sync::candidate_response_digest(&bytes),
            offset,
            bytes: bytes[offset..(offset + size).min(bytes.len())].to_vec(),
        };
        let mut assemblies = BTreeMap::new();
        let mut wrong = request.clone();
        wrong.expected_parent_id = "wrong-parent".into();
        assert!(!active.permits_chunk(&a, &wrong));
        assert!(!active.permits_chunk(&unsolicited, &request));

        // A residual tail from A cannot claim the empty slot after retry B.
        assert!(push_candidate_chunk(&mut assemblies, &a, chunk(size)).is_err());
        assert!(assemblies.is_empty());
        assert_eq!(
            push_candidate_chunk(&mut assemblies, &b, chunk(0)).unwrap(),
            (true, None)
        );
        assert!(push_candidate_chunk(&mut assemblies, &a, chunk(size)).is_err());
        assert_eq!(
            push_candidate_chunk(&mut assemblies, &b, chunk(size)).unwrap(),
            (true, Some(bytes.clone()))
        );
        // A legitimately reordered initial tail can complete on retransmission:
        // no rejected tail advances timers or allocates an assembly.
        assert!(push_candidate_chunk(&mut assemblies, &a, chunk(size)).is_err());
        assert!(assemblies.is_empty());
        assert!(active.permits_chunk(&a, &request));
        assert_eq!(
            push_candidate_chunk(&mut assemblies, &a, chunk(0)).unwrap(),
            (true, None)
        );
        assert!(active.permits_chunk(&b, &request));
        assert!(push_candidate_chunk(&mut assemblies, &b, chunk(size)).is_err());
        assert_eq!(
            push_candidate_chunk(&mut assemblies, &a, chunk(size)).unwrap(),
            (true, Some(bytes.clone()))
        );

        // Reordering after the initial chunk remains supported, and duplicates
        // do not count as progress or extend the unchanged timeout.
        let reordered_bytes = vec![9; size * 2 + 1];
        let reordered = |offset| CandidateResponseChunk {
            request: request.clone(),
            total_bytes: reordered_bytes.len(),
            digest: synergy_sync::candidate_response_digest(&reordered_bytes),
            offset,
            bytes: reordered_bytes[offset..(offset + size).min(reordered_bytes.len())].to_vec(),
        };
        assert_eq!(
            push_candidate_chunk(&mut assemblies, &a, reordered(0)).unwrap(),
            (true, None)
        );
        assert_eq!(
            push_candidate_chunk(&mut assemblies, &a, reordered(size * 2)).unwrap(),
            (true, None)
        );
        assert_eq!(
            push_candidate_chunk(&mut assemblies, &a, reordered(size * 2)).unwrap(),
            (false, None)
        );
        assert_eq!(
            push_candidate_chunk(&mut assemblies, &a, reordered(size)).unwrap(),
            (true, Some(reordered_bytes.clone()))
        );

        let replacement = peer(2, 4);
        ingress
            .admit_session(replacement.node_address.to_string(), replacement.session_id)
            .unwrap();
        assert!(!ingress.is_current_session(&b).unwrap());
        assert!(ingress.is_current_session(&replacement).unwrap());
        assert!(!active.permits_chunk(&replacement, &request));

        for i in 0..MAX_CANDIDATE_SOLICITATIONS {
            active.record_solicitation(&format!("solicited-{i}"), Some(SessionId(1)));
        }
        assert_eq!(active.solicited.len(), MAX_CANDIDATE_SOLICITATIONS);
        assert!(!active.permits_chunk(&a, &request));
    }

    #[test]
    fn candidate_prefetch_rejects_wrong_request_peer_parent_and_replaced_session() {
        let ingress = AuthenticatedIngress::default();
        let mut peer = AuthenticatedPeer::new(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            synergy_protocol_types::SessionId(1),
            vec![],
        )
        .unwrap();
        ingress
            .admit_session(peer.node_address.to_string(), peer.session_id)
            .unwrap();
        let request = FinalizedCandidateRequest {
            height: 11,
            expected_parent_id: "committed-10".into(),
        };
        let accepted = |expected_peer: &str,
                        received: &FinalizedCandidateRequest,
                        height,
                        parent: &str,
                        peer: &AuthenticatedPeer| {
            candidate_response_matches(
                &request,
                expected_peer,
                peer,
                ingress.is_current_session(peer).unwrap(),
                received,
                height,
                parent,
            )
        };
        assert!(accepted(
            peer.node_address.as_str(),
            &request,
            11,
            "committed-10",
            &peer
        ));
        assert!(!accepted(
            "other-source",
            &request,
            11,
            "committed-10",
            &peer
        ));
        assert!(!accepted(
            peer.node_address.as_str(),
            &request,
            12,
            "committed-10",
            &peer
        ));
        assert!(!accepted(
            peer.node_address.as_str(),
            &request,
            11,
            "wrong-parent",
            &peer
        ));
        let wrong_request = FinalizedCandidateRequest {
            height: 12,
            ..request.clone()
        };
        assert!(!accepted(
            peer.node_address.as_str(),
            &wrong_request,
            11,
            "committed-10",
            &peer
        ));
        let wrong_parent_request = FinalizedCandidateRequest {
            expected_parent_id: "wrong-parent".into(),
            ..request.clone()
        };
        assert!(!accepted(
            peer.node_address.as_str(),
            &wrong_parent_request,
            11,
            "committed-10",
            &peer
        ));
        ingress
            .admit_session(
                peer.node_address.to_string(),
                synergy_protocol_types::SessionId(2),
            )
            .unwrap();
        assert!(!accepted(
            peer.node_address.as_str(),
            &request,
            11,
            "committed-10",
            &peer
        ));
        peer.session_id = synergy_protocol_types::SessionId(2);
        assert!(accepted(
            peer.node_address.as_str(),
            &request,
            11,
            "committed-10",
            &peer
        ));
    }

    #[test]
    fn candidate_prefetch_reopens_uncommitted_response_after_session_loss_or_timeout() {
        let ingress = AuthenticatedIngress::default();
        let peer = AuthenticatedPeer::new(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            synergy_protocol_types::SessionId(1),
            vec![],
        )
        .unwrap();
        ingress
            .admit_session(peer.node_address.to_string(), peer.session_id)
            .unwrap();
        let now = Instant::now();
        let mut awaiting = BTreeMap::from([(11, (peer.clone(), now))]);
        retain_candidate_commits(&mut awaiting, 10, now, &ingress).unwrap();
        assert_eq!(awaiting.len(), 1);
        ingress
            .admit_session(
                peer.node_address.to_string(),
                synergy_protocol_types::SessionId(2),
            )
            .unwrap();
        retain_candidate_commits(&mut awaiting, 10, now, &ingress).unwrap();
        assert!(awaiting.is_empty());
        let request = next_candidate_prefetch(
            10,
            "committed-10",
            20,
            &awaiting.keys().copied().collect(),
            |_| panic!("durable successor needs no speculative parent"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(request.height, 11);
        assert_eq!(request.expected_parent_id, "committed-10");
        let mut current = peer;
        current.session_id = synergy_protocol_types::SessionId(2);
        awaiting.insert(11, (current.clone(), now));
        retain_candidate_commits(
            &mut awaiting,
            10,
            now + CANDIDATE_RESPONSE_TIMEOUT,
            &ingress,
        )
        .unwrap();
        assert!(awaiting.is_empty());
        awaiting.insert(11, (current, now));
        retain_candidate_commits(&mut awaiting, 11, now, &ingress).unwrap();
        assert!(awaiting.is_empty());
    }

    #[test]
    fn candidate_prefetch_restart_resumes_only_exact_durable_successor() {
        let request = PersistedCandidateRequest {
            request: FinalizedCandidateRequest {
                height: 11,
                expected_parent_id: "committed-10".into(),
            },
            peer_id: "source".into(),
            attempted: BTreeSet::from(["source".into()]),
        };
        assert!(resumable_candidate_request(&request, 10, "committed-10"));
        assert!(!resumable_candidate_request(&request, 9, "committed-9"));
        assert!(!resumable_candidate_request(&request, 11, "committed-11"));
        assert!(!resumable_candidate_request(
            &request,
            10,
            "different-parent"
        ));
        let restored: PersistedCandidateRequest =
            serde_json::from_slice(&serde_json::to_vec(&request).unwrap()).unwrap();
        assert!(resumable_candidate_request(&restored, 10, "committed-10"));
    }

    #[test]
    fn queue_full_retains_exact_sync_request_until_capacity_returns() {
        let ingress = AuthenticatedIngress::default();
        for _ in 0..8 {
            ingress
                .publish_outbound(OutboundFrame {
                    peer_id: "busy".into(),
                    protocol: ProtocolKind::Sync,
                    payload: vec![0],
                })
                .unwrap();
        }
        let outbox = SyncOutbox::default();
        let payload = serde_json::to_vec(
            &synergy_sync::SyncWireMessage::<synergy_state::WorldState>::FinalizedCandidateRequest(
                FinalizedCandidateRequest {
                    height: 17,
                    expected_parent_id: "verified-parent".into(),
                },
            ),
        )
        .unwrap();
        let frame = OutboundFrame {
            peer_id: "verified-source".into(),
            protocol: ProtocolKind::Sync,
            payload: payload.clone(),
        };
        outbox.publish(&ingress, frame.clone()).unwrap();
        outbox.publish(&ingress, frame).unwrap();
        assert_eq!(outbox.0.borrow().len(), 1);
        assert!(!outbox.flush(&ingress).unwrap());
        for _ in 0..8 {
            assert_eq!(ingress.take_outbound().unwrap().unwrap().peer_id, "busy");
        }
        assert!(outbox.flush(&ingress).unwrap());
        let delivered = ingress.take_outbound().unwrap().unwrap();
        assert_eq!(delivered.peer_id, "verified-source");
        assert_eq!(delivered.payload, payload);
        assert!(!outbox.has_pending());
    }

    #[test]
    fn independently_signed_same_snapshot_keeps_primary_and_rejects_content_conflict() {
        use aegis_pqvm::pqc::signatures::mldsa::mldsa65;
        use pqrust_traits::sign::SecretKey as _;
        let root = std::env::temp_dir().join(format!(
            "sync-snapshot-proof-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = SnapshotChunkStore::new(&root).unwrap();
        let make = |key_name: &str, height: u64, payload: &[u8]| {
            let (_, secret) = mldsa65::keypair();
            let key_id = KeyId::new(key_name).unwrap();
            let signer = LocalSnapshotSigner {
                key_id: key_id.clone(),
                signer: PqvmSigner::from_secret_key_bytes(
                    AegisPolicy {
                        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                        maximum_message_bytes: 1024 * 1024,
                        maximum_signature_bytes: 16 * 1024,
                    },
                    key_id,
                    secret.as_bytes().to_vec(),
                )
                .unwrap(),
            };
            let (manifest, mut chunks) = build_snapshot(
                &AegisSha3_256,
                &signer,
                1266,
                "snapshot-test",
                1,
                height,
                &format!("block-{height}"),
                &format!("finality-{height}"),
                &"a".repeat(64),
                1024,
                payload,
            )
            .unwrap();
            SnapshotChunkResponse {
                request: SnapshotChunkRequest {
                    epoch: 1,
                    height,
                    finalized_block_id: manifest.finalized_block_id.clone(),
                    finality_evidence_id: manifest.finality_evidence_id.clone(),
                    expected_snapshot_root: Some(manifest.state_root),
                    index: 0,
                },
                manifest,
                chunk: chunks.remove(0),
            }
        };
        let first = make("snapshot-a", 10, b"same canonical world");
        let variant = make("snapshot-b", 10, b"same canonical world");
        assert_ne!(first.manifest, variant.manifest);
        store.put(&first).unwrap();
        store.put(&variant).unwrap();
        assert_eq!(
            store.get(&first.request).unwrap().unwrap().manifest,
            first.manifest
        );
        assert_eq!(
            store.chunks(&variant.manifest).unwrap().unwrap()[0],
            first.chunk
        );
        let next = make("snapshot-c", 11, b"same canonical world");
        store.put(&next).unwrap();
        assert_eq!(
            store.get(&next.request).unwrap().unwrap().manifest,
            next.manifest
        );
        let conflict = make("snapshot-d", 10, b"different world");
        assert!(store
            .put(&conflict)
            .unwrap_err()
            .contains("conflicting snapshot content"));
        assert_eq!(
            store.get(&first.request).unwrap().unwrap().manifest,
            first.manifest
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exhausted_verified_candidate_sources_are_revisited_after_timeout() {
        let sources: Vec<_> = ["source-a", "source-b"]
            .into_iter()
            .map(|id| VerifiedHead {
                peer_id: id.into(),
                finalized_height: 17,
                finalized_hash: "verified-tip".into(),
                finality_evidence_id: "verified-finality".into(),
            })
            .collect();
        let attempted = BTreeSet::from(["source-a".into(), "source-b".into()]);
        assert_eq!(
            candidate_retry_source(&sources, &attempted),
            Some(("source-a".into(), true))
        );
        let revisited = BTreeSet::from(["source-a".into()]);
        assert_eq!(
            candidate_retry_source(&sources, &revisited),
            Some(("source-b".into(), false))
        );
        assert_eq!(candidate_retry_source(&[], &attempted), None);
    }
    #[test]
    fn background_mailbox_charge_accounts_for_capacity_and_decoded_output() {
        let bytes = vec![0_u8; 1024];
        assert_eq!(
            preparation_charge(&bytes, 2048),
            Some(2048 + 16 * 1024 + 64 * 1024)
        );
        assert!(preparation_charge(&bytes, BACKGROUND_MAILBOX_BYTES).is_none());
        assert!(preparation_charge(&bytes, usize::MAX).is_none());
    }

    #[test]
    fn native_large_candidate_keeps_existing_sync_owner_fallback() {
        let bytes = vec![0_u8; 1024 * 1024];
        assert!(preparation_charge(&bytes, bytes.capacity()).is_none());
        let small = vec![0_u8; 64 * 1024];
        assert!(preparation_charge(&small, small.capacity()).unwrap() <= BACKGROUND_MAILBOX_BYTES);
    }
}
