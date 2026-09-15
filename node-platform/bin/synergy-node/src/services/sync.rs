use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use synergy_aegis::{
    AegisPolicy, AegisSha3_256, AegisSigner, AegisVerifier, KeyId, PqvmSigner, PqvmVerifier,
    Signature, SignatureAlgorithm, SigningContext,
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
use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind};
use synergy_snapshot::{
    build_snapshot, restore_verified_snapshot, verify_snapshot_manifest, SnapshotChunk,
    SnapshotManifest, SnapshotRestoreSink, SnapshotSigningProvider, SnapshotVerificationProvider,
};
use synergy_storage::{AtomicStore, NodeStorageLayout};
use synergy_sync::{
    BlockRequest, EpochAuthorityRequest, EpochAuthorityResponse, FinalizedCandidateRequest,
    FinalizedCandidateResponse, HeadClaim, SnapshotChunkRequest, SnapshotChunkResponse,
    SyncManager, SyncMetrics, SyncPeerCandidate, SyncPhase, SyncStatus, SyncWireMessage,
    VerifiedHead, VerifiedHeadCollector,
};

use super::authority::{self, AuthorityTransitionSignal, VerifiedAuthority};

use super::ingress::{
    AuthenticatedIngress, OutboundFrame, SnapshotRestoreHandoff, SnapshotRestoreReceipt,
};

const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_MESSAGES_PER_POLL: usize = 64;
const SNAPSHOT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const CANDIDATE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const AUTHORITY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedCandidateRequest {
    request: FinalizedCandidateRequest,
    peer_id: String,
    attempted: BTreeSet<String>,
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

struct SnapshotChunkStore {
    store: AtomicStore,
}

fn state_root_hex(root: &synergy_crypto::Hash32) -> String {
    root.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl SnapshotChunkStore {
    fn new(root: impl AsRef<std::path::Path>) -> Result<Self, String> {
        Ok(Self {
            store: AtomicStore::new(root.as_ref(), 64 * 1024 * 1024)
                .map_err(|error| format!("open snapshot chunk store: {error}"))?,
        })
    }

    fn load_active(&self) -> Result<Option<PersistedSnapshotAcquisition>, String> {
        const PATH: &str = "active-snapshot-request.json";
        if !self.store.exists(PATH).map_err(|error| error.to_string())? {
            return Ok(None);
        }
        serde_json::from_slice::<Option<PersistedSnapshotAcquisition>>(
            &self
                .store
                .read_bounded(PATH)
                .map_err(|error| format!("read persisted snapshot request: {error}"))?,
        )
        .map_err(|error| format!("decode persisted snapshot request: {error}"))
    }

    fn save_active(&self, active: &PersistedSnapshotAcquisition) -> Result<(), String> {
        let bytes = serde_json::to_vec(active)
            .map_err(|error| format!("encode persisted snapshot request: {error}"))?;
        self.store
            .write_atomic("active-snapshot-request.json", &bytes)
            .map_err(|error| format!("persist snapshot request: {error}"))
    }

    fn clear_active(&self) -> Result<(), String> {
        self.store
            .write_atomic("active-snapshot-request.json", b"null")
            .map_err(|error| format!("clear persisted snapshot request: {error}"))
    }

    fn manifest_index_path(height: u64, finalized_block_id: &str) -> String {
        format!(
            "manifest-index/{height:020}-{}.json",
            synergy_block::hash_block_bytes(finalized_block_id.as_bytes())
        )
    }

    fn manifest_path(height: u64, state_root: &synergy_crypto::Hash32) -> String {
        format!("manifest/{height:020}-{}.json", state_root_hex(state_root))
    }

    fn chunk_path(height: u64, state_root: &synergy_crypto::Hash32, index: u64) -> String {
        format!(
            "chunk/{height:020}-{}-{index:020}.json",
            state_root_hex(state_root)
        )
    }

    fn put(&self, response: &SnapshotChunkResponse) -> Result<(), String> {
        response.validate()?;
        let manifest_path =
            Self::manifest_path(response.manifest.height, &response.manifest.state_root);
        let manifest_bytes = serde_json::to_vec(&response.manifest)
            .map_err(|error| format!("encode snapshot manifest: {error}"))?;
        if self
            .store
            .exists(&manifest_path)
            .map_err(|error| error.to_string())?
        {
            let existing = self
                .store
                .read_bounded(&manifest_path)
                .map_err(|error| format!("read stored snapshot manifest: {error}"))?;
            if existing != manifest_bytes {
                return Err("conflicting snapshot manifest for finalized state root".into());
            }
        } else {
            self.store
                .write_atomic(&manifest_path, &manifest_bytes)
                .map_err(|error| format!("persist snapshot manifest: {error}"))?;
        }
        self.store
            .write_atomic(
                Self::manifest_index_path(
                    response.manifest.height,
                    &response.manifest.finalized_block_id,
                ),
                &manifest_bytes,
            )
            .map_err(|error| format!("persist snapshot manifest index: {error}"))?;
        let path = Self::chunk_path(
            response.manifest.height,
            &response.manifest.state_root,
            response.chunk.index,
        );
        let bytes = serde_json::to_vec(&response.chunk)
            .map_err(|error| format!("encode snapshot chunk: {error}"))?;
        if self
            .store
            .exists(&path)
            .map_err(|error| error.to_string())?
        {
            let existing = self
                .store
                .read_bounded(&path)
                .map_err(|error| format!("read stored snapshot chunk: {error}"))?;
            if existing != bytes {
                return Err("conflicting snapshot chunk for finalized state root".into());
            }
            return Ok(());
        }
        self.store
            .write_atomic(path, &bytes)
            .map_err(|error| format!("persist snapshot chunk: {error}"))
    }

    fn get(&self, request: &SnapshotChunkRequest) -> Result<Option<SnapshotChunkResponse>, String> {
        if !request.validate() {
            return Err("invalid snapshot chunk request".into());
        }
        let manifest_bytes = if let Some(state_root) = request.expected_snapshot_root {
            let path = Self::manifest_path(request.height, &state_root);
            if !self
                .store
                .exists(&path)
                .map_err(|error| error.to_string())?
            {
                return Ok(None);
            }
            self.store
                .read_bounded(&path)
                .map_err(|error| format!("read snapshot manifest: {error}"))?
        } else {
            let path = Self::manifest_index_path(request.height, &request.finalized_block_id);
            if !self
                .store
                .exists(&path)
                .map_err(|error| error.to_string())?
            {
                return Ok(None);
            }
            self.store
                .read_bounded(&path)
                .map_err(|error| format!("read snapshot manifest index: {error}"))?
        };
        let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| format!("decode snapshot manifest: {error}"))?;
        if manifest.epoch != request.epoch
            || manifest.height != request.height
            || manifest.finalized_block_id != request.finalized_block_id
            || manifest.finality_evidence_id != request.finality_evidence_id
            || request
                .expected_snapshot_root
                .is_some_and(|root| root != manifest.state_root)
        {
            return Ok(None);
        }
        let path = Self::chunk_path(request.height, &manifest.state_root, request.index);
        if !self
            .store
            .exists(&path)
            .map_err(|error| error.to_string())?
        {
            return Ok(None);
        }
        let chunk: SnapshotChunk = serde_json::from_slice(
            &self
                .store
                .read_bounded(&path)
                .map_err(|error| format!("read snapshot chunk: {error}"))?,
        )
        .map_err(|error| format!("decode snapshot chunk: {error}"))?;
        let response = SnapshotChunkResponse {
            request: request.clone(),
            manifest,
            chunk,
        };
        response.validate()?;
        Ok(Some(response))
    }

    fn chunks(&self, manifest: &SnapshotManifest) -> Result<Option<Vec<SnapshotChunk>>, String> {
        let mut chunks = Vec::with_capacity(manifest.chunk_hashes.len());
        for index in 0..manifest.chunk_hashes.len() as u64 {
            let path = Self::chunk_path(manifest.height, &manifest.state_root, index);
            if !self
                .store
                .exists(&path)
                .map_err(|error| error.to_string())?
            {
                return Ok(None);
            }
            let chunk = serde_json::from_slice::<SnapshotChunk>(
                &self
                    .store
                    .read_bounded(&path)
                    .map_err(|error| format!("read staged snapshot chunk: {error}"))?,
            )
            .map_err(|error| format!("decode staged snapshot chunk: {error}"))?;
            chunks.push(chunk);
        }
        Ok(Some(chunks))
    }
}

impl SnapshotVerificationProvider for VerifiedAuthority {
    fn governed_public_key(&self, key_id: &KeyId) -> Result<Vec<u8>, String> {
        ProofVerifier::governed_public_key(self, key_id)
    }
}

struct IngressSnapshotRestoreSink<'a> {
    ingress: &'a AuthenticatedIngress,
    manifest: &'a SnapshotManifest,
    staged: Option<synergy_state::WorldState>,
}

impl SnapshotRestoreSink for IngressSnapshotRestoreSink<'_> {
    fn stage(&mut self, height: u64, state: &[u8]) -> Result<(), String> {
        if height != self.manifest.height {
            return Err("snapshot restore height differs from verified manifest".into());
        }
        let world_state: synergy_state::WorldState = serde_json::from_slice(state)
            .map_err(|error| format!("decode verified snapshot world state: {error}"))?;
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
                state,
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

pub fn registration(
    configuration: &NodeConfiguration,
    authority: Option<Arc<VerifiedAuthority>>,
    authority_transition: AuthorityTransitionSignal,
    ingress: AuthenticatedIngress,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    let manifest = load_manifest(configuration)?;
    let local_peer_id = load_local_peer_id(configuration)?;
    let local_parent_id = authority
        .as_ref()
        .map(|authority| authority.anchor_parent.block_id().to_string())
        .unwrap_or_else(|| manifest.genesis_hash.clone());
    let manager = SyncManager::new(manifest.genesis_hash.clone());
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    let request_store = SyncRequestStore::new(layout.metadata().join("sync"))?;
    let snapshot_store = SnapshotChunkStore::new(layout.state().join("snapshots"))?;
    let active_request = request_store
        .load()?
        .map(|persisted| ActiveCandidateRequest {
            request: persisted.request,
            peer_id: persisted.peer_id,
            attempted: persisted.attempted,
            sent_at: Instant::now(),
        });
    let snapshot_signer = load_snapshot_signer(configuration, authority.as_deref())?;
    let active_snapshot = match snapshot_store.load_active()? {
        Some(persisted) => {
            let verifier = authority
                .as_ref()
                .ok_or("persisted snapshot acquisition requires frozen authority")?;
            validate_persisted_snapshot(&persisted, &manifest, verifier)?;
            if let Some(snapshot) = persisted.manifest.as_ref() {
                verify_snapshot_manifest(verifier.as_ref(), snapshot)?;
            }
            Some(ActiveSnapshotAcquisition {
                persisted,
                sent_at: Instant::now()
                    .checked_sub(SNAPSHOT_RESPONSE_TIMEOUT)
                    .unwrap_or_else(Instant::now),
                handoff_sent: false,
            })
        }
        None => None,
    };
    Ok((
        ServiceSpec {
            id: ServiceId::new("sync")?,
            dependencies: vec![ServiceId::new("network")?, ServiceId::new("storage")?],
            criticality: Criticality::Critical,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        Box::new(SyncService {
            configuration: configuration.clone(),
            manager,
            manifest,
            local_peer_id,
            ingress,
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
            active_request,
            active_snapshot,
            snapshot_unavailable_height: None,
            status: SyncStatus::collecting(0),
            metrics: SyncMetrics::default(),
            started: false,
            failure: None,
        }),
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
    let signer = PqvmSigner::from_secret_key_bytes(policy.clone(), key_id.clone(), secret)
        .map_err(|error| format!("load snapshot PQVM signer: {error}"))?;
    let verifier = PqvmVerifier::new(policy).map_err(|error| error.to_string())?;
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

struct SyncService {
    configuration: NodeConfiguration,
    manager: SyncManager,
    manifest: NetworkManifest,
    local_peer_id: String,
    ingress: AuthenticatedIngress,
    request_store: SyncRequestStore,
    snapshot_store: SnapshotChunkStore,
    authority: Option<Arc<VerifiedAuthority>>,
    authority_transition: AuthorityTransitionSignal,
    active_authority_request: Option<ActiveAuthorityRequest>,
    snapshot_signer: Option<LocalSnapshotSigner>,
    local_parent_id: String,
    candidates: BTreeMap<String, SyncPeerCandidate>,
    heads: VerifiedHeadCollector,
    advertised: BTreeMap<String, u64>,
    active_request: Option<ActiveCandidateRequest>,
    active_snapshot: Option<ActiveSnapshotAcquisition>,
    snapshot_unavailable_height: Option<u64>,
    status: SyncStatus,
    metrics: SyncMetrics,
    started: bool,
    failure: Option<String>,
}

struct ActiveCandidateRequest {
    request: FinalizedCandidateRequest,
    peer_id: String,
    attempted: BTreeSet<String>,
    sent_at: Instant,
}

impl SyncService {
    fn send_authority_request(
        &self,
        peer_id: &str,
        request: &EpochAuthorityRequest,
    ) -> Result<(), String> {
        self.ingress.publish_outbound(OutboundFrame {
            peer_id: peer_id.to_owned(),
            protocol: ProtocolKind::Sync,
            payload: serde_json::to_vec(&SyncWireMessage::EpochAuthorityRequest(request.clone()))
                .map_err(|error| format!("encode epoch authority request: {error}"))?,
        })
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
        if authority.epoch.epoch != request.current_epoch.saturating_add(1) {
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
        self.ingress.publish_outbound(OutboundFrame {
            peer_id: peer.node_address.to_string(),
            protocol: ProtocolKind::Sync,
            payload: serde_json::to_vec(&SyncWireMessage::EpochAuthorityResponse(response))
                .map_err(|error| format!("encode epoch authority response: {error}"))?,
        })
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
    ) -> Result<(), String> {
        self.ingress.publish_outbound(OutboundFrame {
            peer_id: peer_id.to_string(),
            protocol: ProtocolKind::Sync,
            payload: serde_json::to_vec(&SyncWireMessage::FinalizedCandidateRequest(
                request.clone(),
            ))
            .map_err(|error| format!("encode Sync candidate request: {error}"))?,
        })
    }

    fn publish_snapshot(
        &self,
        publication: super::ingress::SnapshotPublication,
    ) -> Result<(), String> {
        let Some(signer) = self.snapshot_signer.as_ref() else {
            return Ok(());
        };
        let state_bytes = serde_json::to_vec(&publication.state)
            .map_err(|error| format!("encode finalized snapshot state: {error}"))?;
        let (manifest, chunks) = build_snapshot(
            &AegisSha3_256,
            signer,
            &self.manifest.network_id,
            publication.epoch,
            publication.finality.height,
            &publication.finality.block_id,
            &publication.finality.finality_certificate_id,
            &publication.application_state_root,
            1024 * 1024,
            &state_bytes,
        )?;
        if manifest.epoch != publication.epoch
            || manifest.height != publication.finality.height
            || manifest.finalized_block_id != publication.finality.block_id
            || manifest.finality_evidence_id != publication.finality.finality_certificate_id
            || manifest.application_state_root != publication.application_state_root
        {
            return Err("built snapshot is not bound to finalized publication".into());
        }
        for chunk in chunks {
            let request = SnapshotChunkRequest {
                epoch: manifest.epoch,
                height: manifest.height,
                finalized_block_id: manifest.finalized_block_id.clone(),
                finality_evidence_id: manifest.finality_evidence_id.clone(),
                expected_snapshot_root: Some(manifest.state_root),
                index: chunk.index,
            };
            self.snapshot_store.put(&SnapshotChunkResponse {
                request,
                manifest: manifest.clone(),
                chunk,
            })?;
        }
        Ok(())
    }

    fn send_snapshot_request(
        &self,
        peer_id: &str,
        request: &SnapshotChunkRequest,
    ) -> Result<(), String> {
        self.ingress.publish_outbound(OutboundFrame {
            peer_id: peer_id.to_string(),
            protocol: ProtocolKind::Sync,
            payload: serde_json::to_vec(&SyncWireMessage::SnapshotChunkRequest(request.clone()))
                .map_err(|error| format!("encode snapshot chunk request: {error}"))?,
        })
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

    fn accept_snapshot_response(
        &mut self,
        peer: AuthenticatedPeer,
        response: SnapshotChunkResponse,
    ) -> Result<(), String> {
        let expected = self
            .active_snapshot
            .as_ref()
            .filter(|active| {
                active.persisted.peer_id == peer.node_address.as_str() && !active.handoff_sent
            })
            .ok_or("unsolicited snapshot chunk response")?;
        if response.request != expected.persisted.request() {
            self.metrics.record_rejection();
            return Err("snapshot response differs from active finalized request".into());
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
        verify_snapshot_manifest(authority.as_ref(), &response.manifest)?;
        response.chunk.verify(
            &AegisSha3_256,
            &synergy_crypto::CryptoDomain {
                chain_id: response.manifest.chain_id,
                network_id: response.manifest.network_id.clone(),
                purpose: "snapshot-chunk-v1".into(),
                epoch: Some(response.manifest.epoch),
                height: Some(response.manifest.height),
            },
        )?;
        if expected
            .persisted
            .manifest
            .as_ref()
            .is_some_and(|manifest| manifest != &response.manifest)
        {
            return Err("snapshot source changed manifest during acquisition".into());
        }
        self.snapshot_store.put(&response)?;

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
        };
        restore_verified_snapshot(
            &AegisSha3_256,
            authority.as_ref(),
            &manifest,
            &chunks,
            &mut sink,
        )?;
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
        self.status.complete(receipt.finalized_height);
        self.local_parent_id = receipt.finalized_block_id;
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
                return Ok(true);
            }
            if active.sent_at.elapsed() < SNAPSHOT_RESPONSE_TIMEOUT {
                return Ok(true);
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
            return Ok(true);
        }
        if plan.target_height > self.status.local_finalized_height.saturating_add(1)
            && self.snapshot_unavailable_height != Some(plan.target_height)
        {
            let source = plan
                .sources
                .first()
                .ok_or("verified Sync plan has no snapshot source")?;
            self.begin_snapshot_acquisition(source)?;
            return Ok(true);
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

    fn accept_candidate_response(
        &mut self,
        peer: AuthenticatedPeer,
        response: FinalizedCandidateResponse,
    ) -> Result<(), String> {
        let expected = self
            .active_request
            .as_ref()
            .filter(|active| active.peer_id == peer.node_address.as_str())
            .ok_or("unsolicited finalized candidate response")?;
        if expected.request != response.request
            || response.candidate.height != expected.request.height
            || response.candidate.parent_block_id != expected.request.expected_parent_id
        {
            self.metrics.record_rejection();
            return Err("finalized candidate response differs from active request".into());
        }
        self.ingress
            .submit_sync_candidate_response(peer.clone(), response)?;
        self.active_request = None;
        self.request_store.clear()?;
        Ok(())
    }
}

impl SyncMessageSink for SyncService {
    fn receive_sync(&mut self, peer: AuthenticatedPeer, payload: Vec<u8>) -> Result<(), String> {
        let message: SyncWireMessage = serde_json::from_slice(&payload).map_err(|error| {
            self.metrics.record_rejection();
            format!("decode bounded Sync message: {error}")
        })?;
        match message {
            SyncWireMessage::Head(claim) => self.accept_head(peer, claim),
            SyncWireMessage::FinalizedCandidateRequest(request) => {
                self.ingress.submit_sync_candidate_request(peer, request)
            }
            SyncWireMessage::FinalizedCandidateResponse(response) => {
                self.accept_candidate_response(peer, response)
            }
            SyncWireMessage::SnapshotChunkRequest(request) => {
                self.ingress.submit_snapshot_chunk_request(peer, request)
            }
            SyncWireMessage::SnapshotChunkResponse(response) => {
                self.accept_snapshot_response(peer, response)
            }
            SyncWireMessage::EpochAuthorityRequest(request) => {
                self.accept_authority_request(peer, request)
            }
            SyncWireMessage::EpochAuthorityResponse(response) => {
                self.accept_authority_response(peer, response)
            }
        }
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
        if !self.started {
            return Err("sync service is not started".into());
        }
        if let Some((finalized, witness)) = self.ingress.latest_finality_with_witness()? {
            if finalized.height >= self.status.local_finalized_height {
                self.status.complete(finalized.height);
                self.local_parent_id = finalized.block_id.clone();
                for peer_id in self.ingress.authenticated_peers()? {
                    if self.advertised.get(&peer_id).copied().unwrap_or(0) < finalized.height {
                        let claim = HeadClaim {
                            peer_id: self.local_peer_id.clone(),
                            chain_id: self.manifest.chain_id,
                            genesis_hash: self.manifest.genesis_hash.clone(),
                            finalized_height: finalized.height,
                            finalized_hash: finalized.block_id.clone(),
                            finality_evidence_id: finalized.finality_certificate_id.clone(),
                            finality_witness: Some(witness.clone()),
                        };
                        self.ingress.publish_outbound(OutboundFrame {
                            peer_id: peer_id.clone(),
                            protocol: ProtocolKind::Sync,
                            payload: serde_json::to_vec(&SyncWireMessage::Head(claim))
                                .map_err(|error| format!("encode Sync head claim: {error}"))?,
                        })?;
                        self.advertised.insert(peer_id, finalized.height);
                    }
                }
            }
        }
        if self
            .active_request
            .as_ref()
            .is_some_and(|active| self.status.local_finalized_height >= active.request.height)
        {
            self.active_request = None;
            self.request_store.clear()?;
        }
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(frame) = self.ingress.take(ProtocolKind::Sync)? else {
                break;
            };
            SyncAdapter
                .deliver(AdapterEnvelope::from(frame), self)
                .map_err(|error| format!("route authenticated Sync frame: {error:?}"))?;
        }
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(publication) = self.ingress.take_snapshot_publication()? else {
                break;
            };
            self.publish_snapshot(publication)?;
        }
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some((peer, request)) = self.ingress.take_snapshot_chunk_request()? else {
                break;
            };
            if let Some(response) = self.snapshot_store.get(&request)? {
                self.ingress.publish_outbound(OutboundFrame {
                    peer_id: peer.node_address.to_string(),
                    protocol: ProtocolKind::Sync,
                    payload: serde_json::to_vec(&SyncWireMessage::SnapshotChunkResponse(response))
                        .map_err(|error| format!("encode snapshot chunk response: {error}"))?,
                })?;
            }
        }
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some((peer, response)) = self.ingress.take_snapshot_chunk_response()? else {
                break;
            };
            self.accept_snapshot_response(peer, response)?;
        }
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(receipt) = self.ingress.take_snapshot_restore_receipt()? else {
                break;
            };
            self.accept_snapshot_restore_receipt(receipt)?;
        }
        for _ in 0..MAX_MESSAGES_PER_POLL {
            let Some(head) = self.ingress.take_verified_head()? else {
                break;
            };
            self.heads
                .record(head)
                .map_err(|error| format!("record PoSy-verified Sync head: {error:?}"))?;
            self.metrics.record_verified_blocks(1);
        }
        let authenticated = self
            .ingress
            .authenticated_peers()?
            .into_iter()
            .collect::<BTreeSet<_>>();
        self.candidates
            .retain(|peer_id, _| authenticated.contains(peer_id));
        self.heads.retain_authenticated(&authenticated);
        self.advertised
            .retain(|peer_id, _| authenticated.contains(peer_id));
        if self.drive_authority_transition(&authenticated)? {
            return Ok(());
        }
        // Keep a persisted request across a peer disconnect so the next
        // authenticated source can be selected after the bounded timeout.
        let candidates: Vec<_> = self.candidates.values().cloned().collect();
        let heads: Vec<_> = self.heads.heads().cloned().collect();
        if !heads.is_empty() {
            let plan = self
                .manager
                .plan(&candidates, &heads)
                .map_err(|error| format!("select verified Sync source: {error:?}"))?;
            self.status.select_target(plan.target_height);
            if self.drive_snapshot_acquisition(&plan)? {
                // Snapshot transfer owns the catch-up path until its verified
                // state is handed to Execution and acknowledged durably.
            } else if self.status.local_finalized_height >= plan.target_height {
                self.status.complete(plan.target_height);
            } else if let Some(active) = self.active_request.as_ref() {
                if active.sent_at.elapsed() >= CANDIDATE_RESPONSE_TIMEOUT {
                    let next_peer = plan
                        .sources
                        .iter()
                        .find(|source| !active.attempted.contains(&source.peer_id))
                        .map(|source| source.peer_id.clone())
                        .ok_or(
                            "all verified Sync sources exhausted for active candidate request",
                        )?;
                    let request = active.request.clone();
                    self.send_candidate_request(&next_peer, &request)?;
                    let active = self
                        .active_request
                        .as_mut()
                        .ok_or("active Sync request disappeared")?;
                    active.peer_id = next_peer.clone();
                    active.attempted.insert(next_peer);
                    active.sent_at = Instant::now();
                    self.request_store.save(&PersistedCandidateRequest {
                        request: active.request.clone(),
                        peer_id: active.peer_id.clone(),
                        attempted: active.attempted.clone(),
                    })?;
                }
            } else {
                let source = plan
                    .sources
                    .first()
                    .ok_or("verified Sync plan has no source")?;
                let request = FinalizedCandidateRequest {
                    height: self
                        .status
                        .local_finalized_height
                        .checked_add(1)
                        .ok_or("Sync height overflow")?,
                    expected_parent_id: self.local_parent_id.clone(),
                };
                let status_request = BlockRequest {
                    from_height: request.height,
                    through_height: request.height,
                    expected_parent_id: request.expected_parent_id.clone(),
                };
                self.send_candidate_request(&source.peer_id, &request)?;
                self.status.begin_block_request(&status_request);
                let active_request = ActiveCandidateRequest {
                    request,
                    peer_id: source.peer_id.clone(),
                    attempted: BTreeSet::from([source.peer_id.clone()]),
                    sent_at: Instant::now(),
                };
                self.request_store.save(&PersistedCandidateRequest {
                    request: active_request.request.clone(),
                    peer_id: active_request.peer_id.clone(),
                    attempted: active_request.attempted.clone(),
                })?;
                self.active_request = Some(active_request);
            }
        }
        if self.manager.may_determine_finality() || self.status.may_determine_finality() {
            return Err("Sync must never determine PoSy finality".into());
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        self.ingress.clear(ProtocolKind::Sync)?;
        self.advertised.clear();
        self.active_request = None;
        self.active_authority_request = None;
        self.started = false;
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
