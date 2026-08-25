use crate::block::{Block, BlockChain, HOT_CHAIN_RETENTION_BLOCKS_ENV};
use crate::config::{NodeConfig, ResolvedConsensusMode};
use crate::consensus::anti_divergence::{
    current_validator_quarantine_duty_block, record_self_quarantine_for_canonical_lock_conflict,
};
use crate::consensus::chain_durability::{
    append_committed_block_bodies, append_committed_block_body,
};
use crate::consensus::consensus_algorithm::ProofOfSynergy;
use crate::consensus::coordinated_finality_observer::{
    canonical_coordinated_finality_snapshot_from,
    coordinated_finality_observer_next_missing_height, coordinated_finality_observer_snapshot_from,
    import_coordinated_finality_observer_records,
};
use crate::consensus::coordinated_round_robin::{
    AuthenticatedCoordinatedConsensusPeer, COORDINATED_ROUND_ROBIN_V1,
};
use crate::consensus::dual_quorum::{DualQuorumConsensus, QuorumCertificate};
use crate::consensus::legacy_canonical_lock::{
    legacy_canonical_commit_record, quarantine_legacy_canonical_locks_above,
    verify_legacy_canonical_lock, verify_legacy_canonical_locks, write_legacy_canonical_lock,
    write_legacy_canonical_locks,
};
use crate::consensus::simplified_posy::{
    dispatch_simplified_empty_etdag_message, dispatch_simplified_target_admission_package,
    dispatch_simplified_target_admission_vote, load_genesis_bound_simplified_activation,
    AuthenticatedSimplifiedConsensusPeer, GenesisBoundSimplifiedActivation,
    SimplifiedConsensusMessage, SimplifiedEmptyEtdagMessage, POSY_SIMPLIFIED_PROTOCOL_VERSION,
};
use crate::consensus::testnet_v3_bootstrap::{
    authenticate_active_typed_consensus_peer, load_testnet_v3_genesis_bootstrap,
};
use crate::consensus::timing_trace;
use crate::consensus::typed_coordinator::AuthenticatedTypedConsensusPeer;
use crate::consensus::typed_finality_observer::{
    canonical_typed_finality_snapshot_from, import_typed_finality_observer_records,
    typed_finality_observer_next_missing_height, typed_finality_observer_snapshot_from,
};
use crate::consensus::validator_keys::{consensus_algorithm_label, load_local_validator_keypair};
use crate::crypto::aegis_pqvm::{
    AegisPqvmKeyRegistry, AegisPqvmSigner, AegisPqvmVerifier, SYNERGY_P2P_HANDSHAKE_V1,
};
use crate::crypto::pqc::{PQCAlgorithm, PQCPrivateKey, PQCPublicKey};
use crate::etdag::{
    dispatch_etdag_certified_input, CertifiedProtectedInputArtifact, EtdagAuthenticatedIngressPeer,
};
use crate::genesis::canonical_genesis;
use crate::p2p::messages::{
    validate_coordinated_consensus_message_size,
    validate_coordinated_finality_observer_message_size,
    validate_simplified_consensus_message_size, validate_simplified_empty_etdag_message_size,
    validate_simplified_target_admission_message_size,
    validate_typed_finality_observer_message_size, CoordinatedConsensusMessage,
    CoordinatedFinalityObserverMessage, NetworkMessage, SimplifiedTargetAdmissionMessage,
    TypedConsensusMessage, TypedFinalityObserverMessage,
    MAX_SIMPLIFIED_CONSENSUS_CERTIFICATE_FRAME_BYTES, MAX_SIMPLIFIED_CONSENSUS_CONTROL_FRAME_BYTES,
    MAX_SIMPLIFIED_CONSENSUS_PROPOSAL_FRAME_BYTES, MAX_SIMPLIFIED_CONSENSUS_STATE_SYNC_FRAME_BYTES,
    MAX_SIMPLIFIED_CONSENSUS_VOTE_FRAME_BYTES, MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CANDIDATE_FRAME_BYTES,
    MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CONTROL_FRAME_BYTES,
    MAX_SIMPLIFIED_TARGET_ADMISSION_PACKAGE_FRAME_BYTES,
    MAX_SIMPLIFIED_TARGET_ADMISSION_VOTE_FRAME_BYTES,
};
#[cfg(not(test))]
use crate::p2p::validator_transport_registry::refresh_validator_transports;
use crate::p2p::validator_transport_registry::{
    current_validator_transports, has_validator_transports, validator_transport_for,
};
use crate::rpc::rpc_server::{
    cache_last_known_good_chain_tip, prune_transaction_hashes_from_pool, transaction_hashes,
    SYNC_MANAGER, TX_POOL,
};
use crate::sync::SyncState;
use crate::synergy_types::{AegisPqKeyId, AegisPqKeyRole, Epoch, ValidatorId};
use crate::transaction::Transaction;
use crate::validator::{
    apply_validator_activation_transaction, canonical_active_validator_set_hash,
    consensus_membership_validators, is_validator_activation_transaction, ValidatorManager,
    ValidatorRegistration, VALIDATOR_MANAGER,
};
use crate::{debug, error, info, warn};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json;
use socket2::{SockRef, TcpKeepalive};
#[cfg(test)]
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, Once};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime};

#[cfg(test)]
thread_local! {
    static TEST_COMMIT_VERIFIER_VALIDATOR_MANAGER: RefCell<Option<Arc<ValidatorManager>>> =
        RefCell::new(None);
}

// Type aliases to avoid nested generics parsing issues
type PeerMap = HashMap<String, PeerConnection>;
type BlockchainArc = Arc<Mutex<BlockChain>>;
type PeersArc = Arc<Mutex<PeerMap>>;
type DialTargetsArc = Arc<Mutex<Vec<String>>>;
type PeerStateCacheArc = Arc<Mutex<HashMap<String, CachedPeerState>>>;
type DialRegistryArc = Arc<Mutex<HashMap<String, DialReservation>>>;
type PeerMessage = (String, u64, NetworkMessage);

#[cfg(test)]
const DEFAULT_BOOTSTRAP_REFRESH_SECS: u64 = 10;
const NORMAL_BOOTSTRAP_REFRESH_SECS: u64 = 120;
const VALIDATOR_TRANSPORT_REFRESH_SECS: u64 = 30;
const TCP_KEEPALIVE_IDLE_SECS: u64 = 300;
const TCP_KEEPALIVE_INTERVAL_SECS: u64 = 60;
const IMMEDIATE_STATUS_SYNC_BATCH: u32 = 32;
const MAX_STATUS_SYNC_BATCH: u32 = 48;
const PUBLIC_HISTORY_GATEWAY_DIAL_ADDRESSES: &[&str] = &[
    "167.86.83.83:5623",
    "73.79.66.255:5622",
    "rpc.synergynode.xyz:5623",
    "archive.synergynode.xyz:5615",
    "73.79.66.255:5615",
    // Canonical explorer/indexer P2P endpoint from the finalized Testnet-v3
    // service topology. Relayers use this allowlist to serve only the
    // intended public non-signing observer roles.
    "74.208.227.23:5622",
];
const PUBLIC_RELAYER_DIAL_ADDRESSES: &[&str] = &[
    "relay1.synergynode.xyz:5622",
    "relay2.synergynode.xyz:5622",
    "relay3.synergynode.xyz:5622",
];
const MAX_BLOCK_SYNC_RESPONSE_BLOCKS: u32 = 64;
/// A simplified-PoSy validator has a distinct capability so peers cannot
/// confuse the fresh v3 Genesis authority with the retired typed PoSy engine.
const SIMPLIFIED_POSY_VALIDATOR_CAPABILITY: &str = "posy-simplified-v3-validator";
/// This capability is never accepted. Retaining an explicit reject value keeps
/// pre-v3 peers from silently degrading to a generic authenticated session.
const RETIRED_TYPED_POSY_VALIDATOR_CAPABILITY: &str = "typed-posy-v2.2-validator";
const COORDINATED_VALIDATOR_CAPABILITY: &str = "coordinated-round-robin-v1-validator";
// Identity bindings are session-scoped and bounded.  A socket address is not a
// consensus identity, so this registry exists solely to carry the result of a
// verified Genesis-bound handshake into the typed coordinator mailbox.
const MAX_TYPED_CONSENSUS_PEER_SESSIONS: usize = 1024;
const MAX_VALIDATOR_SUPPORT_SYNC_RESPONSE_BLOCKS: u32 = 64;
const MAX_SUPPORT_NODE_BLOCK_SYNC_RESPONSE_BLOCKS: u32 = 128;
const MAX_SUPPORT_PEER_DEEP_SYNC_LAG: u64 = 64_000;
const MAX_P2P_FRAME_BYTES: usize = 64 * 1024 * 1024;
const BLOCK_SYNC_RESPONSE_WRITE_TIMEOUT_SECS: u64 = 1;
const SUPPORT_NODE_BLOCK_SYNC_RESPONSE_WRITE_TIMEOUT_SECS: u64 = 2;
const VALIDATOR_SUPPORT_SYNC_RESPONSE_WRITE_TIMEOUT_MILLIS: u64 = 500;
const P2P_MESSAGE_WRITE_TIMEOUT_MILLIS: u64 = 2_000;
const BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS: u64 = 1;
const VALIDATOR_SUPPORT_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS: u64 = 2;
const SUPPORT_NODE_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS: u64 = 1;
const MAX_BLOCK_BATCH_VERIFY_WORKERS: usize = 4;
const MAX_BLOCK_SYNC_SERVE_WORKERS: usize = 2;
const MAX_BLOCK_SYNC_APPLY_WORKERS: usize = 1;
const BLOCK_SYNC_SERVE_QUEUE_CAPACITY: usize = 128;
const BLOCK_SYNC_APPLY_QUEUE_CAPACITY: usize = 64;
const BLOCK_SYNC_BUSY_QUEUE_CAPACITY: usize = 128;
const BLOCK_SYNC_BUSY_RETRY_MILLIS: u64 = 1_000;
const CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS: u64 = 500;
const CONSENSUS_DIRECT_VOTE_DIAL_TIMEOUT_MILLIS: u64 = 1_200;
const VOTE_REQUEST_PARENT_SYNC_WAIT_MILLIS: u64 = 900;
const VOTE_REQUEST_PARENT_SYNC_POLL_MILLIS: u64 = 25;
const MAX_PENDING_BLOCK_HEIGHTS: usize = 256;
const MAX_PENDING_BLOCKS_PER_HEIGHT: usize = 4;
const OUTBOUND_DIAL_COOLDOWN_SECS: u64 = 3;
const MAX_PENDING_INCOMING_CONNECTIONS_PER_HOST: usize = 8;
const VALIDATOR_P2P_PORT: u16 = 5622;
const VALIDATOR_STATUS_GENESIS_GRACE_SECS: u64 = 30;
const STALE_UNIDENTIFIED_PEER_SECS: u64 = 15;
const STALE_VALIDATOR_STATUS_SECS: u64 = VALIDATOR_STATUS_GENESIS_GRACE_SECS + 15;
const PEER_STATUS_FRESHNESS_TTL_SECS: u64 = STALE_VALIDATOR_STATUS_SECS;
const STATUS_READY_TTL_SECS: u64 = STALE_VALIDATOR_STATUS_SECS;
const DUTY_DISABLED_TTL_SECS: u64 = STALE_VALIDATOR_STATUS_SECS;
const QUARANTINE_STATUS_TTL_SECS: u64 = STALE_VALIDATOR_STATUS_SECS;
const STATUS_REQUEST_MIN_INTERVAL_SECS: u64 = 5;
const STATUS_RESPONSE_MIN_INTERVAL_SECS: u64 = 5;
const MAX_STATUS_RATE_LIMIT_ENTRIES: usize = 1024;
const BACKGROUND_SYNC_POLL_MILLIS: u64 = 1000;
// A bounded historical QC index warm-up can take roughly 70 seconds on large logs.
const SERVICE_BLOCK_SYNC_RESPONSE_TIMEOUT_SECS: u64 = 120;
const SERVICE_BLOCK_SYNC_APPLY_TIMEOUT_SECS: u64 = 180;
const BLOCK_SYNC_RECONCILIATION_LOOKBACK: u64 = 8;
const BLOCK_SYNC_PROGRESS_OVERLAP: u64 = 2;
const TESTNET_NATIVE_CAIP2: &str = "synergy:testnet";
const TESTNET_RESERVED_EIP155: &str = "eip155:1266";
const TESTNET_NETWORK_ID_TEXT: &str = "testnet";
const TESTNET_AEGIS_PQVM_VERSION: &str = "aegis-pqvm-v3";
const DEFAULT_MAX_CHAIN_SNAPSHOT_CLONE_HEIGHT: u64 = 50_000;

static VERIFIED_MLDSA65_HANDSHAKES: AtomicU64 = AtomicU64::new(0);
static VERIFIED_FNDSA_HANDSHAKES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct P2pHandshakeMetricsSnapshot {
    pub mldsa65_verified: u64,
    pub fndsa_verified: u64,
}

pub fn p2p_handshake_metrics_snapshot() -> P2pHandshakeMetricsSnapshot {
    P2pHandshakeMetricsSnapshot {
        mldsa65_verified: VERIFIED_MLDSA65_HANDSHAKES.load(Ordering::Relaxed),
        fndsa_verified: VERIFIED_FNDSA_HANDSHAKES.load(Ordering::Relaxed),
    }
}

fn compact_hot_chain_state_from_env(chain: &mut BlockChain, context: &str) {
    if let Some((retain_recent_blocks, removed_blocks)) = chain.compact_from_env() {
        if removed_blocks > 0 {
            debug!(
                "p2p",
                "Compacted hot chain state from retention setting",
                "context" => context.to_string(),
                "retention_env" => HOT_CHAIN_RETENTION_BLOCKS_ENV,
                "retain_recent_blocks" => retain_recent_blocks,
                "removed_blocks" => removed_blocks as u64,
                "first_retained_height" => chain.chain.first().map(|block| block.block_index).unwrap_or(0),
                "tip_height" => chain.last().map(|block| block.block_index).unwrap_or(0),
                "hot_block_count" => chain.chain.len() as u64
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionDirection {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone, Copy)]
struct DialReservation {
    in_flight: bool,
    last_attempt_at: Instant,
}

#[derive(Debug, Clone)]
struct PendingCommittedBlock {
    block: Block,
    quorum_certificate: QuorumCertificate,
}

lazy_static! {
    static ref LAST_CHAIN_PERSIST: Mutex<Option<(u64, Instant)>> = Mutex::new(None);
    static ref PENDING_BLOCKS: Mutex<BTreeMap<u64, Vec<PendingCommittedBlock>>> =
        Mutex::new(BTreeMap::new());
    static ref CHAIN_PERSIST_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
    static ref BLOCK_SYNC_LAST_SERVED: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
    static ref PEER_WRITE_GATES: Mutex<HashMap<String, Arc<Mutex<()>>>> =
        Mutex::new(HashMap::new());
    static ref PEER_SESSION_IDS: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
    static ref TYPED_CONSENSUS_PEER_SESSIONS: Mutex<HashMap<(String, u64), AuthenticatedTypedConsensusPeer>> =
        Mutex::new(HashMap::new());
    static ref NEXT_PEER_SESSION_ID: AtomicU64 = AtomicU64::new(1);
    static ref BLOCK_SYNC_SERVE_QUEUE: (
        mpsc::SyncSender<BlockServeJob>,
        Arc<Mutex<mpsc::Receiver<BlockServeJob>>>,
    ) = {
        let (sender, receiver) = mpsc::sync_channel(BLOCK_SYNC_SERVE_QUEUE_CAPACITY);
        (sender, Arc::new(Mutex::new(receiver)))
    };
    static ref BLOCK_SYNC_APPLY_QUEUE: (
        mpsc::SyncSender<BlockApplyJob>,
        Arc<Mutex<mpsc::Receiver<BlockApplyJob>>>,
    ) = {
        let (sender, receiver) = mpsc::sync_channel(BLOCK_SYNC_APPLY_QUEUE_CAPACITY);
        (sender, Arc::new(Mutex::new(receiver)))
    };
    static ref BLOCK_SYNC_BUSY_QUEUE: (
        mpsc::SyncSender<BlockSyncBusyJob>,
        Arc<Mutex<mpsc::Receiver<BlockSyncBusyJob>>>,
    ) = {
        let (sender, receiver) = mpsc::sync_channel(BLOCK_SYNC_BUSY_QUEUE_CAPACITY);
        (sender, Arc::new(Mutex::new(receiver)))
    };
    static ref BLOCK_SYNC_SERVE_ACTIVE: Mutex<HashSet<(String, u64)>> = Mutex::new(HashSet::new());
    static ref BLOCK_SYNC_APPLY_ACTIVE: Mutex<HashSet<(String, u64)>> = Mutex::new(HashSet::new());
    static ref BLOCK_SYNC_BUSY_ACTIVE: Mutex<HashSet<(String, u64)>> = Mutex::new(HashSet::new());
    static ref BLOCK_SYNC_RETRY_ACTIVE: Mutex<HashSet<(String, u64)>> = Mutex::new(HashSet::new());
    static ref SERVICE_SYNC_COORDINATOR: Mutex<ServiceSyncCoordinator> =
        Mutex::new(ServiceSyncCoordinator::default());
    static ref STATUS_REQUEST_LAST_SENT: Mutex<HashMap<String, (u64, u64)>> =
        Mutex::new(HashMap::new());
    static ref STATUS_RESPONSE_LAST_SENT: Mutex<HashMap<String, (u64, u64)>> =
        Mutex::new(HashMap::new());
}

#[cfg(not(test))]
static VALIDATOR_TRANSPORT_REFRESH_WORKER_RUNNING: AtomicBool = AtomicBool::new(false);

static BLOCK_SYNC_WORKERS_INIT: Once = Once::new();
static BLOCK_SYNC_SERVE_WORKERS_STARTED: AtomicUsize = AtomicUsize::new(0);
static BLOCK_SYNC_APPLY_WORKERS_STARTED: AtomicUsize = AtomicUsize::new(0);
static BLOCK_SYNC_BUSY_WORKERS_STARTED: AtomicUsize = AtomicUsize::new(0);

struct BlockServeJob {
    blockchain: BlockchainArc,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    config: NodeConfig,
    peer_address: String,
    session_id: u64,
    from_height: u64,
    count: u32,
}

struct BlockApplyJob {
    blockchain: BlockchainArc,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    config: NodeConfig,
    peer_address: String,
    session_id: u64,
    blocks: Vec<Block>,
    quorum_certificates: Vec<QuorumCertificate>,
}

struct BlockSyncBusyJob {
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    peer_address: String,
    session_id: u64,
    reason: &'static str,
    retry_request: Option<(u64, u32)>,
}

#[derive(Clone)]
struct ServiceSyncContext {
    blockchain: BlockchainArc,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    config: NodeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceSyncFlightIdentity {
    peer_address: String,
    session_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceSyncPhase {
    AwaitingResponse,
    Applying,
}

struct ServiceSyncFlight {
    generation: u64,
    identity: ServiceSyncFlightIdentity,
    from_height: u64,
    count: u32,
    remote_height: u64,
    phase: ServiceSyncPhase,
    phase_started_at: Instant,
    context: ServiceSyncContext,
}

#[derive(Default)]
struct ServiceSyncCoordinator {
    next_generation: u64,
    in_flight: Option<ServiceSyncFlight>,
    /// Authenticated source identities consumed by the current sync attempt.
    /// This is cleared only after a batch applies successfully or an explicit
    /// test/operator reset, so watchdog failover cannot cycle indefinitely.
    attempted_sources: HashSet<String>,
}

pub struct P2PNetwork {
    blockchain: BlockchainArc,
    config: NodeConfig,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    discovered_dial_targets: DialTargetsArc,
    outbound_dial_registry: DialRegistryArc,
    is_running: Arc<Mutex<bool>>,
    message_sender: mpsc::Sender<PeerMessage>,
    message_receiver: Arc<Mutex<mpsc::Receiver<PeerMessage>>>,
}

struct PeerConnection {
    address: String,
    /// The endpoint observed on the connected socket. `address` may be a requested
    /// DNS/validator alias and is not sufficient for authorization.
    connected_endpoint: Option<String>,
    direction: ConnectionDirection,
    public_address: Option<String>,
    validator_address: Option<String>,
    connected_at: u64,
    last_seen: u64,
    blocks_sent: u64,
    blocks_received: u64,
    txs_sent: u64,
    txs_received: u64,
    stream: Option<TcpStream>,
    node_id: Option<String>,
    /// The role from the verified handshake. Status messages must not be used for this.
    handshake_role: Option<String>,
    version: Option<String>,
    capabilities: Vec<String>,
    last_known_height: u64,
    best_block_hash: String,
    genesis_hash: String,
    status_received_at: Option<u64>,
    status_reported_at: Option<u64>,
    status_validator_address: Option<String>,
    status_source_session_id: Option<String>,
    active_validator_set_hash: Option<String>,
    quarantined: bool,
    consensus_duties_disabled: bool,
    recovery_state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerStreamIdentity {
    session_id: u64,
    connected_at: u64,
    local_address: SocketAddr,
    peer_address: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockSyncResponsePolicy {
    max_blocks: u32,
    write_timeout: Duration,
}

fn select_block_sync_response_blocks(
    chain: &BlockChain,
    from_height: u64,
    response_count: u32,
) -> Vec<Block> {
    let start = chain
        .chain
        .partition_point(|block| block.block_index < from_height);
    chain.chain[start..]
        .iter()
        .take(response_count as usize)
        .cloned()
        .collect()
}

#[derive(Debug, Clone, Default)]
struct CachedPeerState {
    public_address: Option<String>,
    validator_address: Option<String>,
    node_id: Option<String>,
    handshake_role: Option<String>,
    version: Option<String>,
    capabilities: Vec<String>,
    last_known_height: u64,
    best_block_hash: String,
    genesis_hash: String,
    status_received_at: Option<u64>,
    status_reported_at: Option<u64>,
    status_validator_address: Option<String>,
    status_source_session_id: Option<String>,
    active_validator_set_hash: Option<String>,
    quarantined: bool,
    consensus_duties_disabled: bool,
    recovery_state: Option<String>,
    last_seen: u64,
    connected_at: u64,
}

struct PeerEntryGuard {
    peer_address: String,
    session_id: u64,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
}

struct BootstrapDnsResolver {
    resolver: TokioResolver,
    runtime: TokioRuntime,
}

impl PeerEntryGuard {
    fn new(
        peer_address: String,
        session_id: u64,
        connected_peers: PeersArc,
        peer_state_cache: PeerStateCacheArc,
    ) -> Self {
        Self {
            peer_address,
            session_id,
            connected_peers,
            peer_state_cache,
        }
    }
}

impl Drop for PeerEntryGuard {
    fn drop(&mut self) {
        if let Ok(mut peers) = self.connected_peers.lock() {
            if peer_session_is_current(&self.peer_address, self.session_id)
                && peers.contains_key(&self.peer_address)
            {
                disconnect_peer_entry(&self.peer_state_cache, &mut peers, &self.peer_address);
                info!("p2p", "Peer disconnected", "peer" => self.peer_address.clone());
            }
        }
    }
}

fn should_disconnect_for_status_genesis_mismatch(
    local_genesis_hash: &str,
    remote_genesis_hash: &str,
    peer_validator_address: Option<&str>,
) -> bool {
    if local_genesis_hash.trim().is_empty() {
        return false;
    }

    let peer_is_validator = peer_validator_address
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);

    if remote_genesis_hash.is_empty() {
        return peer_is_validator;
    }

    remote_genesis_hash != local_genesis_hash
}

fn canonical_genesis_hash() -> String {
    canonical_genesis()
        .map(|genesis| genesis.hash().to_string())
        .unwrap_or_default()
}

/// P2P replay separation is part of the canonical Genesis identity. Do not
/// freeze the former chain-incarnation value into wire messages: a fresh
/// block-zero Testnet-v3 Genesis deliberately owns a new value.
fn canonical_chain_incarnation() -> u64 {
    canonical_genesis()
        .map(|genesis| genesis.chain_incarnation())
        .unwrap_or(crate::synergy_types::TESTNET_V3_CHAIN_INCARNATION)
}

fn canonical_consensus_state_schema_version() -> u32 {
    canonical_genesis()
        .map(|genesis| genesis.consensus_state_schema_version())
        .unwrap_or(crate::synergy_types::TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION)
}

fn canonical_network_magic_bytes() -> String {
    canonical_genesis()
        .map(|genesis| genesis.network_magic_bytes().to_string())
        .unwrap_or_default()
}

fn local_chain_id(config: &NodeConfig) -> u64 {
    canonical_genesis()
        .map(|genesis| genesis.chain_id())
        .unwrap_or(config.blockchain.chain_id)
}

fn local_network_id(config: &NodeConfig) -> u64 {
    canonical_genesis()
        .map(|genesis| genesis.network_id())
        .unwrap_or(config.network.id)
}

fn local_protocol_version(config: &NodeConfig) -> String {
    canonical_genesis()
        .map(|genesis| genesis.protocol_version().to_string())
        .unwrap_or_else(|_| config.network.name.clone())
}

fn local_consensus_version(config: &NodeConfig) -> String {
    match config.consensus.algorithm.trim() {
        COORDINATED_ROUND_ROBIN_V1 => return COORDINATED_ROUND_ROBIN_V1.to_string(),
        POSY_SIMPLIFIED_PROTOCOL_VERSION => return POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
        _ => {}
    }
    canonical_genesis()
        .map(|genesis| genesis.consensus_version().to_string())
        .unwrap_or_else(|_| config.consensus.algorithm.clone())
}

fn local_p2p_role(config: &NodeConfig) -> String {
    config
        .identity
        .role
        .trim()
        .split_whitespace()
        .next()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            config
                .node
                .validator_address
                .trim()
                .is_empty()
                .then_some("observer")
        })
        .unwrap_or("validator")
        .to_string()
}

fn canonical_validator_set_hash() -> String {
    canonical_active_validator_set_hash(&VALIDATOR_MANAGER.get_active_validators())
}

fn canonical_json_subtree_hash(path: &[&str]) -> String {
    let Some(mut value) = canonical_genesis().ok().map(|genesis| genesis.value()) else {
        return String::new();
    };
    for segment in path {
        let Some(next) = value.get(*segment) else {
            return String::new();
        };
        value = next;
    }
    serde_json::to_vec(value)
        .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
        .unwrap_or_default()
}

fn canonical_cluster_map_hash() -> String {
    canonical_json_subtree_hash(&["validators"])
}

fn canonical_protocol_config_hash() -> String {
    canonical_json_subtree_hash(&["network"])
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct HandshakePqSigningPayload {
    node_id: String,
    version: String,
    capabilities: Vec<String>,
    chain_id: Option<u64>,
    chain_incarnation: Option<u64>,
    consensus_state_schema_version: Option<u32>,
    network_id: Option<u64>,
    network_id_text: Option<String>,
    genesis_hash: String,
    network_magic_bytes: String,
    protocol_version: Option<String>,
    consensus_version: Option<String>,
    native_caip2: Option<String>,
    reserved_eip155: Option<String>,
    public_address: Option<String>,
    validator_address: Option<String>,
    role: Option<String>,
    active_validator_set_hash: Option<String>,
    cluster_map_hash: Option<String>,
    protocol_config_hash: Option<String>,
    aegis_pqvm_version: Option<String>,
    aegis_pq_public_key_id: Option<String>,
    aegis_pq_public_key_algorithm: Option<String>,
    aegis_pq_public_key: Vec<u8>,
}

fn handshake_pq_signing_payload(message: &NetworkMessage) -> Result<Vec<u8>, String> {
    let NetworkMessage::Handshake {
        node_id,
        version,
        capabilities,
        chain_id,
        chain_incarnation,
        consensus_state_schema_version,
        network_id,
        network_id_text,
        genesis_hash,
        network_magic_bytes,
        protocol_version,
        consensus_version,
        native_caip2,
        reserved_eip155,
        public_address,
        validator_address,
        role,
        active_validator_set_hash,
        cluster_map_hash,
        protocol_config_hash,
        aegis_pqvm_version,
        aegis_pq_public_key_id,
        aegis_pq_public_key_algorithm,
        aegis_pq_public_key,
        ..
    } = message
    else {
        return Err("P2P handshake signature payload requested for non-handshake".to_string());
    };

    serde_json::to_vec(&HandshakePqSigningPayload {
        node_id: node_id.clone(),
        version: version.clone(),
        capabilities: capabilities.clone(),
        chain_id: *chain_id,
        chain_incarnation: *chain_incarnation,
        consensus_state_schema_version: *consensus_state_schema_version,
        network_id: *network_id,
        network_id_text: network_id_text.clone(),
        genesis_hash: genesis_hash.clone(),
        network_magic_bytes: network_magic_bytes.clone(),
        protocol_version: protocol_version.clone(),
        consensus_version: consensus_version.clone(),
        native_caip2: native_caip2.clone(),
        reserved_eip155: reserved_eip155.clone(),
        public_address: public_address.clone(),
        validator_address: validator_address.clone(),
        role: role.clone(),
        active_validator_set_hash: active_validator_set_hash.clone(),
        cluster_map_hash: cluster_map_hash.clone(),
        protocol_config_hash: protocol_config_hash.clone(),
        aegis_pqvm_version: aegis_pqvm_version.clone(),
        aegis_pq_public_key_id: aegis_pq_public_key_id.clone(),
        aegis_pq_public_key_algorithm: aegis_pq_public_key_algorithm.clone(),
        aegis_pq_public_key: aegis_pq_public_key.clone(),
    })
    .map_err(|error| format!("serialize canonical P2P handshake payload: {error}"))
}

fn parse_handshake_pqc_algorithm(value: &str) -> Result<PQCAlgorithm, String> {
    match value.trim() {
        "fndsa" | "FN-DSA-1024" => Ok(PQCAlgorithm::FNDSA),
        "mldsa65" | "ML-DSA-65" => Ok(PQCAlgorithm::MLDSA65),
        "mldsa87" | "ML-DSA-87" => Ok(PQCAlgorithm::MLDSA87),
        "slhdsa" | "SLH-DSA" => Err(format!(
            "unsupported Aegis PQC peer key algorithm: {value}; use fndsa, mldsa65, or mldsa87"
        )),
        other => Err(format!(
            "unsupported Aegis PQC peer key algorithm: {other}; use fndsa, mldsa65, or mldsa87"
        )),
    }
}

fn build_local_handshake(config: &NodeConfig) -> Result<NetworkMessage, String> {
    build_local_handshake_with_extra_capabilities(config, &[])
}

fn build_local_handshake_with_extra_capabilities(
    config: &NodeConfig,
    extra_capabilities: &[&str],
) -> Result<NetworkMessage, String> {
    let mut signer = AegisPqvmSigner::initialize_required()
        .map_err(|error| format!("aegis-pqvm P2P signer initialization failed: {error}"))?;
    let peer_uma = config
        .p2p
        .node_name
        .trim()
        .is_empty()
        .then_some("synergy-node")
        .unwrap_or_else(|| config.p2p.node_name.trim());
    let key_id = if local_consensus_handshake_required(config) {
        let validator_address = announced_validator_address(config).ok_or_else(|| {
            "validator consensus handshake requires a configured validator address".to_string()
        })?;
        let (public_key, private_key) = load_local_validator_keypair(
            &validator_address,
            &VALIDATOR_MANAGER,
        )
        .map_err(|error| {
            format!(
                "validator consensus handshake cannot load the assigned ML-DSA-65 consensus key: {error}"
            )
        })?;
        if config.consensus.algorithm.trim() == POSY_SIMPLIFIED_PROTOCOL_VERSION {
            let genesis = canonical_genesis().map_err(|error| {
                format!(
                    "simplified PoSy validator handshake cannot load canonical Genesis: {error}"
                )
            })?;
            let activation = load_genesis_bound_simplified_activation(genesis.value())?
                .ok_or_else(|| {
                    "simplified PoSy validator handshake requires a Genesis-bound v3 activation"
                        .to_string()
                })?;
            authenticate_fresh_simplified_posy_peer(
                &activation,
                &validator_address,
                &public_key.key_id,
                consensus_algorithm_label(&public_key.algorithm),
                &public_key.key_data,
            )
            .map_err(|error| {
                format!(
                    "simplified PoSy local validator key is not authorized by Genesis activation: {error}"
                )
            })?;
        }
        register_validator_consensus_handshake_key(
            &mut signer,
            &validator_address,
            public_key,
            private_key,
        )?
    } else {
        signer
            .generate_and_register_fndsa_peer_identity(peer_uma, Epoch(0))
            .map_err(|error| format!("aegis-pqvm P2P key loading failed: {error}"))?
    };
    let public_key = signer
        .public_key_record(&key_id)
        .map_err(|error| format!("aegis-pqvm P2P public key loading failed: {error}"))?;
    let mut capabilities = vec!["blocks".to_string(), "transactions".to_string()];
    if local_consensus_handshake_required(config) {
        let capability = validator_consensus_capability(config.consensus.algorithm.trim())?;
        capabilities.push(capability.to_string());
    }
    for capability in extra_capabilities {
        let capability = capability.trim();
        if !capability.is_empty() && !capabilities.iter().any(|value| value == capability) {
            capabilities.push(capability.to_string());
        }
    }
    let mut handshake = NetworkMessage::Handshake {
        node_id: config.p2p.node_name.clone(),
        version: "1.0.0".to_string(),
        capabilities,
        chain_id: Some(local_chain_id(config)),
        chain_incarnation: Some(canonical_chain_incarnation()),
        consensus_state_schema_version: Some(canonical_consensus_state_schema_version()),
        network_id: Some(local_network_id(config)),
        network_id_text: Some(TESTNET_NETWORK_ID_TEXT.to_string()),
        genesis_hash: canonical_genesis_hash(),
        network_magic_bytes: canonical_network_magic_bytes(),
        protocol_version: Some(local_protocol_version(config)),
        consensus_version: Some(local_consensus_version(config)),
        native_caip2: Some(TESTNET_NATIVE_CAIP2.to_string()),
        reserved_eip155: Some(TESTNET_RESERVED_EIP155.to_string()),
        public_address: Some(config.p2p.public_address.clone()),
        validator_address: announced_validator_address(config),
        role: Some(local_p2p_role(config)),
        active_validator_set_hash: Some(canonical_validator_set_hash()),
        cluster_map_hash: Some(canonical_cluster_map_hash()),
        protocol_config_hash: Some(canonical_protocol_config_hash()),
        aegis_pqvm_version: Some(TESTNET_AEGIS_PQVM_VERSION.to_string()),
        aegis_pq_public_key_id: Some(public_key.key_id.0.clone()),
        aegis_pq_public_key_algorithm: Some(public_key.algorithm.clone()),
        aegis_pq_public_key: public_key.key_bytes.clone(),
        aegis_pq_handshake_signature: None,
    };
    let payload = handshake_pq_signing_payload(&handshake)?;
    let signature = signer
        .sign_peer_hello(&payload, &key_id)
        .map_err(|error| format!("aegis-pqvm P2P handshake signing failed: {error}"))?;
    if let NetworkMessage::Handshake {
        aegis_pq_handshake_signature,
        ..
    } = &mut handshake
    {
        *aegis_pq_handshake_signature = Some(signature);
    }
    Ok(handshake)
}

/// A validator consensus handshake proves possession of the exact
/// Genesis-assigned ML-DSA-65 key. No validator may fall back to an ephemeral
/// P2P key.
fn local_consensus_handshake_required(config: &NodeConfig) -> bool {
    matches!(
        config.consensus.algorithm.trim(),
        POSY_SIMPLIFIED_PROTOCOL_VERSION | COORDINATED_ROUND_ROBIN_V1
    ) && !config.node.bootstrap_only
        && !config.node.validator_address.trim().is_empty()
}

fn validator_consensus_capability(algorithm: &str) -> Result<&'static str, String> {
    match algorithm.trim() {
        COORDINATED_ROUND_ROBIN_V1 => Ok(COORDINATED_VALIDATOR_CAPABILITY),
        POSY_SIMPLIFIED_PROTOCOL_VERSION => Ok(SIMPLIFIED_POSY_VALIDATOR_CAPABILITY),
        algorithm => Err(format!(
            "validator consensus handshake does not support algorithm {algorithm}"
        )),
    }
}

fn register_validator_consensus_handshake_key(
    signer: &mut AegisPqvmSigner,
    validator_address: &str,
    public_key: PQCPublicKey,
    private_key: PQCPrivateKey,
) -> Result<AegisPqKeyId, String> {
    if public_key.algorithm != PQCAlgorithm::MLDSA65 {
        return Err(
            "validator consensus handshake requires an ML-DSA-65 consensus key".to_string(),
        );
    }
    signer
        .register_existing_keypair(
            validator_address,
            public_key,
            private_key,
            vec![
                AegisPqKeyRole::PeerIdentity,
                AegisPqKeyRole::ConsensusProposer,
                AegisPqKeyRole::ConsensusVote,
                AegisPqKeyRole::EpochTransition,
            ],
            Epoch(0),
        )
        .map_err(|error| format!("register validator consensus handshake key: {error}"))
}

/// Authenticates a simplified-PoSy validator against the frozen set embedded
/// in the canonical fresh-Genesis activation. The generic P2P signature was
/// verified before this function is reached; this second binding ensures that
/// its ML-DSA-65 public material belongs to one exact Genesis validator.
fn authenticate_fresh_simplified_posy_peer(
    activation: &GenesisBoundSimplifiedActivation,
    validator_operator_address: &str,
    advertised_key_id: &str,
    advertised_algorithm: &str,
    advertised_public_key: &[u8],
) -> Result<AuthenticatedTypedConsensusPeer, String> {
    activation.validate()?;
    if !matches!(
        advertised_algorithm.trim(),
        "ML-DSA-65" | "ml-dsa-65" | "mldsa65"
    ) {
        return Err("simplified PoSy peer handshake key algorithm must be ML-DSA-65".to_string());
    }
    let operator = validator_operator_address.trim();
    if operator.is_empty() {
        return Err("simplified PoSy peer handshake omits validator operator address".to_string());
    }
    let validator = activation
        .frozen_validator_set
        .validators
        .iter()
        .find(|validator| validator.validator_uma_id.0 == operator)
        .ok_or_else(|| {
            "simplified PoSy peer is not in the Genesis-frozen validator set".to_string()
        })?;
    if !validator.is_active_for_epoch(crate::synergy_types::Epoch(activation.activation_epoch)) {
        return Err("simplified PoSy peer is not active for the Genesis epoch".to_string());
    }
    if validator.consensus_public_key.key_id.0 != advertised_key_id.trim()
        || validator.consensus_public_key.key_bytes != advertised_public_key
    {
        return Err(
            "simplified PoSy peer handshake key does not match the Genesis-frozen validator consensus key"
                .to_string(),
        );
    }
    Ok(AuthenticatedTypedConsensusPeer {
        validator_id: validator.validator_id.clone(),
        validator_uma_id: validator.validator_uma_id.clone(),
        consensus_key_id: validator.consensus_public_key.key_id.clone(),
    })
}

fn verify_handshake_pq_signature(
    message: &NetworkMessage,
) -> Result<Option<AuthenticatedTypedConsensusPeer>, String> {
    let NetworkMessage::Handshake {
        node_id,
        capabilities,
        chain_id,
        chain_incarnation,
        consensus_state_schema_version,
        network_id_text,
        validator_address,
        aegis_pq_public_key_id,
        aegis_pq_public_key_algorithm,
        aegis_pq_public_key,
        aegis_pq_handshake_signature,
        ..
    } = message
    else {
        return Err("P2P handshake verification requested for non-handshake".to_string());
    };

    let genesis = canonical_genesis()
        .map_err(|error| format!("Aegis PQC handshake cannot load canonical Genesis: {error}"))?;
    let expected_chain_id = genesis.chain_id();
    let expected_chain_incarnation = genesis.chain_incarnation();
    let expected_state_schema_version = genesis.consensus_state_schema_version();
    if *chain_id != Some(expected_chain_id) {
        return Err(format!(
            "Aegis PQC handshake must bind chain_id {expected_chain_id}"
        ));
    }
    if *chain_incarnation != Some(expected_chain_incarnation) {
        return Err(format!(
            "Aegis PQC handshake must bind Chain 1266 incarnation {}",
            expected_chain_incarnation
        ));
    }
    if *consensus_state_schema_version != Some(expected_state_schema_version) {
        return Err(format!(
            "Aegis PQC handshake must bind consensus state schema {}",
            expected_state_schema_version
        ));
    }
    if network_id_text.as_deref() != Some(TESTNET_NETWORK_ID_TEXT) {
        return Err(format!(
            "Aegis PQC handshake must bind network_id {TESTNET_NETWORK_ID_TEXT}"
        ));
    }
    let key_id = aegis_pq_public_key_id
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "missing Aegis PQC peer key id".to_string())?;
    let algorithm = aegis_pq_public_key_algorithm
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "missing Aegis PQC peer key algorithm".to_string())
        .and_then(|value| parse_handshake_pqc_algorithm(value))?;
    if aegis_pq_public_key.is_empty() {
        return Err("missing Aegis PQC peer public key".to_string());
    }
    let signature = aegis_pq_handshake_signature
        .as_ref()
        .filter(|signature| signature.is_present())
        .ok_or_else(|| "missing Aegis PQC peer handshake signature".to_string())?;

    let payload = handshake_pq_signing_payload(message)?;
    let key_id = AegisPqKeyId(key_id.clone());
    let mut registry = AegisPqvmKeyRegistry::default();
    registry.register_public_key(
        node_id,
        PQCPublicKey {
            algorithm: algorithm.clone(),
            key_data: aegis_pq_public_key.clone(),
            key_id: key_id.0.clone(),
            created_at: 0,
        },
        vec![AegisPqKeyRole::PeerIdentity],
        Epoch(0),
    );
    let verifier = AegisPqvmVerifier::initialize_required(registry)
        .map_err(|error| format!("aegis-pqvm P2P verifier initialization failed: {error}"))?;
    verifier
        .verify_domain_signature(
            SYNERGY_P2P_HANDSHAKE_V1,
            &payload,
            node_id,
            &key_id,
            Epoch(0),
            AegisPqKeyRole::PeerIdentity,
            signature,
        )
        .map_err(|error| format!("Aegis PQC peer handshake verification failed: {error}"))?;
    match algorithm {
        PQCAlgorithm::MLDSA65 => {
            VERIFIED_MLDSA65_HANDSHAKES.fetch_add(1, Ordering::Relaxed);
        }
        PQCAlgorithm::FNDSA => {
            VERIFIED_FNDSA_HANDSHAKES.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }

    if capabilities
        .iter()
        .any(|capability| capability == RETIRED_TYPED_POSY_VALIDATOR_CAPABILITY)
    {
        return Err(
            "retired typed PoSy validator capability is forbidden; use the fresh simplified PoSy v3 capability"
                .to_string(),
        );
    }
    let advertises_simplified_posy = capabilities
        .iter()
        .any(|capability| capability == SIMPLIFIED_POSY_VALIDATOR_CAPABILITY);
    let advertises_coordinated = capabilities
        .iter()
        .any(|capability| capability == COORDINATED_VALIDATOR_CAPABILITY);
    if advertises_simplified_posy && advertises_coordinated {
        return Err(
            "validator handshake cannot advertise both simplified PoSy and coordinated capabilities"
                .to_string(),
        );
    }
    if advertises_simplified_posy || advertises_coordinated {
        let validator_address = validator_address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "validator consensus handshake omits validator_address".to_string())?;
        if advertises_simplified_posy {
            let activation = load_genesis_bound_simplified_activation(genesis.value())?
                .ok_or_else(|| {
                    "simplified PoSy peer handshake requires a Genesis-bound v3 activation"
                        .to_string()
                })?;
            let identity = authenticate_fresh_simplified_posy_peer(
                &activation,
                validator_address,
                key_id.0.as_str(),
                aegis_pq_public_key_algorithm.as_deref().unwrap_or_default(),
                aegis_pq_public_key,
            )
            .map_err(|error| {
                format!("simplified PoSy validator handshake identity binding failed: {error}")
            })?;
            return Ok(Some(identity));
        }

        let bootstrap = load_testnet_v3_genesis_bootstrap(&genesis).map_err(|error| {
            format!("coordinated validator handshake canonical Genesis is not a valid bootstrap: {error}")
        })?;
        let validator = authenticate_active_typed_consensus_peer(
            &bootstrap,
            validator_address,
            key_id.0.as_str(),
            aegis_pq_public_key_algorithm.as_deref().unwrap_or_default(),
            aegis_pq_public_key,
        )
        .map_err(|error| {
            format!("coordinated validator handshake identity binding failed: {error}")
        })?;
        return Ok(Some(AuthenticatedTypedConsensusPeer {
            validator_id: validator.validator_id,
            validator_uma_id: validator.validator_uma_id,
            consensus_key_id: validator.consensus_public_key.key_id,
        }));
    }
    Ok(None)
}

fn handshake_mismatch_reason(
    config: &NodeConfig,
    chain_id: Option<u64>,
    chain_incarnation: Option<u64>,
    consensus_state_schema_version: Option<u32>,
    network_id: Option<u64>,
    network_id_text: Option<&str>,
    genesis_hash: &str,
    network_magic_bytes: &str,
    protocol_version: Option<&str>,
    consensus_version: Option<&str>,
    native_caip2: Option<&str>,
) -> Option<String> {
    let expected_chain_id = local_chain_id(config);
    let expected_network_id = local_network_id(config);
    let expected_genesis_hash = canonical_genesis_hash();
    let expected_network_magic_bytes = canonical_network_magic_bytes();
    let expected_protocol_version = local_protocol_version(config);
    let expected_consensus_version = local_consensus_version(config);

    match chain_id {
        Some(value) if value == expected_chain_id => {}
        Some(value) => {
            return Some(format!(
                "chain_id differs: expected {expected_chain_id}, remote {value}"
            ));
        }
        None => return Some(format!("chain_id missing: expected {expected_chain_id}")),
    }

    let expected_chain_incarnation = canonical_chain_incarnation();
    if chain_incarnation != Some(expected_chain_incarnation) {
        return Some(format!(
            "chain_incarnation differs: expected {}, remote {:?}",
            expected_chain_incarnation, chain_incarnation
        ));
    }
    let expected_state_schema_version = canonical_consensus_state_schema_version();
    if consensus_state_schema_version != Some(expected_state_schema_version) {
        return Some(format!(
            "consensus state schema differs: expected {}, remote {:?}",
            expected_state_schema_version, consensus_state_schema_version
        ));
    }

    match network_id {
        Some(value) if value == expected_network_id => {}
        Some(value) => {
            return Some(format!(
                "network_id differs: expected {expected_network_id}, remote {value}"
            ));
        }
        None => {
            return Some(format!(
                "network_id missing: expected {expected_network_id}"
            ))
        }
    }

    match network_id_text {
        Some(value) if value == TESTNET_NETWORK_ID_TEXT => {}
        Some(value) => {
            return Some(format!(
                "network_id text differs: expected {TESTNET_NETWORK_ID_TEXT}, remote {value}"
            ));
        }
        None => {
            return Some(format!(
                "network_id text missing: expected {TESTNET_NETWORK_ID_TEXT}"
            ));
        }
    }

    if genesis_hash.trim().is_empty() {
        return Some("genesis_hash missing from handshake".to_string());
    }
    if !expected_genesis_hash.is_empty() && genesis_hash != expected_genesis_hash {
        return Some(format!(
            "genesis_hash differs: expected {expected_genesis_hash}, remote {genesis_hash}"
        ));
    }

    if network_magic_bytes.trim().is_empty() {
        return Some("network_magic_bytes missing from handshake".to_string());
    }
    if !expected_network_magic_bytes.is_empty()
        && network_magic_bytes != expected_network_magic_bytes
    {
        return Some(format!(
            "network_magic_bytes differs: expected {expected_network_magic_bytes}, remote {network_magic_bytes}"
        ));
    }

    if let Some(reason) = handshake_version_mismatch_reason(
        "protocol_version",
        &expected_protocol_version,
        protocol_version,
    ) {
        return Some(reason);
    }

    if let Some(reason) = handshake_version_mismatch_reason(
        "consensus_version",
        &expected_consensus_version,
        consensus_version,
    ) {
        return Some(reason);
    }

    if let Some(caip2) = native_caip2 {
        if caip2 != TESTNET_NATIVE_CAIP2 {
            return Some(format!(
                "native CAIP-2 differs: expected {TESTNET_NATIVE_CAIP2}, remote {caip2}"
            ));
        }
    }

    None
}

fn handshake_version_mismatch_reason(
    label: &str,
    expected: &str,
    remote: Option<&str>,
) -> Option<String> {
    match remote.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) if value == expected => None,
        Some(value) => Some(format!(
            "{label} differs: expected {expected}, remote {value}"
        )),
        None => Some(format!("{label} missing: expected {expected}")),
    }
}

fn resolve_local_genesis_hash(blockchain: &BlockchainArc) -> String {
    let canonical = canonical_genesis_hash();
    if !canonical.trim().is_empty() {
        return canonical;
    }

    blockchain
        .lock()
        .ok()
        .and_then(|chain| chain.get_genesis_hash())
        .filter(|hash| !hash.trim().is_empty())
        .unwrap_or_default()
}

fn validator_status_genesis_grace_remaining_secs(connected_at: u64, now: u64) -> u64 {
    VALIDATOR_STATUS_GENESIS_GRACE_SECS.saturating_sub(now.saturating_sub(connected_at))
}

fn validator_status_genesis_within_grace_window(connected_at: u64, now: u64) -> bool {
    now.saturating_sub(connected_at) < VALIDATOR_STATUS_GENESIS_GRACE_SECS
}

fn ensure_peer_status_allows_chain_data(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    peer_address: &str,
    session_id: u64,
    message_kind: &str,
) -> bool {
    let local_genesis_hash = resolve_local_genesis_hash(blockchain);
    let (
        remote_genesis_hash,
        peer_validator_address,
        status_received_at,
        authenticated_public_history_gateway,
    ) = {
        let peers = connected_peers.lock().unwrap();
        if !peer_session_is_current(peer_address, session_id) {
            return false;
        }
        let Some(peer) = peers.get(peer_address) else {
            return false;
        };
        (
            peer.genesis_hash.clone(),
            peer.validator_address.clone(),
            peer.status_received_at,
            peer_has_authenticated_public_history_gateway_status(peer, &local_genesis_hash),
        )
    };

    if remote_genesis_hash.trim().is_empty() && !authenticated_public_history_gateway {
        debug!(
            "p2p",
            "Ignoring chain data until peer status confirms canonical genesis",
            "peer" => peer_address.to_string(),
            "message_kind" => message_kind.to_string()
        );
        request_status_from_connected_peer(
            connected_peers,
            peer_state_cache,
            peer_address,
            session_id,
        );
        return false;
    }

    if should_disconnect_for_status_genesis_mismatch(
        &local_genesis_hash,
        &remote_genesis_hash,
        peer_validator_address.as_deref(),
    ) {
        warn!(
            "p2p",
            "Disconnecting peer attempting chain data exchange with mismatched genesis hash",
            "peer" => peer_address.to_string(),
            "message_kind" => message_kind.to_string(),
            "local_genesis_hash" => local_genesis_hash,
            "remote_genesis_hash" => remote_genesis_hash
        );
        let mut peers = connected_peers.lock().unwrap();
        disconnect_peer_entry_for_session(peer_state_cache, &mut peers, peer_address, session_id);
        return false;
    }

    if status_received_at.is_none() && !authenticated_public_history_gateway {
        debug!(
            "p2p",
            "Ignoring chain data until peer status confirms canonical genesis",
            "peer" => peer_address.to_string(),
            "message_kind" => message_kind.to_string()
        );
        request_status_from_connected_peer(
            connected_peers,
            peer_state_cache,
            peer_address,
            session_id,
        );
        return false;
    }

    true
}

#[derive(Debug, Deserialize)]
struct SeedPeerListResponse {
    #[serde(default)]
    bootnodes: Vec<SeedBootnodeRecord>,
    #[serde(default)]
    dnsaddr_bootstrap: Vec<String>,
    #[serde(default)]
    peers: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SeedBootnodeRecord {
    hostname: String,
    port: u16,
    #[serde(default)]
    reachable: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DuplicateResolution {
    KeepExisting,
    ReplaceExisting,
}

fn resolve_local_validator_address(config: &NodeConfig) -> String {
    let configured = config.node.validator_address.trim();
    if !configured.is_empty() {
        return configured.to_string();
    }

    std::env::var("SYNERGY_VALIDATOR_ADDRESS")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("NODE_ADDRESS")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| config.p2p.node_name.clone())
}

fn announced_validator_address(config: &NodeConfig) -> Option<String> {
    if config.node.bootstrap_only {
        return None;
    }

    let resolved = resolve_local_validator_address(config);
    let trimmed = resolved.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn local_peer_identity(config: &NodeConfig) -> String {
    let validator_address = announced_validator_address(config);
    peer_identity_key(&config.p2p.node_name, validator_address.as_deref())
}

fn peer_identity_key(node_id: &str, validator_address: Option<&str>) -> String {
    validator_address
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("validator:{value}"))
        .unwrap_or_else(|| format!("node:{}", node_id.trim()))
}

fn peer_identity_from_connection(peer: &PeerConnection) -> Option<String> {
    peer.node_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|node_id| peer_identity_key(node_id, peer.validator_address.as_deref()))
}

fn normalized_status_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn claim_status_rate_limit(
    last_sent: &Mutex<HashMap<String, (u64, u64)>>,
    peer_address: &str,
    session_id: u64,
    now: u64,
    min_interval_secs: u64,
) -> bool {
    let mut entries = last_sent
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((last_session_id, last_sent_at)) = entries.get(peer_address).copied() {
        if last_session_id == session_id && now.saturating_sub(last_sent_at) < min_interval_secs {
            return false;
        }
    }

    entries.insert(peer_address.to_string(), (session_id, now));
    if entries.len() > MAX_STATUS_RATE_LIMIT_ENTRIES {
        if let Some((oldest_peer, _)) = entries
            .iter()
            .min_by_key(|(_, (_, sent_at))| *sent_at)
            .map(|(peer, entry)| (peer.clone(), *entry))
        {
            entries.remove(&oldest_peer);
        }
    }
    true
}

fn should_request_status(peer_address: &str, session_id: u64) -> bool {
    claim_status_rate_limit(
        &STATUS_REQUEST_LAST_SENT,
        peer_address,
        session_id,
        current_timestamp(),
        STATUS_REQUEST_MIN_INTERVAL_SECS,
    )
}

fn should_send_status_response(peer_address: &str, session_id: u64) -> bool {
    claim_status_rate_limit(
        &STATUS_RESPONSE_LAST_SENT,
        peer_address,
        session_id,
        current_timestamp(),
        STATUS_RESPONSE_MIN_INTERVAL_SECS,
    )
}

fn peer_has_remote_status(peer: &PeerConnection) -> bool {
    peer.status_received_at.is_some() && !peer.genesis_hash.trim().is_empty()
}

fn peer_status_age_secs_at(peer: &PeerConnection, now: u64) -> Option<u64> {
    peer.status_received_at
        .map(|received_at| now.saturating_sub(received_at))
}

fn peer_has_fresh_remote_status_at(peer: &PeerConnection, now: u64) -> bool {
    !peer.genesis_hash.trim().is_empty()
        && peer_status_age_secs_at(peer, now)
            .map(|age| age <= PEER_STATUS_FRESHNESS_TTL_SECS)
            .unwrap_or(false)
}

fn peer_has_status_ready_lease_at(peer: &PeerConnection, now: u64) -> bool {
    !peer.genesis_hash.trim().is_empty()
        && peer_status_age_secs_at(peer, now)
            .map(|age| age <= STATUS_READY_TTL_SECS)
            .unwrap_or(false)
}

fn peer_quarantine_active_at(peer: &PeerConnection, now: u64) -> bool {
    peer.quarantined
        && peer_status_age_secs_at(peer, now)
            .map(|age| age <= QUARANTINE_STATUS_TTL_SECS)
            .unwrap_or(false)
}

fn peer_duties_disabled_active_at(peer: &PeerConnection, now: u64) -> bool {
    peer.consensus_duties_disabled
        && peer_status_age_secs_at(peer, now)
            .map(|age| age <= DUTY_DISABLED_TTL_SECS)
            .unwrap_or(false)
}

fn peer_readiness_exclusion_reason_at(
    peer: &PeerConnection,
    now: u64,
    expected_validator_set_hash: Option<&str>,
) -> Option<&'static str> {
    if !peer_has_validator_identity(peer) {
        return Some("missing-validator-identity");
    }
    if !peer_has_status_ready_lease_at(peer, now) {
        return Some("stale-status");
    }
    if peer_quarantine_active_at(peer, now) {
        return Some("quarantined");
    }
    if peer_duties_disabled_active_at(peer, now) {
        return Some("duty-disabled");
    }

    let expected_validator_set_hash = expected_validator_set_hash
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let peer_validator_set_hash = peer
        .active_validator_set_hash
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let (Some(expected), Some(peer_hash)) =
        (expected_validator_set_hash, peer_validator_set_hash)
    {
        if peer_hash != expected {
            return Some("wrong-validator-set-hash");
        }
    }

    None
}

fn peer_has_identifying_metadata(peer: &PeerConnection) -> bool {
    peer.node_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
        || peer
            .validator_address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some()
        || peer
            .public_address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some()
}

fn peer_has_validator_identity(peer: &PeerConnection) -> bool {
    peer.validator_address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
}

fn peer_matches_address(peer: &PeerConnection, requested_address: &str) -> bool {
    let requested_address = requested_address.trim();
    peer.address.trim() == requested_address
        || peer
            .public_address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            == Some(requested_address)
        || peer
            .validator_address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            == Some(requested_address)
}

fn peer_is_public_history_gateway(peer: &PeerConnection) -> bool {
    peer.handshake_role
        .as_deref()
        .map(|role| {
            matches!(
                role.trim().to_ascii_lowercase().as_str(),
                "rpc_gateway"
                    | "rpc_gateway_node"
                    | "archive_validator"
                    | "archive_validator_node"
                    | "indexer_explorer"
                    | "indexer_and_explorer_node"
            )
        })
        .unwrap_or(false)
        && PUBLIC_HISTORY_GATEWAY_DIAL_ADDRESSES.iter().any(|address| {
            peer.connected_endpoint.as_deref().is_some_and(|endpoint| {
                connected_endpoint_matches_configured_address(endpoint, address)
            })
        })
}

fn peer_has_authenticated_public_history_gateway_status(
    peer: &PeerConnection,
    local_genesis_hash: &str,
) -> bool {
    !local_genesis_hash.trim().is_empty()
        && peer.genesis_hash.trim() == local_genesis_hash
        && peer_is_public_history_gateway(peer)
}

fn connected_peer_key_for_address(peers: &PeerMap, requested_address: &str) -> Option<String> {
    if peers.contains_key(requested_address) {
        return Some(requested_address.to_string());
    }

    peers.iter().find_map(|(address, peer)| {
        peer_matches_address(peer, requested_address).then(|| address.clone())
    })
}

fn peer_socket_port(address: &str) -> Option<u16> {
    let normalized = parse_bootnode_dial_address(address)?;
    normalized
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
}

fn genesis_validator_slot_from_text(value: &str) -> Option<usize> {
    let lower = value.trim().to_ascii_lowercase();
    let marker = "genesisval";
    let start = lower.find(marker)? + marker.len();
    let digits = lower[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<usize>().ok().filter(|slot| *slot > 0)
}

fn canonical_validator_address_for_slot(slot: usize) -> Option<String> {
    canonical_genesis()
        .ok()
        .and_then(|genesis| {
            genesis
                .validators()
                .get(slot.saturating_sub(1))
                .map(|validator| validator.operator_address.clone())
        })
        .filter(|address| !address.trim().is_empty())
}

fn configured_vote_target_validator_addresses(
    config: &NodeConfig,
    active_validator_addresses: &HashSet<String>,
) -> Vec<String> {
    let mut configured = config
        .node
        .allowed_validator_addresses
        .iter()
        .map(|address| address.trim().to_string())
        .filter(|address| !address.is_empty())
        .collect::<Vec<_>>();

    if configured.is_empty() {
        if let Ok(genesis) = canonical_genesis() {
            configured = genesis
                .validators()
                .iter()
                .map(|validator| validator.operator_address.trim().to_string())
                .filter(|address| !address.is_empty())
                .collect();
        }
    }

    configured.extend(
        current_validator_transports()
            .into_keys()
            .filter(|address| {
                active_validator_addresses.is_empty()
                    || active_validator_addresses.contains(address)
            }),
    );

    configured.retain(|address| {
        active_validator_addresses.is_empty() || active_validator_addresses.contains(address)
    });
    configured.sort();
    configured.dedup();
    configured
}

fn configured_validator_p2p_dials(config: &NodeConfig) -> Vec<String> {
    let mut dials = Vec::new();
    let mut seen = HashSet::new();

    for dial in config
        .network
        .persistent_peers
        .iter()
        .chain(config.network.additional_dial_targets.iter())
    {
        let Some(parsed) = parse_bootnode_dial_address(dial) else {
            continue;
        };
        if peer_socket_port(&parsed) != Some(VALIDATOR_P2P_PORT) {
            continue;
        }
        if !is_assigned_synergy_dial_address(&parsed) {
            continue;
        }
        let host = peer_socket_host(&parsed).to_ascii_lowercase();
        if host.contains("relay")
            || host.contains("rpc")
            || host.contains("archive")
            || host.contains("bootnode")
            || host.contains("seed")
            || host.contains("observer")
        {
            continue;
        }
        if seen.insert(parsed.clone()) {
            dials.push(parsed);
        }
    }

    dials
}

fn configured_validator_public_address_map(
    config: &NodeConfig,
    active_validator_addresses: &HashSet<String>,
) -> HashMap<String, String> {
    // Testnet-v3 peer identity model.
    //
    // A Synergy peer is identified ONLY by its `synv...` node address. A public
    // IP, VPN IP or port is a ROUTE, never an identity. An endpoint therefore
    // resolves to a node identity only through an EXPLICIT binding:
    //   * a dial target that is itself a `synv...` address,
    //   * `network.validator_vpn_transports` (validator_address <-> dial_address),
    //   * transports learned from an authenticated session.
    //
    // Identity is never inferred from the ORDER of configured dial targets. On
    // Testnet-v3 two distinct machines (Val4 and the archive validator) share the
    // public endpoint 73.79.66.255:5622, so an endpoint can never by itself
    // designate a node. Any endpoint claimed by more than one validator is
    // dropped as ambiguous rather than resolved to an arbitrary one.
    let validators = configured_vote_target_validator_addresses(config, active_validator_addresses);
    if validators.is_empty() {
        return HashMap::new();
    }
    let active_filter = validators.iter().cloned().collect::<HashSet<_>>();

    let mut map: HashMap<String, String> = HashMap::new();
    let mut ambiguous: HashSet<String> = HashSet::new();

    fn bind(
        map: &mut HashMap<String, String>,
        ambiguous: &mut HashSet<String>,
        key: String,
        validator: &str,
    ) {
        if key.trim().is_empty() {
            return;
        }
        match map.get(&key) {
            Some(existing) if existing != validator => {
                // Two different node identities claim the same route: the route
                // is ambiguous and must not identify either of them.
                ambiguous.insert(key);
            }
            _ => {
                map.insert(key, validator.to_string());
            }
        }
    }

    // 1. Dial targets that are themselves node identities.
    for target in config
        .network
        .persistent_peers
        .iter()
        .chain(config.network.additional_dial_targets.iter())
    {
        if let Some(validator) = normalize_validator_address_target(target) {
            if active_filter.contains(&validator) {
                bind(&mut map, &mut ambiguous, validator.clone(), &validator);
            }
        }
    }

    // 2. Explicit endpoint <-> node-identity bindings from the topology config.
    for transport in &config.network.validator_vpn_transports {
        let Some(validator) = normalize_validator_address_target(&transport.validator_address)
        else {
            continue;
        };
        if !active_filter.contains(&validator) {
            continue;
        }
        bind(&mut map, &mut ambiguous, validator.clone(), &validator);
        let dial = transport.dial_address.trim();
        if dial.is_empty() {
            continue;
        }
        if let Some(parsed) = parse_bootnode_dial_address(dial) {
            bind(&mut map, &mut ambiguous, parsed.clone(), &validator);
            let host = peer_socket_host(&parsed);
            if !host.trim().is_empty() {
                bind(
                    &mut map,
                    &mut ambiguous,
                    format!("{host}:{VALIDATOR_P2P_PORT}"),
                    &validator,
                );
            }
        } else {
            bind(&mut map, &mut ambiguous, dial.to_string(), &validator);
        }
    }

    // 3. Transports learned from authenticated sessions.
    for (validator, transport) in current_validator_transports() {
        if !active_filter.contains(&validator) {
            continue;
        }
        bind(&mut map, &mut ambiguous, validator.clone(), &validator);
        let dial = transport.trim();
        if dial.is_empty() {
            continue;
        }
        if let Some(parsed) = parse_bootnode_dial_address(dial) {
            bind(&mut map, &mut ambiguous, parsed.clone(), &validator);
            let host = peer_socket_host(&parsed);
            if !host.trim().is_empty() {
                bind(
                    &mut map,
                    &mut ambiguous,
                    format!("{host}:{VALIDATOR_P2P_PORT}"),
                    &validator,
                );
            }
        } else {
            bind(&mut map, &mut ambiguous, dial.to_string(), &validator);
        }
    }

    for key in ambiguous {
        map.remove(&key);
    }
    map
}

fn recover_peer_validator_address_for_vote_target(
    config: &NodeConfig,
    peer: &PeerConnection,
    active_validator_addresses: &HashSet<String>,
) -> Option<String> {
    let enforce_active_validator_filter = !config.node.allowed_validator_addresses.is_empty();
    if let Some(validator_address) = peer
        .validator_address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !enforce_active_validator_filter
            || active_validator_addresses.is_empty()
            || active_validator_addresses.contains(validator_address)
        {
            return Some(validator_address.to_string());
        }
    }

    for identity_text in [
        peer.node_id.as_deref(),
        peer.public_address.as_deref(),
        Some(peer.address.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(slot) = genesis_validator_slot_from_text(identity_text) {
            if let Some(validator_address) = canonical_validator_address_for_slot(slot) {
                if active_validator_addresses.is_empty()
                    || active_validator_addresses.contains(&validator_address)
                {
                    return Some(validator_address);
                }
            }
        }
    }

    let address_map = configured_validator_public_address_map(config, active_validator_addresses);
    for candidate in [peer.public_address.as_deref(), Some(peer.address.as_str())]
        .into_iter()
        .flatten()
    {
        if let Some(validator_address) = normalize_validator_address_target(candidate) {
            if active_validator_addresses.is_empty()
                || active_validator_addresses.contains(&validator_address)
            {
                return Some(validator_address);
            }
        }
        let Some(parsed) = parse_bootnode_dial_address(candidate) else {
            continue;
        };
        if let Some(validator_address) = address_map.get(&parsed) {
            return Some(validator_address.clone());
        }
        let canonical = canonical_validator_public_address(&parsed, Some(&parsed));
        if let Some(canonical) = canonical {
            if let Some(validator_address) = address_map.get(&canonical) {
                return Some(validator_address.clone());
            }
        }
    }

    None
}

fn should_prune_stale_peer(
    config: &NodeConfig,
    peer: &PeerConnection,
    now: u64,
    active_validator_addresses: &HashSet<String>,
) -> bool {
    let connected_age = now.saturating_sub(peer.connected_at);
    let recovered_validator =
        recover_peer_validator_address_for_vote_target(config, peer, active_validator_addresses);
    let has_identifying_metadata =
        peer_has_identifying_metadata(peer) || recovered_validator.is_some();

    if !has_identifying_metadata {
        return connected_age >= STALE_UNIDENTIFIED_PEER_SECS;
    }

    let recently_seen = now.saturating_sub(peer.last_seen) <= STALE_VALIDATOR_STATUS_SECS;

    (peer_has_validator_identity(peer) || recovered_validator.is_some())
        && !peer_has_fresh_remote_status_at(peer, now)
        && connected_age >= STALE_VALIDATOR_STATUS_SECS
        && !recently_seen
}

fn prune_stale_peers(
    config: &NodeConfig,
    peer_state_cache: &PeerStateCacheArc,
    connected_peers: &PeersArc,
) {
    let now = current_timestamp();
    let active_validator_addresses =
        consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators())
            .into_iter()
            .map(|validator| validator.address)
            .collect::<HashSet<_>>();
    let mut peers = connected_peers.lock().unwrap();
    let stale_peer_keys = peers
        .iter()
        .filter_map(|(peer_key, peer)| {
            should_prune_stale_peer(config, peer, now, &active_validator_addresses)
                .then_some(peer_key.clone())
        })
        .collect::<Vec<_>>();

    for peer_key in stale_peer_keys {
        if let Some(peer) = peers.get(&peer_key) {
            warn!(
                "p2p",
                "Disconnecting stale peer to force mesh recovery",
                "peer" => peer_key.clone(),
                "direction" => format!("{:?}", peer.direction),
                "connected_age_secs" => now.saturating_sub(peer.connected_at),
                "last_seen_age_secs" => now.saturating_sub(peer.last_seen),
                "validator_address" => peer.validator_address.clone().unwrap_or_default(),
                "has_identifying_metadata" => peer_has_identifying_metadata(peer)
                    || recover_peer_validator_address_for_vote_target(
                        config,
                        peer,
                        &active_validator_addresses,
                    )
                    .is_some(),
                "has_remote_status" => peer_has_remote_status(peer),
                "has_fresh_remote_status" => peer_has_fresh_remote_status_at(peer, now)
            );
        }
        disconnect_peer_entry(peer_state_cache, &mut peers, &peer_key);
    }
}

fn pending_incoming_connections_from_host(peers: &PeerMap, host: &str) -> usize {
    peers
        .values()
        .filter(|peer| {
            peer.direction == ConnectionDirection::Incoming
                && peer_socket_host(&peer.address) == host
                && !peer_has_identifying_metadata(peer)
        })
        .count()
}

fn build_cached_peer_state(peer: &PeerConnection) -> Option<(String, CachedPeerState)> {
    let identity = peer_identity_from_connection(peer)?;
    Some((
        identity,
        CachedPeerState {
            public_address: peer.public_address.clone(),
            validator_address: peer.validator_address.clone(),
            node_id: peer.node_id.clone(),
            handshake_role: peer.handshake_role.clone(),
            version: peer.version.clone(),
            capabilities: peer.capabilities.clone(),
            last_known_height: peer.last_known_height,
            best_block_hash: peer.best_block_hash.clone(),
            genesis_hash: peer.genesis_hash.clone(),
            status_received_at: peer.status_received_at,
            status_reported_at: peer.status_reported_at,
            status_validator_address: peer.status_validator_address.clone(),
            status_source_session_id: peer.status_source_session_id.clone(),
            active_validator_set_hash: peer.active_validator_set_hash.clone(),
            quarantined: peer.quarantined,
            consensus_duties_disabled: peer.consensus_duties_disabled,
            recovery_state: peer.recovery_state.clone(),
            last_seen: peer.last_seen,
            connected_at: peer.connected_at,
        },
    ))
}

fn cache_peer_state(peer_state_cache: &PeerStateCacheArc, peer: &PeerConnection) {
    if let Some((identity, state)) = build_cached_peer_state(peer) {
        if let Ok(mut cache) = peer_state_cache.lock() {
            cache.insert(identity, state);
        }
    }
}

fn merge_cached_state_into_peer(peer: &mut PeerConnection, state: &CachedPeerState) {
    if peer
        .public_address
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .is_empty()
    {
        peer.public_address = state.public_address.clone();
    }
    if peer
        .validator_address
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .is_empty()
    {
        peer.validator_address = state.validator_address.clone();
    }
    if peer.node_id.is_none() {
        peer.node_id = state.node_id.clone();
    }
    if peer.handshake_role.is_none() {
        peer.handshake_role = state.handshake_role.clone();
    }
    if peer.version.is_none() {
        peer.version = state.version.clone();
    }
    if peer.capabilities.is_empty() {
        peer.capabilities = state.capabilities.clone();
    }
    let now = current_timestamp();
    let cached_status_is_fresh = state
        .status_received_at
        .map(|received_at| now.saturating_sub(received_at) <= PEER_STATUS_FRESHNESS_TTL_SECS)
        .unwrap_or(false);
    let hydrated_status_from_cache = peer.status_received_at.is_none()
        && state.status_received_at.is_some()
        && cached_status_is_fresh;
    if hydrated_status_from_cache {
        peer.last_known_height = state.last_known_height;
        peer.best_block_hash = state.best_block_hash.clone();
        peer.genesis_hash = state.genesis_hash.clone();
        peer.status_received_at = state.status_received_at;
        peer.status_reported_at = state.status_reported_at;
        peer.status_validator_address = state.status_validator_address.clone();
        peer.status_source_session_id = state.status_source_session_id.clone();
        peer.active_validator_set_hash = state.active_validator_set_hash.clone();
    }
    if hydrated_status_from_cache {
        peer.quarantined = state.quarantined;
        peer.consensus_duties_disabled = state.consensus_duties_disabled;
    }
    if peer.recovery_state.is_none() && hydrated_status_from_cache {
        peer.recovery_state = state.recovery_state.clone();
    }
    peer.last_seen = peer.last_seen.max(state.last_seen);
    peer.connected_at = if peer.connected_at == 0 {
        state.connected_at
    } else if state.connected_at == 0 {
        peer.connected_at
    } else {
        peer.connected_at.min(state.connected_at)
    };
}

fn hydrate_peer_from_cache(
    peer_state_cache: &PeerStateCacheArc,
    peer_identity: &str,
    peer: &mut PeerConnection,
) {
    if let Ok(cache) = peer_state_cache.lock() {
        if let Some(state) = cache.get(peer_identity) {
            merge_cached_state_into_peer(peer, state);
        }
    }
}

fn merge_peer_state_from_existing(existing: &PeerConnection, replacement: &mut PeerConnection) {
    merge_cached_state_into_peer(
        replacement,
        &CachedPeerState {
            public_address: existing.public_address.clone(),
            validator_address: existing.validator_address.clone(),
            node_id: existing.node_id.clone(),
            handshake_role: existing.handshake_role.clone(),
            version: existing.version.clone(),
            capabilities: existing.capabilities.clone(),
            last_known_height: existing.last_known_height,
            best_block_hash: existing.best_block_hash.clone(),
            genesis_hash: existing.genesis_hash.clone(),
            status_received_at: existing.status_received_at,
            status_reported_at: existing.status_reported_at,
            status_validator_address: existing.status_validator_address.clone(),
            status_source_session_id: existing.status_source_session_id.clone(),
            active_validator_set_hash: existing.active_validator_set_hash.clone(),
            quarantined: existing.quarantined,
            consensus_duties_disabled: existing.consensus_duties_disabled,
            recovery_state: existing.recovery_state.clone(),
            last_seen: existing.last_seen,
            connected_at: existing.connected_at,
        },
    );
}

fn propagate_identity_to_matching_peers(
    peers: &mut PeerMap,
    peer_state_cache: &PeerStateCacheArc,
    peer_address: &str,
    node_id: &str,
    version: &str,
    capabilities: &[String],
    public_address: Option<&str>,
    validator_address: Option<&str>,
    genesis_hash: &str,
) {
    let validator_address = validator_address
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let public_address = public_address
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let node_id = node_id.trim();
    if node_id.is_empty() && validator_address.is_none() && public_address.is_none() {
        return;
    }

    let mut source_hosts = HashSet::<String>::new();
    source_hosts.insert(peer_socket_host(peer_address));
    if let Some(public_address) = public_address {
        source_hosts.insert(peer_socket_host(public_address));
    }
    if let Some(peer) = peers.get(peer_address) {
        source_hosts.insert(peer_socket_host(&peer.address));
        if let Some(public_address) = peer.public_address.as_deref() {
            source_hosts.insert(peer_socket_host(public_address));
        }
    }
    source_hosts.retain(|host| !host.trim().is_empty());

    let mut target_keys = peers
        .iter()
        .filter_map(|(address, peer)| {
            if address == peer_address {
                return Some(address.clone());
            }

            let existing_validator = peer
                .validator_address
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let same_validator = validator_address
                .zip(existing_validator)
                .map(|(announced, existing)| announced == existing)
                .unwrap_or(false);
            if existing_validator.is_some() && !same_validator {
                return None;
            }

            let existing_node = peer
                .node_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if existing_node.is_some() && existing_node != Some(node_id) && !same_validator {
                return None;
            }

            let peer_hosts = [
                Some(address.as_str()),
                Some(peer.address.as_str()),
                peer.public_address.as_deref(),
            ];
            let shares_source_host = peer_hosts
                .into_iter()
                .flatten()
                .map(peer_socket_host)
                .any(|host| source_hosts.contains(&host));
            let public_address_matches = public_address
                .map(|public_address| {
                    address.trim() == public_address || peer_matches_address(peer, public_address)
                })
                .unwrap_or(false);

            (peer_matches_address(peer, peer_address)
                || public_address_matches
                || shares_source_host)
                .then(|| address.clone())
        })
        .collect::<Vec<_>>();
    target_keys.sort();
    target_keys.dedup();

    for target_key in target_keys {
        if let Some(peer) = peers.get_mut(&target_key) {
            if !node_id.is_empty() {
                peer.node_id = Some(node_id.to_string());
            }
            if !version.trim().is_empty() {
                peer.version = Some(version.to_string());
            }
            if peer.capabilities.is_empty() {
                peer.capabilities = capabilities.to_vec();
            }
            if let Some(public_address) = public_address {
                peer.public_address = Some(public_address.to_string());
            }
            if let Some(validator_address) = validator_address {
                peer.validator_address = Some(validator_address.to_string());
            }
            if !genesis_hash.trim().is_empty() {
                peer.genesis_hash = genesis_hash.to_string();
            }
            cache_peer_state(peer_state_cache, peer);
        }
    }
}

fn apply_status_to_peer(
    peer: &mut PeerConnection,
    block_height: u64,
    best_block_hash: &str,
    genesis_hash: &str,
    status_reported_at: Option<u64>,
    status_validator_address: Option<&str>,
    status_source_session_id: Option<&str>,
    active_validator_set_hash: Option<&str>,
    quarantined: bool,
    consensus_duties_disabled: bool,
    recovery_state: Option<&str>,
    status_received_at: u64,
) {
    if block_height >= peer.last_known_height {
        peer.last_known_height = block_height;
        if !best_block_hash.trim().is_empty() {
            peer.best_block_hash = best_block_hash.to_string();
        }
    }

    if !genesis_hash.trim().is_empty() {
        peer.genesis_hash = genesis_hash.to_string();
    }

    peer.status_received_at = Some(status_received_at);
    peer.status_reported_at = status_reported_at.or(Some(status_received_at));
    peer.status_validator_address = normalized_status_string(status_validator_address);
    if let Some(source_session_id) = normalized_status_string(status_source_session_id) {
        peer.status_source_session_id = Some(source_session_id);
    } else if peer.status_source_session_id.is_none() {
        peer.status_source_session_id = peer.node_id.clone();
    }
    if let Some(validator_set_hash) = normalized_status_string(active_validator_set_hash) {
        peer.active_validator_set_hash = Some(validator_set_hash);
    }
    peer.quarantined = quarantined;
    peer.consensus_duties_disabled = consensus_duties_disabled || quarantined;
    peer.recovery_state = recovery_state
        .map(str::trim)
        .filter(|state| !state.is_empty())
        .map(ToOwned::to_owned);
}

fn propagate_status_to_matching_peers(
    peers: &mut PeerMap,
    peer_state_cache: &PeerStateCacheArc,
    peer_address: &str,
    block_height: u64,
    best_block_hash: &str,
    genesis_hash: &str,
    status_reported_at: Option<u64>,
    status_validator_address: Option<&str>,
    status_source_session_id: Option<&str>,
    active_validator_set_hash: Option<&str>,
    quarantined: bool,
    consensus_duties_disabled: bool,
    recovery_state: Option<&str>,
) {
    let identity = peers
        .get(peer_address)
        .and_then(peer_identity_from_connection);
    let source_hosts = peers
        .get(peer_address)
        .map(|peer| {
            let mut hosts = HashSet::<String>::new();
            hosts.insert(peer_socket_host(peer_address));
            hosts.insert(peer_socket_host(&peer.address));
            if let Some(public_address) = peer.public_address.as_deref() {
                hosts.insert(peer_socket_host(public_address));
            }
            hosts.retain(|host| !host.trim().is_empty());
            hosts
        })
        .unwrap_or_else(|| {
            let mut hosts = HashSet::<String>::new();
            hosts.insert(peer_socket_host(peer_address));
            hosts.retain(|host| !host.trim().is_empty());
            hosts
        });
    let mut target_keys = identity
        .as_deref()
        .map(|peer_identity| {
            peers
                .iter()
                .filter_map(|(address, peer)| {
                    (peer_identity_from_connection(peer).as_deref() == Some(peer_identity))
                        .then(|| address.clone())
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    for (address, peer) in peers.iter() {
        let peer_hosts = [
            Some(address.as_str()),
            Some(peer.address.as_str()),
            peer.public_address.as_deref(),
        ];
        let shares_source_host = peer_hosts
            .into_iter()
            .flatten()
            .map(peer_socket_host)
            .any(|host| source_hosts.contains(&host));
        if address == peer_address
            || peer_matches_address(peer, peer_address)
            || (peer_has_validator_identity(peer) && shares_source_host)
        {
            target_keys.push(address.clone());
        }
    }

    if target_keys.is_empty() {
        target_keys.push(peer_address.to_string());
    }
    target_keys.sort();
    target_keys.dedup();

    let status_received_at = current_timestamp();
    for target_key in target_keys {
        if let Some(peer) = peers.get_mut(&target_key) {
            apply_status_to_peer(
                peer,
                block_height,
                best_block_hash,
                genesis_hash,
                status_reported_at,
                status_validator_address,
                status_source_session_id,
                active_validator_set_hash,
                quarantined,
                consensus_duties_disabled,
                recovery_state,
                status_received_at,
            );
            cache_peer_state(peer_state_cache, peer);
        }
    }
}

fn sync_batch_limit_for_role(config: &NodeConfig) -> u32 {
    if local_node_runs_validator_consensus(config) {
        MAX_STATUS_SYNC_BATCH
    } else {
        MAX_SUPPORT_NODE_BLOCK_SYNC_RESPONSE_BLOCKS
    }
}

fn status_sync_batch(config: &NodeConfig, block_height: u64, local_height: u64) -> Option<u32> {
    if block_height <= local_height {
        return None;
    }

    let behind = block_height.saturating_sub(local_height);
    if !local_node_runs_validator_consensus(config) {
        return Some(sync_batch_limit_for_role(config));
    }

    Some(if behind > 5000 {
        MAX_STATUS_SYNC_BATCH
    } else if behind > 1000 {
        MAX_STATUS_SYNC_BATCH
    } else {
        IMMEDIATE_STATUS_SYNC_BATCH
    })
}

fn block_sync_request_range(
    local_height: u64,
    remote_height: u64,
    desired_new_blocks: u32,
) -> Option<(u64, u32)> {
    block_sync_request_range_with_overlap(local_height, remote_height, desired_new_blocks, true)
}

fn block_sync_request_range_with_overlap(
    local_height: u64,
    remote_height: u64,
    desired_new_blocks: u32,
    include_reconciliation_overlap: bool,
) -> Option<(u64, u32)> {
    if remote_height <= local_height || desired_new_blocks == 0 {
        return None;
    }

    let overlap = if include_reconciliation_overlap {
        block_sync_progress_overlap(desired_new_blocks)
    } else {
        0
    };
    let request_start = local_height.saturating_sub(overlap);
    let target_height = remote_height.min(local_height.saturating_add(desired_new_blocks as u64));
    let request_count = target_height
        .saturating_sub(request_start)
        .saturating_add(1)
        .min(u32::MAX as u64) as u32;

    Some((request_start, request_count.max(1)))
}

fn block_sync_progress_overlap(desired_new_blocks: u32) -> u64 {
    if desired_new_blocks <= 1 {
        return 0;
    }

    BLOCK_SYNC_RECONCILIATION_LOOKBACK
        .min(BLOCK_SYNC_PROGRESS_OVERLAP)
        .min(desired_new_blocks as u64 - 1)
}

fn chain_has_block_sync_overlap(
    chain: &BlockChain,
    local_height: u64,
    desired_new_blocks: u32,
) -> bool {
    let overlap = block_sync_progress_overlap(desired_new_blocks);
    if overlap == 0 {
        return true;
    }

    let start = local_height.saturating_sub(overlap);
    (start..=local_height).all(|height| chain.block_at_height(height).is_some())
}

fn service_sync_context(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
) -> ServiceSyncContext {
    ServiceSyncContext {
        blockchain: Arc::clone(blockchain),
        connected_peers: Arc::clone(connected_peers),
        peer_state_cache: Arc::clone(peer_state_cache),
        config: config.clone(),
    }
}

fn service_sync_identity(peer_address: &str, session_id: u64) -> ServiceSyncFlightIdentity {
    ServiceSyncFlightIdentity {
        peer_address: peer_address.to_string(),
        session_id,
    }
}

fn service_sync_source_key(peer_address: &str, peer: &PeerConnection) -> String {
    peer_identity_from_connection(peer)
        .filter(|identity| !identity.trim().is_empty())
        .unwrap_or_else(|| peer_address.to_string())
}

fn service_sync_phase_timeout(phase: ServiceSyncPhase) -> Duration {
    match phase {
        ServiceSyncPhase::AwaitingResponse => {
            Duration::from_secs(SERVICE_BLOCK_SYNC_RESPONSE_TIMEOUT_SECS)
        }
        ServiceSyncPhase::Applying => Duration::from_secs(SERVICE_BLOCK_SYNC_APPLY_TIMEOUT_SECS),
    }
}

fn service_sync_flight_expired(flight: &ServiceSyncFlight) -> bool {
    flight.phase_started_at.elapsed() >= service_sync_phase_timeout(flight.phase)
}

fn service_sync_has_active_flight() -> bool {
    SERVICE_SYNC_COORDINATOR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .in_flight
        .as_ref()
        .map(|flight| !service_sync_flight_expired(flight))
        .unwrap_or(false)
}

fn service_sync_expired_identity() -> Option<ServiceSyncFlightIdentity> {
    SERVICE_SYNC_COORDINATOR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .in_flight
        .as_ref()
        .filter(|flight| service_sync_flight_expired(flight))
        .map(|flight| flight.identity.clone())
}

fn service_sync_watchdog(generation: u64) {
    loop {
        thread::sleep(Duration::from_secs(1));
        let (expired_identity, extended_active_apply) = {
            let mut coordinator = SERVICE_SYNC_COORDINATOR
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(flight) = coordinator.in_flight.as_mut() else {
                return;
            };
            if flight.generation != generation {
                return;
            }
            if !service_sync_flight_expired(flight) {
                (None, false)
            } else if flight.phase == ServiceSyncPhase::Applying
                && BLOCK_SYNC_APPLY_ACTIVE
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .contains(&block_sync_peer_key(
                        &flight.identity.peer_address,
                        flight.identity.session_id,
                    ))
            {
                // The apply worker is ordered and exclusive. Reassigning while it still owns
                // the slot would only queue overlapping work and strand the replacement flight.
                flight.phase_started_at = Instant::now();
                (None, true)
            } else {
                (Some(flight.identity.clone()), false)
            }
        };
        if extended_active_apply {
            warn!(
                "p2p",
                "Service block sync apply exceeded watchdog interval but remains active"
            );
        }
        if let Some(identity) = expired_identity {
            service_sync_release_and_reassign(generation, Some(identity), false);
            return;
        }
    }
}

fn service_sync_start_flight(
    context: ServiceSyncContext,
    peer_address: String,
    session_id: u64,
    remote_height: u64,
    from_height: u64,
    count: u32,
    expected_generation: Option<u64>,
) -> bool {
    if count == 0 {
        return false;
    }

    let authorized = context
        .connected_peers
        .lock()
        .ok()
        .and_then(|peers| {
            peers.get(&peer_address).map(|peer| {
                peer_is_eligible_block_sync_source_for_local(&context.config, peer)
                    && current_peer_session_id(&peer_address) == Some(session_id)
            })
        })
        .unwrap_or(false);
    if !authorized {
        debug!(
            "p2p",
            "Refusing service block sync request to unauthorized source",
            "peer" => peer_address.clone(),
            "session_id" => session_id
        );
        return false;
    }

    let source_key = context
        .connected_peers
        .lock()
        .ok()
        .and_then(|peers| {
            peers
                .get(&peer_address)
                .map(|peer| service_sync_source_key(&peer_address, peer))
        })
        .unwrap_or_else(|| peer_address.clone());

    let identity = service_sync_identity(&peer_address, session_id);
    let (generation, expired_flight) = {
        let mut coordinator = SERVICE_SYNC_COORDINATOR
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if expected_generation
            .map(|expected| coordinator.next_generation != expected)
            .unwrap_or(false)
        {
            return false;
        }
        if coordinator
            .in_flight
            .as_ref()
            .map(|flight| !service_sync_flight_expired(flight))
            .unwrap_or(false)
        {
            return false;
        }
        if !coordinator.attempted_sources.insert(source_key) {
            debug!(
                "p2p",
                "Refusing to retry an authenticated service sync source in the same attempt",
                "peer" => peer_address.clone()
            );
            return false;
        }

        let expired_flight = coordinator.in_flight.take();
        coordinator.next_generation = coordinator.next_generation.wrapping_add(1);
        let generation = coordinator.next_generation;
        coordinator.in_flight = Some(ServiceSyncFlight {
            generation,
            identity: identity.clone(),
            from_height,
            count,
            remote_height,
            phase: ServiceSyncPhase::AwaitingResponse,
            phase_started_at: Instant::now(),
            context: context.clone(),
        });
        (generation, expired_flight)
    };

    if let Some(expired) = expired_flight {
        warn!(
            "p2p",
            "Replacing expired service block sync flight",
            "peer" => expired.identity.peer_address,
            "phase" => format!("{:?}", expired.phase),
            "from_height" => expired.from_height,
            "count" => expired.count as u64
        );
    }

    let request = NetworkMessage::GetBlocks { from_height, count };
    match send_peer_message_for_session(
        &context.connected_peers,
        &context.peer_state_cache,
        &peer_address,
        session_id,
        &request,
        Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
        "service-block-request",
    ) {
        Ok(true) => {
            #[cfg(not(test))]
            if !spawn_named_thread("p2p-service-sync-watchdog", move || {
                service_sync_watchdog(generation);
            }) {
                service_sync_release_and_reassign(generation, Some(identity), false);
                return false;
            }
            true
        }
        Ok(false) | Err(_) => {
            service_sync_release_and_reassign(generation, Some(identity), false);
            false
        }
    }
}

fn service_sync_start_next(
    context: &ServiceSyncContext,
    excluded: Option<&ServiceSyncFlightIdentity>,
    preferred: Option<&ServiceSyncFlightIdentity>,
    expected_generation: Option<u64>,
) -> bool {
    if service_sync_has_active_flight() {
        return false;
    }
    let expired_identity = service_sync_expired_identity();

    let local_height = context
        .blockchain
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .last()
        .map(|block| block.block_index)
        .unwrap_or(0);
    let batch = sync_batch_limit_for_role(&context.config);
    let include_reconciliation_overlap = {
        let chain = context
            .blockchain
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        chain_has_block_sync_overlap(&chain, local_height, batch)
    };
    let mut candidates = {
        let peers = context
            .connected_peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        peers
            .iter()
            .filter_map(|(address, peer)| {
                if peer.stream.is_none()
                    || !peer_is_eligible_block_sync_source_for_local(&context.config, peer)
                    || peer.last_known_height <= local_height
                {
                    return None;
                }
                let session_id = current_peer_session_id(address)?;
                Some((
                    address.clone(),
                    session_id,
                    peer.last_known_height,
                    peer.status_received_at.unwrap_or(0),
                ))
            })
            .collect::<Vec<_>>()
    };
    if let Some(identity) = excluded {
        candidates.retain(|(address, session_id, _, _)| {
            identity.peer_address != *address || identity.session_id != *session_id
        });
    } else if let Some(identity) = expired_identity.as_ref() {
        if candidates.len() > 1 {
            candidates.retain(|(address, session_id, _, _)| {
                identity.peer_address != *address || identity.session_id != *session_id
            });
        }
    }
    candidates.sort_by(|left, right| {
        let left_preferred = preferred
            .map(|identity| identity.peer_address == left.0 && identity.session_id == left.1)
            .unwrap_or(false);
        let right_preferred = preferred
            .map(|identity| identity.peer_address == right.0 && identity.session_id == right.1)
            .unwrap_or(false);
        right_preferred
            .cmp(&left_preferred)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| left.0.cmp(&right.0))
    });

    for (peer_address, session_id, remote_height, _) in candidates {
        let Some((from_height, count)) = block_sync_request_range_with_overlap(
            local_height,
            remote_height,
            batch,
            include_reconciliation_overlap,
        ) else {
            continue;
        };
        if service_sync_start_flight(
            context.clone(),
            peer_address,
            session_id,
            remote_height,
            from_height,
            count,
            expected_generation,
        ) {
            return true;
        }
    }
    false
}

fn service_sync_release_and_reassign(
    generation: u64,
    failed_identity: Option<ServiceSyncFlightIdentity>,
    continue_with_same_source: bool,
) {
    let flight = {
        let mut coordinator = SERVICE_SYNC_COORDINATOR
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matches_generation = coordinator
            .in_flight
            .as_ref()
            .map(|flight| flight.generation == generation)
            .unwrap_or(false);
        if matches_generation {
            coordinator.in_flight.take()
        } else {
            None
        }
    };
    let Some(flight) = flight else {
        return;
    };

    let identity = failed_identity.unwrap_or_else(|| flight.identity.clone());
    if continue_with_same_source {
        {
            let mut coordinator = SERVICE_SYNC_COORDINATOR
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if coordinator.next_generation != generation {
                return;
            }
            coordinator.attempted_sources.clear();
        }
        let _ = service_sync_start_next(&flight.context, None, Some(&identity), Some(generation));
    } else {
        let _ = service_sync_start_next(&flight.context, Some(&identity), None, Some(generation));
    }
}

fn service_sync_request_from_status(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
) -> bool {
    {
        let mut coordinator = SERVICE_SYNC_COORDINATOR
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if coordinator.in_flight.is_none() && !coordinator.attempted_sources.is_empty() {
            // A fresh authenticated status event is the explicit boundary for a
            // new sync attempt. The preceding attempt remains bounded to one
            // request per source, while the generation bump prevents stale
            // watchdog/disconnect work from re-entering this attempt.
            coordinator.next_generation = coordinator.next_generation.wrapping_add(1);
            coordinator.attempted_sources.clear();
        }
    }
    service_sync_start_next(
        &service_sync_context(blockchain, connected_peers, peer_state_cache, config),
        None,
        None,
        None,
    )
}

fn service_sync_request_explicit(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    session_id: u64,
    from_height: u64,
    count: u32,
) -> bool {
    let remote_height = connected_peers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(peer_address)
        .map(|peer| peer.last_known_height)
        .unwrap_or(0);
    service_sync_start_flight(
        service_sync_context(blockchain, connected_peers, peer_state_cache, config),
        peer_address.to_string(),
        session_id,
        remote_height,
        from_height,
        count,
        None,
    )
}

fn service_sync_response_matches(
    flight: &ServiceSyncFlight,
    peer_address: &str,
    session_id: u64,
    blocks: &[Block],
) -> bool {
    if flight.identity.peer_address != peer_address || flight.identity.session_id != session_id {
        return false;
    }
    if blocks.is_empty() {
        return true;
    }

    let response_start = blocks
        .iter()
        .map(|block| block.block_index)
        .min()
        .unwrap_or(0);
    let response_end = blocks
        .iter()
        .map(|block| block.block_index)
        .max()
        .unwrap_or(0);
    let requested_end = flight
        .from_height
        .saturating_add(flight.count.saturating_sub(1) as u64);
    response_start <= flight.remote_height
        && response_start <= requested_end
        && response_end >= flight.from_height
}

fn service_sync_claim_response(
    peer_address: &str,
    session_id: u64,
    blocks: &[Block],
) -> Option<u64> {
    let mut coordinator = SERVICE_SYNC_COORDINATOR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let flight = coordinator.in_flight.as_mut()?;
    if flight.phase != ServiceSyncPhase::AwaitingResponse
        || !service_sync_response_matches(flight, peer_address, session_id, blocks)
    {
        return None;
    }
    flight.phase = ServiceSyncPhase::Applying;
    flight.phase_started_at = Instant::now();
    Some(flight.generation)
}

fn service_sync_generation_for_response(
    peer_address: &str,
    session_id: u64,
    blocks: &[Block],
) -> Option<u64> {
    let coordinator = SERVICE_SYNC_COORDINATOR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let flight = coordinator.in_flight.as_ref()?;
    (flight.phase == ServiceSyncPhase::Applying
        && service_sync_response_matches(flight, peer_address, session_id, blocks))
    .then_some(flight.generation)
}

fn service_sync_retry_is_current(
    peer_address: &str,
    session_id: u64,
    from_height: u64,
    count: u32,
) -> bool {
    SERVICE_SYNC_COORDINATOR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .in_flight
        .as_ref()
        .map(|flight| {
            flight.phase == ServiceSyncPhase::AwaitingResponse
                && flight.identity.peer_address == peer_address
                && flight.identity.session_id == session_id
                && flight.from_height == from_height
                && flight.count == count
                && !service_sync_flight_expired(flight)
        })
        .unwrap_or(false)
}

fn service_sync_release_disconnected_peer(peer_address: &str, session_id: Option<u64>) {
    let flight = {
        let mut coordinator = SERVICE_SYNC_COORDINATOR
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let should_release = coordinator
            .in_flight
            .as_ref()
            .map(|flight| {
                flight.identity.peer_address == peer_address
                    && session_id
                        .map(|session_id| flight.identity.session_id == session_id)
                        .unwrap_or(true)
            })
            .unwrap_or(false);
        should_release
            .then(|| coordinator.in_flight.take())
            .flatten()
    };
    let Some(flight) = flight else {
        return;
    };

    let identity = flight.identity.clone();
    let generation = flight.generation;
    let _ = spawn_named_thread("p2p-service-sync-disconnect", move || {
        let _ = service_sync_start_next(&flight.context, Some(&identity), None, Some(generation));
    });
}

#[cfg(test)]
fn reset_service_sync_coordinator_for_tests() {
    let mut coordinator = SERVICE_SYNC_COORDINATOR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    coordinator.next_generation = coordinator.next_generation.wrapping_add(1);
    coordinator.in_flight = None;
    coordinator.attempted_sources.clear();
}

fn handle_status_message(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    session_id: u64,
    block_height: u64,
    best_block_hash: &str,
    genesis_hash: &str,
    status_reported_at: Option<u64>,
    status_validator_address: Option<&str>,
    status_source_session_id: Option<&str>,
    active_validator_set_hash: Option<&str>,
    quarantined: bool,
    consensus_duties_disabled: bool,
    recovery_state: Option<&str>,
) {
    if config.node.bootstrap_only {
        debug!(
            "p2p",
            "Bootstrap-only node ignoring remote chain status",
            "peer" => peer_address.to_string(),
            "height" => block_height
        );
        return;
    }

    if !authorize_status_exchange_for_session(
        connected_peers,
        peer_state_cache,
        peer_address,
        session_id,
        "status",
    ) {
        return;
    }

    let local_genesis_hash = resolve_local_genesis_hash(blockchain);
    let (
        peer_validator_address,
        peer_connected_at,
        peer_is_active_validator,
        peer_is_designated_support,
        peer_is_designated_relayer,
        status_validator_identity_matches,
    ) = {
        let peers = connected_peers.lock().unwrap();
        if !peer_session_is_current(peer_address, session_id) {
            return;
        }
        peers
            .get(peer_address)
            .map(|peer| {
                (
                    peer.validator_address.clone(),
                    peer.connected_at,
                    peer_is_active_consensus_validator(config, peer),
                    peer_is_designated_support_sync_source(config, peer),
                    peer_is_designated_relayer_sync_source(config, peer),
                    status_validator_identity_matches_handshake(peer, status_validator_address),
                )
            })
            .unwrap_or((None, current_timestamp(), false, false, false, false))
    };
    if !status_validator_identity_matches {
        warn!(
            "p2p",
            "Disconnecting peer whose status identity does not match its verified handshake",
            "peer" => peer_address.to_string(),
            "handshake_validator_address" => peer_validator_address.clone().unwrap_or_default(),
            "status_validator_address" => status_validator_address.unwrap_or_default().to_string()
        );
        let mut peers = connected_peers.lock().unwrap();
        disconnect_peer_entry_for_session(peer_state_cache, &mut peers, peer_address, session_id);
        return;
    }
    let now = current_timestamp();
    if local_node_runs_validator_consensus(config)
        && (quarantined || consensus_duties_disabled)
        && !peer_is_designated_support
        && !(quarantined && peer_is_active_validator)
    {
        warn!(
            "p2p",
            "Disconnecting duty-disabled or quarantined non-support peer",
            "peer" => peer_address.to_string(),
            "validator_address" => peer_validator_address.clone().unwrap_or_default(),
            "quarantined" => quarantined,
            "consensus_duties_disabled" => consensus_duties_disabled,
            "recovery_state" => recovery_state.unwrap_or_default().to_string()
        );
        let mut peers = connected_peers.lock().unwrap();
        disconnect_peer_entry_for_session(peer_state_cache, &mut peers, peer_address, session_id);
        return;
    }
    let validator_genesis_pending = genesis_hash.is_empty()
        && peer_validator_address
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        && validator_status_genesis_within_grace_window(peer_connected_at, now);
    if validator_genesis_pending {
        {
            let mut peers = connected_peers.lock().unwrap();
            if !peer_session_is_current(peer_address, session_id) {
                return;
            }
            propagate_status_to_matching_peers(
                &mut peers,
                peer_state_cache,
                peer_address,
                block_height,
                best_block_hash,
                genesis_hash,
                status_reported_at,
                status_validator_address,
                status_source_session_id,
                active_validator_set_hash,
                quarantined,
                consensus_duties_disabled,
                recovery_state,
            );
        }
        request_status_from_connected_peer(
            connected_peers,
            peer_state_cache,
            peer_address,
            session_id,
        );
        info!(
            "p2p",
            "Validator status pending canonical genesis sync",
            "peer" => peer_address.to_string(),
            "validator_address" => peer_validator_address.clone().unwrap_or_default(),
            "connected_secs" => now.saturating_sub(peer_connected_at),
            "grace_remaining_secs" => validator_status_genesis_grace_remaining_secs(peer_connected_at, now),
            "reported_height" => block_height
        );
        return;
    }

    if should_disconnect_for_status_genesis_mismatch(
        &local_genesis_hash,
        genesis_hash,
        peer_validator_address.as_deref(),
    ) {
        warn!(
            "p2p",
            "Disconnecting peer with mismatched genesis hash",
            "peer" => peer_address.to_string(),
            "local_genesis_hash" => local_genesis_hash,
            "remote_genesis_hash" => genesis_hash.to_string()
        );
        let mut peers = connected_peers.lock().unwrap();
        disconnect_peer_entry_for_session(peer_state_cache, &mut peers, peer_address, session_id);
        return;
    }

    if genesis_hash.is_empty() {
        debug!(
            "p2p",
            "Keeping discovery peer without genesis hash",
            "peer" => peer_address.to_string()
        );
    }

    {
        let mut peers = connected_peers.lock().unwrap();
        if !peer_session_is_current(peer_address, session_id) {
            return;
        }
        propagate_status_to_matching_peers(
            &mut peers,
            peer_state_cache,
            peer_address,
            block_height,
            best_block_hash,
            genesis_hash,
            status_reported_at,
            status_validator_address,
            status_source_session_id,
            active_validator_set_hash,
            quarantined,
            consensus_duties_disabled,
            recovery_state,
        );
    }
    info!(
        "p2p",
        "Received status",
        "peer" => peer_address.to_string(),
        "height" => block_height
    );

    let local_height = {
        let chain = blockchain.lock().unwrap();
        chain.last().map(|block| block.block_index).unwrap_or(0)
    };
    if !status_peer_is_eligible_block_sync_source(
        config,
        peer_validator_address.as_deref(),
        peer_is_active_validator,
        peer_is_designated_support,
        peer_is_designated_relayer,
        quarantined,
        consensus_duties_disabled,
    ) {
        debug!(
            "p2p",
            "Skipping block sync request to duty-disabled peer",
            "peer" => peer_address.to_string(),
            "reported_height" => block_height,
            "quarantined" => quarantined,
            "consensus_duties_disabled" => consensus_duties_disabled,
            "recovery_state" => recovery_state.clone().unwrap_or_default()
        );
        return;
    }
    if local_node_uses_service_batch_durability(config) {
        let _ =
            service_sync_request_from_status(blockchain, connected_peers, peer_state_cache, config);
    } else if let Some(batch) = status_sync_batch(config, block_height, local_height) {
        let Some((request_start, request_count)) =
            block_sync_request_range(local_height, block_height, batch)
        else {
            return;
        };
        request_blocks_from_connected_peer(
            config,
            connected_peers,
            peer_state_cache,
            peer_address,
            session_id,
            request_start,
            request_count,
        );
    }
}

fn preferred_connection_direction(
    local_identity: &str,
    remote_identity: &str,
) -> Option<ConnectionDirection> {
    let local_identity = local_identity.trim();
    let remote_identity = remote_identity.trim();

    if local_identity.is_empty() || remote_identity.is_empty() || local_identity == remote_identity
    {
        return None;
    }

    if local_identity < remote_identity {
        Some(ConnectionDirection::Outgoing)
    } else {
        Some(ConnectionDirection::Incoming)
    }
}

fn resolve_duplicate_connection(
    local_identity: &str,
    remote_identity: &str,
    existing_direction: ConnectionDirection,
    existing_connected_at: u64,
    new_direction: ConnectionDirection,
    new_connected_at: u64,
) -> DuplicateResolution {
    match preferred_connection_direction(local_identity, remote_identity) {
        Some(preferred) if existing_direction == preferred && new_direction != preferred => {
            DuplicateResolution::KeepExisting
        }
        Some(preferred) if new_direction == preferred && existing_direction != preferred => {
            DuplicateResolution::ReplaceExisting
        }
        _ => {
            if new_connected_at < existing_connected_at {
                DuplicateResolution::ReplaceExisting
            } else {
                DuplicateResolution::KeepExisting
            }
        }
    }
}

fn should_resolve_duplicate_session(direct_vote_session: bool) -> bool {
    !direct_vote_session
}

fn disconnect_peer_entry(
    peer_state_cache: &PeerStateCacheArc,
    peers: &mut PeerMap,
    peer_key: &str,
) {
    let gate = peer_write_gate(peer_key);
    let gate_guard = gate.lock().unwrap();
    let session_id = current_peer_session_id(peer_key);
    service_sync_release_disconnected_peer(peer_key, session_id);
    if let Some(mut peer) = peers.remove(peer_key) {
        cache_peer_state(peer_state_cache, &peer);
        if let Some(stream) = peer.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
    PEER_SESSION_IDS.lock().unwrap().remove(peer_key);
    TYPED_CONSENSUS_PEER_SESSIONS
        .lock()
        .unwrap()
        .retain(|(address, _), _| address != peer_key);
    drop(gate_guard);
    remove_peer_write_gate(peer_key);
}

fn remove_peer_write_gate(peer_address: &str) {
    PEER_WRITE_GATES.lock().unwrap().remove(peer_address);
}

fn begin_peer_session(peer_address: &str) -> u64 {
    let gate = peer_write_gate(peer_address);
    let _gate_guard = gate.lock().unwrap();
    service_sync_release_disconnected_peer(peer_address, None);
    let session_id = NEXT_PEER_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    PEER_SESSION_IDS
        .lock()
        .unwrap()
        .insert(peer_address.to_string(), session_id);
    TYPED_CONSENSUS_PEER_SESSIONS
        .lock()
        .unwrap()
        .retain(|(address, _), _| address != peer_address);
    session_id
}

fn register_typed_consensus_peer_session(
    peer_address: &str,
    session_id: u64,
    identity: AuthenticatedTypedConsensusPeer,
) -> Result<(), String> {
    if !peer_session_is_current(peer_address, session_id) {
        return Err("cannot bind typed consensus identity to a replaced peer session".to_string());
    }
    let mut sessions = TYPED_CONSENSUS_PEER_SESSIONS.lock().unwrap();
    let session_key = (peer_address.to_string(), session_id);
    if !sessions.contains_key(&session_key) && sessions.len() >= MAX_TYPED_CONSENSUS_PEER_SESSIONS {
        return Err("typed consensus peer-session registry capacity is exhausted".to_string());
    }
    sessions.insert(session_key, identity);
    Ok(())
}

fn typed_consensus_peer_for_session(
    peer_address: &str,
    session_id: u64,
) -> Option<AuthenticatedTypedConsensusPeer> {
    if !peer_session_is_current(peer_address, session_id) {
        return None;
    }
    TYPED_CONSENSUS_PEER_SESSIONS
        .lock()
        .unwrap()
        .get(&(peer_address.to_string(), session_id))
        .cloned()
}

fn simplified_consensus_peer_for_session(
    peer_address: &str,
    session_id: u64,
) -> Option<AuthenticatedSimplifiedConsensusPeer> {
    typed_consensus_peer_for_session(peer_address, session_id).map(|peer| {
        AuthenticatedSimplifiedConsensusPeer {
            validator_id: peer.validator_id,
            validator_uma_id: peer.validator_uma_id,
            consensus_key_id: peer.consensus_key_id,
        }
    })
}

fn validate_simplified_consensus_target_identity(
    identity: &AuthenticatedSimplifiedConsensusPeer,
    expected_validator_id: &ValidatorId,
    frozen_validator_ids: &BTreeSet<ValidatorId>,
) -> Result<(), String> {
    if !frozen_validator_ids.contains(&identity.validator_id) {
        return Err(
            "simplified consensus target peer is outside the frozen validator set".to_string(),
        );
    }
    if &identity.validator_id != expected_validator_id {
        return Err(
            "simplified consensus target address was rebound to another validator".to_string(),
        );
    }
    Ok(())
}

/// Converts the P2P handshake identity into the narrower ETDAG ingress
/// identity.  It is intentionally derived from the same session-scoped,
/// Genesis-bound authentication record as typed consensus traffic rather than
/// from a mutable peer address or a field in the ETDAG wire artifact.
fn etdag_ingress_peer_for_session(
    peer_address: &str,
    session_id: u64,
) -> Option<EtdagAuthenticatedIngressPeer> {
    typed_consensus_peer_for_session(peer_address, session_id).map(|peer| {
        EtdagAuthenticatedIngressPeer {
            validator_id: peer.validator_id,
            validator_uma_id: peer.validator_uma_id,
            consensus_key_id: peer.consensus_key_id,
        }
    })
}

fn dispatch_simplified_target_admission_ingress(
    authenticated_peer: Option<EtdagAuthenticatedIngressPeer>,
    message: SimplifiedTargetAdmissionMessage,
) -> Result<(), String> {
    match message {
        SimplifiedTargetAdmissionMessage::Vote { request } => {
            dispatch_simplified_target_admission_vote(authenticated_peer, request)?;
        }
        SimplifiedTargetAdmissionMessage::CertifiedPackage { package } => {
            dispatch_simplified_target_admission_package(authenticated_peer, package)?;
        }
    }
    Ok(())
}

fn dispatch_simplified_empty_etdag_ingress(
    authenticated_peer: Option<EtdagAuthenticatedIngressPeer>,
    message: SimplifiedEmptyEtdagMessage,
) -> Result<(), String> {
    validate_simplified_empty_etdag_message_size(&message)?;
    dispatch_simplified_empty_etdag_message(authenticated_peer, message)
}

fn current_peer_session_id(peer_address: &str) -> Option<u64> {
    PEER_SESSION_IDS.lock().unwrap().get(peer_address).copied()
}

fn peer_session_is_current(peer_address: &str, session_id: u64) -> bool {
    current_peer_session_id(peer_address) == Some(session_id)
}

fn peer_for_session_mut<'a>(
    peers: &'a mut PeerMap,
    peer_address: &str,
    session_id: u64,
) -> Option<&'a mut PeerConnection> {
    if !peer_session_is_current(peer_address, session_id) {
        return None;
    }
    peers.get_mut(peer_address)
}

fn disconnect_peer_entry_for_session(
    peer_state_cache: &PeerStateCacheArc,
    peers: &mut PeerMap,
    peer_address: &str,
    session_id: u64,
) {
    if peer_session_is_current(peer_address, session_id) {
        disconnect_peer_entry(peer_state_cache, peers, peer_address);
    }
}

fn disconnect_peer_after_poisoned_write(
    peer_state_cache: &PeerStateCacheArc,
    peers: &mut PeerMap,
    peer_key: &str,
    reason: &str,
) {
    warn!(
        "p2p",
        "Disconnecting peer after partial/failed framed write",
        "peer" => peer_key.to_string(),
        "reason" => reason.to_string()
    );
    disconnect_peer_entry(peer_state_cache, peers, peer_key);
}

fn peer_write_gate(peer_address: &str) -> Arc<Mutex<()>> {
    let mut gates = PEER_WRITE_GATES.lock().unwrap();
    gates
        .entry(peer_address.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

fn with_peer_stream_outside_peers_lock<T>(
    connected_peers: &PeersArc,
    peer_address: &str,
    expected_session_id: u64,
    write: impl FnOnce(&mut TcpStream) -> T,
) -> Option<(PeerStreamIdentity, T)> {
    let (session_identity, mut stream) = {
        let peers = connected_peers.lock().unwrap();
        let peer = peers.get(peer_address)?;
        let stream = peer.stream.as_ref()?;
        if current_peer_session_id(peer_address)? != expected_session_id {
            return None;
        }
        let session_identity = PeerStreamIdentity {
            session_id: expected_session_id,
            connected_at: peer.connected_at,
            local_address: stream.local_addr().ok()?,
            peer_address: stream.peer_addr().ok()?,
        };
        (session_identity, stream.try_clone().ok()?)
    };

    let gate = peer_write_gate(peer_address);
    let _write_guard = gate.lock().unwrap();
    if current_peer_session_id(peer_address) != Some(expected_session_id) {
        return None;
    }
    let result = write(&mut stream);
    Some((session_identity, result))
}

fn send_peer_message_for_session(
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    peer_address: &str,
    session_id: u64,
    message: &NetworkMessage,
    timeout: Duration,
    message_kind: &str,
) -> Result<bool, String> {
    let Some((session_identity, send_result)) =
        with_peer_stream_outside_peers_lock(connected_peers, peer_address, session_id, |stream| {
            send_message_with_write_timeout(stream, message, timeout)
        })
    else {
        return Ok(false);
    };

    match send_result {
        Ok(()) => Ok(true),
        Err(error) => {
            let error = error.to_string();
            let mut peers = connected_peers.lock().unwrap();
            if peers.get(peer_address).is_some_and(|peer| {
                peer_stream_matches_identity(peer_address, peer, &session_identity)
            }) {
                let reason = format!("{message_kind}-send-failed: {error}");
                disconnect_peer_after_poisoned_write(
                    peer_state_cache,
                    &mut peers,
                    peer_address,
                    &reason,
                );
            }
            Err(error)
        }
    }
}

fn peer_stream_matches_identity(
    peer_address: &str,
    peer: &PeerConnection,
    identity: &PeerStreamIdentity,
) -> bool {
    peer_session_is_current(peer_address, identity.session_id)
        && peer.connected_at == identity.connected_at
        && peer.stream.as_ref().is_some_and(|stream| {
            stream.local_addr().ok().as_ref() == Some(&identity.local_address)
                && stream.peer_addr().ok().as_ref() == Some(&identity.peer_address)
        })
}

fn spawn_named_thread<F>(name: &str, task: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    match thread::Builder::new().name(name.to_string()).spawn(task) {
        Ok(_) => true,
        Err(error) => {
            error!(
                "p2p",
                "Failed to spawn thread",
                "thread" => name.to_string(),
                "error" => error.to_string()
            );
            false
        }
    }
}

#[cfg(not(test))]
fn start_validator_transport_refresh_worker(is_running: Arc<Mutex<bool>>) {
    if VALIDATOR_TRANSPORT_REFRESH_WORKER_RUNNING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    if !spawn_named_thread("validator-transport-refresh", move || {
        loop {
            if !is_running.lock().map(|running| *running).unwrap_or(false) {
                break;
            }

            match refresh_validator_transports() {
                Ok(refresh) if refresh.changed => info!(
                    "p2p",
                    "Installed fresh provider-signed validator transport registry",
                    "generation" => refresh.generation
                ),
                Ok(_) => {}
                Err(error) => warn!(
                    "p2p",
                    "Validator transport registry refresh failed; retaining last verified state",
                    "error" => error
                ),
            }

            for _ in 0..VALIDATOR_TRANSPORT_REFRESH_SECS {
                thread::sleep(Duration::from_secs(1));
                if !is_running.lock().map(|running| *running).unwrap_or(false) {
                    break;
                }
            }
        }
        VALIDATOR_TRANSPORT_REFRESH_WORKER_RUNNING.store(false, Ordering::SeqCst);
    }) {
        VALIDATOR_TRANSPORT_REFRESH_WORKER_RUNNING.store(false, Ordering::SeqCst);
    }
}

fn process_block_serve_job(job: BlockServeJob) {
    handle_get_blocks_message(
        &job.blockchain,
        &job.connected_peers,
        &job.peer_state_cache,
        &job.config,
        &job.peer_address,
        job.session_id,
        job.from_height,
        job.count,
    );
}

fn process_block_apply_job(job: BlockApplyJob) -> bool {
    handle_blocks_message(
        &job.blockchain,
        &job.connected_peers,
        &job.peer_state_cache,
        &job.config,
        &job.peer_address,
        job.session_id,
        job.blocks,
        job.quorum_certificates,
    )
}

fn block_sync_peer_key(peer_address: &str, session_id: u64) -> (String, u64) {
    (peer_address.to_string(), session_id)
}

fn reserve_block_sync_peer(
    active: &Mutex<HashSet<(String, u64)>>,
    peer_address: &str,
    session_id: u64,
) -> bool {
    active
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(block_sync_peer_key(peer_address, session_id))
}

fn release_block_sync_peer(
    active: &Mutex<HashSet<(String, u64)>>,
    peer_address: &str,
    session_id: u64,
) {
    active
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&block_sync_peer_key(peer_address, session_id));
}

fn release_block_sync_apply_slot_after_worker(
    peer_address: &str,
    session_id: u64,
    service_sync_generation: Option<u64>,
    service_sync_handoff_completed: bool,
) {
    if service_sync_handoff_completed {
        return;
    }

    if let Some(generation) = service_sync_generation {
        let coordinator = SERVICE_SYNC_COORDINATOR
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let should_release = match coordinator.in_flight.as_ref() {
            None => true,
            Some(flight) if flight.generation == generation => true,
            Some(flight)
                if flight.identity.peer_address != peer_address
                    || flight.identity.session_id != session_id =>
            {
                true
            }
            Some(flight) => flight.phase == ServiceSyncPhase::AwaitingResponse,
        };
        if should_release {
            // Keep the coordinator locked while releasing the reservation so a replacement
            // service flight cannot claim the same peer between the check and the release.
            release_block_sync_peer(&BLOCK_SYNC_APPLY_ACTIVE, peer_address, session_id);
        }
    } else {
        // Service apply handlers release the slot before handing the coordinator to the next
        // flight. A second release here could clear that next flight's reservation.
        release_block_sync_peer(&BLOCK_SYNC_APPLY_ACTIVE, peer_address, session_id);
    }
}

fn process_block_sync_busy_job(job: &BlockSyncBusyJob) {
    let retry_range = job
        .retry_request
        .map(|(from_height, count)| format!("; from-height={from_height}; count={count}"))
        .unwrap_or_default();
    let response = NetworkMessage::Error {
        message: format!(
            "block-sync-busy: {}; retry-after-millis={}{}",
            job.reason, BLOCK_SYNC_BUSY_RETRY_MILLIS, retry_range
        ),
    };
    if let Err(error) = send_peer_message_for_session(
        &job.connected_peers,
        &job.peer_state_cache,
        &job.peer_address,
        job.session_id,
        &response,
        Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
        "block-sync-busy",
    ) {
        warn!(
            "p2p",
            "Failed to send block sync retry signal",
            "peer" => job.peer_address.clone(),
            "error" => error
        );
    }
}

fn parse_block_sync_busy_retry(message: &str) -> Option<(Duration, u64, u32)> {
    let mut retry_after_millis = None;
    let mut from_height = None;
    let mut count = None;
    for field in message.split(';').map(str::trim) {
        if let Some(value) = field.strip_prefix("retry-after-millis=") {
            retry_after_millis = value.parse::<u64>().ok();
        } else if let Some(value) = field.strip_prefix("from-height=") {
            from_height = value.parse::<u64>().ok();
        } else if let Some(value) = field.strip_prefix("count=") {
            count = value.parse::<u32>().ok();
        }
    }
    Some((
        Duration::from_millis(retry_after_millis?),
        from_height?,
        count.filter(|count| *count > 0)?,
    ))
}

fn schedule_block_sync_retry(
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    peer_address: String,
    session_id: u64,
    message: &str,
    service_single_flight: bool,
) {
    let Some((retry_after, from_height, count)) = parse_block_sync_busy_retry(message) else {
        return;
    };
    if service_single_flight
        && !service_sync_retry_is_current(&peer_address, session_id, from_height, count)
    {
        return;
    }
    // Keep one delayed retry per session so a peer cannot turn busy errors into
    // an unbounded retry-thread source while the bounded sync workers are full.
    let retry_key = (peer_address.clone(), session_id);
    if !BLOCK_SYNC_RETRY_ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(retry_key.clone())
    {
        return;
    }

    let retry_peer_address = peer_address.clone();
    let thread_retry_key = retry_key.clone();
    let spawned = spawn_named_thread("p2p-block-sync-retry", move || {
        thread::sleep(retry_after);
        if peer_session_is_current(&retry_peer_address, session_id)
            && (!service_single_flight
                || service_sync_retry_is_current(
                    &retry_peer_address,
                    session_id,
                    from_height,
                    count,
                ))
        {
            let request = NetworkMessage::GetBlocks { from_height, count };
            if let Err(error) = send_peer_message_for_session(
                &connected_peers,
                &peer_state_cache,
                &retry_peer_address,
                session_id,
                &request,
                Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
                "block-sync-retry",
            ) {
                debug!(
                    "p2p",
                    "Failed to retry deferred block sync request",
                    "peer" => retry_peer_address.clone(),
                    "error" => error
                );
            }
        }
        BLOCK_SYNC_RETRY_ACTIVE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&thread_retry_key);
    });
    if !spawned {
        BLOCK_SYNC_RETRY_ACTIVE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&retry_key);
    }
}

fn ensure_block_sync_workers_started() {
    BLOCK_SYNC_WORKERS_INIT.call_once(|| {
        for worker_index in 0..MAX_BLOCK_SYNC_SERVE_WORKERS {
            let receiver = Arc::clone(&BLOCK_SYNC_SERVE_QUEUE.1);
            if spawn_named_thread(&format!("p2p-block-serve-{worker_index}"), move || loop {
                let job = {
                    let receiver = receiver
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    receiver.recv()
                };
                let Ok(job) = job else {
                    break;
                };
                let peer_address = job.peer_address.clone();
                let session_id = job.session_id;
                if catch_unwind(AssertUnwindSafe(|| process_block_serve_job(job))).is_err() {
                    error!("p2p", "Block sync serve worker recovered from a panic");
                }
                release_block_sync_peer(&BLOCK_SYNC_SERVE_ACTIVE, &peer_address, session_id);
            }) {
                BLOCK_SYNC_SERVE_WORKERS_STARTED.fetch_add(1, Ordering::Release);
            }
        }

        for worker_index in 0..MAX_BLOCK_SYNC_APPLY_WORKERS {
            let receiver = Arc::clone(&BLOCK_SYNC_APPLY_QUEUE.1);
            if spawn_named_thread(&format!("p2p-block-apply-{worker_index}"), move || loop {
                let job = {
                    let receiver = receiver
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    receiver.recv()
                };
                let Ok(job) = job else {
                    break;
                };
                let peer_address = job.peer_address.clone();
                let session_id = job.session_id;
                let service_sync_generation =
                    if local_node_uses_service_batch_durability(&job.config) {
                        service_sync_generation_for_response(
                            &job.peer_address,
                            job.session_id,
                            &job.blocks,
                        )
                    } else {
                        None
                    };
                match catch_unwind(AssertUnwindSafe(|| process_block_apply_job(job))) {
                    Ok(service_sync_handoff_completed) => {
                        release_block_sync_apply_slot_after_worker(
                            &peer_address,
                            session_id,
                            service_sync_generation,
                            service_sync_handoff_completed,
                        );
                    }
                    Err(_) => {
                        error!("p2p", "Block sync apply worker recovered from a panic");
                        release_block_sync_apply_slot_after_worker(
                            &peer_address,
                            session_id,
                            service_sync_generation,
                            false,
                        );
                        if let Some(generation) = service_sync_generation {
                            service_sync_release_and_reassign(
                                generation,
                                Some(service_sync_identity(&peer_address, session_id)),
                                false,
                            );
                        }
                    }
                }
            }) {
                BLOCK_SYNC_APPLY_WORKERS_STARTED.fetch_add(1, Ordering::Release);
            }
        }

        let receiver = Arc::clone(&BLOCK_SYNC_BUSY_QUEUE.1);
        if spawn_named_thread("p2p-block-sync-busy", move || loop {
            let job = {
                let receiver = receiver
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                receiver.recv()
            };
            let Ok(job) = job else {
                break;
            };
            let peer_address = job.peer_address.clone();
            let session_id = job.session_id;
            if catch_unwind(AssertUnwindSafe(|| process_block_sync_busy_job(&job))).is_err() {
                error!(
                    "p2p",
                    "Block sync retry-signal worker recovered from a panic"
                );
            }
            release_block_sync_peer(&BLOCK_SYNC_BUSY_ACTIVE, &peer_address, session_id);
        }) {
            BLOCK_SYNC_BUSY_WORKERS_STARTED.fetch_add(1, Ordering::Release);
        }
    });
}

fn enqueue_block_sync_busy_job(job: BlockSyncBusyJob) {
    ensure_block_sync_workers_started();
    if !reserve_block_sync_peer(&BLOCK_SYNC_BUSY_ACTIVE, &job.peer_address, job.session_id) {
        return;
    }
    if BLOCK_SYNC_BUSY_WORKERS_STARTED.load(Ordering::Acquire) == 0 {
        process_block_sync_busy_job(&job);
        release_block_sync_peer(&BLOCK_SYNC_BUSY_ACTIVE, &job.peer_address, job.session_id);
        return;
    }
    if let Err(error) = BLOCK_SYNC_BUSY_QUEUE.0.try_send(job) {
        let job = match error {
            mpsc::TrySendError::Full(job) | mpsc::TrySendError::Disconnected(job) => job,
        };
        release_block_sync_peer(&BLOCK_SYNC_BUSY_ACTIVE, &job.peer_address, job.session_id);
        warn!(
            "p2p",
            "Block sync retry-signal queue is unavailable; disconnecting overloaded peer",
            "peer" => job.peer_address.clone()
        );
        let mut peers = job.connected_peers.lock().unwrap();
        disconnect_peer_entry_for_session(
            &job.peer_state_cache,
            &mut peers,
            &job.peer_address,
            job.session_id,
        );
    }
}

fn enqueue_block_serve_job(job: BlockServeJob) {
    ensure_block_sync_workers_started();
    if !reserve_block_sync_peer(&BLOCK_SYNC_SERVE_ACTIVE, &job.peer_address, job.session_id) {
        let retry_request = Some((job.from_height, job.count));
        enqueue_block_sync_busy_job(BlockSyncBusyJob {
            connected_peers: Arc::clone(&job.connected_peers),
            peer_state_cache: Arc::clone(&job.peer_state_cache),
            peer_address: job.peer_address,
            session_id: job.session_id,
            reason: "a block response for this peer is already pending",
            retry_request,
        });
        return;
    }
    if BLOCK_SYNC_SERVE_WORKERS_STARTED.load(Ordering::Acquire) == 0 {
        let peer_address = job.peer_address.clone();
        let session_id = job.session_id;
        process_block_serve_job(job);
        release_block_sync_peer(&BLOCK_SYNC_SERVE_ACTIVE, &peer_address, session_id);
        return;
    }
    if let Err(error) = BLOCK_SYNC_SERVE_QUEUE.0.try_send(job) {
        let job = match error {
            mpsc::TrySendError::Full(job) | mpsc::TrySendError::Disconnected(job) => job,
        };
        release_block_sync_peer(&BLOCK_SYNC_SERVE_ACTIVE, &job.peer_address, job.session_id);
        enqueue_block_sync_busy_job(BlockSyncBusyJob {
            connected_peers: job.connected_peers,
            peer_state_cache: job.peer_state_cache,
            peer_address: job.peer_address,
            session_id: job.session_id,
            reason: "the bounded block response queue is full",
            retry_request: Some((job.from_height, job.count)),
        });
    }
}

fn enqueue_block_apply_job(job: BlockApplyJob) {
    ensure_block_sync_workers_started();
    let service_sync_generation = if local_node_uses_service_batch_durability(&job.config) {
        let generation =
            service_sync_claim_response(&job.peer_address, job.session_id, &job.blocks);
        if generation.is_none() {
            debug!(
                "p2p",
                "Ignoring overlapping service block response before apply",
                "peer" => job.peer_address.clone(),
                "count" => job.blocks.len() as u64
            );
            return;
        }
        generation
    } else {
        None
    };
    if !reserve_block_sync_peer(&BLOCK_SYNC_APPLY_ACTIVE, &job.peer_address, job.session_id) {
        if let Some(generation) = service_sync_generation {
            service_sync_release_and_reassign(
                generation,
                Some(service_sync_identity(&job.peer_address, job.session_id)),
                false,
            );
            return;
        }
        enqueue_block_sync_busy_job(BlockSyncBusyJob {
            connected_peers: Arc::clone(&job.connected_peers),
            peer_state_cache: Arc::clone(&job.peer_state_cache),
            peer_address: job.peer_address,
            session_id: job.session_id,
            reason: "a block batch from this peer is already being applied",
            retry_request: None,
        });
        return;
    }
    if BLOCK_SYNC_APPLY_WORKERS_STARTED.load(Ordering::Acquire) == 0 {
        let peer_address = job.peer_address.clone();
        let session_id = job.session_id;
        let service_sync_handoff_completed = process_block_apply_job(job);
        release_block_sync_apply_slot_after_worker(
            &peer_address,
            session_id,
            service_sync_generation,
            service_sync_handoff_completed,
        );
        return;
    }
    if let Err(error) = BLOCK_SYNC_APPLY_QUEUE.0.try_send(job) {
        let job = match error {
            mpsc::TrySendError::Full(job) | mpsc::TrySendError::Disconnected(job) => job,
        };
        release_block_sync_peer(&BLOCK_SYNC_APPLY_ACTIVE, &job.peer_address, job.session_id);
        if let Some(generation) = service_sync_generation {
            service_sync_release_and_reassign(
                generation,
                Some(service_sync_identity(&job.peer_address, job.session_id)),
                false,
            );
            return;
        }
        enqueue_block_sync_busy_job(BlockSyncBusyJob {
            connected_peers: job.connected_peers,
            peer_state_cache: job.peer_state_cache,
            peer_address: job.peer_address,
            session_id: job.session_id,
            reason: "the bounded block apply queue is full",
            retry_request: None,
        });
    }
}

fn reserve_outbound_dial(
    dial_registry: &DialRegistryArc,
    connected_peers: &PeersArc,
    target: &str,
    max_peers: usize,
) -> bool {
    let target = target.trim();
    if target.is_empty() {
        return false;
    }

    {
        let peers = connected_peers.lock().unwrap();
        if peers.len() >= max_peers {
            return false;
        }
        if connected_peer_key_for_address(&peers, target).is_some() {
            return false;
        }
    }

    let now = Instant::now();
    let mut registry = dial_registry.lock().unwrap();
    match registry.get_mut(target) {
        Some(state) => {
            if state.in_flight {
                return false;
            }
            if now.duration_since(state.last_attempt_at)
                < Duration::from_secs(OUTBOUND_DIAL_COOLDOWN_SECS)
            {
                return false;
            }
            state.in_flight = true;
            state.last_attempt_at = now;
        }
        None => {
            registry.insert(
                target.to_string(),
                DialReservation {
                    in_flight: true,
                    last_attempt_at: now,
                },
            );
        }
    }

    true
}

fn release_outbound_dial(dial_registry: &DialRegistryArc, target: &str) {
    let now = Instant::now();
    let mut registry = dial_registry.lock().unwrap();
    match registry.get_mut(target) {
        Some(state) => {
            state.in_flight = false;
            state.last_attempt_at = now;
        }
        None => {
            registry.insert(
                target.to_string(),
                DialReservation {
                    in_flight: false,
                    last_attempt_at: now,
                },
            );
        }
    }
    registry.retain(|_, state| {
        state.in_flight || now.duration_since(state.last_attempt_at) < Duration::from_secs(300)
    });
}

fn peer_socket_host(address: &str) -> String {
    let raw = address.trim();
    if let Some(stripped) = raw.strip_prefix('[') {
        if let Some((host, _)) = stripped.rsplit_once("]:") {
            return host.to_string();
        }
    }
    raw.rsplit_once(':')
        .map(|(host, _)| host.trim().to_string())
        .unwrap_or_else(|| raw.to_string())
}

fn dial_target_host(dial: &str) -> Option<String> {
    let normalized = parse_bootnode_dial_address(dial)?;
    if let Some(stripped) = normalized.strip_prefix('[') {
        return stripped.rsplit_once("]:").map(|(host, _)| host.to_string());
    }
    normalized
        .rsplit_once(':')
        .map(|(host, _)| host.trim().to_string())
}

fn canonical_validator_public_address(
    peer_address: &str,
    announced_public_address: Option<&str>,
) -> Option<String> {
    if let Some(stable_validator_address) =
        announced_public_address.and_then(normalize_validator_address_target)
    {
        return Some(stable_validator_address);
    }

    if let Some(peer_dial) = parse_bootnode_dial_address(peer_address) {
        if is_public_history_gateway_dial_address(&peer_dial) {
            return Some(peer_dial);
        }
    }

    if let Some(announced_dial) = announced_public_address.and_then(parse_bootnode_dial_address) {
        if is_public_history_gateway_dial_address(&announced_dial) {
            return Some(announced_dial);
        }
    }

    let announced_host = announced_public_address
        .and_then(dial_target_host)
        .filter(|host| is_public_synergy_advertise_host(host));
    if let Some(host) = announced_host {
        return Some(format!("{host}:{VALIDATOR_P2P_PORT}"));
    }

    let peer_host = dial_target_host(peer_address)?;
    if is_public_synergy_advertise_host(&peer_host) {
        Some(format!("{peer_host}:{VALIDATOR_P2P_PORT}"))
    } else {
        None
    }
}

fn should_canonicalize_validator_public_address(validator_address: Option<&str>) -> bool {
    validator_address
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| value.starts_with("synv1"))
}

fn is_public_history_gateway_dial_address(address: &str) -> bool {
    let normalized =
        parse_bootnode_dial_address(address).unwrap_or_else(|| address.trim().to_string());
    PUBLIC_HISTORY_GATEWAY_DIAL_ADDRESSES
        .iter()
        .any(|dial| *dial == normalized)
}

fn is_validator_allowed(config: &NodeConfig, validator_address: &str) -> bool {
    if !config.node.strict_validator_allowlist {
        return true;
    }

    config
        .node
        .allowed_validator_addresses
        .iter()
        .any(|allowed| allowed == validator_address)
}

fn resolve_bootstrap_dial_targets(config: &NodeConfig) -> Vec<String> {
    let mut targets = HashSet::<String>::new();

    for bootnode in &config.network.bootnodes {
        if let Some(dial) = normalize_peer_target(config, bootnode) {
            targets.insert(dial);
        }
    }

    for dial in resolve_dns_bootstrap_targets(&config.network.bootstrap_dns_records) {
        if let Some(dial) = normalize_peer_target(config, &dial) {
            targets.insert(dial);
        }
    }

    for dial in resolve_seed_server_targets(&config.network.seed_servers) {
        if let Some(dial) = normalize_peer_target(config, &dial) {
            targets.insert(dial);
        }
    }

    for dial in config
        .network
        .persistent_peers
        .iter()
        .chain(config.network.additional_dial_targets.iter())
    {
        if let Some(target) = normalize_peer_target(config, dial) {
            targets.insert(target);
        }
    }

    for validator in consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators()) {
        if validator_vpn_transport_for_target(config, &validator.address).is_some() {
            targets.insert(validator.address);
        }
    }

    let self_aliases = self_dial_aliases(config);
    if !self_aliases.is_empty() {
        targets.retain(|target| !self_aliases.contains(target));
    }

    let mut ordered = targets.into_iter().collect::<Vec<_>>();
    ordered.sort();
    ordered
}

fn self_dial_aliases(config: &NodeConfig) -> HashSet<String> {
    let mut aliases = HashSet::new();

    if let Some(address) = parse_bootnode_dial_address(&config.p2p.public_address) {
        aliases.insert(address);
    } else if let Some(address) = normalize_validator_address_target(&config.p2p.public_address) {
        aliases.insert(address);
    }
    if let Some(address) = parse_bootnode_dial_address(&config.p2p.listen_address) {
        aliases.insert(address);
    }
    if let Some(address) = announced_validator_address(config) {
        aliases.insert(address);
    }

    if let Some(slot) = local_validator_slot(config) {
        aliases.insert(format!(
            "genesisval{slot}.synergy-network.io:{}",
            config.network.p2p_port
        ));
    }

    aliases
}

fn is_self_dial_target(config: &NodeConfig, dial: &str) -> bool {
    if let Some(validator_address) = normalize_validator_address_target(dial) {
        return self_dial_aliases(config).contains(&validator_address);
    }
    let Some(normalized) = parse_bootnode_dial_address(dial) else {
        return false;
    };
    self_dial_aliases(config).contains(&normalized)
}

fn local_validator_slot(config: &NodeConfig) -> Option<u64> {
    let validator_address = announced_validator_address(config)?;
    let workspace_root = Path::new(&config.storage.path).parent()?;
    let manifest_path = workspace_root
        .join("config")
        .join("operational-manifest.json");
    let contents = fs::read_to_string(manifest_path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&contents).ok()?;

    value
        .get("validators")
        .and_then(serde_json::Value::as_array)?
        .iter()
        .find(|entry| {
            entry
                .get("address")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .is_some_and(|address| address.eq_ignore_ascii_case(validator_address.as_str()))
        })
        .and_then(|entry| entry.get("slot"))
        .and_then(serde_json::Value::as_u64)
}

#[cfg(test)]
fn connected_validator_participants(config: &NodeConfig, connected_peers: &PeersArc) -> usize {
    let mut validators = HashSet::<String>::new();

    if let Some(local_validator) = announced_validator_address(config) {
        validators.insert(local_validator);
    }

    if let Ok(peers) = connected_peers.lock() {
        for peer in peers.values() {
            if let Some(address) = peer.validator_address.as_deref() {
                let trimmed = address.trim();
                if !trimmed.is_empty() {
                    validators.insert(trimmed.to_string());
                }
            }
        }
    }

    validators.len()
}

fn status_ready_validator_addresses(
    config: &NodeConfig,
    connected_peers: &PeersArc,
) -> Vec<String> {
    let mut validators = HashSet::<String>::new();
    let active_validator_addresses =
        consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators())
            .into_iter()
            .map(|validator| validator.address)
            .collect::<HashSet<_>>();
    let expected_validator_set_hash = canonical_validator_set_hash();
    let now = current_timestamp();

    if current_validator_quarantine_duty_block().is_none() {
        if let Some(local_validator) = announced_validator_address(config) {
            validators.insert(local_validator);
        }
    }

    if let Ok(peers) = connected_peers.lock() {
        for peer in peers.values() {
            if !peer_has_status_ready_lease_at(peer, now) {
                continue;
            }
            let Some(recovered_validator) = recover_peer_validator_address_for_vote_target(
                config,
                peer,
                &active_validator_addresses,
            ) else {
                continue;
            };
            if peer_readiness_exclusion_reason_at(peer, now, Some(&expected_validator_set_hash))
                .is_some()
            {
                continue;
            }
            validators.insert(recovered_validator);
        }
    }

    let mut validators = validators.into_iter().collect::<Vec<_>>();
    validators.sort();
    validators
}

#[cfg(test)]
fn status_ready_validator_addresses_with_local_duty_gate(
    config: &NodeConfig,
    connected_peers: &PeersArc,
    local_duties_disabled: bool,
) -> Vec<String> {
    let mut validators = HashSet::<String>::new();
    let expected_validator_set_hash = canonical_validator_set_hash();

    if !local_duties_disabled {
        if let Some(local_validator) = announced_validator_address(config) {
            validators.insert(local_validator);
        }
    }

    let now = current_timestamp();
    if let Ok(peers) = connected_peers.lock() {
        for peer in peers.values() {
            if peer_readiness_exclusion_reason_at(peer, now, Some(&expected_validator_set_hash))
                .is_some()
            {
                continue;
            }
            if let Some(address) = peer.validator_address.as_deref() {
                let trimmed = address.trim();
                if !trimmed.is_empty() {
                    validators.insert(trimmed.to_string());
                }
            }
        }
    }

    let mut validators = validators.into_iter().collect::<Vec<_>>();
    validators.sort();
    validators
}

fn status_ready_validator_participants(config: &NodeConfig, connected_peers: &PeersArc) -> usize {
    status_ready_validator_addresses(config, connected_peers).len()
}

fn best_connected_validator_height(connected_peers: &PeersArc) -> u64 {
    connected_peers
        .lock()
        .map(|peers| {
            peers
                .values()
                .filter(|peer| peer_is_active_validator_sync_source(peer))
                .map(|peer| peer.last_known_height)
                .max()
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

fn peer_is_active_validator_sync_source(peer: &PeerConnection) -> bool {
    let now = current_timestamp();
    peer.validator_address
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
        && peer_has_fresh_remote_status_at(peer, now)
        && !peer_quarantine_active_at(peer, now)
        && !peer_duties_disabled_active_at(peer, now)
}

fn peer_is_eligible_block_sync_source(config: &NodeConfig, peer: &PeerConnection) -> bool {
    let now = current_timestamp();
    if peer_quarantine_active_at(peer, now) {
        return false;
    }

    (peer_is_active_consensus_validator(config, peer)
        && peer_has_fresh_remote_status_at(peer, now)
        && !peer_duties_disabled_active_at(peer, now))
        || peer_is_designated_support_sync_source(config, peer)
}

fn peer_connected_endpoint(peer: &PeerConnection) -> Option<String> {
    peer.connected_endpoint.clone().or_else(|| {
        peer.stream
            .as_ref()
            .and_then(|stream| stream.peer_addr().ok())
            .map(|address| address.to_string())
    })
}

fn configured_support_endpoint_matches(config: &NodeConfig, peer: &PeerConnection) -> bool {
    let Some(endpoint) = peer_connected_endpoint(peer) else {
        return false;
    };
    PUBLIC_HISTORY_GATEWAY_DIAL_ADDRESSES
        .iter()
        .copied()
        .chain(PUBLIC_RELAYER_DIAL_ADDRESSES.iter().copied())
        .chain(
            config
                .network
                .persistent_peers
                .iter()
                .chain(config.network.additional_dial_targets.iter())
                .map(|value| value.as_str()),
        )
        .filter_map(|address| parse_bootnode_dial_address(address))
        .any(|address| connected_endpoint_matches_configured_address(&endpoint, &address))
}

fn peer_endpoint_matches_configured_list(
    peer: &PeerConnection,
    configured_addresses: impl IntoIterator<Item = impl AsRef<str>>,
) -> bool {
    let Some(endpoint) = peer_connected_endpoint(peer) else {
        return false;
    };
    configured_addresses.into_iter().any(|address| {
        parse_bootnode_dial_address(address.as_ref()).is_some_and(|configured| {
            match peer.direction {
                // A locally initiated connection must terminate at the exact
                // configured listener.  This keeps the ordinary dial path
                // strict, including its port.
                ConnectionDirection::Outgoing => {
                    connected_endpoint_matches_configured_address(&endpoint, &configured)
                }
                // On a remotely initiated TCP connection, the peer's source
                // port is intentionally ephemeral.  Accept it only when the
                // observed source *host* is the configured host and the
                // authenticated handshake commits to that exact configured
                // advertised listener.  A claimed public address alone is
                // never sufficient, and neither is a source-host match alone.
                ConnectionDirection::Incoming => {
                    connected_endpoint_host_matches_configured_address(&endpoint, &configured)
                        && peer
                            .public_address
                            .as_deref()
                            .and_then(parse_bootnode_dial_address)
                            .is_some_and(|advertised| advertised == configured)
                }
            }
        })
    })
}

fn connected_endpoint_host_matches_configured_address(
    connected_address: &str,
    configured_address: &str,
) -> bool {
    let Some((connected_host, _connected_port)) = endpoint_host_port(connected_address) else {
        return false;
    };
    let Some((configured_host, configured_port)) = endpoint_host_port(configured_address) else {
        return false;
    };

    let Some(connected_ip) = connected_host.parse::<std::net::IpAddr>().ok() else {
        // The observed socket endpoint must be numeric.  A self-reported
        // hostname is not transport evidence.
        return false;
    };
    if let Some(configured_ip) = configured_host.parse::<std::net::IpAddr>().ok() {
        return connected_ip == configured_ip;
    }

    // `str::to_socket_addrs` requires a `host:port` string. Resolving the bare
    // host alone always fails, which silently rejected every DNS-named
    // allowlist entry on the incoming path and left a peer that advertises a
    // hostname unauthorizable: the numeric entry matched its source host but
    // not its advertised address, and the DNS entry matched its advertised
    // address but never resolved. Resolve host and port together, as the
    // port-exact sibling check already does.
    (configured_host.as_str(), configured_port)
        .to_socket_addrs()
        .map(|addresses| {
            addresses
                .into_iter()
                .any(|address| address.ip() == connected_ip)
        })
        .unwrap_or(false)
}

fn connected_endpoint_matches_configured_address(
    connected_address: &str,
    configured_address: &str,
) -> bool {
    let Some((connected_host, connected_port)) = endpoint_host_port(connected_address) else {
        return false;
    };
    let Some((configured_host, configured_port)) = endpoint_host_port(configured_address) else {
        return false;
    };
    if connected_port != configured_port {
        return false;
    }

    let Some(connected_ip) = connected_host.parse::<std::net::IpAddr>().ok() else {
        // A peer's authenticated transport endpoint must come from the socket,
        // which is represented as a numeric address. A self-reported hostname
        // is not evidence of where the connection actually came from.
        return false;
    };
    if let Some(configured_ip) = configured_host.parse::<std::net::IpAddr>().ok() {
        return connected_ip == configured_ip;
    }

    (configured_host.as_str(), configured_port)
        .to_socket_addrs()
        .map(|addresses| {
            addresses
                .into_iter()
                .any(|address| address.ip() == connected_ip)
        })
        .unwrap_or(false)
}

fn validator_transport_endpoint_matches_peer(
    peer: &PeerConnection,
    configured_address: &str,
) -> bool {
    let Some(endpoint) = peer_connected_endpoint(peer) else {
        return false;
    };
    let Some((connected_host, _connected_port)) = endpoint_host_port(&endpoint) else {
        return false;
    };
    let Some((configured_host, configured_port)) = endpoint_host_port(configured_address) else {
        return false;
    };
    if configured_port != VALIDATOR_P2P_PORT {
        return false;
    }

    match peer.direction {
        ConnectionDirection::Outgoing => {
            connected_endpoint_matches_configured_address(&endpoint, configured_address)
        }
        ConnectionDirection::Incoming => {
            let Ok(connected_ip) = connected_host.parse::<std::net::IpAddr>() else {
                return false;
            };
            let Ok(configured_ip) = configured_host.parse::<std::net::IpAddr>() else {
                return false;
            };
            connected_ip == configured_ip
        }
    }
}

fn endpoint_host_port(address: &str) -> Option<(String, u16)> {
    let normalized = parse_bootnode_dial_address(address)?;
    if let Some(stripped) = normalized.strip_prefix('[') {
        let (host, port) = stripped.rsplit_once("]:")?;
        return Some((host.to_string(), port.parse().ok()?));
    }
    let (host, port) = normalized.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

fn peer_is_designated_support_sync_source(config: &NodeConfig, peer: &PeerConnection) -> bool {
    let history_endpoint = peer_endpoint_matches_configured_list(
        peer,
        PUBLIC_HISTORY_GATEWAY_DIAL_ADDRESSES.iter().copied(),
    );
    let relayer_endpoint =
        peer_endpoint_matches_configured_list(peer, PUBLIC_RELAYER_DIAL_ADDRESSES.iter().copied());
    let configured_endpoint = configured_support_endpoint_matches(config, peer);
    let role = peer
        .handshake_role
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase());

    (history_endpoint
        && matches!(
            role.as_deref(),
            Some(
                "rpc_gateway"
                    | "rpc_gateway_node"
                    | "archive_validator"
                    | "archive_validator_node"
                    | "indexer_explorer"
                    | "indexer_and_explorer_node"
            )
        ))
        || ((relayer_endpoint || configured_endpoint)
            && matches!(role.as_deref(), Some("relayer" | "relayer_node")))
}

fn peer_is_designated_relayer_sync_source(config: &NodeConfig, peer: &PeerConnection) -> bool {
    peer.handshake_role
        .as_deref()
        .map(|role| {
            matches!(
                role.trim().to_ascii_lowercase().as_str(),
                "relayer" | "relayer_node"
            )
        })
        .unwrap_or(false)
        && peer_endpoint_matches_configured_list(
            peer,
            PUBLIC_RELAYER_DIAL_ADDRESSES
                .iter()
                .copied()
                .chain(
                    config
                        .network
                        .persistent_peers
                        .iter()
                        .map(|value| value.as_str()),
                )
                .chain(
                    config
                        .network
                        .additional_dial_targets
                        .iter()
                        .map(|value| value.as_str()),
                ),
        )
}

/// Relayers are the only non-validator peers allowed to pull a validator's
/// finalized typed journal. The transport address is observed from the live
/// WireGuard socket, and the relayer role is covered by the peer's PQC
/// handshake; neither a self-reported status field nor a public endpoint can
/// obtain this replay path.
fn peer_is_validator_vpn_relayer(peer: &PeerConnection) -> bool {
    peer.handshake_role
        .as_deref()
        .map(|role| {
            matches!(
                role.trim().to_ascii_lowercase().as_str(),
                "relayer" | "relayer_node"
            )
        })
        .unwrap_or(false)
        && peer_connected_endpoint(peer)
            .as_deref()
            .is_some_and(|endpoint| match peer.direction {
                ConnectionDirection::Outgoing => {
                    is_current_validator_vpn_relayer_dial_address(endpoint)
                }
                // A relayer may also connect into a validator.  TCP assigns
                // that connection an ephemeral source port, so retain the
                // signed relayer role and verify only the canonical VPN host
                // range on this inbound path.
                ConnectionDirection::Incoming => validator_vpn_dial_octets(endpoint)
                    .map(|octets| {
                        octets[0] == 10
                            && octets[1] == 70
                            && octets[2] == 20
                            && (1..=254).contains(&octets[3])
                    })
                    .unwrap_or(false),
            })
}

fn local_is_typed_finality_relayer(config: &NodeConfig) -> bool {
    matches!(
        config.identity.role.trim().to_ascii_lowercase().as_str(),
        "relayer" | "relayer_node"
    ) || matches!(
        config
            .role
            .compiled_profile
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "relayer" | "relayer_node"
    )
}

fn local_is_typed_finality_service_observer(config: &NodeConfig) -> bool {
    matches!(
        config.identity.role.trim().to_ascii_lowercase().as_str(),
        "rpc_gateway" | "rpc_gateway_node" | "indexer_explorer" | "indexer_and_explorer_node"
    ) || matches!(
        config
            .role
            .compiled_profile
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "rpc_gateway" | "rpc_gateway_node" | "indexer_explorer" | "indexer_and_explorer_node"
    )
}

/// Returns the release-validated P1 configuration only when this process is
/// actually configured for `coordinated_round_robin_v1`. A support role must
/// never accept P1 observer traffic merely because a peer asks for it.
fn local_coordinated_finality_observer_config(
    config: &NodeConfig,
) -> Option<crate::consensus::coordinated_round_robin::CoordinatedRoundRobinConfig> {
    match config
        .consensus
        .resolve_mode(config.blockchain.chain_id, &config.network.network_id)
        .ok()?
    {
        ResolvedConsensusMode::CoordinatedRoundRobinV1(coordinated) => Some(coordinated),
        ResolvedConsensusMode::PosySimplifiedV3 => None,
    }
}

fn local_validator_requires_designated_sync_sources(config: &NodeConfig) -> bool {
    local_node_runs_validator_consensus(config)
        && (current_validator_quarantine_duty_block().is_some()
            || !announced_validator_address(config).is_some_and(|address| {
                consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators())
                    .into_iter()
                    .any(|validator| validator.address == address)
            }))
}

fn peer_is_eligible_block_sync_source_for_local(
    config: &NodeConfig,
    peer: &PeerConnection,
) -> bool {
    if local_node_uses_relayer_only_topology(config) {
        return peer_is_designated_relayer_sync_source(config, peer);
    }
    if local_validator_requires_designated_sync_sources(config) {
        return peer_is_designated_support_sync_source(config, peer)
            || peer_is_active_validator_recovery_sync_source(config, peer);
    }
    peer_is_eligible_block_sync_source(config, peer)
}

fn status_peer_is_eligible_block_sync_source(
    config: &NodeConfig,
    peer_validator_address: Option<&str>,
    peer_is_active_validator: bool,
    peer_is_designated_support: bool,
    peer_is_designated_relayer: bool,
    quarantined: bool,
    consensus_duties_disabled: bool,
) -> bool {
    if quarantined {
        return false;
    }

    if local_node_uses_relayer_only_topology(config) {
        return peer_is_designated_relayer;
    }
    if local_validator_requires_designated_sync_sources(config) {
        return peer_is_designated_support
            || (local_validator_can_request_recovery_from_active_validators(config)
                && !consensus_duties_disabled
                && peer_is_active_validator);
    }
    (!consensus_duties_disabled && peer_is_active_validator)
        || peer_is_designated_support
        || peer_validator_address.is_none() && peer_is_designated_relayer
}

fn peer_is_authorized_block_sync_requester(config: &NodeConfig, peer: &PeerConnection) -> bool {
    if !peer.quarantined
        && !peer.consensus_duties_disabled
        && (peer_is_active_consensus_validator(config, peer)
            || peer_is_designated_support_sync_source(config, peer))
    {
        return true;
    }

    peer.quarantined
        && peer.consensus_duties_disabled
        && peer_has_verified_handshake(peer)
        && peer_is_active_consensus_validator(config, peer)
}

fn peer_is_active_validator_recovery_sync_source(
    config: &NodeConfig,
    peer: &PeerConnection,
) -> bool {
    local_validator_can_request_recovery_from_active_validators(config)
        && peer_is_active_consensus_validator(config, peer)
        && peer_has_fresh_remote_status_at(peer, current_timestamp())
        && !peer_quarantine_active_at(peer, current_timestamp())
        && !peer_duties_disabled_active_at(peer, current_timestamp())
}

fn local_validator_can_request_recovery_from_active_validators(config: &NodeConfig) -> bool {
    local_node_runs_validator_consensus(config)
        && current_validator_quarantine_duty_block().is_some()
}

fn peer_has_verified_handshake(peer: &PeerConnection) -> bool {
    peer.node_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
        && peer
            .version
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some()
}

fn status_validator_identity_matches_handshake(
    peer: &PeerConnection,
    status_validator_address: Option<&str>,
) -> bool {
    let handshake_validator_address = normalized_status_string(peer.validator_address.as_deref());
    let status_validator_address = normalized_status_string(status_validator_address);

    status_validator_address == handshake_validator_address
}

fn authorize_status_exchange_for_session(
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    peer_address: &str,
    session_id: u64,
    request_kind: &str,
) -> bool {
    let authorized = {
        let peers = connected_peers.lock().unwrap();
        peer_session_is_current(peer_address, session_id)
            && peers
                .get(peer_address)
                .map(peer_has_verified_handshake)
                .unwrap_or(false)
    };
    if authorized {
        return true;
    }

    warn!(
        "p2p",
        "Refusing status exchange before verified handshake",
        "peer" => peer_address.to_string(),
        "session_id" => session_id,
        "request_kind" => request_kind.to_string()
    );
    let mut peers = connected_peers.lock().unwrap();
    disconnect_peer_entry_for_session(peer_state_cache, &mut peers, peer_address, session_id);
    false
}

fn authorize_chain_requester_for_session(
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    session_id: u64,
    request_kind: &str,
) -> bool {
    if !local_node_runs_validator_consensus(config) {
        return true;
    }

    let authorized = {
        let peers = connected_peers.lock().unwrap();
        peer_session_is_current(peer_address, session_id)
            && peers
                .get(peer_address)
                .map(|peer| peer_is_authorized_block_sync_requester(config, peer))
                .unwrap_or(false)
    };
    if authorized {
        return true;
    }

    warn!(
        "p2p",
        "Refusing canonical chain request from non-active, non-support peer",
        "peer" => peer_address.to_string(),
        "session_id" => session_id,
        "request_kind" => request_kind.to_string()
    );
    let mut peers = connected_peers.lock().unwrap();
    disconnect_peer_entry_for_session(peer_state_cache, &mut peers, peer_address, session_id);
    false
}

fn select_block_sync_targets(
    config: &NodeConfig,
    peers: &PeerMap,
    max_targets: usize,
) -> Vec<String> {
    let mut candidates = peers
        .iter()
        .filter(|(_, peer)| {
            peer.stream.is_some() && peer_is_eligible_block_sync_source_for_local(config, peer)
        })
        .map(|(address, peer)| {
            let has_validator_identity = peer
                .validator_address
                .as_deref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);
            (
                address.clone(),
                peer.last_known_height,
                has_validator_identity,
                peer.status_received_at.unwrap_or(0),
            )
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| left.0.cmp(&right.0))
    });

    candidates
        .into_iter()
        .take(max_targets.max(1))
        .map(|(address, _, _, _)| address)
        .collect()
}

fn best_connected_block_sync_source_height(config: &NodeConfig, peers: &PeerMap) -> u64 {
    peers
        .values()
        .filter(|peer| peer_is_eligible_block_sync_source_for_local(config, peer))
        .map(|peer| peer.last_known_height)
        .max()
        .unwrap_or(0)
}

fn best_connected_validator_height_with_support(
    connected_peers: &PeersArc,
    min_support: usize,
) -> u64 {
    let min_support = min_support.max(1);
    connected_peers
        .lock()
        .map(|peers| {
            let mut active_heights = peers
                .values()
                .filter(|peer| peer_is_active_validator_sync_source(peer))
                .map(|peer| peer.last_known_height)
                .collect::<Vec<_>>();
            active_heights.sort_unstable_by(|left, right| right.cmp(left));
            active_heights
                .get(min_support.saturating_sub(1))
                .copied()
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

fn current_bootstrap_refresh_interval(config: &NodeConfig, connected_peers: &PeersArc) -> Duration {
    let required_validators = config.consensus.min_validators.max(1);
    let discovered_validators = status_ready_validator_participants(config, connected_peers);
    let bootstrap_refresh_secs = config.p2p.bootstrap_refresh_secs.max(1);

    let interval = if discovered_validators < required_validators {
        Duration::from_secs(bootstrap_refresh_secs)
    } else {
        Duration::from_secs(NORMAL_BOOTSTRAP_REFRESH_SECS)
    };
    if local_node_uses_signed_validator_transports(config) {
        interval.min(Duration::from_secs(VALIDATOR_TRANSPORT_REFRESH_SECS))
    } else {
        interval
    }
}

fn resolve_dns_bootstrap_targets(record_names: &[String]) -> Vec<String> {
    if record_names.is_empty() {
        return Vec::new();
    }

    let resolver = match build_dns_resolver() {
        Ok(resolver) => resolver,
        Err(error) => {
            warn!("p2p", "Failed to initialize DNS resolver for bootstrap discovery", "error" => error);
            return Vec::new();
        }
    };

    let mut visited = HashSet::<String>::new();
    let mut out = HashSet::<String>::new();

    for record_name in record_names {
        collect_dnsaddr_record_targets(&resolver, record_name, 0, &mut visited, &mut out);
    }

    let mut ordered = out.into_iter().collect::<Vec<_>>();
    ordered.sort();
    ordered
}

fn build_dns_resolver() -> Result<BootstrapDnsResolver, String> {
    let runtime = TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;

    let resolver = TokioResolver::builder_tokio()
        .and_then(|builder| builder.build())
        .or_else(|_| {
            Resolver::builder_with_config(
                ResolverConfig::default(),
                TokioRuntimeProvider::default(),
            )
            .build()
        })
        .map_err(|error| error.to_string())?;

    Ok(BootstrapDnsResolver { resolver, runtime })
}

fn collect_dnsaddr_record_targets(
    resolver: &BootstrapDnsResolver,
    record_name: &str,
    depth: usize,
    visited: &mut HashSet<String>,
    out: &mut HashSet<String>,
) {
    let record_name = record_name.trim();
    if record_name.is_empty() || depth > 4 {
        return;
    }

    let canonical = record_name.trim_end_matches('.').to_string();
    if !visited.insert(canonical.clone()) {
        return;
    }

    match resolver
        .runtime
        .block_on(resolver.resolver.txt_lookup(canonical.clone()))
    {
        Ok(records) => {
            for record in records.answers() {
                let RData::TXT(txt_record) = &record.data else {
                    continue;
                };

                for txt in txt_record.txt_data.iter() {
                    let Ok(value) = std::str::from_utf8(txt) else {
                        continue;
                    };
                    collect_dnsaddr_txt_target(resolver, value, depth, visited, out);
                }
            }
        }
        Err(error) => {
            debug!(
                "p2p",
                "Bootstrap DNS TXT lookup failed",
                "record" => canonical,
                "error" => error.to_string()
            );
        }
    }
}

fn collect_dnsaddr_txt_target(
    resolver: &BootstrapDnsResolver,
    value: &str,
    depth: usize,
    visited: &mut HashSet<String>,
    out: &mut HashSet<String>,
) {
    let value = value
        .trim()
        .trim_matches('"')
        .strip_prefix("dnsaddr=")
        .unwrap_or(value.trim())
        .trim();
    if value.is_empty() {
        return;
    }

    if let Some(next_record) = parse_dnsaddr_reference_record(value) {
        collect_dnsaddr_record_targets(resolver, &next_record, depth + 1, visited, out);
        return;
    }

    if let Some(dial) = parse_dnsaddr_multiaddr_to_dial_address(value) {
        out.insert(dial);
    }
}

fn parse_dnsaddr_reference_record(value: &str) -> Option<String> {
    let referenced = value.strip_prefix("/dnsaddr/")?;
    let referenced = referenced.split('/').next()?.trim().trim_end_matches('.');
    if referenced.is_empty() {
        None
    } else {
        Some(format!("_dnsaddr.{}", referenced))
    }
}

fn parse_dnsaddr_multiaddr_to_dial_address(value: &str) -> Option<String> {
    let segments = value
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();

    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut transport: Option<&str> = None;
    let mut index = 0usize;

    while index + 1 < segments.len() {
        let key = segments[index];
        let val = segments[index + 1];
        match key {
            "dns" | "dns4" | "dns6" | "ip4" | "ip6" if host.is_none() => {
                host = Some(val.to_string());
            }
            "tcp" => {
                if let Ok(parsed) = val.parse::<u16>() {
                    port = Some(parsed);
                    transport = Some("tcp");
                }
            }
            "udp" => {
                transport = Some("udp");
            }
            _ => {}
        }
        index += 2;
    }

    match (host, port, transport) {
        (Some(host), Some(port), Some("tcp")) => Some(format!("{host}:{port}")),
        _ => None,
    }
}

fn resolve_seed_server_targets(seed_servers: &[String]) -> Vec<String> {
    if seed_servers.is_empty() {
        return Vec::new();
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            warn!(
                "p2p",
                "Failed to build HTTP client for seed discovery",
                "error" => error.to_string()
            );
            return Vec::new();
        }
    };

    let mut out = HashSet::<String>::new();
    let configured_seed_endpoints = configured_seed_server_dial_targets(seed_servers);
    for seed_server in seed_servers {
        fetch_seed_server_targets(&client, seed_server, &configured_seed_endpoints, &mut out);
    }

    let mut ordered = out.into_iter().collect::<Vec<_>>();
    ordered.sort();
    ordered
}

fn configured_seed_server_dial_targets(seed_servers: &[String]) -> HashSet<String> {
    seed_servers
        .iter()
        .filter_map(|seed_server| {
            let raw = seed_server.trim();
            let authority = raw
                .strip_prefix("http://")
                .or_else(|| raw.strip_prefix("https://"))
                .unwrap_or(raw)
                .split(['/', '?', '#'])
                .next()
                .unwrap_or_default();
            parse_bootnode_dial_address(authority)
        })
        .collect()
}

fn insert_seed_server_target(
    out: &mut HashSet<String>,
    configured_seed_endpoints: &HashSet<String>,
    dial: String,
) {
    if !configured_seed_endpoints.contains(&dial) {
        out.insert(dial);
    }
}

fn fetch_seed_server_targets(
    client: &reqwest::blocking::Client,
    seed_server: &str,
    configured_seed_endpoints: &HashSet<String>,
    out: &mut HashSet<String>,
) {
    let json_url = normalize_seed_server_url(seed_server, "/peer-list.json");
    if !json_url.is_empty() {
        match client.get(&json_url).send() {
            Ok(response) if response.status().is_success() => {
                match response.json::<SeedPeerListResponse>() {
                    Ok(payload) => {
                        for bootnode in payload.bootnodes {
                            if bootnode.reachable.unwrap_or(true) {
                                let dial = format!("{}:{}", bootnode.hostname, bootnode.port);
                                if is_assigned_or_validator_vpn_dial_address(&dial) {
                                    insert_seed_server_target(out, configured_seed_endpoints, dial);
                                }
                            }
                        }
                        for value in payload.dnsaddr_bootstrap {
                            if let Some(dial) = parse_dnsaddr_multiaddr_to_dial_address(&value) {
                                if is_assigned_or_validator_vpn_dial_address(&dial) {
                                    insert_seed_server_target(out, configured_seed_endpoints, dial);
                                }
                            }
                        }
                        for peer in payload.peers {
                            if let Some(dial) = parse_bootnode_dial_address(&peer) {
                                if is_assigned_or_validator_vpn_dial_address(&dial) {
                                    insert_seed_server_target(out, configured_seed_endpoints, dial);
                                }
                            }
                        }
                        return;
                    }
                    Err(error) => {
                        debug!(
                            "p2p",
                            "Failed to parse seed peer list JSON",
                            "seed_server" => seed_server.to_string(),
                            "error" => error.to_string()
                        );
                    }
                }
            }
            Ok(response) => {
                debug!(
                    "p2p",
                    "Seed peer list request returned non-success status",
                    "seed_server" => seed_server.to_string(),
                    "status" => response.status().as_u16()
                );
            }
            Err(error) => {
                debug!(
                    "p2p",
                    "Seed peer list request failed",
                    "seed_server" => seed_server.to_string(),
                    "error" => error.to_string()
                );
            }
        }
    }

    let text_url = normalize_seed_server_url(seed_server, "/dns/bootstrap.txt");
    if text_url.is_empty() {
        return;
    }

    match client.get(&text_url).send() {
        Ok(response) if response.status().is_success() => {
            if let Ok(body) = response.text() {
                for line in body.lines() {
                    let value = line.trim();
                    if value.is_empty() {
                        continue;
                    }
                    if let Some(dial) = parse_dnsaddr_multiaddr_to_dial_address(
                        value.strip_prefix("dnsaddr=").unwrap_or(value),
                    ) {
                        insert_seed_server_target(out, configured_seed_endpoints, dial);
                    }
                }
            }
        }
        Ok(_) | Err(_) => {}
    }
}

fn register_self_with_seed_servers(config: &NodeConfig) {
    if config.node.bootstrap_only || config.network.seed_servers.is_empty() {
        return;
    }
    let role_id = config.identity.role.trim().to_string();
    if !role_id.eq_ignore_ascii_case("validator") {
        return;
    }
    let public_address = config.p2p.public_address.trim().to_string();
    if public_address.is_empty()
        || public_address.starts_with("127.")
        || public_address.starts_with("0.0.0.0")
        || !is_assigned_synergy_dial_address(&public_address)
    {
        return;
    }
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let validator_address = config.node.validator_address.trim().to_string();
    if validator_address.is_empty() {
        return;
    }
    let mut payload = serde_json::json!({
        "node_id": config.p2p.node_name,
        "role_id": role_id,
        "dial": public_address,
    });
    payload["wallet_address"] = serde_json::Value::String(validator_address);
    for seed_server in &config.network.seed_servers {
        let register_url = normalize_seed_server_url(seed_server, "/peers/register");
        if register_url.is_empty() {
            continue;
        }
        match client.post(&register_url).json(&payload).send() {
            Ok(resp) if resp.status().is_success() => {
                debug!(
                    "p2p",
                    "Registered self with seed server",
                    "seed_server" => seed_server.clone(),
                    "dial" => public_address.clone()
                );
            }
            Ok(resp) => {
                debug!(
                    "p2p",
                    "Seed server self-registration returned non-success",
                    "seed_server" => seed_server.clone(),
                    "status" => resp.status().as_u16()
                );
            }
            Err(e) => {
                debug!(
                    "p2p",
                    "Failed to register self with seed server",
                    "seed_server" => seed_server.clone(),
                    "error" => e.to_string()
                );
            }
        }
    }
}

fn normalize_seed_server_url(seed_server: &str, default_path: &str) -> String {
    let trimmed = seed_server.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }

    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let remainder = trimmed
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(trimmed);
        if remainder.contains('/') {
            trimmed.to_string()
        } else {
            format!("{trimmed}{default_path}")
        }
    } else {
        format!("http://{trimmed}{default_path}")
    }
}

fn configure_peer_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    // Keep long-lived validator sockets active so NAT devices do not reap them
    // between proposal/vote rounds.
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(TCP_KEEPALIVE_IDLE_SECS))
        .with_interval(Duration::from_secs(TCP_KEEPALIVE_INTERVAL_SECS));
    let socket = SockRef::from(stream);
    let _ = socket.set_tcp_keepalive(&keepalive);
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);
}

#[derive(Debug, Clone, Default)]
pub struct PeerSnapshot {
    pub address: String,
    pub direction: String,
    pub node_id: Option<String>,
    /// Derived only after the signed P2P handshake and endpoint authorization.
    pub authenticated_designated_support: bool,
    pub authenticated_designated_relayer: bool,
    pub public_address: Option<String>,
    pub validator_address: Option<String>,
    pub version: Option<String>,
    pub capabilities: Vec<String>,
    pub block_height: u64,
    pub best_block_hash: String,
    pub genesis_hash: String,
    pub status_received_at: Option<u64>,
    pub status_reported_at: Option<u64>,
    pub status_validator_address: Option<String>,
    pub status_source_session_id: Option<String>,
    pub active_validator_set_hash: Option<String>,
    pub status_fresh: bool,
    pub status_age_secs: Option<u64>,
    pub readiness_exclusion_reason: Option<String>,
    pub quarantined: bool,
    pub consensus_duties_disabled: bool,
    pub recovery_state: Option<String>,
    pub connected_at: u64,
    pub last_seen: u64,
    pub blocks_sent: u64,
    pub blocks_received: u64,
    pub txs_sent: u64,
    pub txs_received: u64,
}

fn build_peer_snapshot(config: &NodeConfig, peer: &PeerConnection, now: u64) -> PeerSnapshot {
    let expected_validator_set_hash = canonical_validator_set_hash();
    PeerSnapshot {
        address: peer
            .public_address
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| peer.address.clone()),
        direction: match peer.direction {
            ConnectionDirection::Incoming => "incoming".to_string(),
            ConnectionDirection::Outgoing => "outgoing".to_string(),
        },
        node_id: peer.node_id.clone(),
        authenticated_designated_support: peer_is_designated_support_sync_source(config, peer),
        authenticated_designated_relayer: peer_is_designated_relayer_sync_source(config, peer),
        public_address: peer.public_address.clone(),
        validator_address: peer.validator_address.clone(),
        version: peer.version.clone(),
        capabilities: peer.capabilities.clone(),
        block_height: peer.last_known_height,
        best_block_hash: peer.best_block_hash.clone(),
        genesis_hash: peer.genesis_hash.clone(),
        status_received_at: peer.status_received_at,
        status_reported_at: peer.status_reported_at,
        status_validator_address: peer.status_validator_address.clone(),
        status_source_session_id: peer.status_source_session_id.clone(),
        active_validator_set_hash: peer.active_validator_set_hash.clone(),
        status_fresh: peer_has_fresh_remote_status_at(peer, now),
        status_age_secs: peer_status_age_secs_at(peer, now),
        readiness_exclusion_reason: peer_readiness_exclusion_reason_at(
            peer,
            now,
            Some(&expected_validator_set_hash),
        )
        .map(ToOwned::to_owned),
        quarantined: peer_quarantine_active_at(peer, now),
        consensus_duties_disabled: peer_duties_disabled_active_at(peer, now),
        recovery_state: peer.recovery_state.clone(),
        connected_at: peer.connected_at,
        last_seen: peer.last_seen,
        blocks_sent: peer.blocks_sent,
        blocks_received: peer.blocks_received,
        txs_sent: peer.txs_sent,
        txs_received: peer.txs_received,
    }
}

impl P2PNetwork {
    pub fn new(blockchain: BlockchainArc, config: &NodeConfig) -> Self {
        let (sender, receiver) = mpsc::channel();

        P2PNetwork {
            blockchain,
            config: config.clone(),
            connected_peers: Arc::new(Mutex::new(HashMap::new())),
            peer_state_cache: Arc::new(Mutex::new(HashMap::new())),
            discovered_dial_targets: Arc::new(Mutex::new(Vec::new())),
            outbound_dial_registry: Arc::new(Mutex::new(HashMap::new())),
            is_running: Arc::new(Mutex::new(false)),
            message_sender: sender,
            message_receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    pub fn sync_batch_limit(&self) -> u64 {
        sync_batch_limit_for_role(&self.config) as u64
    }

    pub fn start(&mut self, listen_address: &str) {
        let is_running = Arc::clone(&self.is_running);
        let blockchain = Arc::clone(&self.blockchain);
        let connected_peers = Arc::clone(&self.connected_peers);
        let peer_state_cache = Arc::clone(&self.peer_state_cache);
        let config = self.config.clone();
        let addr_string = listen_address.to_string();
        let message_sender = self.message_sender.clone();

        // Set running flag
        *is_running.lock().unwrap() = true;

        #[cfg(not(test))]
        if local_node_uses_signed_validator_transports(&self.config)
            && !chain1266_private_qualification_mode()
        {
            match refresh_validator_transports() {
                Ok(refresh) => info!(
                    "p2p",
                    "Loaded fresh provider-signed validator transport registry before network start",
                    "generation" => refresh.generation
                ),
                Err(error) => {
                    error!(
                        "p2p",
                        "Fresh validator transport registry is unavailable; refusing production validator-network start",
                        "error" => error
                    );
                    *is_running.lock().unwrap() = false;
                    return;
                }
            }
            start_validator_transport_refresh_worker(Arc::clone(&is_running));
        }

        // Start listener thread
        let _ = spawn_named_thread("p2p-listener", move || {
            if let Err(e) = start_listener(
                &addr_string,
                blockchain,
                connected_peers,
                peer_state_cache,
                config,
                message_sender,
            ) {
                error!("p2p", "P2P listener error", "error" => e.to_string());
            }
        });

        // Start message handler thread
        let blockchain_handler = Arc::clone(&self.blockchain);
        let peers_handler = Arc::clone(&self.connected_peers);
        let peer_state_cache_handler = Arc::clone(&self.peer_state_cache);
        let discovered_targets_handler = Arc::clone(&self.discovered_dial_targets);
        let dial_registry_handler = Arc::clone(&self.outbound_dial_registry);
        let receiver = Arc::clone(&self.message_receiver);
        let handler_config = self.config.clone();
        let handler_sender = self.message_sender.clone();

        let _ = spawn_named_thread("p2p-message-handler", move || {
            handle_messages(
                blockchain_handler,
                peers_handler,
                peer_state_cache_handler,
                discovered_targets_handler,
                dial_registry_handler,
                receiver,
                handler_sender,
                handler_config,
            );
        });

        info!(
            "p2p",
            "P2P network started",
            "listen_address" => listen_address.to_string(),
            "public_address" => self.config.p2p.public_address.clone(),
            "bootnodes" => self.config.network.bootnodes.len() as u64
        );
    }

    pub fn connect_to_peer(&self, address: &str) -> Result<(), Box<dyn std::error::Error>> {
        let peer_address = normalize_peer_target(&self.config, address)
            .unwrap_or_else(|| address.trim().to_string());
        let Some(transport_address) = resolve_peer_transport_address(&self.config, &peer_address)
        else {
            warn!(
                "p2p",
                "Failed to resolve peer transport address",
                "peer" => peer_address.clone()
            );
            return Ok(());
        };
        if !reserve_outbound_dial(
            &self.outbound_dial_registry,
            &self.connected_peers,
            &peer_address,
            self.config.network.max_peers as usize,
        ) {
            return Ok(());
        }

        let blockchain = Arc::clone(&self.blockchain);
        let connected_peers = Arc::clone(&self.connected_peers);
        let peer_state_cache = Arc::clone(&self.peer_state_cache);
        let dial_registry = Arc::clone(&self.outbound_dial_registry);
        let message_sender = self.message_sender.clone();
        let config = self.config.clone();
        let cleanup_address = peer_address.clone();

        let spawned = spawn_named_thread("p2p-connect-peer", move || {
            match dial_with_timeout(&transport_address, std::time::Duration::from_secs(5)) {
                Ok(stream) => {
                    if let Err(e) = handle_outgoing_connection(
                        stream,
                        peer_address,
                        blockchain,
                        connected_peers,
                        peer_state_cache,
                        message_sender,
                        config,
                    ) {
                        error!("p2p", "Outgoing connection error", "error" => e.to_string());
                    }
                }
                Err(e) => {
                    warn!(
                        "p2p",
                        "Failed to dial peer",
                        "peer" => peer_address,
                        "transport" => transport_address,
                        "error" => e.to_string()
                    );
                }
            }
            release_outbound_dial(&dial_registry, &cleanup_address);
        });
        if !spawned {
            release_outbound_dial(&self.outbound_dial_registry, address);
        }

        Ok(())
    }

    pub fn broadcast_block(&self, block: &Block) {
        let Some(qc) = DualQuorumConsensus::committed_qc_for_block_hash(&block.hash) else {
            warn!(
                "p2p",
                "Refusing to broadcast committed block without locally stored QC",
                "height" => block.block_index,
                "hash" => block.hash.clone()
            );
            return;
        };
        self.broadcast_committed_block(block, &qc);
    }

    pub fn broadcast_committed_block(&self, block: &Block, qc: &QuorumCertificate) {
        let message = NetworkMessage::Block {
            block_data: block.clone(),
            quorum_certificate: Some(qc.clone()),
        };

        let mut sent = 0usize;
        let mut failed_peers = Vec::new();
        let block_targets = peer_session_targets(&self.connected_peers);
        let send_results = run_with_bounded_parallelism(
            &block_targets,
            block_targets.len(),
            "consensus fanout",
            |(address, session_id)| {
                send_peer_message_for_session(
                    &self.connected_peers,
                    &self.peer_state_cache,
                    address,
                    *session_id,
                    &message,
                    Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
                    "committed-block",
                )
            },
        );
        for ((address, session_id), send_result) in block_targets.into_iter().zip(send_results) {
            match send_result {
                Ok(true) => {
                    let mut peers = self.connected_peers.lock().unwrap();
                    if let Some(peer) = peer_for_session_mut(&mut peers, &address, session_id) {
                        peer.blocks_sent += 1;
                        sent += 1;
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    warn!("p2p", "Failed to send block", "peer" => address.clone(), "error" => error);
                    failed_peers.push(address);
                }
            }
        }

        info!(
            "p2p",
            "Block broadcast",
            "peers" => sent as u64,
            "dropped_peers" => failed_peers.len() as u64,
            "height" => block.block_index
        );
    }

    /// Sends a typed PoSy v2.2 artifact only to currently connected,
    /// consensus-eligible validator peers. The coordinator remains
    /// responsible for verifying every inbound context/certificate; this
    /// method only supplies the bounded authenticated transport fanout.
    pub fn broadcast_typed_consensus(
        &self,
        message: &TypedConsensusMessage,
    ) -> Result<usize, String> {
        if coordinated_consensus_active(&self.config) {
            return Err("typed PoSy egress is disabled in coordinated_round_robin_v1".to_string());
        }
        crate::p2p::messages::validate_typed_consensus_message_size(message)?;
        let wire_message = NetworkMessage::TypedConsensus {
            chain_incarnation: canonical_chain_incarnation(),
            genesis_hash: canonical_genesis_hash(),
            message: message.clone(),
        };
        let targets = {
            let peers = self.connected_peers.lock().unwrap();
            peers
                .iter()
                .filter_map(|(address, peer)| {
                    if peer.stream.is_none()
                        || !peer_is_active_consensus_validator(&self.config, peer)
                    {
                        return None;
                    }
                    current_peer_session_id(address).map(|session_id| (address.clone(), session_id))
                })
                .collect::<Vec<_>>()
        };
        let send_results = run_with_bounded_parallelism(
            &targets,
            targets.len(),
            "typed consensus fanout",
            |(address, session_id)| {
                send_peer_message_for_session(
                    &self.connected_peers,
                    &self.peer_state_cache,
                    address,
                    *session_id,
                    &wire_message,
                    Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
                    "typed-consensus",
                )
            },
        );
        let mut sent = 0usize;
        for ((address, _session_id), result) in targets.into_iter().zip(send_results) {
            match result {
                Ok(true) => sent += 1,
                Ok(false) => {}
                Err(error) => warn!(
                    "p2p",
                    "Failed to send typed consensus message",
                    "peer" => address,
                    "error" => error
                ),
            }
        }
        Ok(sent)
    }

    /// Sends a PoSy v3 artifact only over the already authenticated validator
    /// sessions. The simplified driver rebinds each peer to its dynamic frozen
    /// epoch validator set before processing the message.
    pub fn broadcast_simplified_consensus(
        &self,
        message: &SimplifiedConsensusMessage,
        frozen_validator_ids: &BTreeSet<ValidatorId>,
    ) -> Result<usize, String> {
        if coordinated_consensus_active(&self.config) {
            return Err(
                "simplified PoSy egress is disabled while coordinated_round_robin_v1 is selected"
                    .to_string(),
            );
        }
        validate_simplified_consensus_message_size(message)?;
        if frozen_validator_ids.is_empty() {
            return Err("simplified consensus frozen egress set is empty".to_string());
        }
        let wire_message = NetworkMessage::SimplifiedConsensus {
            chain_incarnation: canonical_chain_incarnation(),
            genesis_hash: canonical_genesis_hash(),
            message: message.clone(),
        };
        let targets = {
            let peers = self.connected_peers.lock().unwrap();
            peers
                .iter()
                .filter_map(|(address, peer)| {
                    if peer.stream.is_none() {
                        return None;
                    }
                    let session_id = current_peer_session_id(address)?;
                    let identity = simplified_consensus_peer_for_session(address, session_id)?;
                    frozen_validator_ids
                        .contains(&identity.validator_id)
                        .then(|| (address.clone(), session_id))
                })
                .collect::<Vec<_>>()
        };
        let send_results = run_with_bounded_parallelism(
            &targets,
            targets.len(),
            "simplified consensus fanout",
            |(address, session_id)| {
                send_peer_message_for_session(
                    &self.connected_peers,
                    &self.peer_state_cache,
                    address,
                    *session_id,
                    &wire_message,
                    Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
                    "simplified-consensus",
                )
            },
        );
        let mut sent = 0usize;
        for ((address, _), result) in targets.into_iter().zip(send_results) {
            match result {
                Ok(true) => sent += 1,
                Ok(false) => {}
                Err(error) => warn!(
                    "p2p",
                    "Failed to send simplified consensus message",
                    "peer" => address,
                    "error" => error
                ),
            }
        }
        Ok(sent)
    }

    /// Sends a coordinated-mode artifact only to authenticated validator peers.
    /// This retained compatibility surface is not selected by simplified PoSy.
    pub fn broadcast_coordinated_consensus(
        &self,
        message: &CoordinatedConsensusMessage,
    ) -> Result<usize, String> {
        validate_coordinated_consensus_message_size(message)?;
        let wire_message = NetworkMessage::CoordinatedConsensus {
            chain_incarnation: canonical_chain_incarnation(),
            genesis_hash: canonical_genesis_hash(),
            message: message.clone(),
        };
        let targets = {
            let peers = self.connected_peers.lock().unwrap();
            peers
                .iter()
                .filter_map(|(address, peer)| {
                    if peer.stream.is_none()
                        || !peer_is_active_consensus_validator(&self.config, peer)
                    {
                        return None;
                    }
                    current_peer_session_id(address).map(|session_id| (address.clone(), session_id))
                })
                .collect::<Vec<_>>()
        };
        let send_results = run_with_bounded_parallelism(
            &targets,
            targets.len(),
            "coordinated consensus fanout",
            |(address, session_id)| {
                send_peer_message_for_session(
                    &self.connected_peers,
                    &self.peer_state_cache,
                    address,
                    *session_id,
                    &wire_message,
                    Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
                    "coordinated-consensus",
                )
            },
        );
        let mut sent = 0usize;
        for ((address, _session_id), result) in targets.into_iter().zip(send_results) {
            match result {
                Ok(true) => sent += 1,
                Ok(false) => {}
                Err(error) => warn!(
                    "p2p",
                    "Failed to send coordinated consensus message",
                    "peer" => address,
                    "error" => error
                ),
            }
        }
        Ok(sent)
    }

    /// Sends an assigned producer block directly to the authenticated
    /// coordinator. Simplified PoSy never calls this compatibility path.
    pub fn send_coordinated_consensus_to_validator(
        &self,
        validator_id: &str,
        message: &CoordinatedConsensusMessage,
    ) -> Result<(), String> {
        validate_coordinated_consensus_message_size(message)?;
        let wire_message = NetworkMessage::CoordinatedConsensus {
            chain_incarnation: canonical_chain_incarnation(),
            genesis_hash: canonical_genesis_hash(),
            message: message.clone(),
        };
        let target = {
            let peers = self
                .connected_peers
                .lock()
                .map_err(|_| "coordinated peer registry lock is poisoned".to_string())?;
            peers.iter().find_map(|(address, peer)| {
                if peer.stream.is_none() {
                    return None;
                }
                let session_id = current_peer_session_id(address)?;
                let identity = typed_consensus_peer_for_session(address, session_id)?;
                (identity.validator_id.0 == validator_id).then(|| (address.clone(), session_id))
            })
        }
        .ok_or_else(|| {
            format!("coordinated producer has no authenticated route to {validator_id}")
        })?;
        let sent = send_peer_message_for_session(
            &self.connected_peers,
            &self.peer_state_cache,
            &target.0,
            target.1,
            &wire_message,
            Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
            "coordinated-producer-block",
        )?;
        if !sent {
            return Err(format!(
                "coordinated producer session to {validator_id} was replaced"
            ));
        }
        Ok(())
    }

    /// Broadcasts one bounded H+3 target-admission vote or certified package
    /// only to authenticated sessions in the caller's frozen dynamic epoch.
    pub fn broadcast_simplified_target_admission(
        &self,
        message: &SimplifiedTargetAdmissionMessage,
        frozen_validator_ids: &BTreeSet<ValidatorId>,
    ) -> Result<usize, String> {
        if coordinated_consensus_active(&self.config) {
            return Err(
                "simplified target-admission egress is disabled while coordinated_round_robin_v1 is selected"
                    .to_string(),
            );
        }
        validate_simplified_target_admission_message_size(message)?;
        if frozen_validator_ids.is_empty() {
            return Err("simplified target-admission frozen egress set is empty".to_string());
        }
        let wire_message = NetworkMessage::SimplifiedTargetAdmission {
            chain_incarnation: canonical_chain_incarnation(),
            genesis_hash: canonical_genesis_hash(),
            message: message.clone(),
        };
        let targets = {
            let peers = self.connected_peers.lock().unwrap();
            peers
                .iter()
                .filter_map(|(address, peer)| {
                    if peer.stream.is_none() {
                        return None;
                    }
                    let session_id = current_peer_session_id(address)?;
                    let identity = etdag_ingress_peer_for_session(address, session_id)?;
                    frozen_validator_ids
                        .contains(&identity.validator_id)
                        .then(|| (address.clone(), session_id))
                })
                .collect::<Vec<_>>()
        };
        let send_results = run_with_bounded_parallelism(
            &targets,
            targets.len(),
            "simplified target-admission fanout",
            |(address, session_id)| {
                send_peer_message_for_session(
                    &self.connected_peers,
                    &self.peer_state_cache,
                    address,
                    *session_id,
                    &wire_message,
                    Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
                    "simplified-target-admission",
                )
            },
        );
        let mut sent = 0usize;
        for ((address, _), result) in targets.into_iter().zip(send_results) {
            match result {
                Ok(true) => sent += 1,
                Ok(false) => {}
                Err(error) => warn!(
                    "p2p",
                    "Failed to send simplified target-admission message",
                    "peer" => address,
                    "error" => error
                ),
            }
        }
        Ok(sent)
    }

    /// Broadcasts one bounded empty-ETDAG assembly artifact only to
    /// authenticated validator sessions in the caller's frozen dynamic epoch.
    pub fn broadcast_simplified_empty_etdag(
        &self,
        message: &SimplifiedEmptyEtdagMessage,
        frozen_validator_ids: &BTreeSet<ValidatorId>,
    ) -> Result<usize, String> {
        if coordinated_consensus_active(&self.config) {
            return Err(
                "simplified empty-ETDAG egress is disabled while coordinated_round_robin_v1 is selected"
                    .to_string(),
            );
        }
        validate_simplified_empty_etdag_message_size(message)?;
        if frozen_validator_ids.is_empty() {
            return Err("simplified empty-ETDAG frozen egress set is empty".to_string());
        }
        let wire_message = NetworkMessage::SimplifiedEtdagAssembly {
            message: message.clone(),
            chain_incarnation: canonical_chain_incarnation(),
            genesis_hash: canonical_genesis_hash(),
        };
        let targets = {
            let peers = self.connected_peers.lock().unwrap();
            peers
                .iter()
                .filter_map(|(address, peer)| {
                    if peer.stream.is_none() {
                        return None;
                    }
                    let session_id = current_peer_session_id(address)?;
                    let identity = etdag_ingress_peer_for_session(address, session_id)?;
                    frozen_validator_ids
                        .contains(&identity.validator_id)
                        .then(|| (address.clone(), session_id))
                })
                .collect::<Vec<_>>()
        };
        let send_results = run_with_bounded_parallelism(
            &targets,
            targets.len(),
            "simplified empty-ETDAG fanout",
            |(address, session_id)| {
                send_peer_message_for_session(
                    &self.connected_peers,
                    &self.peer_state_cache,
                    address,
                    *session_id,
                    &wire_message,
                    Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
                    "simplified-empty-etdag",
                )
            },
        );
        let mut sent = 0usize;
        for ((address, _), result) in targets.into_iter().zip(send_results) {
            match result {
                Ok(true) => sent += 1,
                Ok(false) => {}
                Err(error) => warn!(
                    "p2p",
                    "Failed to send simplified empty-ETDAG message",
                    "peer" => address,
                    "error" => error
                ),
            }
        }
        Ok(sent)
    }

    /// Sends a simplified-consensus response only to the authenticated session
    /// that requested it. State-sync chunks are request-correlated and must not
    /// be amplified across the full validator ring.
    pub fn send_simplified_consensus_to_peer(
        &self,
        peer_address: &str,
        expected_validator_id: &ValidatorId,
        message: &SimplifiedConsensusMessage,
        frozen_validator_ids: &BTreeSet<ValidatorId>,
    ) -> Result<usize, String> {
        if coordinated_consensus_active(&self.config) {
            return Err(
                "simplified PoSy direct egress is disabled while coordinated_round_robin_v1 is selected"
                    .to_string(),
            );
        }
        validate_simplified_consensus_message_size(message)?;
        if frozen_validator_ids.is_empty() {
            return Err("simplified consensus frozen egress set is empty".to_string());
        }
        let session_id = {
            let peers = self.connected_peers.lock().unwrap();
            let peer = peers
                .get(peer_address)
                .ok_or_else(|| "simplified consensus target peer is disconnected".to_string())?;
            if peer.stream.is_none() {
                return Err("simplified consensus target peer has no live stream".to_string());
            }
            let session_id = current_peer_session_id(peer_address).ok_or_else(|| {
                "simplified consensus target peer has no current session".to_string()
            })?;
            let identity = simplified_consensus_peer_for_session(peer_address, session_id)
                .ok_or_else(|| {
                    "simplified consensus target peer lacks an authenticated validator identity"
                        .to_string()
                })?;
            validate_simplified_consensus_target_identity(
                &identity,
                expected_validator_id,
                frozen_validator_ids,
            )?;
            session_id
        };
        let wire_message = NetworkMessage::SimplifiedConsensus {
            chain_incarnation: canonical_chain_incarnation(),
            genesis_hash: canonical_genesis_hash(),
            message: message.clone(),
        };
        match send_peer_message_for_session(
            &self.connected_peers,
            &self.peer_state_cache,
            peer_address,
            session_id,
            &wire_message,
            Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
            "simplified-consensus-targeted",
        ) {
            Ok(true) => Ok(1),
            Ok(false) => Ok(0),
            Err(error) => Err(error),
        }
    }

    /// Pulls the next bounded finalized-typed segment for an installed
    /// non-signing observer. A relayer may ask only a session-authenticated
    /// validator across the validator VPN; RPC/indexer roles may ask only a
    /// configured public relayer. Validators never use this method and never
    /// expose RPC as a substitute for the verified P2P path.
    pub fn request_typed_finality_observer_records(&self) -> Result<usize, String> {
        let Some(next_height) = typed_finality_observer_next_missing_height() else {
            return Ok(0);
        };
        let is_relayer = local_is_typed_finality_relayer(&self.config);
        let is_service_observer = local_is_typed_finality_service_observer(&self.config);
        if !is_relayer && !is_service_observer {
            return Err(
                "typed finality observer receiver is installed for an unsupported local role"
                    .to_string(),
            );
        }
        let wire_message = NetworkMessage::TypedFinalityObserver {
            chain_incarnation: canonical_chain_incarnation(),
            genesis_hash: canonical_genesis_hash(),
            message: TypedFinalityObserverMessage::Request { next_height },
        };
        let targets = {
            let peers = self.connected_peers.lock().unwrap();
            peers
                .iter()
                .filter_map(|(address, peer)| {
                    if peer.stream.is_none() {
                        return None;
                    }
                    let session_id = current_peer_session_id(address)?;
                    let authorized = if is_relayer {
                        // A validated typed-consensus session is bound to the
                        // exact finalized Genesis validator identity.
                        typed_consensus_peer_for_session(address, session_id).is_some()
                    } else {
                        peer_is_designated_relayer_sync_source(&self.config, peer)
                    };
                    authorized.then_some((address.clone(), session_id))
                })
                .collect::<Vec<_>>()
        };
        let send_results = run_with_bounded_parallelism(
            &targets,
            targets.len(),
            "typed finality observer request fanout",
            |(address, session_id)| {
                send_peer_message_for_session(
                    &self.connected_peers,
                    &self.peer_state_cache,
                    address,
                    *session_id,
                    &wire_message,
                    Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
                    "typed-finality-observer-request",
                )
            },
        );
        let mut sent = 0usize;
        for ((address, _session_id), result) in targets.into_iter().zip(send_results) {
            match result {
                Ok(true) => sent += 1,
                Ok(false) => {}
                Err(error) => warn!(
                    "p2p",
                    "Failed to request typed finality observer records",
                    "peer" => address,
                    "error" => error
                ),
            }
        }
        Ok(sent)
    }

    /// Pulls the next bounded `coordinated_round_robin_v1` finality segment
    /// for an installed non-signing support observer. The topology is the
    /// same narrow bridge as typed finality: validator -> VPN relayer ->
    /// configured public RPC/indexer observer. P1 coordinator traffic is
    /// never used as a support-tier synchronization channel.
    pub fn request_coordinated_finality_observer_records(&self) -> Result<usize, String> {
        let Some(next_height) = coordinated_finality_observer_next_missing_height() else {
            return Ok(0);
        };
        let Some(_coordinated_config) = local_coordinated_finality_observer_config(&self.config)
        else {
            return Err(
                "coordinated finality observer receiver is installed outside coordinated_round_robin_v1"
                    .to_string(),
            );
        };
        let is_relayer = local_is_typed_finality_relayer(&self.config);
        let is_service_observer = local_is_typed_finality_service_observer(&self.config);
        if !is_relayer && !is_service_observer {
            return Err(
                "coordinated finality observer receiver is installed for an unsupported local role"
                    .to_string(),
            );
        }
        let wire_message = NetworkMessage::CoordinatedFinalityObserver {
            chain_incarnation: canonical_chain_incarnation(),
            genesis_hash: canonical_genesis_hash(),
            message: CoordinatedFinalityObserverMessage::Request { next_height },
        };
        let targets = {
            let peers = self.connected_peers.lock().unwrap();
            peers
                .iter()
                .filter_map(|(address, peer)| {
                    if peer.stream.is_none() {
                        return None;
                    }
                    let session_id = current_peer_session_id(address)?;
                    let authorized = if is_relayer {
                        typed_consensus_peer_for_session(address, session_id).is_some()
                    } else {
                        peer_is_designated_relayer_sync_source(&self.config, peer)
                    };
                    authorized.then_some((address.clone(), session_id))
                })
                .collect::<Vec<_>>()
        };
        let send_results = run_with_bounded_parallelism(
            &targets,
            targets.len(),
            "coordinated finality observer request fanout",
            |(address, session_id)| {
                send_peer_message_for_session(
                    &self.connected_peers,
                    &self.peer_state_cache,
                    address,
                    *session_id,
                    &wire_message,
                    Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
                    "coordinated-finality-observer-request",
                )
            },
        );
        let mut sent = 0usize;
        for ((address, _session_id), result) in targets.into_iter().zip(send_results) {
            match result {
                Ok(true) => sent += 1,
                Ok(false) => {}
                Err(error) => warn!(
                    "p2p",
                    "Failed to request coordinated finality observer records",
                    "peer" => address,
                    "error" => error
                ),
            }
        }
        Ok(sent)
    }

    /// Relays one complete certified ETDAG input package only to currently
    /// authenticated, consensus-eligible validator peers.  The receiver does
    /// not trust this fanout: it rechecks the sender identity and every proof
    /// against its own immutable height/finality authority before persistence.
    pub fn broadcast_etdag_certified_input(
        &self,
        artifact: &CertifiedProtectedInputArtifact,
    ) -> Result<usize, String> {
        artifact.validate_wire_size()?;
        let wire_message = NetworkMessage::EtdagCertifiedInput {
            artifact: artifact.clone(),
        };
        let targets = {
            let peers = self.connected_peers.lock().unwrap();
            peers
                .iter()
                .filter_map(|(address, peer)| {
                    if peer.stream.is_none()
                        || !peer_is_active_consensus_validator(&self.config, peer)
                    {
                        return None;
                    }
                    current_peer_session_id(address).map(|session_id| (address.clone(), session_id))
                })
                .collect::<Vec<_>>()
        };
        let send_results = run_with_bounded_parallelism(
            &targets,
            targets.len(),
            "certified ETDAG input fanout",
            |(address, session_id)| {
                send_peer_message_for_session(
                    &self.connected_peers,
                    &self.peer_state_cache,
                    address,
                    *session_id,
                    &wire_message,
                    Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
                    "etdag-certified-input",
                )
            },
        );
        let mut sent = 0usize;
        for ((address, _session_id), result) in targets.into_iter().zip(send_results) {
            match result {
                Ok(true) => sent += 1,
                Ok(false) => {}
                Err(error) => warn!(
                    "p2p",
                    "Failed to send certified ETDAG input",
                    "peer" => address,
                    "error" => error
                ),
            }
        }
        Ok(sent)
    }

    pub fn broadcast_vote_request(
        &self,
        block: &Block,
        epoch_number: u64,
        round_number: u64,
    ) -> usize {
        if coordinated_consensus_active(&self.config) {
            warn!(
                "p2p",
                "Refused validator-voting egress in coordinated mode",
                "message_type" => "VoteRequest"
            );
            return 0;
        }
        let message = NetworkMessage::VoteRequest {
            block_data: block.clone(),
            epoch_number,
            round_number,
        };

        let mut recipients = 0usize;
        let mut failed_peers = Vec::new();
        let active_validator_addresses =
            consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators())
                .into_iter()
                .map(|validator| validator.address)
                .collect::<HashSet<_>>();
        let expected_validator_set_hash = canonical_validator_set_hash();
        let now = current_timestamp();
        let mut sent_validator_addresses = HashSet::new();
        let vote_targets = {
            let mut peers = self.connected_peers.lock().unwrap();
            peers
                .iter_mut()
                .filter_map(|(address, peer)| {
                    peer.stream.as_ref()?;
                    let session_id = current_peer_session_id(address)?;
                    let validator_address = recover_peer_validator_address_for_vote_target(
                        &self.config,
                        peer,
                        &active_validator_addresses,
                    )?;
                    let recovered_validator_identity = peer
                        .validator_address
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .is_none();
                    if !active_validator_addresses.contains(&validator_address)
                        || sent_validator_addresses.contains(&validator_address)
                    {
                        return None;
                    }
                    if recovered_validator_identity {
                        info!(
                            "p2p",
                            "Recovered vote request target validator identity",
                            "peer" => address.clone(),
                            "node_id" => peer.node_id.clone().unwrap_or_default(),
                            "public_address" => peer.public_address.clone().unwrap_or_default(),
                            "validator_address" => validator_address.clone(),
                            "height" => block.block_index
                        );
                        peer.validator_address = Some(validator_address.clone());
                    }
                    if let Some(reason) = peer_readiness_exclusion_reason_at(
                        peer,
                        now,
                        Some(&expected_validator_set_hash),
                    ) {
                        debug!(
                            "p2p",
                            "Skipping vote request to non-ready validator peer",
                            "peer" => address.clone(),
                            "validator_address" => validator_address,
                            "height" => block.block_index,
                            "reason" => reason
                        );
                        return None;
                    }
                    Some((address.clone(), session_id, validator_address))
                })
                .collect::<Vec<_>>()
        };
        let send_results = run_with_bounded_parallelism(
            &vote_targets,
            vote_targets.len(),
            "consensus fanout",
            |(address, session_id, _validator_address)| {
                send_peer_message_for_session(
                    &self.connected_peers,
                    &self.peer_state_cache,
                    address,
                    *session_id,
                    &message,
                    Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
                    "vote-request",
                )
            },
        );
        for ((address, _session_id, validator_address), send_result) in
            vote_targets.into_iter().zip(send_results)
        {
            match send_result {
                Ok(true) => {
                    sent_validator_addresses.insert(validator_address);
                    recipients += 1;
                }
                Ok(false) => {}
                Err(error) => {
                    warn!("p2p", "Failed to send vote request", "peer" => address.clone(), "error" => error);
                    failed_peers.push(address);
                }
            }
        }

        let mut sent_validators = sent_validator_addresses.into_iter().collect::<Vec<_>>();
        sent_validators.sort();
        info!(
            "p2p",
            "Vote request broadcast",
            "peers" => recipients as u64,
            "dropped_peers" => failed_peers.len() as u64,
            "height" => block.block_index,
            "epoch" => epoch_number,
            "round" => round_number,
            "sent_validator_addresses" => sent_validators.join(",")
        );
        recipients
    }

    pub fn broadcast_transaction(&self, transaction: &Transaction) {
        let message = NetworkMessage::Transaction {
            transaction_data: transaction.clone(),
        };

        let mut sent = 0usize;
        for (address, session_id) in peer_session_targets(&self.connected_peers) {
            match send_peer_message_for_session(
                &self.connected_peers,
                &self.peer_state_cache,
                &address,
                session_id,
                &message,
                Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
                "transaction-broadcast",
            ) {
                Ok(true) => {
                    let mut peers = self.connected_peers.lock().unwrap();
                    if let Some(peer) = peer_for_session_mut(&mut peers, &address, session_id) {
                        peer.txs_sent += 1;
                        sent += 1;
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    warn!("p2p", "Failed to send transaction", "peer" => address, "error" => error);
                }
            }
        }

        info!("p2p", "Transaction broadcast", "peers" => sent as u64, "tx_hash" => transaction.hash());
    }

    pub fn get_peer_count(&self) -> usize {
        // Return only peers that have completed handshake and identified as
        // validators, matching the count shown by get_connected_validator_addresses().
        // Previously this returned ALL entries (including bootnodes and
        // pre-handshake connections), inflating the dashboard peer count.
        let peers = self.connected_peers.lock().unwrap();
        peers
            .values()
            .filter(|peer| {
                peer.validator_address
                    .as_ref()
                    .map(|a| !a.trim().is_empty())
                    .unwrap_or(false)
            })
            .count()
    }

    pub fn get_peer_info(&self) -> Vec<serde_json::Value> {
        self.collect_peer_snapshots()
            .into_iter()
            .map(|peer| {
                serde_json::json!({
                    "address": peer.address,
                    "connected_at": peer.connected_at,
                    "last_seen": peer.last_seen,
                    "blocks_sent": peer.blocks_sent,
                    "blocks_received": peer.blocks_received,
                    "txs_sent": peer.txs_sent,
                    "txs_received": peer.txs_received,
                    "node_id": peer.node_id,
                    "authenticated_designated_support": peer.authenticated_designated_support,
                    "authenticated_designated_relayer": peer.authenticated_designated_relayer,
                    "public_address": peer.public_address,
                    "validator_address": peer.validator_address,
                    "version": peer.version,
                    "capabilities": peer.capabilities,
                    "genesis_hash": peer.genesis_hash,
                    "status_received_at": peer.status_received_at,
                    "status_reported_at": peer.status_reported_at,
                    "status_validator_address": peer.status_validator_address,
                    "status_source_session_id": peer.status_source_session_id,
                    "active_validator_set_hash": peer.active_validator_set_hash,
                    "status_fresh": peer.status_fresh,
                    "status_age_secs": peer.status_age_secs,
                    "readiness_exclusion_reason": peer.readiness_exclusion_reason,
                    "quarantined": peer.quarantined,
                    "consensus_duties_disabled": peer.consensus_duties_disabled,
                    "recovery_state": peer.recovery_state,
                })
            })
            .collect()
    }

    pub fn get_connected_validator_addresses(&self) -> Vec<String> {
        let peers = self.connected_peers.lock().unwrap();
        let mut validator_addresses = peers
            .values()
            .filter_map(|peer| peer.validator_address.clone())
            .filter(|address| !address.trim().is_empty())
            .collect::<Vec<_>>();
        validator_addresses.sort();
        validator_addresses.dedup();
        validator_addresses
    }

    pub fn get_status_ready_validator_count(&self) -> usize {
        status_ready_validator_participants(&self.config, &self.connected_peers)
    }

    pub fn get_status_ready_validator_addresses(&self) -> Vec<String> {
        status_ready_validator_addresses(&self.config, &self.connected_peers)
    }

    /// Returns only fresh session-authenticated validator identities from the
    /// immutable v3 frozen set. Address counts or mutable membership cannot
    /// satisfy simplified startup readiness.
    pub fn get_status_ready_simplified_validator_ids(
        &self,
        frozen_validator_ids: &BTreeSet<ValidatorId>,
    ) -> BTreeSet<ValidatorId> {
        let now = current_timestamp();
        let peers = self.connected_peers.lock().unwrap();
        peers
            .iter()
            .filter_map(|(address, peer)| {
                if peer.stream.is_none()
                    || peer_readiness_exclusion_reason_at(peer, now, None).is_some()
                {
                    return None;
                }
                let session_id = current_peer_session_id(address)?;
                let identity = simplified_consensus_peer_for_session(address, session_id)?;
                frozen_validator_ids
                    .contains(&identity.validator_id)
                    .then_some(identity.validator_id)
            })
            .collect()
    }

    pub fn get_best_validator_peer_height(&self) -> u64 {
        best_connected_validator_height(&self.connected_peers)
    }

    pub fn get_best_validator_peer_height_with_support(&self, min_support: usize) -> u64 {
        best_connected_validator_height_with_support(&self.connected_peers, min_support)
    }

    pub fn collect_peer_snapshots(&self) -> Vec<PeerSnapshot> {
        let now = current_timestamp();
        let peers = self.connected_peers.lock().unwrap();
        peers
            .values()
            .map(|peer| build_peer_snapshot(&self.config, peer, now))
            .collect()
    }

    /// Return the local sync-source policy from the same onboarding, duty, and
    /// quarantine state used by role startup. Caller-provided flags are only a
    /// compatibility fallback when no network is attached to the sync manager.
    pub fn support_sources_only_policy(&self) -> bool {
        local_sync_requires_support_sources_authoritatively(&self.config)
    }

    pub fn request_blocks(&self, from_height: u64, count: u32) {
        if local_node_uses_service_batch_durability(&self.config) {
            let target = {
                let peers = self.connected_peers.lock().unwrap();
                select_block_sync_targets(&self.config, &peers, 1)
                    .into_iter()
                    .next()
            };
            if let Some(target) = target {
                let _ = self.request_blocks_from_peer(&target, from_height, count);
            }
            return;
        }

        let message = NetworkMessage::GetBlocks { from_height, count };

        let target_sessions = {
            let peers = self.connected_peers.lock().unwrap();
            select_block_sync_targets(&self.config, &peers, 1)
                .into_iter()
                .filter_map(|address| Some((address.clone(), current_peer_session_id(&address)?)))
                .collect::<Vec<_>>()
        };
        for (address, session_id) in target_sessions {
            if let Err(error) = send_peer_message_for_session(
                &self.connected_peers,
                &self.peer_state_cache,
                &address,
                session_id,
                &message,
                Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
                "block-request",
            ) {
                eprintln!("❌ Failed to request blocks from {}: {}", address, error);
            }
        }
    }

    pub fn request_blocks_from_peer(
        &self,
        peer_address: &str,
        from_height: u64,
        count: u32,
    ) -> bool {
        let message = NetworkMessage::GetBlocks { from_height, count };
        let Some((resolved_peer_address, session_id)) =
            peer_session_target_for_address(&self.connected_peers, peer_address)
        else {
            return false;
        };
        let authorized = self
            .connected_peers
            .lock()
            .ok()
            .and_then(|peers| {
                peers
                    .get(&resolved_peer_address)
                    .map(|peer| peer_is_eligible_block_sync_source_for_local(&self.config, peer))
            })
            .unwrap_or(false);
        if !authorized {
            debug!(
                "p2p",
                "Refusing explicit block sync request to unauthorized source",
                "peer" => resolved_peer_address.clone()
            );
            return false;
        }
        if local_node_uses_service_batch_durability(&self.config) {
            return service_sync_request_explicit(
                &self.blockchain,
                &self.connected_peers,
                &self.peer_state_cache,
                &self.config,
                &resolved_peer_address,
                session_id,
                from_height,
                count,
            );
        }
        match send_peer_message_for_session(
            &self.connected_peers,
            &self.peer_state_cache,
            &resolved_peer_address,
            session_id,
            &message,
            Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
            "block-request",
        ) {
            Ok(true) => true,
            Ok(false) | Err(_) => false,
        }
    }

    pub fn request_peers(&self) {
        let message = NetworkMessage::GetPeers;
        for (address, session_id) in peer_session_targets(&self.connected_peers) {
            if let Err(error) = send_peer_message_for_session(
                &self.connected_peers,
                &self.peer_state_cache,
                &address,
                session_id,
                &message,
                Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
                "peer-request",
            ) {
                warn!("p2p", "Failed to request peers", "peer" => address, "error" => error);
            }
        }
    }

    pub fn ping_peers(&self) {
        let message = NetworkMessage::Ping;

        for (address, session_id) in peer_session_targets(&self.connected_peers) {
            if let Err(error) = send_peer_message_for_session(
                &self.connected_peers,
                &self.peer_state_cache,
                &address,
                session_id,
                &message,
                Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
                "ping",
            ) {
                eprintln!("❌ Failed to ping {}: {}", address, error);
            }
        }
    }

    pub fn request_peer_statuses(&self) {
        for (address, session_id) in peer_session_targets(&self.connected_peers) {
            request_status_from_connected_peer(
                &self.connected_peers,
                &self.peer_state_cache,
                &address,
                session_id,
            );
        }
    }

    /// Starts a background bootstrap loop:
    /// - dials configured bootnodes
    /// - requests peers
    /// - requests missing blocks
    /// - pings peers
    pub fn start_bootstrap(self: &Arc<Self>) {
        let network = Arc::clone(self);
        let _ = spawn_named_thread("p2p-bootstrap", move || {
            let heartbeat =
                std::time::Duration::from_secs(network.config.p2p.heartbeat_interval.max(1));
            let mut bootnode_dials = Vec::<String>::new();
            let mut last_refresh = Instant::now()
                - current_bootstrap_refresh_interval(&network.config, &network.connected_peers);

            loop {
                let bootstrap_refresh_interval =
                    current_bootstrap_refresh_interval(&network.config, &network.connected_peers);
                if last_refresh.elapsed() >= bootstrap_refresh_interval || bootnode_dials.is_empty()
                {
                    bootnode_dials = resolve_bootstrap_dial_targets(&network.config);
                    last_refresh = Instant::now();
                    register_self_with_seed_servers(&network.config);

                    if bootnode_dials.is_empty() {
                        warn!(
                            "p2p",
                            "Bootstrap resolution returned no dialable peers",
                            "bootnodes" => format!("{:?}", network.config.network.bootnodes),
                            "seed_servers" => format!("{:?}", network.config.network.seed_servers),
                            "dns_records" => format!(
                                "{:?}",
                                network.config.network.bootstrap_dns_records
                            )
                        );
                    } else {
                        if let Ok(mut discovered) = network.discovered_dial_targets.lock() {
                            *discovered = bootnode_dials.clone();
                        }
                        info!(
                            "p2p",
                            "Resolved bootstrap dial targets",
                            "targets" => format!("{:?}", bootnode_dials)
                        );
                    }
                }

                prune_stale_peers(
                    &network.config,
                    &network.peer_state_cache,
                    &network.connected_peers,
                );

                // Keep trying bootnodes until at least one peer is connected.
                for addr in &bootnode_dials {
                    // Avoid self-dial if the config accidentally includes itself.
                    if is_self_dial_target(&network.config, addr) {
                        continue;
                    }
                    let already_connected = {
                        let peers = network.connected_peers.lock().unwrap();
                        connected_peer_key_for_address(&peers, addr).is_some()
                    };
                    if !already_connected {
                        let _ = network.connect_to_peer(addr);
                    }
                }

                // Ask connected peers for their peer lists and status.
                if peer_exchange_enabled(&network.config) {
                    network.request_peers();
                }
                if !network.config.node.bootstrap_only {
                    network.request_peer_statuses();
                }
                if let Err(error) = network.request_typed_finality_observer_records() {
                    warn!(
                        "p2p",
                        "Typed finality observer recovery request rejected",
                        "error" => error
                    );
                }
                if let Err(error) = network.request_coordinated_finality_observer_records() {
                    warn!(
                        "p2p",
                        "Coordinated finality observer recovery request rejected",
                        "error" => error
                    );
                }

                let sync_active = sync_manager_is_active();

                // Try to sync missing blocks, but only when the dedicated sync manager
                // is not already driving catch-up. Running both paths at once creates a
                // request storm and starves block-batch processing on lagging nodes.
                if should_request_missing_blocks(&network.config, sync_active) {
                    let required_validator_support =
                        if network.config.consensus.status_ready_min_validators == 0 {
                            network.config.consensus.min_validators.max(1)
                        } else {
                            network.config.consensus.status_ready_min_validators.max(1)
                        }
                        .saturating_sub(1)
                        .max(1);
                    let (local_height, best_peer_height) = {
                        let chain = network.blockchain.lock().unwrap();
                        let local = chain.last().map(|b| b.block_index).unwrap_or(0);
                        let best =
                            if local_validator_requires_designated_sync_sources(&network.config)
                                || local_node_uses_relayer_only_topology(&network.config)
                            {
                                let peers = network.connected_peers.lock().unwrap();
                                best_connected_block_sync_source_height(&network.config, &peers)
                            } else {
                                let supported_best = network
                                    .get_best_validator_peer_height_with_support(
                                        required_validator_support,
                                    );
                                if supported_best > 0 {
                                    supported_best
                                } else {
                                    let peers = network.connected_peers.lock().unwrap();
                                    best_connected_block_sync_source_height(&network.config, &peers)
                                }
                            };
                        (local, best)
                    };
                    // Keep validator catch-up batches bounded while allowing service
                    // roles to use the support-peer response budget.
                    let batch = status_sync_batch(&network.config, best_peer_height, local_height)
                        .unwrap_or(IMMEDIATE_STATUS_SYNC_BATCH);
                    let include_reconciliation_overlap = {
                        let chain = network.blockchain.lock().unwrap();
                        chain_has_block_sync_overlap(&chain, local_height, batch)
                    };
                    if let Some((request_start, request_count)) =
                        block_sync_request_range_with_overlap(
                            local_height,
                            best_peer_height,
                            batch,
                            include_reconciliation_overlap,
                        )
                    {
                        network.request_blocks(request_start, request_count);
                    }
                }

                // Keep connections alive.
                network.ping_peers();

                // When catching up, loop immediately without sleeping.
                // When synced, use normal heartbeat interval.
                let (local_height, best_peer_height) = {
                    let chain = network.blockchain.lock().unwrap();
                    let local = chain.last().map(|b| b.block_index).unwrap_or(0);
                    let peers = network.connected_peers.lock().unwrap();
                    let best = peers
                        .values()
                        .map(|p| p.last_known_height)
                        .max()
                        .unwrap_or(0);
                    (local, best)
                };
                let behind = best_peer_height.saturating_sub(local_height);
                thread::sleep(background_poll_interval(behind, heartbeat, sync_active));
            }
        });
    }
}

fn start_listener(
    listen_address: &str,
    blockchain: BlockchainArc,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    config: NodeConfig,
    message_sender: mpsc::Sender<PeerMessage>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen_address)?;
    info!("p2p", "P2P listener bound", "listen_address" => listen_address.to_string());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer_address = stream.peer_addr()?.to_string();
                let peer_host = peer_socket_host(&peer_address);
                let pending_incoming_from_host = {
                    let peers = connected_peers.lock().unwrap();
                    pending_incoming_connections_from_host(&peers, &peer_host)
                };
                if pending_incoming_from_host >= MAX_PENDING_INCOMING_CONNECTIONS_PER_HOST {
                    warn!(
                        "p2p",
                        "Rejecting excess pending incoming connections from host",
                        "peer" => peer_address.clone(),
                        "host" => peer_host,
                        "active_pending_incoming_connections" => pending_incoming_from_host as u64
                    );
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                info!("p2p", "Incoming peer connection", "peer" => peer_address.clone());

                let blockchain_clone = Arc::clone(&blockchain);
                let peers_clone = Arc::clone(&connected_peers);
                let peer_state_cache_clone = Arc::clone(&peer_state_cache);
                let sender_clone = message_sender.clone();
                let config_clone = config.clone();

                let _ = spawn_named_thread("p2p-accept-peer", move || {
                    if let Err(e) = handle_incoming_connection(
                        stream,
                        peer_address,
                        blockchain_clone,
                        peers_clone,
                        peer_state_cache_clone,
                        sender_clone,
                        config_clone,
                    ) {
                        error!("p2p", "Incoming connection error", "error" => e.to_string());
                    }
                });
            }
            Err(e) => {
                warn!("p2p", "Incoming connection accept error", "error" => e.to_string());
            }
        }
    }

    Ok(())
}

fn peer_session_targets(connected_peers: &PeersArc) -> Vec<(String, u64)> {
    let peers = connected_peers.lock().unwrap();
    peers
        .iter()
        .filter_map(|(address, peer)| {
            peer.stream.as_ref()?;
            Some((address.clone(), current_peer_session_id(address)?))
        })
        .collect()
}

fn peer_session_target_for_address(
    connected_peers: &PeersArc,
    peer_address: &str,
) -> Option<(String, u64)> {
    let peers = connected_peers.lock().unwrap();
    let resolved_peer_address = connected_peer_key_for_address(&peers, peer_address)
        .unwrap_or_else(|| peer_address.to_string());
    let peer = peers.get(&resolved_peer_address)?;
    peer.stream.as_ref()?;
    Some((
        resolved_peer_address.clone(),
        current_peer_session_id(&resolved_peer_address)?,
    ))
}

fn request_status_from_connected_peer(
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    peer_address: &str,
    session_id: u64,
) {
    if !should_request_status(peer_address, session_id) {
        debug!(
            "p2p",
            "Suppressing status request inside peer-session rate limit",
            "peer" => peer_address.to_string(),
            "session_id" => session_id
        );
        return;
    }

    let message = NetworkMessage::GetStatus;
    if let Err(error) = send_peer_message_for_session(
        connected_peers,
        peer_state_cache,
        peer_address,
        session_id,
        &message,
        Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
        "status-request",
    ) {
        warn!(
            "p2p",
            "Failed to request status from peer",
            "peer" => peer_address.to_string(),
            "error" => error
        );
    }
}

fn request_blocks_from_connected_peer(
    config: &NodeConfig,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    peer_address: &str,
    session_id: u64,
    from_height: u64,
    count: u32,
) {
    let authorized = connected_peers
        .lock()
        .ok()
        .and_then(|peers| {
            peers.get(peer_address).map(|peer| {
                peer_is_eligible_block_sync_source_for_local(config, peer)
                    && current_peer_session_id(peer_address) == Some(session_id)
            })
        })
        .unwrap_or(false);
    if !authorized {
        debug!(
            "p2p",
            "Refusing lower-level block sync request to unauthorized source",
            "peer" => peer_address.to_string(),
            "session_id" => session_id
        );
        return;
    }
    let message = NetworkMessage::GetBlocks { from_height, count };
    if let Err(error) = send_peer_message_for_session(
        connected_peers,
        peer_state_cache,
        peer_address,
        session_id,
        &message,
        Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
        "block-request",
    ) {
        warn!(
            "p2p",
            "Failed to request blocks from peer",
            "peer" => peer_address.to_string(),
            "requested_peer" => peer_address.to_string(),
            "error" => error
        );
    }
}

fn request_recovery_batch_after_canonical_lock_conflict(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    session_id: u64,
    conflicting_block: &Block,
) {
    if conflicting_block.block_index == 0 {
        return;
    }

    let local_height = blockchain
        .lock()
        .unwrap()
        .last()
        .map(|block| block.block_index)
        .unwrap_or(0);
    if conflicting_block.block_index <= local_height {
        return;
    }

    let Some(local_lock) = legacy_canonical_commit_record(local_height).ok().flatten() else {
        return;
    };
    let local_tip_hash = blockchain
        .lock()
        .unwrap()
        .block_at_height(local_height)
        .map(|block| block.hash.clone());
    if local_tip_hash.as_deref() != Some(local_lock.block_hash.as_str()) {
        return;
    }

    let batch = status_sync_batch(config, conflicting_block.block_index, local_height)
        .unwrap_or(IMMEDIATE_STATUS_SYNC_BATCH);
    let include_reconciliation_overlap = {
        let chain = blockchain.lock().unwrap();
        chain_has_block_sync_overlap(&chain, local_height, batch)
    };
    let Some((from_height, count)) = block_sync_request_range_with_overlap(
        local_height,
        conflicting_block.block_index,
        batch,
        include_reconciliation_overlap,
    ) else {
        return;
    };

    warn!(
        "p2p",
        "Requesting source-majority recovery batch after canonical lock conflict",
        "peer" => peer_address.to_string(),
        "conflict_height" => conflicting_block.block_index,
        "local_height" => local_height,
        "from_height" => from_height,
        "count" => count as u64
    );
    request_blocks_from_connected_peer(
        config,
        connected_peers,
        peer_state_cache,
        peer_address,
        session_id,
        from_height,
        count,
    );
}

fn send_vote_to_requester(
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    request_peer_address: &str,
    proposer_validator_address: &str,
    response: &NetworkMessage,
) -> Result<String, String> {
    let mut failed_peers = Vec::new();

    // The vote request arrived over an authenticated, full-duplex peer stream.
    // Reuse it before paying for a new TCP connection and signed handshake on
    // every consensus round. The direct route remains the recovery fallback.
    if let Some((request_peer_key, request_session_id)) =
        peer_session_target_for_address(connected_peers, request_peer_address)
    {
        match send_peer_message_for_session(
            connected_peers,
            peer_state_cache,
            &request_peer_key,
            request_session_id,
            response,
            Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
            "vote-response",
        ) {
            Ok(true) => {
                info!(
                    "p2p",
                    "Vote sent over persistent requester path",
                    "request_peer" => request_peer_address.to_string(),
                    "response_peer" => request_peer_key.clone(),
                    "proposer" => proposer_validator_address.to_string()
                );
                return Ok(request_peer_key);
            }
            Ok(false) => {}
            Err(error) => failed_peers.push((request_peer_key, error)),
        }
    }

    if let Some(proposer_public_address) =
        configured_public_address_for_validator(config, proposer_validator_address)
    {
        match send_direct_vote_to_configured_proposer(config, &proposer_public_address, response) {
            Ok(()) => {
                info!(
                    "p2p",
                    "Vote sent over direct proposer path",
                    "request_peer" => request_peer_address.to_string(),
                    "response_peer" => proposer_public_address.clone(),
                    "proposer" => proposer_validator_address.to_string()
                );
                return Ok(proposer_public_address);
            }
            Err(error) => {
                warn!(
                    "p2p",
                    "Direct proposer vote path failed; falling back",
                    "request_peer" => request_peer_address.to_string(),
                    "response_peer" => proposer_public_address.clone(),
                    "proposer" => proposer_validator_address.to_string(),
                    "error" => error.clone()
                );
                failed_peers.push((proposer_public_address, error));
            }
        }
    }

    let fallback_peer = {
        let peers = connected_peers.lock().unwrap();
        peers.iter().find_map(|(address, peer)| {
            (address != request_peer_address
                && peer.stream.is_some()
                && peer.validator_address.as_deref().map(str::trim)
                    == Some(proposer_validator_address))
            .then(|| Some((address.clone(), current_peer_session_id(address)?)))
            .flatten()
        })
    };

    if let Some((fallback_peer_key, fallback_session_id)) = fallback_peer {
        match send_peer_message_for_session(
            connected_peers,
            peer_state_cache,
            &fallback_peer_key,
            fallback_session_id,
            response,
            Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
            "vote-response-fallback",
        ) {
            Ok(true) => return Ok(fallback_peer_key),
            Ok(false) => {}
            Err(error) => return Err(error),
        }
    }

    if let Some((failed_peer, error)) = failed_peers.into_iter().next() {
        return Err(format!("failed to write vote to {failed_peer}: {error}"));
    }

    Err(format!(
        "no writable connection for proposer {} (request peer {})",
        proposer_validator_address, request_peer_address
    ))
}

fn send_direct_vote_to_configured_proposer(
    config: &NodeConfig,
    proposer_public_address: &str,
    response: &NetworkMessage,
) -> Result<(), String> {
    let transport_address = resolve_peer_transport_address(config, proposer_public_address)
        .ok_or_else(|| format!("no transport route for {proposer_public_address}"))?;
    let mut stream = dial_with_timeout(
        &transport_address,
        Duration::from_millis(CONSENSUS_DIRECT_VOTE_DIAL_TIMEOUT_MILLIS),
    )
    .map_err(|error| error.to_string())?;

    let handshake = build_local_handshake_with_extra_capabilities(config, &["direct-vote"])
        .map_err(|error| format!("build direct vote handshake: {error}"))?;
    send_consensus_message(&mut stream, &handshake)
        .map_err(|error| format!("send direct vote handshake: {error}"))?;
    send_consensus_message(&mut stream, response)
        .map_err(|error| format!("send direct vote payload: {error}"))?;
    let _ = stream.shutdown(Shutdown::Write);

    Ok(())
}

fn configured_public_address_for_validator(
    config: &NodeConfig,
    validator_address: &str,
) -> Option<String> {
    let validator_address = validator_address.trim();
    if validator_address.is_empty() {
        return None;
    }

    let canonical_active =
        consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators())
            .into_iter()
            .map(|validator| validator.address)
            .collect::<HashSet<_>>();
    let active_validator_addresses = if canonical_active.is_empty() {
        config
            .node
            .allowed_validator_addresses
            .iter()
            .map(|address| address.trim().to_string())
            .filter(|address| !address.is_empty())
            .collect::<HashSet<_>>()
    } else {
        canonical_active
    };

    configured_public_address_for_validator_in_set(
        config,
        validator_address,
        &active_validator_addresses,
    )
}

fn configured_public_address_for_validator_in_set(
    config: &NodeConfig,
    validator_address: &str,
    active_validator_addresses: &HashSet<String>,
) -> Option<String> {
    configured_validator_public_address_map(config, active_validator_addresses)
        .into_iter()
        .find_map(|(public_address, mapped_validator)| {
            (mapped_validator == validator_address).then_some(public_address)
        })
}

fn handle_vote_request_message(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    session_id: u64,
    block_data: Block,
    epoch_number: u64,
    round_number: u64,
) {
    if !peer_session_is_current(peer_address, session_id) {
        return;
    }
    let vote_request_received_at = Instant::now();
    let local_validator = crate::config::resolve_runtime_validator_address();
    let network_peer_count = connected_peers
        .lock()
        .ok()
        .map(|peers| {
            peers
                .values()
                .filter(|peer| {
                    peer.validator_address
                        .as_ref()
                        .map(|address| !address.trim().is_empty())
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0);
    timing_trace::emit(
        "vote_request_received",
        serde_json::json!({
            "height": block_data.block_index,
            "block_hash": block_data.hash.clone(),
            "previous_hash": block_data.previous_hash.clone(),
            "proposer": block_data.validator_id.clone(),
            "validator": local_validator,
            "peer": peer_address,
            "epoch": epoch_number,
            "round": round_number,
            "network_peer_count": network_peer_count
        }),
    );
    if config.node.bootstrap_only {
        debug!(
            "p2p",
            "Bootstrap-only node ignoring vote request",
            "peer" => peer_address.to_string(),
            "height" => block_data.block_index,
            "epoch" => epoch_number,
            "round" => round_number
        );
        return;
    }
    if let Some(record) = current_validator_quarantine_duty_block() {
        warn!(
            "p2p",
            "Quarantined validator refusing vote request",
            "peer" => peer_address.to_string(),
            "height" => block_data.block_index,
            "epoch" => epoch_number,
            "round" => round_number,
            "quarantine_height" => record.divergence_height.0,
            "quarantine_source" => record.source,
            "reason" => record.reason
        );
        return;
    }

    let mut local_tip = vote_request_local_tip(blockchain);
    if validate_vote_request_extends_local_tip(local_tip.as_ref(), &block_data).is_err() {
        request_vote_request_parent_sync(local_tip.clone(), block_data.block_index);
        let parent_wait_started = Instant::now();
        if vote_request_can_wait_for_parent(local_tip.as_ref(), &block_data)
            && wait_for_vote_request_parent(blockchain, &block_data)
        {
            local_tip = vote_request_local_tip(blockchain);
            timing_trace::emit(
                "vote_request_parent_sync_wait",
                serde_json::json!({
                    "height": block_data.block_index,
                    "block_hash": block_data.hash.clone(),
                    "previous_hash": block_data.previous_hash.clone(),
                    "proposer": block_data.validator_id.clone(),
                    "validator": crate::config::resolve_runtime_validator_address(),
                    "peer": peer_address,
                    "epoch": epoch_number,
                    "round": round_number,
                    "duration_ms": timing_trace::duration_ms(parent_wait_started.elapsed()),
                    "status": "ok"
                }),
            );
        } else {
            timing_trace::emit(
                "vote_request_parent_sync_wait",
                serde_json::json!({
                    "height": block_data.block_index,
                    "block_hash": block_data.hash.clone(),
                    "previous_hash": block_data.previous_hash.clone(),
                    "proposer": block_data.validator_id.clone(),
                    "validator": crate::config::resolve_runtime_validator_address(),
                    "peer": peer_address,
                    "epoch": epoch_number,
                    "round": round_number,
                    "duration_ms": timing_trace::duration_ms(parent_wait_started.elapsed()),
                    "status": "not_ready"
                }),
            );
        }
    }

    if let Err(error) = validate_vote_request_extends_local_tip(local_tip.as_ref(), &block_data) {
        timing_trace::emit(
            "vote_request_rejected",
            serde_json::json!({
                "height": block_data.block_index,
                "block_hash": block_data.hash.clone(),
                "previous_hash": block_data.previous_hash.clone(),
                "proposer": block_data.validator_id.clone(),
                "validator": crate::config::resolve_runtime_validator_address(),
                "peer": peer_address,
                "epoch": epoch_number,
                "round": round_number,
                "reason": error.clone()
            }),
        );
        warn!(
            "p2p",
            "Refusing vote request",
            "peer" => peer_address.to_string(),
            "height" => block_data.block_index,
            "epoch" => epoch_number,
            "round" => round_number,
            "error" => error
        );
        request_vote_request_parent_sync(local_tip, block_data.block_index);
        return;
    }

    info!(
        "p2p",
        "Received vote request",
        "peer" => peer_address.to_string(),
        "proposer" => block_data.validator_id.clone(),
        "height" => block_data.block_index,
        "epoch" => epoch_number,
        "round" => round_number
    );

    let transient_recovery_min_age_secs = vote_request_transient_recovery_min_age_secs(config);
    let validation_started = Instant::now();
    timing_trace::emit(
        "vote_validation_start",
        serde_json::json!({
            "height": block_data.block_index,
            "block_hash": block_data.hash.clone(),
            "previous_hash": block_data.previous_hash.clone(),
            "proposer": block_data.validator_id.clone(),
            "validator": crate::config::resolve_runtime_validator_address(),
            "peer": peer_address,
            "epoch": epoch_number,
            "round": round_number
        }),
    );
    match DualQuorumConsensus::build_local_vote_for_proposal_with_recovery(
        &block_data,
        epoch_number,
        round_number,
        transient_recovery_min_age_secs,
    ) {
        Ok(vote) => {
            timing_trace::emit(
                "vote_validation_end",
                serde_json::json!({
                    "height": block_data.block_index,
                    "block_hash": block_data.hash.clone(),
                    "previous_hash": block_data.previous_hash.clone(),
                    "proposer": block_data.validator_id.clone(),
                    "validator": vote.validator_address.clone(),
                    "peer": peer_address,
                    "epoch": epoch_number,
                    "round": round_number,
                    "duration_ms": timing_trace::duration_ms(validation_started.elapsed()),
                    "status": "ok"
                }),
            );
            let response = NetworkMessage::Vote { vote };
            if !peer_session_is_current(peer_address, session_id) {
                return;
            }
            match send_vote_to_requester(
                connected_peers,
                peer_state_cache,
                config,
                peer_address,
                block_data.validator_id.as_str(),
                &response,
            ) {
                Ok(response_peer) => {
                    timing_trace::emit(
                        "vote_response_sent",
                        serde_json::json!({
                            "height": block_data.block_index,
                            "block_hash": block_data.hash.clone(),
                            "previous_hash": block_data.previous_hash.clone(),
                            "proposer": block_data.validator_id.clone(),
                            "validator": crate::config::resolve_runtime_validator_address(),
                            "request_peer": peer_address,
                            "response_peer": response_peer.clone(),
                            "epoch": epoch_number,
                            "round": round_number,
                            "elapsed_since_request_ms": timing_trace::duration_ms(vote_request_received_at.elapsed())
                        }),
                    );
                    info!(
                        "p2p",
                        "Vote sent",
                        "request_peer" => peer_address.to_string(),
                        "response_peer" => response_peer,
                        "proposer" => block_data.validator_id.clone(),
                        "height" => block_data.block_index,
                        "epoch" => epoch_number,
                        "round" => round_number
                    );
                }
                Err(error) => {
                    timing_trace::emit(
                        "vote_response_send_failed",
                        serde_json::json!({
                            "height": block_data.block_index,
                            "block_hash": block_data.hash.clone(),
                            "previous_hash": block_data.previous_hash.clone(),
                            "proposer": block_data.validator_id.clone(),
                            "validator": crate::config::resolve_runtime_validator_address(),
                            "peer": peer_address,
                            "epoch": epoch_number,
                            "round": round_number,
                            "elapsed_since_request_ms": timing_trace::duration_ms(vote_request_received_at.elapsed()),
                            "error": error.clone()
                        }),
                    );
                    warn!(
                        "p2p",
                        "Failed to send vote",
                        "peer" => peer_address.to_string(),
                        "proposer" => block_data.validator_id.clone(),
                        "height" => block_data.block_index,
                        "epoch" => epoch_number,
                        "round" => round_number,
                        "error" => error
                    );
                }
            }
        }
        Err(error) => {
            timing_trace::emit(
                "vote_validation_end",
                serde_json::json!({
                    "height": block_data.block_index,
                    "block_hash": block_data.hash.clone(),
                    "previous_hash": block_data.previous_hash.clone(),
                    "proposer": block_data.validator_id.clone(),
                    "validator": crate::config::resolve_runtime_validator_address(),
                    "peer": peer_address,
                    "epoch": epoch_number,
                    "round": round_number,
                    "duration_ms": timing_trace::duration_ms(validation_started.elapsed()),
                    "status": "error",
                    "error": error.clone()
                }),
            );
            timing_trace::emit(
                "vote_request_rejected",
                serde_json::json!({
                    "height": block_data.block_index,
                    "block_hash": block_data.hash.clone(),
                    "previous_hash": block_data.previous_hash.clone(),
                    "proposer": block_data.validator_id.clone(),
                    "validator": crate::config::resolve_runtime_validator_address(),
                    "peer": peer_address,
                    "epoch": epoch_number,
                    "round": round_number,
                    "reason": error.clone()
                }),
            );
            warn!(
                "p2p",
                "Refusing vote request",
                "peer" => peer_address.to_string(),
                "height" => block_data.block_index,
                "epoch" => epoch_number,
                "round" => round_number,
                "error" => error
            );
        }
    }
}

fn vote_request_transient_recovery_min_age_secs(config: &NodeConfig) -> u64 {
    let block_time_secs = config.consensus.block_time_secs.max(1);
    let leader_timeout_secs = if config.consensus.leader_timeout_secs == 0 {
        block_time_secs.saturating_mul(2).max(3)
    } else {
        config.consensus.leader_timeout_secs.max(block_time_secs)
    };

    leader_timeout_secs
        .saturating_mul(2)
        .max(block_time_secs.saturating_mul(3))
        .max(6)
}

fn vote_request_local_tip(blockchain: &BlockchainArc) -> Option<(u64, String)> {
    blockchain
        .lock()
        .ok()
        .and_then(|chain| chain.last().map(|tip| (tip.block_index, tip.hash.clone())))
}

fn validate_vote_request_extends_local_tip(
    local_tip: Option<&(u64, String)>,
    block_data: &Block,
) -> Result<(), String> {
    let Some((tip_height, tip_hash)) = local_tip else {
        return Err("local chain has no tip to extend".to_string());
    };

    let expected_height = tip_height.saturating_add(1);
    if block_data.block_index != expected_height {
        return Err(format!(
            "proposal height {} does not extend local tip {}",
            block_data.block_index, tip_height
        ));
    }

    if block_data.previous_hash != *tip_hash {
        return Err(format!(
            "proposal parent hash does not match local tip at height {}",
            tip_height
        ));
    }

    Ok(())
}

fn vote_request_can_wait_for_parent(local_tip: Option<&(u64, String)>, block_data: &Block) -> bool {
    let Some((tip_height, _)) = local_tip else {
        return false;
    };

    block_data.block_index > tip_height.saturating_add(1)
}

fn wait_for_vote_request_parent(blockchain: &BlockchainArc, block_data: &Block) -> bool {
    let deadline = Instant::now() + Duration::from_millis(VOTE_REQUEST_PARENT_SYNC_WAIT_MILLIS);
    while Instant::now() < deadline {
        if validate_vote_request_extends_local_tip(
            vote_request_local_tip(blockchain).as_ref(),
            block_data,
        )
        .is_ok()
        {
            return true;
        }
        thread::sleep(Duration::from_millis(VOTE_REQUEST_PARENT_SYNC_POLL_MILLIS));
    }

    false
}

fn request_vote_request_parent_sync(local_tip: Option<(u64, String)>, proposal_height: u64) {
    let Some((tip_height, _)) = local_tip else {
        return;
    };
    let Some((request_start, request_count)) =
        vote_request_parent_sync_range(tip_height, proposal_height)
    else {
        return;
    };

    if let Some(network) = crate::p2p::get_p2p_network() {
        network.request_blocks(request_start, request_count);
    }
}

fn vote_request_parent_sync_range(tip_height: u64, proposal_height: u64) -> Option<(u64, u32)> {
    if proposal_height <= tip_height.saturating_add(1) {
        return None;
    }

    let request_start = tip_height.saturating_add(1);
    let request_count = proposal_height.saturating_sub(request_start);
    if request_count == 0 {
        return None;
    }

    Some((request_start, request_count.min(u32::MAX as u64) as u32))
}

fn handle_vote_message(
    connected_peers: &PeersArc,
    config: &NodeConfig,
    peer_address: &str,
    session_id: u64,
    vote: crate::consensus::dual_quorum::Vote,
) {
    if config.node.bootstrap_only {
        debug!(
            "p2p",
            "Bootstrap-only node ignoring vote payload",
            "peer" => peer_address.to_string(),
            "validator" => vote.validator_address.clone(),
            "epoch" => vote.epoch_number,
            "round" => vote.round_number
        );
        return;
    }

    let announced_validator = {
        let peers = connected_peers.lock().unwrap();
        if !peer_session_is_current(peer_address, session_id) {
            return;
        }
        resolve_announced_validator_for_vote(&peers, peer_address, &vote.validator_address)
            .or_else(|| recover_active_vote_validator_from_payload(config, &vote.validator_address))
    };
    let Some((announced_validator, recovered_peer_key)) = announced_validator else {
        warn!(
            "p2p",
            "Ignoring vote from peer without validator identity",
            "peer" => peer_address.to_string(),
            "validator" => vote.validator_address.clone()
        );
        return;
    };
    if let Some(recovered_peer_key) = recovered_peer_key {
        info!(
            "p2p",
            "Recovered vote peer identity from active validator mapping",
            "peer" => peer_address.to_string(),
            "recovered_peer" => recovered_peer_key,
            "validator" => announced_validator.clone()
        );
    }
    if announced_validator != vote.validator_address {
        warn!(
            "p2p",
            "Ignoring vote with mismatched validator identity",
            "peer" => peer_address.to_string(),
            "announced_validator" => announced_validator,
            "vote_validator" => vote.validator_address.clone()
        );
        return;
    }

    timing_trace::emit(
        "vote_response_received_by_peer",
        serde_json::json!({
            "height": vote.block_index,
            "block_hash": vote.block_hash.clone(),
            "validator": vote.validator_address.clone(),
            "peer": peer_address,
            "announced_validator": announced_validator,
            "epoch": vote.epoch_number,
            "round": vote.round_number,
            "vote_timestamp": vote.timestamp
        }),
    );
    DualQuorumConsensus::record_network_vote(vote.clone());
    debug!(
        "p2p",
        "Recorded network vote",
        "peer" => peer_address.to_string(),
        "validator" => vote.validator_address.clone(),
        "block_hash" => vote.block_hash.clone(),
        "epoch" => vote.epoch_number,
        "round" => vote.round_number
    );
}

fn recover_active_vote_validator_from_payload(
    _config: &NodeConfig,
    vote_validator_address: &str,
) -> Option<(String, Option<String>)> {
    let vote_validator_address = vote_validator_address.trim();
    if vote_validator_address.is_empty() {
        return None;
    }

    let active_validator_addresses =
        consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators())
            .into_iter()
            .map(|validator| validator.address)
            .collect::<HashSet<_>>();
    if active_validator_addresses.contains(vote_validator_address) {
        return Some((vote_validator_address.to_string(), None));
    }

    None
}

fn handle_block_message(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    session_id: u64,
    block_data: Block,
    quorum_certificate: Option<QuorumCertificate>,
) {
    if config.node.bootstrap_only {
        debug!(
            "p2p",
            "Bootstrap-only node ignoring block propagation",
            "peer" => peer_address.to_string(),
            "height" => block_data.block_index
        );
        return;
    }

    info!("p2p", "Received block", "peer" => peer_address.to_string());

    if !ensure_peer_status_allows_chain_data(
        blockchain,
        connected_peers,
        peer_state_cache,
        peer_address,
        session_id,
        "block",
    ) {
        return;
    }

    {
        let mut peers = connected_peers.lock().unwrap();
        if let Some(peer) = peer_for_session_mut(&mut peers, peer_address, session_id) {
            peer.blocks_received += 1;
            peer.last_known_height = block_data.block_index;
            peer.best_block_hash = block_data.hash.clone();
        }
    }

    if apply_block_if_new(blockchain, block_data.clone(), quorum_certificate) {
        info!(
            "p2p",
            "Block applied",
            "height" => block_data.block_index,
            "hash" => block_data.hash.clone(),
            "txs" => block_data.transactions.len() as u64
        );
    } else {
        request_recovery_batch_after_canonical_lock_conflict(
            blockchain,
            connected_peers,
            peer_state_cache,
            config,
            peer_address,
            session_id,
            &block_data,
        );
        debug!(
            "p2p",
            "Block ignored (duplicate/out-of-order)",
            "height" => block_data.block_index,
            "hash" => block_data.hash.clone()
        );
    }
}

fn handle_get_blocks_message(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    session_id: u64,
    from_height: u64,
    count: u32,
) {
    if config.node.bootstrap_only {
        debug!(
            "p2p",
            "Bootstrap-only node returning empty block response",
            "peer" => peer_address.to_string(),
            "from_height" => from_height,
            "count" => count as u64
        );
        let response = NetworkMessage::Blocks {
            blocks: Vec::new(),
            quorum_certificates: Vec::new(),
        };
        if let Err(error) = send_peer_message_for_session(
            connected_peers,
            peer_state_cache,
            peer_address,
            session_id,
            &response,
            Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
            "bootstrap-block-sync",
        ) {
            warn!(
                "p2p",
                "Failed to send bootstrap-only block response",
                "peer" => peer_address.to_string(),
                "error" => error
            );
        }
        return;
    }

    if !authorize_chain_requester_for_session(
        connected_peers,
        peer_state_cache,
        config,
        peer_address,
        session_id,
        "blocks",
    ) {
        return;
    }

    let (policy, min_serve_interval_secs, refuse_deep_support_sync) = {
        let local_height = {
            let chain = blockchain.lock().unwrap();
            chain.last().map(|block| block.block_index).unwrap_or(0)
        };
        let peers = connected_peers.lock().unwrap();
        if !peer_session_is_current(peer_address, session_id) {
            return;
        }
        let peer = peers.get(peer_address);
        (
            block_sync_response_policy(config, peer),
            block_sync_min_serve_interval_secs(config, peer),
            support_peer_sync_request_is_too_deep(config, peer, local_height, from_height),
        )
    };
    let now = current_timestamp();
    let rate_limit_key = peer_socket_host(peer_address);
    let should_serve = BLOCK_SYNC_LAST_SERVED
        .lock()
        .map(|mut served| {
            let last_served = served.get(&rate_limit_key).copied().unwrap_or(0);
            if now.saturating_sub(last_served) < min_serve_interval_secs {
                return false;
            }
            served.insert(rate_limit_key.clone(), now);
            true
        })
        .unwrap_or(false);
    if !should_serve {
        debug!(
            "p2p",
            "Throttling block sync response",
            "peer" => peer_address.to_string(),
            "host" => rate_limit_key,
            "from_height" => from_height,
            "count" => count as u64,
            "min_serve_interval_secs" => min_serve_interval_secs
        );
        enqueue_block_sync_busy_job(BlockSyncBusyJob {
            connected_peers: Arc::clone(connected_peers),
            peer_state_cache: Arc::clone(peer_state_cache),
            peer_address: peer_address.to_string(),
            session_id,
            reason: "the peer-specific block response rate limit is active",
            retry_request: Some((from_height, count)),
        });
        return;
    }

    debug!(
        "p2p",
        "Serving block sync response",
        "peer" => peer_address.to_string(),
        "host" => rate_limit_key,
        "from_height" => from_height,
        "count" => count as u64,
        "max_blocks" => policy.max_blocks as u64
    );

    if refuse_deep_support_sync {
        warn!(
            "p2p",
            "Refusing deep support-peer block sync request",
            "peer" => peer_address.to_string(),
            "from_height" => from_height,
            "max_support_peer_deep_sync_lag" => MAX_SUPPORT_PEER_DEEP_SYNC_LAG
        );
        let mut peers = connected_peers.lock().unwrap();
        disconnect_peer_entry_for_session(peer_state_cache, &mut peers, peer_address, session_id);
        return;
    }
    let response_count = count.min(policy.max_blocks);
    let blocks = {
        let chain = blockchain.lock().unwrap();
        select_block_sync_response_blocks(&chain, from_height, response_count)
    };
    // Historical QC lookup may scan the full archive; keep it outside the chain mutex.
    let quorum_certificates = DualQuorumConsensus::committed_qcs_for_block_hashes(
        blocks.iter().map(|block| block.hash.as_str()),
    );
    let response = NetworkMessage::Blocks {
        blocks,
        quorum_certificates,
    };

    let Some((session_identity, send_result)) =
        with_peer_stream_outside_peers_lock(connected_peers, peer_address, session_id, |stream| {
            send_message_with_write_timeout(stream, &response, policy.write_timeout)
        })
    else {
        return;
    };

    let mut peers = connected_peers.lock().unwrap();
    if peers
        .get(peer_address)
        .map(|peer| peer_stream_matches_identity(peer_address, peer, &session_identity))
        != Some(true)
    {
        return;
    }
    if let Err(e) = send_result {
        let error = e.to_string();
        warn!(
            "p2p",
            "Failed to send blocks",
            "peer" => peer_address.to_string(),
            "requested" => count as u64,
            "served" => response_count as u64,
            "max_blocks" => policy.max_blocks as u64,
            "error" => error.clone()
        );
        let reason = format!("block-sync-send-failed: {error}");
        if peer_session_is_current(peer_address, session_id) {
            disconnect_peer_after_poisoned_write(
                peer_state_cache,
                &mut peers,
                peer_address,
                &reason,
            );
        }
    } else if let Some(peer) = peer_for_session_mut(&mut peers, peer_address, session_id) {
        peer.blocks_sent += 1;
    }
}

fn handle_blocks_message(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    session_id: u64,
    blocks: Vec<Block>,
    quorum_certificates: Vec<QuorumCertificate>,
) -> bool {
    if config.node.bootstrap_only {
        let service_sync_generation = if local_node_uses_service_batch_durability(config) {
            service_sync_generation_for_response(peer_address, session_id, &blocks)
        } else {
            None
        };
        if let Some(generation) = service_sync_generation {
            release_block_sync_peer(&BLOCK_SYNC_APPLY_ACTIVE, peer_address, session_id);
            service_sync_release_and_reassign(
                generation,
                Some(service_sync_identity(peer_address, session_id)),
                false,
            );
        }
        debug!(
            "p2p",
            "Bootstrap-only node ignoring bulk blocks",
            "peer" => peer_address.to_string(),
            "count" => blocks.len()
        );
        return service_sync_generation.is_some();
    }

    let service_sync_generation = if local_node_uses_service_batch_durability(config) {
        let generation = service_sync_generation_for_response(peer_address, session_id, &blocks);
        if generation.is_none() {
            debug!(
                "p2p",
                "Ignoring service block response without the global sync reservation",
                "peer" => peer_address.to_string(),
                "count" => blocks.len()
            );
            return false;
        }
        generation
    } else {
        None
    };

    if !ensure_peer_status_allows_chain_data(
        blockchain,
        connected_peers,
        peer_state_cache,
        peer_address,
        session_id,
        "blocks",
    ) {
        if let Some(generation) = service_sync_generation {
            release_block_sync_peer(&BLOCK_SYNC_APPLY_ACTIVE, peer_address, session_id);
            service_sync_release_and_reassign(
                generation,
                Some(service_sync_identity(peer_address, session_id)),
                false,
            );
            return true;
        }
        return false;
    }

    let applied = apply_block_batch_for_role(
        blockchain,
        blocks,
        quorum_certificates,
        local_node_uses_service_batch_durability(config),
    );
    if applied > 0 {
        info!(
            "p2p",
            "Blocks applied",
            "count" => applied,
            "peer" => peer_address.to_string()
        );
    }
    if let Some(generation) = service_sync_generation {
        // Release the sole ordered apply slot before requesting the next batch. Otherwise a
        // fast response can arrive while the completed job still appears active and be discarded.
        release_block_sync_peer(&BLOCK_SYNC_APPLY_ACTIVE, peer_address, session_id);
        service_sync_release_and_reassign(
            generation,
            Some(service_sync_identity(peer_address, session_id)),
            applied > 0,
        );
        return true;
    }
    false
}

fn sync_manager_is_active() -> bool {
    SYNC_MANAGER
        .lock()
        .ok()
        .map(|manager| {
            matches!(
                manager.get_state(),
                SyncState::Discovering
                    | SyncState::Downloading
                    | SyncState::Validating
                    | SyncState::Applying
            )
        })
        .unwrap_or(false)
}

fn should_request_missing_blocks(config: &NodeConfig, sync_active: bool) -> bool {
    !config.node.bootstrap_only && !sync_active
}

fn local_node_runs_validator_consensus(config: &NodeConfig) -> bool {
    let identity_role = config.identity.role.trim().to_ascii_lowercase();
    let compiled_profile = config.role.compiled_profile.trim().to_ascii_lowercase();
    let exposes_consensus_service = config
        .role
        .services
        .iter()
        .any(|service| service.trim().eq_ignore_ascii_case("consensus"));
    identity_role == "validator"
        || compiled_profile == "validator_node"
        || exposes_consensus_service
}

fn local_sync_requires_support_sources_authoritatively(config: &NodeConfig) -> bool {
    if !local_node_runs_validator_consensus(config) || config.node.bootstrap_only {
        return false;
    }

    let local_validator = announced_validator_address(config);
    let consensus_authorized = local_validator.as_deref().is_some_and(|address| {
        consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators())
            .into_iter()
            .any(|validator| validator.address == address)
    });
    let onboarding = config.validator.state_sync_before_join && !consensus_authorized;
    let quarantined =
        current_validator_quarantine_duty_block().is_some() && !local_vote_only_rejoin_active();
    // The finalized on-chain validator set is authoritative. Installer-era
    // allowlists may lag newly activated validators and must not suppress duty.
    let consensus_duties_disabled = !consensus_authorized;

    consensus_duties_disabled || onboarding || quarantined
}

fn local_node_uses_service_batch_durability(config: &NodeConfig) -> bool {
    if local_node_runs_validator_consensus(config) {
        return false;
    }

    const SERVICE_ROLE_IDS: &[&str] = &[
        "relayer",
        "witness",
        "oracle",
        "uma_coordinator",
        "cross_chain_verifier",
        "synq_execution",
        "analytics_simulation",
        "aegis_cryptography",
        "data_availability",
        "governance_auditor",
        "treasury_controller",
        "security_council",
        "rpc_gateway",
        "indexer_explorer",
        "observer_light",
        "archive_validator",
    ];
    const SERVICE_COMPILED_PROFILES: &[&str] = &[
        "relayer_node",
        "witness_node",
        "oracle_node",
        "uma_coordinator_node",
        "cross_chain_verifier_node",
        "synq_execution_node",
        "analytics_and_simulation_node",
        "aegis_cryptography_node",
        "data_availability_node",
        "governance_auditor_node",
        "treasury_controller_node",
        "security_council_node",
        "rpc_gateway_node",
        "indexer_and_explorer_node",
        "observer_light_node",
        "archive_validator_node",
    ];

    let role = config.identity.role.trim().to_ascii_lowercase();
    let compiled_profile = config.role.compiled_profile.trim().to_ascii_lowercase();
    SERVICE_ROLE_IDS.contains(&role.as_str())
        || SERVICE_COMPILED_PROFILES.contains(&compiled_profile.as_str())
}

fn configured_validator_transport_matches_peer(
    config: &NodeConfig,
    peer: &PeerConnection,
    validator_address: &str,
) -> bool {
    validator_vpn_transport_for_target(config, validator_address)
        .is_some_and(|configured| validator_transport_endpoint_matches_peer(peer, &configured))
}

fn configured_validator_identity_matches_peer(
    config: &NodeConfig,
    peer: &PeerConnection,
    validator_address: &str,
) -> bool {
    let Some(node_id) = peer.node_id.as_deref().map(str::trim) else {
        return false;
    };
    if node_id.is_empty() {
        return false;
    }

    let configured_addresses = if config.node.allowed_validator_addresses.is_empty() {
        canonical_genesis()
            .ok()
            .map(|genesis| {
                genesis
                    .validators()
                    .iter()
                    .map(|validator| validator.operator_address.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    } else {
        config.node.allowed_validator_addresses.clone()
    };
    let Some(slot) = configured_addresses
        .iter()
        .position(|configured| configured.trim() == validator_address)
        .map(|slot| slot + 1)
    else {
        return false;
    };
    [
        format!("validator-node-{slot:02}"),
        format!("genesisval{slot}"),
    ]
    .iter()
    .any(|expected| node_id.eq_ignore_ascii_case(expected))
}

fn peer_is_active_consensus_validator(config: &NodeConfig, peer: &PeerConnection) -> bool {
    let Some(peer_validator_address) = peer
        .validator_address
        .as_deref()
        .map(str::trim)
        .filter(|address| !address.is_empty())
    else {
        return false;
    };

    let active = consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators())
        .into_iter()
        .any(|validator| validator.address == peer_validator_address);
    if !active {
        return false;
    }

    if validator_vpn_transport_for_target(config, peer_validator_address).is_some() {
        configured_validator_transport_matches_peer(config, peer, peer_validator_address)
    } else {
        configured_validator_identity_matches_peer(config, peer, peer_validator_address)
    }
}

fn block_sync_response_policy(
    config: &NodeConfig,
    peer: Option<&PeerConnection>,
) -> BlockSyncResponsePolicy {
    if !local_node_runs_validator_consensus(config) {
        return BlockSyncResponsePolicy {
            max_blocks: MAX_SUPPORT_NODE_BLOCK_SYNC_RESPONSE_BLOCKS,
            write_timeout: Duration::from_secs(SUPPORT_NODE_BLOCK_SYNC_RESPONSE_WRITE_TIMEOUT_SECS),
        };
    }

    let serving_support_peer = !peer
        .map(|peer| peer_is_active_consensus_validator(config, peer))
        .unwrap_or(false);

    if serving_support_peer {
        BlockSyncResponsePolicy {
            max_blocks: MAX_VALIDATOR_SUPPORT_SYNC_RESPONSE_BLOCKS,
            write_timeout: Duration::from_millis(
                VALIDATOR_SUPPORT_SYNC_RESPONSE_WRITE_TIMEOUT_MILLIS,
            ),
        }
    } else {
        BlockSyncResponsePolicy {
            max_blocks: MAX_BLOCK_SYNC_RESPONSE_BLOCKS,
            write_timeout: Duration::from_secs(BLOCK_SYNC_RESPONSE_WRITE_TIMEOUT_SECS),
        }
    }
}

fn block_sync_min_serve_interval_secs(config: &NodeConfig, peer: Option<&PeerConnection>) -> u64 {
    if !local_node_runs_validator_consensus(config) {
        SUPPORT_NODE_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS
    } else if peer
        .map(|peer| peer_is_active_consensus_validator(config, peer))
        .unwrap_or(false)
    {
        BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS
    } else {
        VALIDATOR_SUPPORT_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS
    }
}

fn support_peer_sync_request_is_too_deep(
    config: &NodeConfig,
    peer: Option<&PeerConnection>,
    local_height: u64,
    from_height: u64,
) -> bool {
    let serving_support_peer = !peer
        .map(|peer| peer_is_active_consensus_validator(config, peer))
        .unwrap_or(false);
    serving_support_peer
        && local_height.saturating_sub(from_height) > MAX_SUPPORT_PEER_DEEP_SYNC_LAG
}

fn background_poll_interval(behind: u64, heartbeat: Duration, sync_active: bool) -> Duration {
    if sync_active {
        heartbeat
    } else if behind > 0 {
        Duration::from_millis(BACKGROUND_SYNC_POLL_MILLIS)
    } else {
        heartbeat
    }
}

fn bypasses_shared_message_queue(message: &NetworkMessage) -> bool {
    matches!(
        message,
        NetworkMessage::VoteRequest { .. }
            | NetworkMessage::Vote { .. }
            | NetworkMessage::TypedConsensus { .. }
            | NetworkMessage::CoordinatedConsensus { .. }
            | NetworkMessage::SimplifiedConsensus { .. }
            | NetworkMessage::SimplifiedTargetAdmission { .. }
            | NetworkMessage::SimplifiedEtdagAssembly { .. }
            | NetworkMessage::TypedFinalityObserver { .. }
            | NetworkMessage::CoordinatedFinalityObserver { .. }
            | NetworkMessage::EtdagCertifiedInput { .. }
            | NetworkMessage::Block { .. }
            | NetworkMessage::GetBlocks { .. }
            | NetworkMessage::Blocks { .. }
    )
}

fn coordinated_consensus_active(config: &NodeConfig) -> bool {
    matches!(
        config
            .consensus
            .resolve_mode(config.blockchain.chain_id, &config.network.network_id),
        Ok(crate::config::ResolvedConsensusMode::CoordinatedRoundRobinV1(_))
    )
}

/// Handles non-signing finalized-chain replication. This path is intentionally
/// separate from typed consensus ingress: neither a relayer nor a public
/// observer can submit a proposal/vote or obtain a validator private key.
fn handle_typed_finality_observer_message(
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    session_id: u64,
    message: TypedFinalityObserverMessage,
) -> Result<(), String> {
    if !peer_session_is_current(peer_address, session_id) {
        return Err("typed finality observer message belongs to a replaced session".to_string());
    }
    match message {
        TypedFinalityObserverMessage::Request { next_height } => {
            let peer_is_vpn_relayer = connected_peers
                .lock()
                .map_err(|_| "typed finality observer peer registry lock is poisoned".to_string())?
                .get(peer_address)
                .is_some_and(peer_is_validator_vpn_relayer);
            let peer_is_public_service = connected_peers
                .lock()
                .map_err(|_| "typed finality observer peer registry lock is poisoned".to_string())?
                .get(peer_address)
                .is_some_and(|peer| peer_is_designated_support_sync_source(config, peer));

            let records = if local_is_typed_finality_relayer(config) {
                if !peer_is_public_service {
                    return Err(
                        "typed finality observer request to relayer is not from a configured public service role"
                            .to_string(),
                    );
                }
                typed_finality_observer_snapshot_from(next_height)?
            } else if local_node_runs_validator_consensus(config) {
                if !peer_is_vpn_relayer {
                    return Err(
                        "typed finality observer request to validator is not from an authenticated validator-VPN relayer"
                            .to_string(),
                    );
                }
                canonical_typed_finality_snapshot_from(next_height)?
            } else {
                return Err(
                    "typed finality observer request reached a role that cannot serve finalized records"
                        .to_string(),
                );
            };
            // A clean pre-genesis journal has no certified record yet. The
            // requester retries from its immutable next height on heartbeat.
            if records.is_empty() {
                return Ok(());
            }
            let response = TypedFinalityObserverMessage::Records { records };
            validate_typed_finality_observer_message_size(&response)?;
            let sent = send_peer_message_for_session(
                connected_peers,
                peer_state_cache,
                peer_address,
                session_id,
                &NetworkMessage::TypedFinalityObserver {
                    chain_incarnation: canonical_chain_incarnation(),
                    genesis_hash: canonical_genesis_hash(),
                    message: response,
                },
                Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
                "typed-finality-observer-response",
            )?;
            if !sent {
                return Err("typed finality observer response session was replaced".to_string());
            }
            Ok(())
        }
        TypedFinalityObserverMessage::Records { records } => {
            let source_allowed = if local_is_typed_finality_relayer(config) {
                // This is the strongest available binding: the sender proved
                // possession of an exact active validator ML-DSA-65 key in
                // the session's canonical Genesis handshake.
                typed_consensus_peer_for_session(peer_address, session_id).is_some()
            } else if local_is_typed_finality_service_observer(config) {
                connected_peers
                    .lock()
                    .map_err(|_| {
                        "typed finality observer peer registry lock is poisoned".to_string()
                    })?
                    .get(peer_address)
                    .is_some_and(|peer| peer_is_designated_relayer_sync_source(config, peer))
            } else {
                false
            };
            if !source_allowed {
                return Err(
                    "typed finality observer records are not from an authorized finalized-chain source"
                        .to_string(),
                );
            }
            let message = TypedFinalityObserverMessage::Records { records };
            validate_typed_finality_observer_message_size(&message)?;
            let TypedFinalityObserverMessage::Records { records } = message else {
                unreachable!("the observer records message was reconstructed above")
            };
            let imported = import_typed_finality_observer_records(&records)?;
            info!(
                "p2p",
                "Verified typed finality observer records",
                "peer" => peer_address.to_string(),
                "imported" => imported as u64,
                "next_height" => typed_finality_observer_next_missing_height().map(|height| height.0).unwrap_or(0)
            );
            Ok(())
        }
    }
}

/// Handles P1 finalized-only replication. Unlike `CoordinatedConsensus`, this
/// path never dispatches into a validator mailbox: it is limited to verified
/// durable coordinator packages and the same authenticated tier boundaries as
/// the typed observer bridge.
fn handle_coordinated_finality_observer_message(
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    session_id: u64,
    message: CoordinatedFinalityObserverMessage,
) -> Result<(), String> {
    if !peer_session_is_current(peer_address, session_id) {
        return Err(
            "coordinated finality observer message belongs to a replaced session".to_string(),
        );
    }
    let coordinated_config =
        local_coordinated_finality_observer_config(config).ok_or_else(|| {
            "coordinated finality observer traffic is disabled outside coordinated_round_robin_v1"
                .to_string()
        })?;
    match message {
        CoordinatedFinalityObserverMessage::Request { next_height } => {
            let peer_is_vpn_relayer = connected_peers
                .lock()
                .map_err(|_| {
                    "coordinated finality observer peer registry lock is poisoned".to_string()
                })?
                .get(peer_address)
                .is_some_and(peer_is_validator_vpn_relayer);
            let peer_is_public_service = connected_peers
                .lock()
                .map_err(|_| {
                    "coordinated finality observer peer registry lock is poisoned".to_string()
                })?
                .get(peer_address)
                .is_some_and(|peer| peer_is_designated_support_sync_source(config, peer));
            let records = if local_is_typed_finality_relayer(config) {
                if !peer_is_public_service {
                    return Err(
                        "coordinated finality observer request to relayer is not from a configured public service role"
                            .to_string(),
                    );
                }
                coordinated_finality_observer_snapshot_from(next_height)?
            } else if local_node_runs_validator_consensus(config) {
                if !peer_is_vpn_relayer {
                    return Err(
                        "coordinated finality observer request to validator is not from an authenticated validator-VPN relayer"
                            .to_string(),
                    );
                }
                canonical_coordinated_finality_snapshot_from(&coordinated_config, next_height)?
            } else {
                return Err(
                    "coordinated finality observer request reached a role that cannot serve finalized records"
                        .to_string(),
                );
            };
            if records.is_empty() {
                return Ok(());
            }
            let response = CoordinatedFinalityObserverMessage::Records { records };
            validate_coordinated_finality_observer_message_size(&response)?;
            let sent = send_peer_message_for_session(
                connected_peers,
                peer_state_cache,
                peer_address,
                session_id,
                &NetworkMessage::CoordinatedFinalityObserver {
                    chain_incarnation: canonical_chain_incarnation(),
                    genesis_hash: canonical_genesis_hash(),
                    message: response,
                },
                Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
                "coordinated-finality-observer-response",
            )?;
            if !sent {
                return Err(
                    "coordinated finality observer response session was replaced".to_string(),
                );
            }
            Ok(())
        }
        CoordinatedFinalityObserverMessage::Records { records } => {
            let source_allowed = if local_is_typed_finality_relayer(config) {
                typed_consensus_peer_for_session(peer_address, session_id).is_some()
            } else if local_is_typed_finality_service_observer(config) {
                connected_peers
                    .lock()
                    .map_err(|_| {
                        "coordinated finality observer peer registry lock is poisoned".to_string()
                    })?
                    .get(peer_address)
                    .is_some_and(|peer| peer_is_designated_relayer_sync_source(config, peer))
            } else {
                false
            };
            if !source_allowed {
                return Err(
                    "coordinated finality observer records are not from an authorized finalized-chain source"
                        .to_string(),
                );
            }
            let message = CoordinatedFinalityObserverMessage::Records { records };
            validate_coordinated_finality_observer_message_size(&message)?;
            let CoordinatedFinalityObserverMessage::Records { records } = message else {
                unreachable!("the coordinated observer records message was reconstructed above")
            };
            let imported = import_coordinated_finality_observer_records(&records)?;
            info!(
                "p2p",
                "Verified coordinated finality observer records",
                "peer" => peer_address.to_string(),
                "imported" => imported as u64,
                "next_height" => coordinated_finality_observer_next_missing_height().map(|height| height.0).unwrap_or(0)
            );
            Ok(())
        }
    }
}

fn dispatch_peer_message(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    message_sender: &mpsc::Sender<PeerMessage>,
    config: &NodeConfig,
    peer_address: &str,
    session_id: u64,
    message: NetworkMessage,
) -> Result<(), mpsc::SendError<PeerMessage>> {
    if !peer_session_is_current(peer_address, session_id) {
        debug!(
            "p2p",
            "Ignoring message from replaced peer session",
            "peer" => peer_address.to_string(),
            "session_id" => session_id
        );
        return Ok(());
    }
    if !bypasses_shared_message_queue(&message) {
        return message_sender.send((peer_address.to_string(), session_id, message));
    }

    match message {
        NetworkMessage::VoteRequest {
            block_data,
            epoch_number,
            round_number,
        } => {
            if coordinated_consensus_active(config) {
                warn!(
                    "p2p",
                    "Rejected validator-voting message in coordinated mode",
                    "peer" => peer_address.to_string(),
                    "message_type" => "VoteRequest"
                );
                return Ok(());
            }
            // Vote requests and vote payloads sit directly on the block production
            // critical path. Handle them immediately instead of routing them through
            // the shared background queue with status, ping, and sync traffic.
            handle_vote_request_message(
                blockchain,
                connected_peers,
                peer_state_cache,
                config,
                peer_address,
                session_id,
                block_data,
                epoch_number,
                round_number,
            );
            Ok(())
        }
        NetworkMessage::Vote { vote } => {
            if coordinated_consensus_active(config) {
                warn!(
                    "p2p",
                    "Rejected validator-voting message in coordinated mode",
                    "peer" => peer_address.to_string(),
                    "message_type" => "Vote"
                );
                return Ok(());
            }
            handle_vote_message(connected_peers, config, peer_address, session_id, vote);
            Ok(())
        }
        NetworkMessage::TypedConsensus {
            chain_incarnation,
            genesis_hash,
            message,
        } => {
            if coordinated_consensus_active(config) {
                warn!(
                    "p2p",
                    "Rejected typed PoSy message in coordinated mode",
                    "peer" => peer_address.to_string()
                );
                return Ok(());
            }
            if chain_incarnation != canonical_chain_incarnation()
                || genesis_hash != canonical_genesis_hash()
            {
                warn!(
                    "p2p",
                    "Rejected typed consensus frame from a different chain incarnation",
                    "peer" => peer_address.to_string(),
                    "incarnation" => chain_incarnation
                );
                return Ok(());
            }
            if let Err(error) =
                crate::consensus::typed_coordinator::dispatch_typed_consensus_message(
                    peer_address,
                    typed_consensus_peer_for_session(peer_address, session_id),
                    message,
                )
            {
                warn!(
                    "p2p",
                    "Rejected typed consensus message",
                    "peer" => peer_address.to_string(),
                    "error" => error
                );
            }
            Ok(())
        }
        NetworkMessage::CoordinatedConsensus {
            chain_incarnation,
            genesis_hash,
            message,
        } => {
            if chain_incarnation != canonical_chain_incarnation()
                || genesis_hash != canonical_genesis_hash()
            {
                warn!(
                    "p2p",
                    "Rejected coordinated consensus frame from a different chain incarnation",
                    "peer" => peer_address.to_string(),
                    "incarnation" => chain_incarnation
                );
                return Ok(());
            }
            let authenticated_peer = typed_consensus_peer_for_session(peer_address, session_id)
                .map(|peer| AuthenticatedCoordinatedConsensusPeer {
                    validator_id: peer.validator_id,
                    validator_uma_id: peer.validator_uma_id,
                    consensus_key_id: peer.consensus_key_id,
                });
            if let Err(error) =
                crate::consensus::coordinated_round_robin::dispatch_coordinated_consensus_message(
                    peer_address,
                    authenticated_peer,
                    message,
                )
            {
                warn!(
                    "p2p",
                    "Rejected coordinated consensus message",
                    "peer" => peer_address.to_string(),
                    "error" => error
                );
            }
            Ok(())
        }
        NetworkMessage::SimplifiedConsensus {
            chain_incarnation,
            genesis_hash,
            message,
        } => {
            if coordinated_consensus_active(config) {
                warn!(
                    "p2p",
                    "Rejected simplified consensus message while coordinated mode is selected",
                    "peer" => peer_address.to_string()
                );
                return Ok(());
            }
            if chain_incarnation != canonical_chain_incarnation()
                || genesis_hash != canonical_genesis_hash()
            {
                warn!(
                    "p2p",
                    "Rejected simplified consensus frame from a different chain incarnation",
                    "peer" => peer_address.to_string(),
                    "incarnation" => chain_incarnation
                );
                return Ok(());
            }
            if let Err(error) =
                crate::consensus::simplified_posy::dispatch_simplified_consensus_message(
                    peer_address,
                    simplified_consensus_peer_for_session(peer_address, session_id),
                    message,
                )
            {
                warn!(
                    "p2p",
                    "Rejected simplified consensus message",
                    "peer" => peer_address.to_string(),
                    "error" => error
                );
            }
            Ok(())
        }
        NetworkMessage::SimplifiedTargetAdmission {
            chain_incarnation,
            genesis_hash,
            message,
        } => {
            if coordinated_consensus_active(config) {
                warn!(
                    "p2p",
                    "Rejected simplified target-admission message while coordinated mode is selected",
                    "peer" => peer_address.to_string()
                );
                return Ok(());
            }
            if chain_incarnation != canonical_chain_incarnation()
                || genesis_hash != canonical_genesis_hash()
            {
                warn!(
                    "p2p",
                    "Rejected simplified target-admission frame from a different chain incarnation",
                    "peer" => peer_address.to_string(),
                    "incarnation" => chain_incarnation
                );
                return Ok(());
            }
            if let Err(error) = dispatch_simplified_target_admission_ingress(
                etdag_ingress_peer_for_session(peer_address, session_id),
                message,
            ) {
                warn!(
                    "p2p",
                    "Rejected simplified target-admission message",
                    "peer" => peer_address.to_string(),
                    "error" => error
                );
            }
            Ok(())
        }
        NetworkMessage::SimplifiedEtdagAssembly {
            chain_incarnation,
            genesis_hash,
            message,
        } => {
            if coordinated_consensus_active(config) {
                warn!(
                    "p2p",
                    "Rejected simplified empty-ETDAG message while coordinated mode is selected",
                    "peer" => peer_address.to_string()
                );
                return Ok(());
            }
            if chain_incarnation != canonical_chain_incarnation()
                || genesis_hash != canonical_genesis_hash()
            {
                warn!(
                    "p2p",
                    "Rejected simplified empty-ETDAG frame from a different chain incarnation",
                    "peer" => peer_address.to_string(),
                    "incarnation" => chain_incarnation
                );
                return Ok(());
            }
            if let Err(error) = dispatch_simplified_empty_etdag_ingress(
                etdag_ingress_peer_for_session(peer_address, session_id),
                message,
            ) {
                warn!(
                    "p2p",
                    "Rejected simplified empty-ETDAG message",
                    "peer" => peer_address.to_string(),
                    "error" => error
                );
            }
            Ok(())
        }
        NetworkMessage::TypedFinalityObserver {
            chain_incarnation,
            genesis_hash,
            message,
        } => {
            if chain_incarnation != canonical_chain_incarnation()
                || genesis_hash != canonical_genesis_hash()
            {
                warn!(
                    "p2p",
                    "Rejected typed observer frame from a different chain incarnation",
                    "peer" => peer_address.to_string(),
                    "incarnation" => chain_incarnation
                );
                return Ok(());
            }
            if let Err(error) = handle_typed_finality_observer_message(
                connected_peers,
                peer_state_cache,
                config,
                peer_address,
                session_id,
                message,
            ) {
                warn!(
                    "p2p",
                    "Rejected typed finality observer message",
                    "peer" => peer_address.to_string(),
                    "error" => error
                );
            }
            Ok(())
        }
        NetworkMessage::CoordinatedFinalityObserver {
            chain_incarnation,
            genesis_hash,
            message,
        } => {
            if chain_incarnation != canonical_chain_incarnation()
                || genesis_hash != canonical_genesis_hash()
            {
                warn!(
                    "p2p",
                    "Rejected coordinated observer frame from a different chain incarnation",
                    "peer" => peer_address.to_string(),
                    "incarnation" => chain_incarnation
                );
                return Ok(());
            }
            if let Err(error) = handle_coordinated_finality_observer_message(
                connected_peers,
                peer_state_cache,
                config,
                peer_address,
                session_id,
                message,
            ) {
                warn!(
                    "p2p",
                    "Rejected coordinated finality observer message",
                    "peer" => peer_address.to_string(),
                    "error" => error
                );
            }
            Ok(())
        }
        NetworkMessage::EtdagCertifiedInput { artifact } => {
            if let Err(error) = dispatch_etdag_certified_input(
                etdag_ingress_peer_for_session(peer_address, session_id),
                artifact,
            ) {
                warn!(
                    "p2p",
                    "Rejected certified ETDAG input",
                    "peer" => peer_address.to_string(),
                    "error" => error
                );
            }
            Ok(())
        }
        NetworkMessage::Block {
            block_data,
            quorum_certificate,
        } => {
            handle_block_message(
                blockchain,
                connected_peers,
                peer_state_cache,
                config,
                peer_address,
                session_id,
                block_data,
                quorum_certificate,
            );
            Ok(())
        }
        NetworkMessage::GetBlocks { from_height, count } => {
            enqueue_block_serve_job(BlockServeJob {
                blockchain: Arc::clone(blockchain),
                connected_peers: Arc::clone(connected_peers),
                peer_state_cache: Arc::clone(peer_state_cache),
                config: config.clone(),
                peer_address: peer_address.to_string(),
                session_id,
                from_height,
                count,
            });
            Ok(())
        }
        NetworkMessage::Blocks {
            blocks,
            quorum_certificates,
        } => {
            enqueue_block_apply_job(BlockApplyJob {
                blockchain: Arc::clone(blockchain),
                connected_peers: Arc::clone(connected_peers),
                peer_state_cache: Arc::clone(peer_state_cache),
                config: config.clone(),
                peer_address: peer_address.to_string(),
                session_id,
                blocks,
                quorum_certificates,
            });
            Ok(())
        }
        other => {
            unreachable!("non-priority message {other:?} should not reach direct dispatch path")
        }
    }
}

fn resolve_announced_validator_for_vote(
    peers: &PeerMap,
    peer_address: &str,
    vote_validator_address: &str,
) -> Option<(String, Option<String>)> {
    if let Some(validator_address) = peers
        .get(peer_address)
        .and_then(|peer| peer.validator_address.clone())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Some((validator_address, None));
    }

    let mut matching_peer_keys = peers
        .iter()
        .filter_map(|(address, peer)| {
            (peer.validator_address.as_deref().map(str::trim) == Some(vote_validator_address))
                .then_some(address.clone())
        })
        .collect::<Vec<_>>();
    matching_peer_keys.sort();
    matching_peer_keys.dedup();

    if matching_peer_keys.len() == 1 {
        Some((
            vote_validator_address.to_string(),
            matching_peer_keys.into_iter().next(),
        ))
    } else {
        None
    }
}

fn build_local_status_message(blockchain: &BlockchainArc, config: &NodeConfig) -> NetworkMessage {
    let genesis_hash = resolve_local_genesis_hash(blockchain);
    let (block_height, best_block_hash) = {
        let chain = blockchain.lock().unwrap();
        (
            if config.node.bootstrap_only {
                0
            } else {
                chain.last().map(|b| b.block_index).unwrap_or(0)
            },
            if config.node.bootstrap_only {
                String::new()
            } else {
                chain.last().map(|b| b.hash.clone()).unwrap_or_default()
            },
        )
    };
    let quarantine_block = current_validator_quarantine_duty_block();
    let vote_only_rejoin = local_vote_only_rejoin_active();
    let quarantined = quarantine_block.is_some() && !vote_only_rejoin;
    let recovery_state = if vote_only_rejoin {
        Some("VOTE_ONLY".to_string())
    } else {
        quarantine_block.map(|block| block.source)
    };

    NetworkMessage::Status {
        block_height,
        best_block_hash,
        genesis_hash,
        status_timestamp: Some(current_timestamp()),
        validator_address: announced_validator_address(config),
        source_session_id: Some(config.p2p.node_name.clone()),
        active_validator_set_hash: normalized_status_string(Some(&canonical_validator_set_hash())),
        quarantined,
        consensus_duties_disabled: quarantined,
        recovery_state,
    }
}

fn local_vote_only_rejoin_active() -> bool {
    let path = crate::utils::resolve_data_path("data/self_heal_status.json");
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    ["typed_status", "new_state", "recovery_state", "status"]
        .iter()
        .filter_map(|key| value.get(*key).and_then(|item| item.as_str()))
        .any(|state| {
            matches!(
                state.trim().to_ascii_uppercase().as_str(),
                "VOTE_ONLY" | "VOTEONLY"
            )
        })
        || value
            .get("vote_only_rejoin")
            .and_then(|item| item.as_bool())
            .unwrap_or(false)
}

fn publish_peer_connection(
    writer: &BufWriter<TcpStream>,
    peer_address: &str,
    direction: ConnectionDirection,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
) -> io::Result<PeerEntryGuard> {
    let stream = writer.get_ref().try_clone()?;
    let now = current_timestamp();
    let session_id = {
        let mut peers = connected_peers.lock().unwrap();
        if peers.contains_key(peer_address) {
            disconnect_peer_entry(peer_state_cache, &mut peers, peer_address);
        }
        let session_id = begin_peer_session(peer_address);
        peers.insert(
            peer_address.to_string(),
            PeerConnection {
                address: peer_address.to_string(),
                connected_endpoint: writer
                    .get_ref()
                    .peer_addr()
                    .ok()
                    .map(|address| address.to_string()),
                direction,
                public_address: None,
                validator_address: None,
                connected_at: now,
                last_seen: now,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: Some(stream),
                node_id: None,
                handshake_role: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        session_id
    };

    Ok(PeerEntryGuard::new(
        peer_address.to_string(),
        session_id,
        Arc::clone(connected_peers),
        Arc::clone(peer_state_cache),
    ))
}

fn handle_incoming_connection(
    stream: TcpStream,
    peer_address: String,
    blockchain: BlockchainArc,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    message_sender: mpsc::Sender<PeerMessage>,
    config: NodeConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    configure_peer_stream(&stream);
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = BufWriter::new(stream);

    // Send handshake
    let handshake = build_local_handshake(&config)
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;

    send_message(&mut writer, &handshake)?;
    writer.flush()?;

    let status = build_local_status_message(&blockchain, &config);
    if let Err(error) = send_message(&mut writer, &status) {
        warn!(
            "p2p",
            "Failed to proactively send status after handshake",
            "peer" => peer_address.clone(),
            "error" => error.to_string()
        );
        return Err(error.into());
    } else {
        writer.flush()?;
    }
    let peer_entry_guard = publish_peer_connection(
        &writer,
        &peer_address,
        ConnectionDirection::Incoming,
        &connected_peers,
        &peer_state_cache,
    )?;

    // Listen for messages
    loop {
        match receive_message(&mut reader) {
            Ok(message) => {
                // Update last seen
                {
                    let mut peers = connected_peers.lock().unwrap();
                    if let Some(peer) =
                        peer_for_session_mut(&mut peers, &peer_address, peer_entry_guard.session_id)
                    {
                        peer.last_seen = current_timestamp();
                    }
                }

                if let Err(_) = dispatch_peer_message(
                    &blockchain,
                    &connected_peers,
                    &peer_state_cache,
                    &message_sender,
                    &config,
                    &peer_address,
                    peer_entry_guard.session_id,
                    message,
                ) {
                    break;
                }
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("❌ Error receiving message from {}: {}", peer_address, e);
                }
                break;
            }
        }
    }
    Ok(())
}

fn handle_outgoing_connection(
    stream: TcpStream,
    peer_address: String,
    blockchain: BlockchainArc,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    message_sender: mpsc::Sender<PeerMessage>,
    config: NodeConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    configure_peer_stream(&stream);
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = BufWriter::new(stream);

    // Send handshake
    let handshake = build_local_handshake(&config)
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;

    send_message(&mut writer, &handshake)?;
    writer.flush()?;

    let status = build_local_status_message(&blockchain, &config);
    if let Err(error) = send_message(&mut writer, &status) {
        warn!(
            "p2p",
            "Failed to proactively send status after handshake",
            "peer" => peer_address.clone(),
            "error" => error.to_string()
        );
        return Err(error.into());
    } else {
        writer.flush()?;
    }
    let peer_entry_guard = publish_peer_connection(
        &writer,
        &peer_address,
        ConnectionDirection::Outgoing,
        &connected_peers,
        &peer_state_cache,
    )?;

    // Listen for messages
    loop {
        match receive_message(&mut reader) {
            Ok(message) => {
                // Update last seen
                {
                    let mut peers = connected_peers.lock().unwrap();
                    if let Some(peer) =
                        peer_for_session_mut(&mut peers, &peer_address, peer_entry_guard.session_id)
                    {
                        peer.last_seen = current_timestamp();
                    }
                }

                if let Err(_) = dispatch_peer_message(
                    &blockchain,
                    &connected_peers,
                    &peer_state_cache,
                    &message_sender,
                    &config,
                    &peer_address,
                    peer_entry_guard.session_id,
                    message,
                ) {
                    break;
                }
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("❌ Error receiving message from {}: {}", peer_address, e);
                }
                break;
            }
        }
    }
    Ok(())
}

fn handle_messages(
    blockchain: BlockchainArc,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    discovered_dial_targets: DialTargetsArc,
    dial_registry: DialRegistryArc,
    receiver: Arc<Mutex<mpsc::Receiver<PeerMessage>>>,
    message_sender: mpsc::Sender<PeerMessage>,
    config: NodeConfig,
) {
    loop {
        let receiver = receiver.lock().unwrap();
        match receiver.recv() {
            Ok((peer_address, session_id, message)) => {
                drop(receiver); // Release lock before processing

                if !peer_session_is_current(&peer_address, session_id) {
                    debug!(
                        "p2p",
                        "Discarding queued message from replaced peer session",
                        "peer" => peer_address.clone(),
                        "session_id" => session_id
                    );
                    continue;
                }

                match message {
                    NetworkMessage::Handshake {
                        node_id,
                        version,
                        capabilities,
                        chain_id,
                        chain_incarnation,
                        consensus_state_schema_version,
                        network_id,
                        network_id_text,
                        genesis_hash,
                        network_magic_bytes,
                        protocol_version,
                        consensus_version,
                        native_caip2,
                        reserved_eip155,
                        public_address,
                        validator_address,
                        role,
                        active_validator_set_hash,
                        cluster_map_hash,
                        protocol_config_hash,
                        aegis_pqvm_version,
                        aegis_pq_public_key_id,
                        aegis_pq_public_key_algorithm,
                        aegis_pq_public_key,
                        aegis_pq_handshake_signature,
                    } => {
                        let node_id = node_id.trim().to_string();
                        let handshake_for_verification = NetworkMessage::Handshake {
                            node_id: node_id.clone(),
                            version: version.clone(),
                            capabilities: capabilities.clone(),
                            chain_id,
                            chain_incarnation,
                            consensus_state_schema_version,
                            network_id,
                            network_id_text: network_id_text.clone(),
                            genesis_hash: genesis_hash.clone(),
                            network_magic_bytes: network_magic_bytes.clone(),
                            protocol_version: protocol_version.clone(),
                            consensus_version: consensus_version.clone(),
                            native_caip2: native_caip2.clone(),
                            reserved_eip155: reserved_eip155.clone(),
                            public_address: public_address.clone(),
                            validator_address: validator_address.clone(),
                            role: role.clone(),
                            active_validator_set_hash: active_validator_set_hash.clone(),
                            cluster_map_hash: cluster_map_hash.clone(),
                            protocol_config_hash: protocol_config_hash.clone(),
                            aegis_pqvm_version: aegis_pqvm_version.clone(),
                            aegis_pq_public_key_id: aegis_pq_public_key_id.clone(),
                            aegis_pq_public_key_algorithm: aegis_pq_public_key_algorithm.clone(),
                            aegis_pq_public_key: aegis_pq_public_key.clone(),
                            aegis_pq_handshake_signature: aegis_pq_handshake_signature.clone(),
                        };
                        if node_id.is_empty() {
                            warn!(
                                "p2p",
                                "Rejecting handshake with empty node_id",
                                "peer" => peer_address.clone()
                            );
                            let mut peers = connected_peers.lock().unwrap();
                            disconnect_peer_entry_for_session(
                                &peer_state_cache,
                                &mut peers,
                                &peer_address,
                                session_id,
                            );
                            continue;
                        }

                        if node_id == config.p2p.node_name {
                            warn!(
                                "p2p",
                                "Rejecting self-connection handshake",
                                "peer" => peer_address.clone(),
                                "node_id" => node_id.clone()
                            );
                            let mut peers = connected_peers.lock().unwrap();
                            disconnect_peer_entry_for_session(
                                &peer_state_cache,
                                &mut peers,
                                &peer_address,
                                session_id,
                            );
                            continue;
                        }

                        if let Some(reason) = handshake_mismatch_reason(
                            &config,
                            chain_id,
                            chain_incarnation,
                            consensus_state_schema_version,
                            network_id,
                            network_id_text.as_deref(),
                            &genesis_hash,
                            &network_magic_bytes,
                            protocol_version.as_deref(),
                            consensus_version.as_deref(),
                            native_caip2.as_deref(),
                        ) {
                            warn!(
                                "p2p",
                                "Rejecting peer handshake for canonical testnet identity mismatch",
                                "peer" => peer_address.clone(),
                                "node_id" => node_id.clone(),
                                "reason" => reason,
                                "local_chain_id" => local_chain_id(&config),
                                "local_network_id" => local_network_id(&config),
                                "local_genesis_hash" => canonical_genesis_hash(),
                                "local_network_magic_bytes" => canonical_network_magic_bytes()
                            );
                            let mut peers = connected_peers.lock().unwrap();
                            disconnect_peer_entry_for_session(
                                &peer_state_cache,
                                &mut peers,
                                &peer_address,
                                session_id,
                            );
                            continue;
                        }

                        let typed_consensus_peer = match verify_handshake_pq_signature(
                            &handshake_for_verification,
                        ) {
                            Ok(identity) => identity,
                            Err(reason) => {
                                warn!(
                                    "p2p",
                                    "Rejecting peer handshake because Aegis PQC authentication failed",
                                    "peer" => peer_address.clone(),
                                    "node_id" => node_id.clone(),
                                    "reason" => reason
                                );
                                let mut peers = connected_peers.lock().unwrap();
                                disconnect_peer_entry_for_session(
                                    &peer_state_cache,
                                    &mut peers,
                                    &peer_address,
                                    session_id,
                                );
                                continue;
                            }
                        };
                        if let Some(identity) = typed_consensus_peer {
                            if let Err(reason) = register_typed_consensus_peer_session(
                                &peer_address,
                                session_id,
                                identity,
                            ) {
                                warn!(
                                    "p2p",
                                    "Rejecting typed PoSy peer because its authenticated session cannot be bound",
                                    "peer" => peer_address.clone(),
                                    "reason" => reason
                                );
                                let mut peers = connected_peers.lock().unwrap();
                                disconnect_peer_entry_for_session(
                                    &peer_state_cache,
                                    &mut peers,
                                    &peer_address,
                                    session_id,
                                );
                                continue;
                            }
                        }

                        if reserved_eip155
                            .as_deref()
                            .filter(|value| !value.is_empty())
                            .is_some()
                            && native_caip2.as_deref() != Some(TESTNET_NATIVE_CAIP2)
                        {
                            warn!(
                                "p2p",
                                "Rejecting peer handshake because reserved EIP-155 identity cannot override native Synergy identity",
                                "peer" => peer_address.clone(),
                                "node_id" => node_id.clone(),
                                "reserved_eip155" => reserved_eip155.unwrap_or_default()
                            );
                            let mut peers = connected_peers.lock().unwrap();
                            disconnect_peer_entry_for_session(
                                &peer_state_cache,
                                &mut peers,
                                &peer_address,
                                session_id,
                            );
                            continue;
                        }

                        // `role` is covered by the verified handshake signature. Keep only
                        // this authenticated value for history-source authorization.
                        let authenticated_handshake_role = role
                            .as_deref()
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(ToOwned::to_owned);

                        let announced_validator_address = validator_address
                            .as_ref()
                            .map(|value| value.trim().to_string())
                            .filter(|value| !value.is_empty());
                        let canonicalize_validator_public_address =
                            should_canonicalize_validator_public_address(
                                announced_validator_address.as_deref(),
                            );
                        let normalized_public_address = if canonicalize_validator_public_address {
                            canonical_validator_public_address(
                                &peer_address,
                                public_address.as_deref(),
                            )
                        } else {
                            public_address
                                .as_deref()
                                .and_then(parse_bootnode_dial_address)
                                .or_else(|| public_address.clone())
                        };
                        if canonicalize_validator_public_address
                            && normalized_public_address != public_address
                        {
                            warn!(
                                "p2p",
                                "Normalized validator public address to canonical port",
                                "peer" => peer_address.clone(),
                                "advertised_public_address" => public_address.clone().unwrap_or_default(),
                                "normalized_public_address" => normalized_public_address.clone().unwrap_or_default()
                            );
                        }
                        let peer_identity =
                            peer_identity_key(&node_id, announced_validator_address.as_deref());
                        let local_identity = local_peer_identity(&config);
                        let direct_vote_session = capabilities
                            .iter()
                            .any(|capability| capability == "direct-vote");

                        info!(
                            "p2p",
                            "Handshake received",
                            "peer" => peer_address.clone(),
                            "node_id" => node_id.clone(),
                            "validator_address" => announced_validator_address.clone().unwrap_or_default(),
                            "version" => version.clone(),
                            "protocol_version" => protocol_version.unwrap_or_default(),
                            "consensus_version" => consensus_version.unwrap_or_default(),
                            "genesis_hash" => genesis_hash.clone(),
                            "network_magic_bytes" => network_magic_bytes,
                            "public_address" => normalized_public_address.clone().unwrap_or_default()
                        );

                        // Update peer info and deduplicate by stable peer identity.
                        let mut deferred_status_request = None;
                        let mut skip_handshake_followup = false;
                        {
                            let mut peers = connected_peers.lock().unwrap();
                            if !peer_session_is_current(&peer_address, session_id) {
                                continue;
                            }

                            // Prefer validator identity when present; fall back to node_id for
                            // non-validator/discovery peers.
                            let existing_peer_key = peers
                                .iter()
                                .find(|(_, peer)| {
                                    peer_identity_from_connection(peer).as_deref()
                                        == Some(peer_identity.as_str())
                                })
                                .map(|(key, _)| key.clone());

                            if let Some(existing_key) = existing_peer_key.clone() {
                                if existing_key != peer_address {
                                    let existing_metadata = peers.get(&existing_key).map(|peer| {
                                        (
                                            peer.direction,
                                            peer.connected_at,
                                            peer.public_address.clone(),
                                        )
                                    });
                                    let new_metadata = peers
                                        .get(&peer_address)
                                        .map(|peer| (peer.direction, peer.connected_at));

                                    let existing_cached_state =
                                        peers.get(&existing_key).and_then(|peer| {
                                            build_cached_peer_state(peer).map(|(_, state)| state)
                                        });

                                    if direct_vote_session {
                                        if let Some(peer) = peer_for_session_mut(
                                            &mut peers,
                                            &peer_address,
                                            session_id,
                                        ) {
                                            peer.node_id = Some(node_id.clone());
                                            peer.handshake_role =
                                                authenticated_handshake_role.clone();
                                            peer.version = Some(version.clone());
                                            peer.capabilities = capabilities.clone();
                                            peer.public_address = normalized_public_address.clone();
                                            peer.validator_address =
                                                announced_validator_address.clone();
                                            if !genesis_hash.trim().is_empty() {
                                                peer.genesis_hash = genesis_hash.clone();
                                            }
                                            peer.active_validator_set_hash =
                                                active_validator_set_hash.clone();
                                        }
                                        info!(
                                            "p2p",
                                            "Duplicate direct vote session allowed to drain",
                                            "node_id" => node_id.clone(),
                                            "kept_address" => existing_key.clone(),
                                            "direct_vote_peer" => peer_address.clone(),
                                            "validator_address" => announced_validator_address.clone().unwrap_or_default()
                                        );
                                        skip_handshake_followup = true;
                                    }

                                    if should_resolve_duplicate_session(direct_vote_session) {
                                        if let (
                                            Some((
                                                existing_direction,
                                                existing_connected_at,
                                                existing_public_address,
                                            )),
                                            Some((new_direction, new_connected_at)),
                                        ) = (existing_metadata, new_metadata)
                                        {
                                            let duplicate_resolution = resolve_duplicate_connection(
                                                &local_identity,
                                                &peer_identity,
                                                existing_direction,
                                                existing_connected_at,
                                                new_direction,
                                                new_connected_at,
                                            );

                                            match duplicate_resolution {
                                                DuplicateResolution::KeepExisting => {
                                                    if let Some(peer) = peers.get_mut(&existing_key)
                                                    {
                                                        peer.node_id = Some(node_id.clone());
                                                        peer.handshake_role =
                                                            authenticated_handshake_role.clone();
                                                        peer.version = Some(version.clone());
                                                        peer.capabilities = capabilities.clone();
                                                        if normalized_public_address
                                                            .as_deref()
                                                            .map(str::trim)
                                                            .filter(|value| !value.is_empty())
                                                            .is_some()
                                                        {
                                                            peer.public_address =
                                                                normalized_public_address.clone();
                                                        }
                                                        if announced_validator_address.is_some() {
                                                            peer.validator_address =
                                                                announced_validator_address.clone();
                                                        }
                                                        if !genesis_hash.trim().is_empty() {
                                                            peer.genesis_hash =
                                                                genesis_hash.clone();
                                                        }
                                                        peer.active_validator_set_hash =
                                                            active_validator_set_hash.clone();
                                                        hydrate_peer_from_cache(
                                                            &peer_state_cache,
                                                            &peer_identity,
                                                            peer,
                                                        );
                                                        cache_peer_state(&peer_state_cache, peer);
                                                    }
                                                    propagate_identity_to_matching_peers(
                                                        &mut peers,
                                                        &peer_state_cache,
                                                        &existing_key,
                                                        &node_id,
                                                        &version,
                                                        &capabilities,
                                                        normalized_public_address.as_deref(),
                                                        announced_validator_address.as_deref(),
                                                        &genesis_hash,
                                                    );
                                                    deferred_status_request =
                                                        current_peer_session_id(&existing_key).map(
                                                            |session_id| {
                                                                (existing_key.clone(), session_id)
                                                            },
                                                        );
                                                    warn!(
                                                        "p2p",
                                                        "Duplicate peer session detected; keeping stable connection",
                                                        "node_id" => node_id.clone(),
                                                        "kept_address" => existing_key.clone(),
                                                        "kept_direction" => format!("{:?}", existing_direction),
                                                        "dropped_address" => peer_address.clone(),
                                                        "dropped_direction" => format!("{:?}", new_direction),
                                                        "preferred_direction" => format!(
                                                            "{:?}",
                                                            preferred_connection_direction(
                                                                &local_identity,
                                                                &peer_identity
                                                            )
                                                        ),
                                                        "kept_public_address" => existing_public_address.unwrap_or_default()
                                                    );
                                                    disconnect_peer_entry(
                                                        &peer_state_cache,
                                                        &mut peers,
                                                        &peer_address,
                                                    );
                                                    skip_handshake_followup = true;
                                                }
                                                DuplicateResolution::ReplaceExisting => {
                                                    if let (Some(existing_state), Some(peer)) = (
                                                        existing_cached_state.as_ref(),
                                                        peers.get_mut(&peer_address),
                                                    ) {
                                                        let existing_peer = PeerConnection {
                                                            address: String::new(),
                                                            connected_endpoint: None,
                                                            direction:
                                                                ConnectionDirection::Outgoing,
                                                            public_address: existing_state
                                                                .public_address
                                                                .clone(),
                                                            validator_address: existing_state
                                                                .validator_address
                                                                .clone(),
                                                            connected_at: existing_state
                                                                .connected_at,
                                                            last_seen: existing_state.last_seen,
                                                            blocks_sent: 0,
                                                            blocks_received: 0,
                                                            txs_sent: 0,
                                                            txs_received: 0,
                                                            stream: None,
                                                            node_id: existing_state.node_id.clone(),
                                                            handshake_role: existing_state
                                                                .handshake_role
                                                                .clone(),
                                                            version: existing_state.version.clone(),
                                                            capabilities: existing_state
                                                                .capabilities
                                                                .clone(),
                                                            last_known_height: existing_state
                                                                .last_known_height,
                                                            best_block_hash: existing_state
                                                                .best_block_hash
                                                                .clone(),
                                                            genesis_hash: existing_state
                                                                .genesis_hash
                                                                .clone(),
                                                            status_received_at: existing_state
                                                                .status_received_at,
                                                            status_reported_at: existing_state
                                                                .status_reported_at,
                                                            status_validator_address:
                                                                existing_state
                                                                    .status_validator_address
                                                                    .clone(),
                                                            status_source_session_id:
                                                                existing_state
                                                                    .status_source_session_id
                                                                    .clone(),
                                                            active_validator_set_hash:
                                                                existing_state
                                                                    .active_validator_set_hash
                                                                    .clone(),
                                                            quarantined: existing_state.quarantined,
                                                            consensus_duties_disabled:
                                                                existing_state
                                                                    .consensus_duties_disabled,
                                                            recovery_state: existing_state
                                                                .recovery_state
                                                                .clone(),
                                                        };
                                                        merge_peer_state_from_existing(
                                                            &existing_peer,
                                                            peer,
                                                        );
                                                    }
                                                    if let Some(peer) = peers.get(&existing_key) {
                                                        cache_peer_state(&peer_state_cache, peer);
                                                    }
                                                    warn!(
                                                        "p2p",
                                                        "Duplicate peer session detected; replacing non-preferred connection",
                                                        "node_id" => node_id.clone(),
                                                        "old_address" => existing_key.clone(),
                                                        "old_direction" => format!("{:?}", existing_direction),
                                                        "new_address" => peer_address.clone(),
                                                        "new_direction" => format!("{:?}", new_direction),
                                                        "preferred_direction" => format!(
                                                            "{:?}",
                                                            preferred_connection_direction(
                                                                &local_identity,
                                                                &peer_identity
                                                            )
                                                        )
                                                    );
                                                    disconnect_peer_entry(
                                                        &peer_state_cache,
                                                        &mut peers,
                                                        &existing_key,
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Update peer info
                            if let Some(peer) =
                                peer_for_session_mut(&mut peers, &peer_address, session_id)
                            {
                                peer.node_id = Some(node_id.clone());
                                peer.handshake_role = authenticated_handshake_role.clone();
                                peer.version = Some(version.clone());
                                peer.capabilities = capabilities.clone();
                                peer.public_address = normalized_public_address.clone();
                                peer.validator_address = announced_validator_address.clone();
                                if !genesis_hash.trim().is_empty() {
                                    peer.genesis_hash = genesis_hash.clone();
                                }
                                peer.active_validator_set_hash = active_validator_set_hash.clone();
                                hydrate_peer_from_cache(&peer_state_cache, &peer_identity, peer);
                                cache_peer_state(&peer_state_cache, peer);
                            }
                            propagate_identity_to_matching_peers(
                                &mut peers,
                                &peer_state_cache,
                                &peer_address,
                                &node_id,
                                &version,
                                &capabilities,
                                normalized_public_address.as_deref(),
                                announced_validator_address.as_deref(),
                                &genesis_hash,
                            );
                            if !skip_handshake_followup {
                                deferred_status_request = current_peer_session_id(&peer_address)
                                    .map(|session_id| (peer_address.clone(), session_id));
                            }
                        }

                        if let Some((status_peer, status_session_id)) = deferred_status_request {
                            request_status_from_connected_peer(
                                &connected_peers,
                                &peer_state_cache,
                                &status_peer,
                                status_session_id,
                            );
                        }
                        if skip_handshake_followup {
                            continue;
                        }

                        // Candidate validators are discovered here, but funding and consensus
                        // activation must run through the explicit source-level workflow.
                        {
                            // Only auto-register if auto-registration is enabled in config
                            if config.node.bootstrap_only {
                                debug!(
                                    "p2p",
                                    "Bootstrap-only mode enabled; skipping validator auto-registration for peer",
                                    "peer" => peer_address.clone(),
                                    "peer_identity" => peer_identity.clone()
                                );
                                continue;
                            }

                            if config.node.auto_register_validator
                                && !config.node.strict_validator_allowlist
                            {
                                debug!(
                                    "p2p",
                                    "Skipping unsafe validator auto-registration because strict validator allowlist is disabled",
                                    "peer" => peer_address.clone(),
                                    "peer_identity" => peer_identity.clone()
                                );
                                continue;
                            }

                            if config.node.auto_register_validator {
                                let Some(validator_address) = announced_validator_address.clone()
                                else {
                                    debug!(
                                        "p2p",
                                        "Peer did not advertise a validator address; skipping validator auto-registration",
                                        "peer" => peer_address.clone(),
                                        "peer_identity" => peer_identity.clone()
                                    );
                                    continue;
                                };

                                if !is_validator_allowed(&config, &validator_address) {
                                    warn!(
                                        "p2p",
                                        "Skipping validator auto-registration: address not in allowlist",
                                        "address" => validator_address.clone()
                                    );
                                    continue;
                                }
                                let validator_manager = VALIDATOR_MANAGER.clone();
                                let is_registered = validator_manager
                                    .get_validator(&validator_address)
                                    .is_some();
                                let is_pending = validator_manager.is_pending(&validator_address);

                                if !is_registered && !is_pending {
                                    info!(
                                        "p2p",
                                        "Observed candidate validator; explicit 5,000 SNRG funding and activation are required before consensus membership",
                                        "address" => validator_address.clone()
                                    );
                                }
                            }
                        }
                    }
                    NetworkMessage::Block {
                        block_data,
                        quorum_certificate,
                    } => {
                        handle_block_message(
                            &blockchain,
                            &connected_peers,
                            &peer_state_cache,
                            &config,
                            &peer_address,
                            session_id,
                            block_data,
                            quorum_certificate,
                        );
                    }
                    NetworkMessage::VoteRequest {
                        block_data,
                        epoch_number,
                        round_number,
                    } => handle_vote_request_message(
                        &blockchain,
                        &connected_peers,
                        &peer_state_cache,
                        &config,
                        &peer_address,
                        session_id,
                        block_data,
                        epoch_number,
                        round_number,
                    ),
                    NetworkMessage::Vote { vote } => handle_vote_message(
                        &connected_peers,
                        &config,
                        &peer_address,
                        session_id,
                        vote,
                    ),
                    NetworkMessage::TypedConsensus {
                        chain_incarnation,
                        genesis_hash,
                        message,
                    } => {
                        if chain_incarnation != canonical_chain_incarnation()
                            || genesis_hash != canonical_genesis_hash()
                        {
                            warn!(
                                "p2p",
                                "Rejected old-incarnation typed consensus message",
                                "peer" => peer_address.clone(),
                                "incarnation" => chain_incarnation
                            );
                            continue;
                        }
                        if let Err(error) =
                            crate::consensus::typed_coordinator::dispatch_typed_consensus_message(
                                &peer_address,
                                typed_consensus_peer_for_session(&peer_address, session_id),
                                message,
                            )
                        {
                            warn!(
                                "p2p",
                                "Rejected typed consensus message",
                                "peer" => peer_address.clone(),
                                "error" => error
                            );
                        }
                    }
                    NetworkMessage::CoordinatedConsensus {
                        chain_incarnation,
                        genesis_hash,
                        message,
                    } => {
                        if chain_incarnation != canonical_chain_incarnation()
                            || genesis_hash != canonical_genesis_hash()
                        {
                            warn!(
                                "p2p",
                                "Rejected old-incarnation coordinated consensus message",
                                "peer" => peer_address.clone(),
                                "incarnation" => chain_incarnation
                            );
                            continue;
                        }
                        let authenticated_peer =
                            typed_consensus_peer_for_session(&peer_address, session_id).map(
                                |peer| AuthenticatedCoordinatedConsensusPeer {
                                    validator_id: peer.validator_id,
                                    validator_uma_id: peer.validator_uma_id,
                                    consensus_key_id: peer.consensus_key_id,
                                },
                            );
                        if let Err(error) = crate::consensus::coordinated_round_robin::dispatch_coordinated_consensus_message(
                            &peer_address,
                            authenticated_peer,
                            message,
                        ) {
                            warn!(
                                "p2p",
                                "Rejected coordinated consensus message",
                                "peer" => peer_address.clone(),
                                "error" => error
                            );
                        }
                    }
                    NetworkMessage::SimplifiedConsensus {
                        chain_incarnation,
                        genesis_hash,
                        message,
                    } => {
                        if coordinated_consensus_active(&config) {
                            warn!(
                                "p2p",
                                "Rejected simplified consensus message while coordinated mode is selected",
                                "peer" => peer_address.clone()
                            );
                            continue;
                        }
                        if chain_incarnation != canonical_chain_incarnation()
                            || genesis_hash != canonical_genesis_hash()
                        {
                            warn!(
                                "p2p",
                                "Rejected old-incarnation simplified consensus message",
                                "peer" => peer_address.clone(),
                                "incarnation" => chain_incarnation
                            );
                            continue;
                        }
                        if let Err(error) =
                            crate::consensus::simplified_posy::dispatch_simplified_consensus_message(
                                &peer_address,
                                simplified_consensus_peer_for_session(&peer_address, session_id),
                                message,
                            )
                        {
                            warn!(
                                "p2p",
                                "Rejected simplified consensus message",
                                "peer" => peer_address.clone(),
                                "error" => error
                            );
                        }
                    }
                    NetworkMessage::SimplifiedTargetAdmission {
                        chain_incarnation,
                        genesis_hash,
                        message,
                    } => {
                        if coordinated_consensus_active(&config) {
                            warn!(
                                "p2p",
                                "Rejected simplified target-admission message while coordinated mode is selected",
                                "peer" => peer_address.clone()
                            );
                            continue;
                        }
                        if chain_incarnation != canonical_chain_incarnation()
                            || genesis_hash != canonical_genesis_hash()
                        {
                            warn!(
                                "p2p",
                                "Rejected old-incarnation simplified target-admission message",
                                "peer" => peer_address.clone(),
                                "incarnation" => chain_incarnation
                            );
                            continue;
                        }
                        if let Err(error) = dispatch_simplified_target_admission_ingress(
                            etdag_ingress_peer_for_session(&peer_address, session_id),
                            message,
                        ) {
                            warn!(
                                "p2p",
                                "Rejected simplified target-admission message",
                                "peer" => peer_address.clone(),
                                "error" => error
                            );
                        }
                    }
                    NetworkMessage::SimplifiedEtdagAssembly {
                        chain_incarnation,
                        genesis_hash,
                        message,
                    } => {
                        if coordinated_consensus_active(&config) {
                            warn!(
                                "p2p",
                                "Rejected simplified empty-ETDAG message while coordinated mode is selected",
                                "peer" => peer_address.clone()
                            );
                            continue;
                        }
                        if chain_incarnation != canonical_chain_incarnation()
                            || genesis_hash != canonical_genesis_hash()
                        {
                            warn!(
                                "p2p",
                                "Rejected old-incarnation simplified empty-ETDAG message",
                                "peer" => peer_address.clone(),
                                "incarnation" => chain_incarnation
                            );
                            continue;
                        }
                        if let Err(error) = dispatch_simplified_empty_etdag_ingress(
                            etdag_ingress_peer_for_session(&peer_address, session_id),
                            message,
                        ) {
                            warn!(
                                "p2p",
                                "Rejected simplified empty-ETDAG message",
                                "peer" => peer_address.clone(),
                                "error" => error
                            );
                        }
                    }
                    NetworkMessage::TypedFinalityObserver {
                        chain_incarnation,
                        genesis_hash,
                        message,
                    } => {
                        if chain_incarnation != canonical_chain_incarnation()
                            || genesis_hash != canonical_genesis_hash()
                        {
                            warn!(
                                "p2p",
                                "Rejected old-incarnation typed observer message",
                                "peer" => peer_address.clone(),
                                "incarnation" => chain_incarnation
                            );
                            continue;
                        }
                        if let Err(error) = handle_typed_finality_observer_message(
                            &connected_peers,
                            &peer_state_cache,
                            &config,
                            &peer_address,
                            session_id,
                            message,
                        ) {
                            warn!(
                                "p2p",
                                "Rejected typed finality observer message",
                                "peer" => peer_address.clone(),
                                "error" => error
                            );
                        }
                    }
                    NetworkMessage::EtdagCertifiedInput { artifact } => {
                        if let Err(error) = dispatch_etdag_certified_input(
                            etdag_ingress_peer_for_session(&peer_address, session_id),
                            artifact,
                        ) {
                            warn!(
                                "p2p",
                                "Rejected certified ETDAG input",
                                "peer" => peer_address.clone(),
                                "error" => error
                            );
                        }
                    }
                    NetworkMessage::Transaction { transaction_data } => {
                        if config.node.bootstrap_only {
                            debug!(
                                "p2p",
                                "Bootstrap-only node ignoring transaction propagation",
                                "peer" => peer_address.clone(),
                                "tx_hash" => transaction_data.hash()
                            );
                            continue;
                        }

                        info!("p2p", "Received transaction", "peer" => peer_address.clone());

                        // Update peer stats
                        {
                            let mut peers = connected_peers.lock().unwrap();
                            if let Some(peer) =
                                peer_for_session_mut(&mut peers, &peer_address, session_id)
                            {
                                peer.txs_received += 1;
                            }
                        }

                        let validation = transaction_data.validate_for_admission();
                        if !validation.is_valid {
                            warn!(
                                "p2p",
                                "Rejecting transaction before DAG/mempool admission",
                                "peer" => peer_address.clone(),
                                "tx_hash" => transaction_data.hash(),
                                "error" => validation
                                    .error_message
                                    .unwrap_or_else(|| "invalid transaction".to_string())
                            );
                            continue;
                        }

                        if let Err(error) =
                            ProofOfSynergy::validate_transaction_for_mempool(&transaction_data)
                        {
                            let tx_hash = transaction_data.hash();
                            let pruned = prune_transaction_hashes_from_pool(&transaction_hashes(
                                std::slice::from_ref(&transaction_data),
                            ));
                            warn!(
                                "p2p",
                                "Rejecting transaction after runtime validation",
                                "peer" => peer_address.clone(),
                                "tx_hash" => tx_hash,
                                "error" => error,
                                "pruned_count" => pruned as u64
                            );
                            continue;
                        }

                        let tx_hash = transaction_data.hash();
                        let should_forward = {
                            let mut pool = TX_POOL.lock().unwrap();
                            if !pool.iter().any(|t| t.hash() == tx_hash) {
                                pool.push(transaction_data.clone());
                                info!("p2p", "Transaction added to pool", "tx_hash" => tx_hash.clone());
                                true
                            } else {
                                debug!("p2p", "Duplicate transaction ignored", "tx_hash" => tx_hash.clone());
                                false
                            }
                        };

                        if should_forward {
                            let message = NetworkMessage::Transaction { transaction_data };
                            let mut forwarded_peers = 0u64;

                            let targets = peer_session_targets(&connected_peers)
                                .into_iter()
                                .filter(|(address, _)| address != &peer_address)
                                .collect::<Vec<_>>();
                            for (address, target_session_id) in targets {
                                match send_peer_message_for_session(
                                    &connected_peers,
                                    &peer_state_cache,
                                    &address,
                                    target_session_id,
                                    &message,
                                    Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
                                    "transaction-forward",
                                ) {
                                    Ok(true) => {
                                        let mut peers = connected_peers.lock().unwrap();
                                        if let Some(peer) = peer_for_session_mut(
                                            &mut peers,
                                            &address,
                                            target_session_id,
                                        ) {
                                            peer.txs_sent += 1;
                                            forwarded_peers += 1;
                                        }
                                    }
                                    Ok(false) => {}
                                    Err(error) => {
                                        warn!(
                                            "p2p",
                                            "Failed to forward transaction",
                                            "peer" => address,
                                            "tx_hash" => tx_hash.clone(),
                                            "error" => error
                                        );
                                    }
                                }
                            }

                            info!(
                                "p2p",
                                "Transaction forwarded",
                                "tx_hash" => tx_hash,
                                "from_peer" => peer_address.clone(),
                                "peers" => forwarded_peers
                            );
                        }
                    }
                    NetworkMessage::GetBlocks { from_height, count } => {
                        handle_get_blocks_message(
                            &blockchain,
                            &connected_peers,
                            &peer_state_cache,
                            &config,
                            &peer_address,
                            session_id,
                            from_height,
                            count,
                        );
                    }
                    NetworkMessage::GetStatus => {
                        if !authorize_status_exchange_for_session(
                            &connected_peers,
                            &peer_state_cache,
                            &peer_address,
                            session_id,
                            "status-request",
                        ) {
                            continue;
                        }
                        if !should_send_status_response(&peer_address, session_id) {
                            debug!(
                                "p2p",
                                "Suppressing status response inside peer-session rate limit",
                                "peer" => peer_address.clone(),
                                "session_id" => session_id
                            );
                            continue;
                        }
                        let status = build_local_status_message(&blockchain, &config);

                        if let Err(error) = send_peer_message_for_session(
                            &connected_peers,
                            &peer_state_cache,
                            &peer_address,
                            session_id,
                            &status,
                            Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
                            "status-response",
                        ) {
                            warn!("p2p", "Failed to send status", "peer" => peer_address.clone(), "error" => error);
                        }
                    }
                    NetworkMessage::Status {
                        block_height,
                        best_block_hash,
                        genesis_hash,
                        status_timestamp,
                        validator_address,
                        source_session_id,
                        active_validator_set_hash,
                        quarantined,
                        consensus_duties_disabled,
                        recovery_state,
                    } => {
                        handle_status_message(
                            &blockchain,
                            &connected_peers,
                            &peer_state_cache,
                            &config,
                            &peer_address,
                            session_id,
                            block_height,
                            &best_block_hash,
                            &genesis_hash,
                            status_timestamp,
                            validator_address.as_deref(),
                            source_session_id.as_deref(),
                            active_validator_set_hash.as_deref(),
                            quarantined,
                            consensus_duties_disabled,
                            recovery_state.as_deref(),
                        );
                    }
                    NetworkMessage::GetBlockHeaders {
                        start_height,
                        count,
                    } => {
                        if config.node.bootstrap_only {
                            let response = NetworkMessage::BlockHeaders {
                                headers: Vec::new(),
                            };
                            if let Err(error) = send_peer_message_for_session(
                                &connected_peers,
                                &peer_state_cache,
                                &peer_address,
                                session_id,
                                &response,
                                Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
                                "bootstrap-block-headers",
                            ) {
                                warn!("p2p", "Failed to send bootstrap-only block headers", "peer" => peer_address.clone(), "error" => error);
                            }
                            continue;
                        }

                        if !authorize_chain_requester_for_session(
                            &connected_peers,
                            &peer_state_cache,
                            &config,
                            &peer_address,
                            session_id,
                            "block-headers",
                        ) {
                            continue;
                        }

                        let headers = {
                            let chain = blockchain.lock().unwrap();
                            chain
                                .chain
                                .iter()
                                .filter(|block| block.block_index >= start_height)
                                .take(count.min(MAX_BLOCK_SYNC_RESPONSE_BLOCKS as u64) as usize)
                                .map(|block| block.header())
                                .collect::<Vec<_>>()
                        };
                        let response = NetworkMessage::BlockHeaders { headers };
                        if let Err(error) = send_peer_message_for_session(
                            &connected_peers,
                            &peer_state_cache,
                            &peer_address,
                            session_id,
                            &response,
                            Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
                            "block-headers",
                        ) {
                            warn!("p2p", "Failed to send block headers", "peer" => peer_address.clone(), "error" => error);
                        }
                    }
                    NetworkMessage::BlockHeaders { headers } => {
                        if config.node.bootstrap_only {
                            debug!(
                                "p2p",
                                "Bootstrap-only node ignoring block headers",
                                "peer" => peer_address.clone(),
                                "count" => headers.len()
                            );
                            continue;
                        }

                        debug!("p2p", "Received block headers", "peer" => peer_address.clone(), "count" => headers.len());
                    }
                    NetworkMessage::GetBlockBodies { hashes } => {
                        if config.node.bootstrap_only {
                            let response = NetworkMessage::BlockBodies {
                                blocks: Vec::new(),
                                quorum_certificates: Vec::new(),
                            };
                            if let Err(error) = send_peer_message_for_session(
                                &connected_peers,
                                &peer_state_cache,
                                &peer_address,
                                session_id,
                                &response,
                                Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
                                "bootstrap-block-bodies",
                            ) {
                                warn!("p2p", "Failed to send bootstrap-only block bodies", "peer" => peer_address.clone(), "error" => error);
                            }
                            continue;
                        }

                        if !authorize_chain_requester_for_session(
                            &connected_peers,
                            &peer_state_cache,
                            &config,
                            &peer_address,
                            session_id,
                            "block-bodies",
                        ) {
                            continue;
                        }

                        let blocks = {
                            let chain = blockchain.lock().unwrap();
                            hashes
                                .iter()
                                .filter_map(|hash| {
                                    chain
                                        .chain
                                        .iter()
                                        .find(|block| &block.hash == hash)
                                        .cloned()
                                })
                                .collect::<Vec<_>>()
                        };
                        // Historical QC lookup may scan the full archive; keep it outside the chain mutex.
                        let quorum_certificates =
                            DualQuorumConsensus::committed_qcs_for_block_hashes(
                                blocks.iter().map(|block| block.hash.as_str()),
                            );
                        let response = NetworkMessage::BlockBodies {
                            blocks,
                            quorum_certificates,
                        };
                        if let Err(error) = send_peer_message_for_session(
                            &connected_peers,
                            &peer_state_cache,
                            &peer_address,
                            session_id,
                            &response,
                            Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
                            "block-bodies",
                        ) {
                            warn!("p2p", "Failed to send block bodies", "peer" => peer_address.clone(), "error" => error);
                        }
                    }
                    NetworkMessage::BlockBodies {
                        blocks,
                        quorum_certificates,
                    } => {
                        if config.node.bootstrap_only {
                            debug!(
                                "p2p",
                                "Bootstrap-only node ignoring block bodies",
                                "peer" => peer_address.clone(),
                                "count" => blocks.len()
                            );
                            continue;
                        }
                        if local_node_uses_service_batch_durability(&config) {
                            debug!(
                                "p2p",
                                "Service node ignoring unsolicited block bodies outside coordinated sync",
                                "peer" => peer_address.clone(),
                                "count" => blocks.len() as u64
                            );
                            continue;
                        }

                        debug!("p2p", "Received block bodies", "peer" => peer_address.clone(), "count" => blocks.len());
                        let applied = apply_block_batch_for_role(
                            &blockchain,
                            blocks,
                            quorum_certificates,
                            local_node_uses_service_batch_durability(&config),
                        );
                        if applied > 0 {
                            info!("p2p", "Body blocks applied", "count" => applied);
                        }
                    }
                    NetworkMessage::Blocks {
                        blocks,
                        quorum_certificates,
                    } => {
                        handle_blocks_message(
                            &blockchain,
                            &connected_peers,
                            &peer_state_cache,
                            &config,
                            &peer_address,
                            session_id,
                            blocks,
                            quorum_certificates,
                        );
                    }
                    NetworkMessage::GetPeers => {
                        // Respond with known peer dial addresses.
                        let peer_addresses = if peer_exchange_enabled(&config) {
                            collect_known_peer_addresses(
                                &connected_peers,
                                &discovered_dial_targets,
                                &config,
                            )
                        } else {
                            Vec::new()
                        };
                        let response = NetworkMessage::Peers { peer_addresses };

                        if let Err(error) = send_peer_message_for_session(
                            &connected_peers,
                            &peer_state_cache,
                            &peer_address,
                            session_id,
                            &response,
                            Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
                            "peers-response",
                        ) {
                            warn!("p2p", "Failed to send peers list", "peer" => peer_address.clone(), "error" => error);
                        }
                    }
                    NetworkMessage::Peers { peer_addresses } => {
                        if !peer_exchange_enabled(&config) {
                            debug!(
                                "p2p",
                                "Ignoring peer discovery response because discovery is disabled",
                                "peer" => peer_address.clone()
                            );
                            continue;
                        }

                        // Attempt to dial new peers (best-effort).
                        let max_peers = config.network.max_peers as usize;
                        for addr in peer_addresses {
                            if !peer_session_is_current(&peer_address, session_id) {
                                break;
                            }
                            let Some(addr) = normalize_peer_target(&config, &addr) else {
                                debug!(
                                    "p2p",
                                    "Ignoring non-dialable peer discovery address",
                                    "peer" => peer_address.clone(),
                                    "address" => addr
                                );
                                continue;
                            };
                            if is_self_dial_target(&config, &addr) {
                                continue;
                            }
                            let should_dial = {
                                let peers = connected_peers.lock().unwrap();
                                if peers.len() >= max_peers {
                                    false
                                } else {
                                    connected_peer_key_for_address(&peers, &addr).is_none()
                                }
                            };
                            if should_dial && peer_session_is_current(&peer_address, session_id) {
                                info!(
                                    "p2p",
                                    "Dialing discovered peer",
                                    "source_peer" => peer_address.clone(),
                                    "target" => addr.clone()
                                );
                                let _ = dial_peer_async(
                                    addr.clone(),
                                    Arc::clone(&blockchain),
                                    Arc::clone(&connected_peers),
                                    Arc::clone(&peer_state_cache),
                                    Arc::clone(&dial_registry),
                                    message_sender.clone(),
                                    config.clone(),
                                    Some((peer_address.clone(), session_id)),
                                );
                            }
                        }
                    }
                    NetworkMessage::Error { message }
                        if message.starts_with("block-sync-busy:") =>
                    {
                        schedule_block_sync_retry(
                            Arc::clone(&connected_peers),
                            Arc::clone(&peer_state_cache),
                            peer_address.clone(),
                            session_id,
                            &message,
                            local_node_uses_service_batch_durability(&config),
                        );
                        debug!(
                            "p2p",
                            "Peer deferred block sync work; scheduled block sync retry",
                            "peer" => peer_address.clone(),
                            "message" => message
                        );
                    }
                    NetworkMessage::Ping => {
                        debug!("p2p", "Ping received", "peer" => peer_address.clone());

                        let pong = NetworkMessage::Pong;
                        if let Err(error) = send_peer_message_for_session(
                            &connected_peers,
                            &peer_state_cache,
                            &peer_address,
                            session_id,
                            &pong,
                            Duration::from_millis(P2P_MESSAGE_WRITE_TIMEOUT_MILLIS),
                            "pong-response",
                        ) {
                            warn!("p2p", "Failed to send pong", "peer" => peer_address.clone(), "error" => error);
                        }
                    }
                    NetworkMessage::Pong => {
                        debug!("p2p", "Pong received", "peer" => peer_address.clone());
                    }
                    _ => {
                        debug!("p2p", "Unhandled P2P message", "peer" => peer_address.clone(), "message" => format!("{:?}", message));
                    }
                }
            }
            Err(_) => {
                break;
            }
        }
    }
}

fn send_message(
    stream: &mut impl Write,
    message: &NetworkMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string(message)?;
    let data = json.as_bytes();
    let len = validate_outbound_frame_length(data.len())?;

    // Send length prefix
    stream.write_all(&len.to_le_bytes())?;
    // Send message data
    stream.write_all(data)?;
    stream.flush()?;

    Ok(())
}

fn validate_outbound_frame_length(length: usize) -> io::Result<u32> {
    if length > MAX_P2P_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "outbound p2p frame length {} exceeds limit {MAX_P2P_FRAME_BYTES}",
                length
            ),
        ));
    }
    u32::try_from(length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("outbound p2p frame length {length} exceeds u32"),
        )
    })
}

fn send_consensus_message(
    stream: &mut TcpStream,
    message: &NetworkMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    send_message_with_write_timeout(
        stream,
        message,
        Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
    )
}

fn send_message_with_write_timeout(
    stream: &mut TcpStream,
    message: &NetworkMessage,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let previous_timeout = stream.write_timeout()?;
    stream.set_write_timeout(Some(timeout))?;
    let send_result = send_message(stream, message);
    let restore_result = stream.set_write_timeout(previous_timeout);

    match (send_result, restore_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(Box::new(error)),
        (Ok(_), Ok(_)) => Ok(()),
    }
}

fn receive_message(stream: &mut impl Read) -> Result<NetworkMessage, io::Error> {
    // Read length prefix
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_P2P_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("p2p frame length {len} exceeds limit {MAX_P2P_FRAME_BYTES}"),
        ));
    }

    // Read a small envelope prefix before allocating the declared payload.
    // Simplified consensus uses JSON's externally tagged enum representation,
    // so its outer and inner kind are visible here. This prevents an
    // authenticated peer from forcing a 64-MiB allocation before the tighter
    // consensus-kind cap is known.
    const PREDECODE_PREFIX_BYTES: usize = 4 * 1024;
    let prefix_len = len.min(PREDECODE_PREFIX_BYTES);
    let mut prefix = vec![0u8; prefix_len];
    stream.read_exact(&mut prefix)?;
    validate_simplified_predecode_frame_length(len, &prefix)?;

    // Read the remainder after the predecode allocation gate.
    let mut data = vec![0u8; len];
    data[..prefix_len].copy_from_slice(&prefix);
    stream.read_exact(&mut data[prefix_len..])?;

    // Parse JSON message
    let json =
        String::from_utf8(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let message: NetworkMessage =
        serde_json::from_str(&json).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(message)
}

fn validate_simplified_predecode_frame_length(len: usize, prefix: &[u8]) -> io::Result<()> {
    let mut cursor = 0usize;
    // Serde encodes unit `NetworkMessage` variants as JSON strings. These
    // control frames occur immediately after the initial handshake/status
    // exchange, so treating every frame as an externally-tagged object tears
    // down otherwise authenticated validator sessions before consensus can
    // establish peer readiness. Keep the predecode gate fail-closed by
    // admitting only the complete, known unit control variants.
    skip_json_whitespace(prefix, &mut cursor);
    if prefix.get(cursor) == Some(&b'"') {
        let unit_kind = consume_json_key(prefix, &mut cursor, "network control frame")?;
        if !matches!(unit_kind, b"GetPeers" | b"Ping" | b"Pong" | b"GetStatus") {
            return Err(invalid_predecode(
                "network control frame is not an allowed unit NetworkMessage variant",
            ));
        }
        skip_json_whitespace(prefix, &mut cursor);
        if cursor != prefix.len() || len != prefix.len() {
            return Err(invalid_predecode(
                "network control frame must be fully visible in the bounded predecode prefix",
            ));
        }
        return Ok(());
    }
    consume_json_byte(prefix, &mut cursor, b'{', "network envelope")?;
    let outer_kind = consume_json_key(prefix, &mut cursor, "network envelope kind")?;
    if outer_kind == b"SimplifiedTargetAdmission" {
        consume_json_byte(prefix, &mut cursor, b':', "target-admission envelope")?;
        consume_json_byte(prefix, &mut cursor, b'{', "target-admission body")?;
        if consume_json_key(prefix, &mut cursor, "target-admission body field")? != b"message" {
            return Err(invalid_predecode(
                "target-admission message must be the first canonical body field",
            ));
        }
        consume_json_byte(prefix, &mut cursor, b':', "target-admission message field")?;
        consume_json_byte(prefix, &mut cursor, b'{', "target-admission message")?;
        let message_kind = consume_json_key(prefix, &mut cursor, "target-admission message kind")?;
        let (kind, maximum) = match message_kind {
            b"Vote" => ("vote", MAX_SIMPLIFIED_TARGET_ADMISSION_VOTE_FRAME_BYTES),
            b"CertifiedPackage" => (
                "certified package",
                MAX_SIMPLIFIED_TARGET_ADMISSION_PACKAGE_FRAME_BYTES,
            ),
            _ => {
                return Err(invalid_predecode(
                    "target-admission frame does not declare a bounded message kind in its predecode prefix",
                ));
            }
        };
        let frame_len = len
            .checked_add(4)
            .ok_or_else(|| invalid_predecode("target-admission frame length overflow"))?;
        if frame_len > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "simplified target-admission {kind} frame length {frame_len} exceeds limit {maximum}"
                ),
            ));
        }
        return Ok(());
    }
    if outer_kind == b"SimplifiedEtdagAssembly" {
        consume_json_byte(prefix, &mut cursor, b':', "empty-ETDAG assembly envelope")?;
        consume_json_byte(prefix, &mut cursor, b'{', "empty-ETDAG assembly body")?;
        if consume_json_key(prefix, &mut cursor, "empty-ETDAG assembly body field")? != b"message" {
            return Err(invalid_predecode(
                "empty-ETDAG assembly message must be the first canonical body field",
            ));
        }
        consume_json_byte(
            prefix,
            &mut cursor,
            b':',
            "empty-ETDAG assembly message field",
        )?;
        consume_json_byte(prefix, &mut cursor, b'{', "empty-ETDAG assembly message")?;
        let message_kind =
            consume_json_key(prefix, &mut cursor, "empty-ETDAG assembly message kind")?;
        let (kind, maximum) = match message_kind {
            b"Marker" | b"VacVote" | b"DccVote" | b"BvcVote" | b"BocVote" => {
                ("control", MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CONTROL_FRAME_BYTES)
            }
            b"DccCandidate" | b"BvcCandidate" | b"BocCandidate" => (
                "candidate",
                MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CANDIDATE_FRAME_BYTES,
            ),
            _ => {
                return Err(invalid_predecode(
                    "empty-ETDAG assembly frame does not declare a bounded message kind in its predecode prefix",
                ));
            }
        };
        let frame_len = len
            .checked_add(4)
            .ok_or_else(|| invalid_predecode("empty-ETDAG assembly frame length overflow"))?;
        if frame_len > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "simplified empty-ETDAG assembly {kind} frame length {frame_len} exceeds limit {maximum}",
                ),
            ));
        }
        return Ok(());
    }
    if outer_kind != b"SimplifiedConsensus" {
        return Ok(());
    }
    consume_json_byte(prefix, &mut cursor, b':', "simplified consensus envelope")?;
    consume_json_byte(prefix, &mut cursor, b'{', "simplified consensus body")?;
    if consume_json_key(prefix, &mut cursor, "simplified consensus body field")? != b"message" {
        return Err(invalid_predecode(
            "simplified consensus message must be the first canonical body field",
        ));
    }
    consume_json_byte(
        prefix,
        &mut cursor,
        b':',
        "simplified consensus message field",
    )?;
    consume_json_byte(prefix, &mut cursor, b'{', "simplified consensus message")?;
    let message_kind = consume_json_key(prefix, &mut cursor, "simplified consensus message kind")?;
    let (kind, maximum) = match message_kind {
        b"Proposal" => ("proposal", MAX_SIMPLIFIED_CONSENSUS_PROPOSAL_FRAME_BYTES),
        b"ReliableDelivery" | b"Vote" | b"TimeoutVote" => {
            ("vote", MAX_SIMPLIFIED_CONSENSUS_VOTE_FRAME_BYTES)
        }
        b"QuorumCertificate" | b"TimeoutCertificate" => (
            "certificate",
            MAX_SIMPLIFIED_CONSENSUS_CERTIFICATE_FRAME_BYTES,
        ),
        b"StateSyncRequest" | b"MaterialRequest" => (
            "state-sync request",
            MAX_SIMPLIFIED_CONSENSUS_CONTROL_FRAME_BYTES,
        ),
        b"StateSyncChunk" | b"MaterialChunk" => (
            "state-sync chunk",
            MAX_SIMPLIFIED_CONSENSUS_STATE_SYNC_FRAME_BYTES,
        ),
        _ => {
            return Err(invalid_predecode(
                "simplified consensus frame does not declare a bounded message kind in its predecode prefix",
            ));
        }
    };
    let frame_len = len
        .checked_add(4)
        .ok_or_else(|| invalid_predecode("simplified consensus frame length overflow"))?;
    if frame_len > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("simplified consensus {kind} frame length {frame_len} exceeds limit {maximum}"),
        ));
    }
    Ok(())
}

fn consume_json_byte(
    prefix: &[u8],
    cursor: &mut usize,
    expected: u8,
    label: &str,
) -> io::Result<()> {
    skip_json_whitespace(prefix, cursor);
    if prefix.get(*cursor) != Some(&expected) {
        return Err(invalid_predecode(&format!(
            "{label} is not visible in the bounded predecode prefix"
        )));
    }
    *cursor = cursor
        .checked_add(1)
        .ok_or_else(|| invalid_predecode("predecode cursor overflow"))?;
    Ok(())
}

fn consume_json_key<'a>(prefix: &'a [u8], cursor: &mut usize, label: &str) -> io::Result<&'a [u8]> {
    consume_json_byte(prefix, cursor, b'"', label)?;
    let start = *cursor;
    while let Some(byte) = prefix.get(*cursor).copied() {
        match byte {
            b'"' => {
                let key = &prefix[start..*cursor];
                *cursor = cursor
                    .checked_add(1)
                    .ok_or_else(|| invalid_predecode("predecode cursor overflow"))?;
                return Ok(key);
            }
            b'\\' => {
                return Err(invalid_predecode(&format!(
                    "{label} must use its canonical unescaped wire spelling"
                )));
            }
            0x00..=0x1f | 0x80..=0xff => {
                return Err(invalid_predecode(&format!(
                    "{label} contains a non-ASCII tag byte"
                )));
            }
            _ => {
                *cursor = cursor
                    .checked_add(1)
                    .ok_or_else(|| invalid_predecode("predecode cursor overflow"))?;
            }
        }
    }
    Err(invalid_predecode(&format!(
        "{label} is incomplete in the bounded predecode prefix"
    )))
}

fn skip_json_whitespace(prefix: &[u8], cursor: &mut usize) {
    while prefix
        .get(*cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
    {
        *cursor = cursor.saturating_add(1);
    }
}

fn invalid_predecode(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn parse_bootnode_dial_address(bootnode: &str) -> Option<String> {
    let raw = bootnode.trim();
    if raw.is_empty() {
        return None;
    }

    // Strip common schemes
    let raw = raw
        .strip_prefix("snr://")
        .or_else(|| raw.strip_prefix("enode://"))
        .unwrap_or(raw);

    // Use part after '@' if present.
    let raw = raw.rsplit_once('@').map(|(_, right)| right).unwrap_or(raw);

    // Strip path / query / fragment.
    let raw = raw.split('/').next().unwrap_or(raw);
    let raw = raw.split('?').next().unwrap_or(raw);
    let raw = raw.split('#').next().unwrap_or(raw);

    normalize_dial_target(raw.trim())
}

fn normalize_dial_target(dial: &str) -> Option<String> {
    let dial = dial.trim();
    if dial.is_empty() {
        return None;
    }

    if let Some(stripped) = dial.strip_prefix('[') {
        let (host, port) = stripped.rsplit_once("]:")?;
        return normalize_host_port(host, port);
    }

    let (host, port) = dial.rsplit_once(':')?;
    normalize_host_port(host, port)
}

fn normalize_host_port(host: &str, port: &str) -> Option<String> {
    let host = host
        .trim()
        .trim_matches('[')
        .trim_matches(']')
        .trim_end_matches('.');
    let port = port.trim().parse::<u16>().ok()?;
    if port == 0 || host.is_empty() || !is_plausible_dial_host(host) {
        return None;
    }

    match host.parse::<std::net::IpAddr>() {
        // Preserve IPv6 literals in normalized form even though the dialer later
        // constrains outbound connections to IPv4 endpoints.
        Ok(std::net::IpAddr::V6(_)) => Some(format!("[{host}]:{port}")),
        Ok(std::net::IpAddr::V4(_)) => Some(format!("{host}:{port}")),
        Err(_) if host.contains(':') => None,
        Err(_) => Some(format!("{host}:{port}")), // DNS hostnames
    }
}

fn is_plausible_dial_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }

    host.contains('.')
        && host.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '.'
        })
}

fn dial_with_timeout(peer: &str, timeout: std::time::Duration) -> io::Result<TcpStream> {
    let mut last_err: Option<io::Error> = None;
    let addrs = peer.to_socket_addrs()?;
    // Only dial IPv4 addresses — IPv6 peers behind NAT/firewalls cause
    // spurious timeouts that flood the logs and waste connection budget.
    let ipv4_addrs: Vec<_> = addrs.filter(|a| a.is_ipv4()).collect();
    if ipv4_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("No IPv4 addresses resolved for {peer}"),
        ));
    }
    for addr in ipv4_addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                configure_peer_stream(&stream);
                return Ok(stream);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "No resolved addresses")))
}

fn normalize_validator_address_target(value: &str) -> Option<String> {
    let value = value.trim();
    if value.starts_with("synv1")
        && !value.contains(':')
        && value.len() >= 12
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        Some(value.to_string())
    } else {
        None
    }
}

fn validator_vpn_transport_for_target(
    config: &NodeConfig,
    validator_address: &str,
) -> Option<String> {
    validator_vpn_transport_for_target_with_static_fallback(
        config,
        validator_address,
        cfg!(test) || chain1266_private_qualification_mode(),
    )
}

fn validator_vpn_transport_for_target_with_static_fallback(
    config: &NodeConfig,
    validator_address: &str,
    allow_static_fallback: bool,
) -> Option<String> {
    let qualification_mode = chain1266_private_qualification_mode();
    let validator_address = normalize_validator_address_target(validator_address)?;
    // Qualification has a disposable WireGuard mesh and its own rendered
    // validator transport map. Never load a public coordinator snapshot there:
    // even a valid public mapping would reconnect the isolated release to the
    // public Chain 1266 overlay.
    if !qualification_mode {
        if let Some(dial_address) = validator_transport_for(&validator_address) {
            let dial_address = parse_bootnode_dial_address(&dial_address)?;
            if is_validator_vpn_dial_address(&dial_address) {
                return Some(dial_address);
            }
        }
        if has_validator_transports() {
            return None;
        }
    }
    if !allow_static_fallback {
        return None;
    }
    configured_validator_vpn_transport_for_target(config, &validator_address, qualification_mode)
}

fn configured_validator_vpn_transport_for_target(
    config: &NodeConfig,
    validator_address: &str,
    require_private_qualification_overlay: bool,
) -> Option<String> {
    config
        .network
        .validator_vpn_transports
        .iter()
        .find_map(|transport| {
            let configured_validator =
                normalize_validator_address_target(&transport.validator_address)?;
            if configured_validator == validator_address {
                let dial_address = parse_bootnode_dial_address(&transport.dial_address)?;
                let approved = if require_private_qualification_overlay {
                    is_private_qualification_innernet_dial_address(&dial_address, 10)
                } else {
                    is_validator_vpn_dial_address(&dial_address)
                };
                if approved {
                    Some(dial_address)
                } else {
                    None
                }
            } else {
                None
            }
        })
}

fn resolve_peer_transport_address(config: &NodeConfig, target: &str) -> Option<String> {
    if let Some(validator_address) = normalize_validator_address_target(target) {
        validator_vpn_transport_for_target(config, &validator_address)
    } else {
        let parsed = parse_bootnode_dial_address(target)?;
        if local_node_uses_signed_validator_transports(config)
            && is_current_validator_vpn_dial_address(&parsed)
        {
            return None;
        }
        peer_target_allowed_by_local_scope(config, &parsed).then_some(parsed)
    }
}

fn normalize_peer_target(config: &NodeConfig, value: &str) -> Option<String> {
    if let Some(validator_address) = normalize_validator_address_target(value) {
        if self_dial_aliases(config).contains(&validator_address) {
            return Some(validator_address);
        }
        if peer_target_allowed_by_local_scope(config, &validator_address)
            && validator_vpn_transport_for_target(config, &validator_address).is_some()
        {
            return Some(validator_address);
        }
        return None;
    }

    let parsed = parse_bootnode_dial_address(value)?;
    if local_node_uses_signed_validator_transports(config)
        && is_current_validator_vpn_dial_address(&parsed)
    {
        return None;
    }
    peer_target_allowed_by_local_scope(config, &parsed).then_some(parsed)
}

fn insert_advertised_peer_target(out: &mut HashSet<String>, config: &NodeConfig, address: String) {
    if config.p2p.reject_private_advertise_addrs && is_private_dial_address(&address) {
        return;
    }
    out.insert(address);
}

fn collect_known_peer_addresses(
    connected_peers: &PeersArc,
    discovered_dial_targets: &DialTargetsArc,
    config: &NodeConfig,
) -> Vec<String> {
    let mut out = HashSet::<String>::new();

    if let Some(address) = normalize_peer_target(config, &config.p2p.public_address) {
        insert_advertised_peer_target(&mut out, config, address);
    }

    for dial in config
        .network
        .persistent_peers
        .iter()
        .chain(config.network.additional_dial_targets.iter())
    {
        if let Some(address) = normalize_peer_target(config, dial) {
            insert_advertised_peer_target(&mut out, config, address);
        }
    }

    if let Ok(discovered) = discovered_dial_targets.lock() {
        for dial in discovered.iter() {
            if let Some(address) = normalize_peer_target(config, dial) {
                insert_advertised_peer_target(&mut out, config, address);
            }
        }
    }

    if let Ok(peers) = connected_peers.lock() {
        for peer in peers.values() {
            let has_validator_identity = peer
                .validator_address
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty());
            if !has_validator_identity {
                continue;
            }
            if let Some(pub_addr) = peer.public_address.as_ref() {
                if let Some(address) = normalize_peer_target(config, pub_addr) {
                    insert_advertised_peer_target(&mut out, config, address);
                    continue;
                }
            }
            if peer.direction == ConnectionDirection::Outgoing {
                if let Some(address) = normalize_peer_target(config, &peer.address) {
                    insert_advertised_peer_target(&mut out, config, address);
                }
            }
        }
    }

    let mut ordered = out.into_iter().collect::<Vec<_>>();
    ordered.sort();
    ordered
}

fn is_assigned_synergy_dial_address(value: &str) -> bool {
    let Some(normalized) = parse_bootnode_dial_address(value) else {
        return false;
    };
    let Some((host, _port)) = normalized.rsplit_once(':') else {
        return false;
    };
    let host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    is_public_synergy_advertise_host(&host)
}

fn is_assigned_or_validator_vpn_dial_address(value: &str) -> bool {
    is_assigned_synergy_dial_address(value) || is_current_validator_vpn_dial_address(value)
}

fn local_validator_vpn_peer_scope(config: &NodeConfig) -> bool {
    local_node_runs_validator_consensus(config)
}

fn local_node_uses_signed_validator_transports(config: &NodeConfig) -> bool {
    local_validator_vpn_peer_scope(config) || local_p2p_role(config).eq_ignore_ascii_case("relayer")
}

fn chain1266_private_qualification_mode() -> bool {
    std::env::var(crate::desired_state::CHAIN1266_QUALIFICATION_MODE_ENV).as_deref() == Ok("1")
}

fn local_node_uses_relayer_only_topology(config: &NodeConfig) -> bool {
    !local_node_runs_validator_consensus(config)
        && !local_p2p_role(config).eq_ignore_ascii_case("relayer")
}

fn is_public_relayer_dial_address(value: &str) -> bool {
    let Some(normalized) = parse_bootnode_dial_address(value) else {
        return false;
    };
    PUBLIC_RELAYER_DIAL_ADDRESSES
        .iter()
        .any(|relay| *relay == normalized)
}

fn peer_target_allowed_by_local_scope(config: &NodeConfig, value: &str) -> bool {
    if local_validator_vpn_peer_scope(config) {
        normalize_validator_address_target(value).is_some()
            || is_current_validator_vpn_relayer_dial_address(value)
    } else if local_p2p_role(config).eq_ignore_ascii_case("relayer") {
        normalize_validator_address_target(value).is_some()
            || is_current_validator_vpn_relayer_dial_address(value)
            || is_assigned_synergy_dial_address(value)
    } else if local_node_uses_relayer_only_topology(config) {
        is_public_relayer_dial_address(value)
    } else {
        normalize_validator_address_target(value).is_some()
            || is_assigned_or_validator_vpn_dial_address(value)
    }
}

fn is_validator_vpn_dial_address(value: &str) -> bool {
    is_canonical_innernet_dial_address(value, 10)
}

fn is_current_validator_vpn_dial_address(value: &str) -> bool {
    is_validator_vpn_dial_address(value)
        || (chain1266_private_qualification_mode()
            && is_private_qualification_innernet_dial_address(value, 10))
}

fn is_canonical_innernet_dial_address(value: &str, third_octet: u8) -> bool {
    // The fresh public P3 provider uses 10.69.10.0/24 for validators and
    // 10.69.1.0/24 for relayers.  The test-only 10.70 fixtures remain accepted
    // below solely so isolated historical unit fixtures do not become a
    // production routing fallback.
    is_innernet_dial_address(value, 69, third_octet)
        || (cfg!(test) && is_innernet_dial_address(value, 70, third_octet))
}

fn is_private_qualification_innernet_dial_address(value: &str, third_octet: u8) -> bool {
    is_innernet_dial_address(value, 126, third_octet)
}

fn is_innernet_dial_address(value: &str, second_octet: u8, third_octet: u8) -> bool {
    let Some(normalized) = parse_bootnode_dial_address(value) else {
        return false;
    };
    let Some((_, port)) = normalized.rsplit_once(':') else {
        return false;
    };
    if port.parse::<u16>().ok() != Some(VALIDATOR_P2P_PORT) {
        return false;
    }
    validator_vpn_dial_octets(&normalized)
        .map(|octets| {
            octets[0] == 10
                && octets[1] == second_octet
                && octets[2] == third_octet
                && (1..=254).contains(&octets[3])
        })
        .unwrap_or(false)
}

fn is_validator_vpn_relayer_dial_address(value: &str) -> bool {
    is_innernet_dial_address(value, 69, 1)
        || (cfg!(test) && is_innernet_dial_address(value, 70, 20))
}

fn is_current_validator_vpn_relayer_dial_address(value: &str) -> bool {
    is_validator_vpn_relayer_dial_address(value)
        || (chain1266_private_qualification_mode()
            && is_private_qualification_innernet_dial_address(value, 20))
}

fn validator_vpn_dial_octets(value: &str) -> Option<[u8; 4]> {
    let normalized = parse_bootnode_dial_address(value)?;
    let (host, _port) = normalized.rsplit_once(':')?;
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::Ipv4Addr>()
        .ok()
        .map(|addr| addr.octets())
}

fn is_public_synergy_advertise_host(host: &str) -> bool {
    let host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if host.is_empty() || host == "localhost" {
        return false;
    }

    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified())
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local())
        }
        Err(_) => host.ends_with(".synergynode.xyz") || host.ends_with(".synergy-network.io"),
    }
}

fn is_private_dial_address(value: &str) -> bool {
    let Some(normalized) = parse_bootnode_dial_address(value) else {
        return false;
    };
    let Some((host, _)) = normalized.rsplit_once(':') else {
        return false;
    };
    match host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
    {
        Ok(std::net::IpAddr::V4(ip)) => {
            ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
        Err(_) => false,
    }
}

fn peer_exchange_enabled(config: &NodeConfig) -> bool {
    config.p2p.enable_discovery && config.p2p.enable_peer_exchange
}

fn verify_network_block(block: &Block) -> Result<(), String> {
    if block.block_index == 0 {
        return Ok(());
    }
    block.verify_proposer_signature()
}

fn verify_network_commit_certificate(
    block: &Block,
    qc: Option<&QuorumCertificate>,
) -> Result<QuorumCertificate, String> {
    let validator_manager = commit_verifier_validator_manager();
    verify_network_commit_certificate_with_manager(block, qc, &validator_manager)
}

fn verify_network_commit_certificate_with_manager(
    block: &Block,
    qc: Option<&QuorumCertificate>,
    validator_manager: &Arc<ValidatorManager>,
) -> Result<QuorumCertificate, String> {
    if let Err(error) = verify_network_block(block) {
        return Err(format!("invalid Aegis PQC proposer signature: {error}"));
    }

    if block.block_index == 0 {
        return Ok(QuorumCertificate {
            block_hash: block.hash.clone(),
            cluster_id: None,
            epoch_number: 0,
            round_number: 0,
            aggregate_signature: vec![0],
            participant_bitmap: vec![0],
            cumulative_weight: 0.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: block.timestamp,
            votes: Vec::new(),
        });
    }

    let qc = qc
        .cloned()
        .ok_or_else(|| "missing QC for committed network block".to_string())?;
    DualQuorumConsensus::verify_commit_certificate_for_block_static(
        block,
        &qc,
        &validator_manager,
    )?;
    Ok(qc)
}

fn run_with_bounded_parallelism<T, R, F>(
    items: &[T],
    max_workers: usize,
    operation_name: &str,
    operation: F,
) -> Vec<Result<R, String>>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> Result<R, String> + Sync,
{
    if items.is_empty() {
        return Vec::new();
    }

    let worker_count = max_workers.max(1).min(items.len());
    let next_index = AtomicUsize::new(0);
    let spawn_error = Mutex::new(None::<String>);
    let results = Mutex::new(
        (0..items.len())
            .map(|_| None)
            .collect::<Vec<Option<Result<R, String>>>>(),
    );

    thread::scope(|scope| {
        for worker_index in 0..worker_count {
            let spawned = thread::Builder::new()
                .name(format!("{operation_name}-{worker_index}"))
                .spawn_scoped(scope, || {
                    let _ = catch_unwind(AssertUnwindSafe(|| loop {
                        let index = next_index.fetch_add(1, Ordering::Relaxed);
                        if index >= items.len() {
                            break;
                        }
                        let result = catch_unwind(AssertUnwindSafe(|| operation(&items[index])))
                            .unwrap_or_else(|_| {
                                Err(format!("{operation_name} panicked for item {index}"))
                            });
                        let mut results = match results.lock() {
                            Ok(results) => results,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        results[index] = Some(result);
                    }));
                });
            if let Err(error) = spawned {
                let mut spawn_error = match spawn_error.lock() {
                    Ok(spawn_error) => spawn_error,
                    Err(poisoned) => poisoned.into_inner(),
                };
                *spawn_error = Some(format!("failed to spawn {operation_name} worker: {error}"));
            }
        }
    });

    let spawn_error = match spawn_error.into_inner() {
        Ok(spawn_error) => spawn_error,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(error) = spawn_error {
        return (0..items.len()).map(|_| Err(error.clone())).collect();
    }

    let results = match results.into_inner() {
        Ok(results) => results,
        Err(poisoned) => poisoned.into_inner(),
    };
    results
        .into_iter()
        .enumerate()
        .map(|(index, result)| {
            result.unwrap_or_else(|| {
                Err(format!(
                    "{operation_name} worker terminated before item {index} completed"
                ))
            })
        })
        .collect()
}

fn verify_batch_with_bounded_parallelism<T, F>(
    items: &[T],
    max_workers: usize,
    verify: F,
) -> Vec<Result<(), String>>
where
    T: Sync,
    F: Fn(&T) -> Result<(), String> + Sync,
{
    run_with_bounded_parallelism(items, max_workers, "batch verifier", verify)
}

fn commit_verifier_validator_manager() -> Arc<ValidatorManager> {
    #[cfg(test)]
    if let Some(validator_manager) =
        TEST_COMMIT_VERIFIER_VALIDATOR_MANAGER.with(|slot| slot.borrow().clone())
    {
        return validator_manager;
    }

    let validator_manager = Arc::new(ValidatorManager::new());
    copy_active_validators_into_commit_verifier(&validator_manager, &VALIDATOR_MANAGER);
    if validator_manager.get_active_validators().is_empty() {
        hydrate_commit_verifier_validator_manager(&validator_manager);
    }
    validator_manager
}

fn copy_active_validators_into_commit_verifier(
    target: &Arc<ValidatorManager>,
    source: &Arc<ValidatorManager>,
) {
    let active_validators = source.get_active_validators();
    if active_validators.is_empty() {
        return;
    }

    if let Ok(mut registry) = target.registry.lock() {
        for validator in active_validators {
            registry
                .validators
                .entry(validator.address.clone())
                .or_insert(validator);
        }
    }
}

fn hydrate_commit_verifier_validator_manager(validator_manager: &Arc<ValidatorManager>) {
    let canonical_validator_addresses = canonical_genesis()
        .ok()
        .map(|genesis| {
            genesis
                .validators()
                .iter()
                .map(|validator| validator.operator_address.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let required_validator_count = canonical_validator_addresses.len();

    if validator_manager
        .load_registry("data/validator_registry.json")
        .is_ok()
        && commit_verifier_has_active_validators(
            &validator_manager,
            &canonical_validator_addresses,
            required_validator_count,
        )
    {
        return;
    }

    let Ok(genesis) = canonical_genesis() else {
        return;
    };

    for validator in genesis.validators() {
        let address = validator.operator_address.as_str();
        if validator_manager.get_validator(address).is_none() {
            let _ = validator_manager.register_validator(ValidatorRegistration {
                address: validator.operator_address.clone(),
                public_key: validator.consensus_public_key.clone(),
                name: validator.moniker.clone(),
                stake_amount: validator.stake_nwei,
                submitted_at: genesis.timestamp(),
                registration_tx_hash: "genesis".to_string(),
            });
        }
        let _ = validator_manager.approve_validator(address);
        validator_manager.update_validator_stake(address, validator.stake_nwei);
        validator_manager.update_synergy_score(address, 100.0);
    }

    #[cfg(not(test))]
    let _ = validator_manager.save_registry("data/validator_registry.json");
}

fn commit_verifier_has_active_validators(
    validator_manager: &Arc<ValidatorManager>,
    required_addresses: &[String],
    required_validator_count: usize,
) -> bool {
    let active_validators = validator_manager.get_active_validators();
    if active_validators.len() < required_validator_count {
        return false;
    }

    if required_addresses.is_empty() {
        return true;
    }

    required_addresses.iter().all(|address| {
        active_validators
            .iter()
            .any(|validator| validator.address == *address)
    })
}

fn record_peer_canonical_lock_conflict(block: &Block, error: &str) {
    let local_locked_hash = legacy_canonical_commit_record(block.block_index)
        .ok()
        .flatten()
        .map(|record| record.block_hash);
    warn!(
        "p2p",
        "Rejected peer block that conflicts with local canonical lock",
        "height" => block.block_index,
        "local_locked_hash" => local_locked_hash.unwrap_or_else(|| "unknown".to_string()),
        "conflicting_hash" => block.hash.clone(),
        "error" => error.to_string()
    );
}

fn record_canonical_lock_conflict_from_peer(
    _blockchain: &BlockchainArc,
    block: &Block,
    error: &str,
) {
    record_peer_canonical_lock_conflict(block, error);
}

#[derive(Debug, Clone)]
struct CanonicalLockRecoveryPlan {
    common_height: u64,
    conflict_height: u64,
    local_locked_hash: String,
    conflicting_hash: String,
}

/// A valid QC is the source-majority proof for its exact block. Recovery is
/// allowed only for a contiguous branch with a local overlap and a conflict
/// against the local lock suffix; incomplete or ambiguous batches remain
/// rejected by the normal canonical-lock path.
fn source_majority_canonical_lock_recovery_plan(
    blockchain: &BlockchainArc,
    blocks: &[Block],
    verified_source_hashes: &HashSet<String>,
) -> Result<Option<CanonicalLockRecoveryPlan>, String> {
    let chain = blockchain.lock().unwrap();
    let local_tip_height = chain.last().map(|entry| entry.block_index).unwrap_or(0);
    let common_height = blocks.iter().rev().find_map(|block| {
        if block.block_index > local_tip_height {
            return None;
        }
        chain
            .block_at_height(block.block_index)
            .filter(|local| local.hash == block.hash)
            .map(|_| block.block_index)
    });
    let Some(common_height) = common_height.filter(|height| *height < local_tip_height) else {
        return Ok(None);
    };

    let mut expected_height = common_height.saturating_add(1);
    let Some(mut expected_parent_hash) = chain
        .block_at_height(common_height)
        .map(|block| block.hash.clone())
    else {
        return Ok(None);
    };
    for block in blocks
        .iter()
        .filter(|block| block.block_index <= common_height)
    {
        if let Some(record) = legacy_canonical_commit_record(block.block_index)? {
            if record.block_hash != block.hash {
                return Ok(None);
            }
        }
    }
    let mut conflict = None;
    for block in blocks
        .iter()
        .filter(|block| block.block_index > common_height)
    {
        if block.block_index != expected_height {
            return Ok(None);
        }
        if block.previous_hash != expected_parent_hash {
            return Ok(None);
        }
        if !verified_source_hashes.contains(&block.hash) {
            return Ok(None);
        }

        if let Some(record) = legacy_canonical_commit_record(block.block_index)? {
            if record.block_hash != block.hash {
                let Some(local_block) = chain.block_at_height(block.block_index) else {
                    return Ok(None);
                };
                if local_block.hash != record.block_hash {
                    return Ok(None);
                }
                if conflict.is_none() {
                    conflict = Some(CanonicalLockRecoveryPlan {
                        common_height,
                        conflict_height: block.block_index,
                        local_locked_hash: record.block_hash,
                        conflicting_hash: block.hash.clone(),
                    });
                }
            }
        }

        expected_height = expected_height.saturating_add(1);
        expected_parent_hash = block.hash.clone();
    }

    Ok(conflict)
}

fn quarantine_local_suffix_for_recovery(
    plan: &CanonicalLockRecoveryPlan,
    context: &str,
) -> Result<usize, String> {
    let reason = format!(
        "source-majority catch-up at h{} conflicts with local canonical lock; quarantining local fork suffix from h{}",
        plan.conflict_height, plan.common_height.saturating_add(1)
    );
    record_self_quarantine_for_canonical_lock_conflict(
        plan.conflict_height,
        Some(plan.local_locked_hash.clone()),
        &plan.conflicting_hash,
        &reason,
    )
    .map_err(|error| format!("persist recovery duty quarantine ({context}): {error}"))?;

    let quarantined = quarantine_legacy_canonical_locks_above(plan.common_height)
        .map_err(|error| format!("quarantine local canonical lock suffix ({context}): {error}"))?;
    warn!(
        "p2p",
        "Quarantined local fork suffix before source-majority catch-up",
        "context" => context.to_string(),
        "common_height" => plan.common_height,
        "conflict_height" => plan.conflict_height,
        "quarantined_locks" => quarantined.len() as u64,
        "duties_disabled" => true
    );
    Ok(quarantined.len())
}

fn preflight_validator_activation_transactions<'a, I>(blocks: I) -> Result<(), String>
where
    I: IntoIterator<Item = &'a Block>,
{
    let token_manager = crate::token::TOKEN_MANAGER.clone();
    let validator_manager = VALIDATOR_MANAGER.clone();

    for block in blocks {
        for tx in &block.transactions {
            if !is_validator_activation_transaction(tx) {
                continue;
            }
            crate::validator::validate_validator_activation_transaction(
                tx,
                &token_manager,
                &validator_manager,
            )?;
        }
    }
    Ok(())
}

fn apply_block_if_new(
    blockchain: &BlockchainArc,
    block: Block,
    quorum_certificate: Option<QuorumCertificate>,
) -> bool {
    let qc = match verify_network_commit_certificate(&block, quorum_certificate.as_ref()) {
        Ok(qc) => qc,
        Err(error) => {
            warn!(
                "p2p",
                "Rejecting block without valid Aegis PQC quorum certificate",
                "height" => block.block_index,
                "hash" => block.hash.clone(),
                "error" => error
            );
            return false;
        }
    };
    if block.block_index > 0 {
        if let Err(error) = verify_legacy_canonical_lock(&block) {
            record_canonical_lock_conflict_from_peer(blockchain, &block, &error);
            warn!(
                "p2p",
                "Rejecting block that conflicts with canonical block lock",
                "height" => block.block_index,
                "hash" => block.hash.clone(),
                "error" => error
            );
            return false;
        }
    }

    let mut applied_blocks = Vec::new();
    let mut confirmed_hashes = HashSet::new();
    let (tip_height, snapshot) = {
        let mut chain = blockchain.lock().unwrap();
        let mut candidate = Some(PendingCommittedBlock {
            block,
            quorum_certificate: qc,
        });
        let mut final_tip_height = chain.last().map(|entry| entry.block_index).unwrap_or(0);

        while let Some(next) = candidate {
            let next_block = next.block;
            let next_qc = next.quorum_certificate;
            let Some(tip) = chain.last() else {
                if next_block.block_index != 0 {
                    break;
                }
                confirmed_hashes.extend(transaction_hashes(&next_block.transactions));
                chain.add_block(next_block.clone());
                final_tip_height = next_block.block_index;
                applied_blocks.push(next_block);
                break;
            };

            if next_block.block_index <= tip.block_index {
                break;
            }

            if next_block.block_index > tip.block_index.saturating_add(1) {
                cache_pending_block(next_block, next_qc);
                break;
            }

            if next_block.previous_hash != tip.hash {
                break;
            }

            if next_block.block_index > 0 {
                if let Err(error) = verify_legacy_canonical_lock(&next_block) {
                    record_canonical_lock_conflict_from_peer(blockchain, &next_block, &error);
                    warn!(
                        "p2p",
                        "Rejecting pending block because it conflicts with canonical block lock",
                        "height" => next_block.block_index,
                        "hash" => next_block.hash.clone(),
                        "error" => error
                    );
                    break;
                }
                if let Err(error) =
                    preflight_validator_activation_transactions(std::iter::once(&next_block))
                {
                    warn!(
                        "p2p",
                        "Rejecting block because validator activation preflight failed",
                        "height" => next_block.block_index,
                        "hash" => next_block.hash.clone(),
                        "error" => error
                    );
                    break;
                }
                if let Err(error) = append_committed_block_body(&next_block) {
                    warn!(
                        "p2p",
                        "Rejecting block because durable committed block body could not be written",
                        "height" => next_block.block_index,
                        "hash" => next_block.hash.clone(),
                        "error" => error
                    );
                    break;
                }
            }

            confirmed_hashes.extend(transaction_hashes(&next_block.transactions));
            if chain.add_block_extending_tip(next_block.clone()).is_err() {
                warn!(
                    "p2p",
                    "Rejecting block because it could not be materialized on the local chain tip after durable body write",
                    "height" => next_block.block_index,
                    "hash" => next_block.hash.clone()
                );
                break;
            }

            if next_block.block_index > 0 {
                if let Err(error) =
                    DualQuorumConsensus::record_committed_qc_checked(next_qc.clone())
                {
                    warn!(
                        "p2p",
                        "Rejecting block because durable committed QC could not be written",
                        "height" => next_block.block_index,
                        "hash" => next_block.hash.clone(),
                        "error" => error
                    );
                    break;
                }
                if let Err(error) = write_legacy_canonical_lock(&next_block, &next_qc) {
                    record_canonical_lock_conflict_from_peer(blockchain, &next_block, &error);
                    warn!(
                        "p2p",
                        "Rejecting block because canonical lock could not be written",
                        "height" => next_block.block_index,
                        "hash" => next_block.hash.clone(),
                        "error" => error
                    );
                    break;
                }
            }

            final_tip_height = next_block.block_index;
            applied_blocks.push(next_block.clone());

            let next_tip = chain.last().cloned();
            candidate = next_tip.as_ref().and_then(take_pending_block_extending_tip);
        }

        if let Some(tip) = chain.last() {
            cache_last_known_good_chain_tip(tip);
        }
        compact_hot_chain_state_from_env(&mut chain, "p2p_apply_block_if_new");
        let snapshot = if !applied_blocks.is_empty() && should_persist_chain_tip(final_tip_height) {
            note_chain_persist(final_tip_height);
            if can_clone_chain_for_snapshot(final_tip_height) {
                Some(chain.clone())
            } else {
                None
            }
        } else {
            None
        };
        (final_tip_height, snapshot)
    };

    if applied_blocks.is_empty() {
        return false;
    }

    if let Some(snapshot) = snapshot {
        let chain_path = crate::utils::resolve_data_path("data/chain.json");
        persist_chain_snapshot_async(snapshot, chain_path, tip_height);
    }

    prune_transaction_hashes_from_pool(&confirmed_hashes);
    crate::dag::commit_blocks(&applied_blocks);
    if let Err(error) = apply_token_state_for_blocks(&applied_blocks) {
        quarantine_after_validator_activation_failure(
            applied_blocks
                .last()
                .expect("applied block list is non-empty"),
            &error,
        );
        return false;
    }

    true
}

fn cache_pending_block(block: Block, quorum_certificate: QuorumCertificate) {
    if let Err(error) = verify_network_commit_certificate(&block, Some(&quorum_certificate)) {
        warn!(
            "p2p",
            "Rejecting pending block without valid Aegis PQC quorum certificate",
            "height" => block.block_index,
            "hash" => block.hash.clone(),
            "error" => error
        );
        return;
    }

    let Ok(mut pending) = PENDING_BLOCKS.lock() else {
        return;
    };

    if pending.len() >= MAX_PENDING_BLOCK_HEIGHTS && !pending.contains_key(&block.block_index) {
        if let Some(oldest_height) = pending.keys().next().copied() {
            pending.remove(&oldest_height);
        }
    }

    let entry = pending.entry(block.block_index).or_default();
    if entry
        .iter()
        .any(|candidate| candidate.block.hash == block.hash)
    {
        return;
    }
    if entry.len() >= MAX_PENDING_BLOCKS_PER_HEIGHT {
        entry.remove(0);
    }
    entry.push(PendingCommittedBlock {
        block,
        quorum_certificate,
    });
}

fn take_pending_block_extending_tip(tip: &Block) -> Option<PendingCommittedBlock> {
    let Ok(mut pending) = PENDING_BLOCKS.lock() else {
        return None;
    };
    let next_height = tip.block_index.saturating_add(1);
    let entry = pending.get_mut(&next_height)?;
    let position = entry
        .iter()
        .position(|candidate| candidate.block.previous_hash == tip.hash)?;
    let pending_block = entry.remove(position);
    if entry.is_empty() {
        pending.remove(&next_height);
    }
    Some(pending_block)
}

#[cfg(test)]
fn apply_block_batch(
    blockchain: &BlockchainArc,
    blocks: Vec<Block>,
    quorum_certificates: Vec<QuorumCertificate>,
) -> u64 {
    apply_block_batch_for_role(blockchain, blocks, quorum_certificates, false)
}

fn apply_block_batch_for_role(
    blockchain: &BlockchainArc,
    blocks: Vec<Block>,
    quorum_certificates: Vec<QuorumCertificate>,
    service_role_batched_durability: bool,
) -> u64 {
    if service_role_batched_durability {
        return apply_block_batch_batched_durability(blockchain, blocks, quorum_certificates);
    }
    apply_block_batch_legacy(blockchain, blocks, quorum_certificates)
}

fn apply_block_batch_batched_durability(
    blockchain: &BlockchainArc,
    mut blocks: Vec<Block>,
    quorum_certificates: Vec<QuorumCertificate>,
) -> u64 {
    if blocks.is_empty() {
        return 0;
    }

    blocks.sort_by_key(|block| block.block_index);
    blocks.dedup_by(|left, right| left.block_index == right.block_index && left.hash == right.hash);

    let qc_by_hash = quorum_certificates
        .into_iter()
        .map(|qc| (qc.block_hash.clone(), qc))
        .collect::<HashMap<_, _>>();

    let locally_matching_prefix = {
        let chain = blockchain.lock().unwrap();
        let local_tip_height = chain.last().map(|entry| entry.block_index).unwrap_or(0);
        blocks
            .iter()
            .filter(|block| {
                chain
                    .block_at_height(block.block_index)
                    .map(|local| local.hash == block.hash)
                    .unwrap_or_else(|| {
                        block.block_index <= local_tip_height
                            && block_matches_legacy_canonical_lock(block)
                    })
            })
            .map(|block| block.hash.clone())
            .collect::<HashSet<_>>()
    };

    let blocks_to_verify = blocks
        .iter()
        .filter(|block| !locally_matching_prefix.contains(&block.hash))
        .collect::<Vec<_>>();
    let verification_results = if blocks_to_verify.is_empty() {
        Vec::new()
    } else {
        let commit_verifier = commit_verifier_validator_manager();
        verify_batch_with_bounded_parallelism(
            &blocks_to_verify,
            thread::available_parallelism()
                .map(|parallelism| parallelism.get())
                .unwrap_or(1)
                .min(MAX_BLOCK_BATCH_VERIFY_WORKERS),
            |block| {
                let block = *block;
                verify_network_commit_certificate_with_manager(
                    block,
                    qc_by_hash.get(&block.hash),
                    &commit_verifier,
                )
                .map(|_| ())
            },
        )
    };

    for (block, verification_result) in blocks_to_verify.iter().zip(verification_results) {
        if let Err(error) = verification_result {
            warn!(
                "p2p",
                "Rejecting block batch without valid Aegis PQC quorum certificate",
                "height" => block.block_index,
                "hash" => block.hash.clone(),
                "error" => error
            );
            return 0;
        }
    }
    let verified_source_hashes = blocks_to_verify
        .iter()
        .map(|block| block.hash.clone())
        .collect::<HashSet<_>>();
    let recovery_plan = match source_majority_canonical_lock_recovery_plan(
        blockchain,
        &blocks,
        &verified_source_hashes,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            warn!(
                "p2p",
                "Rejecting service block batch because canonical lock recovery could not be evaluated",
                "error" => error
            );
            return 0;
        }
    };
    let blocks_to_check = blocks_to_verify
        .iter()
        .copied()
        .filter(|block| block.block_index > 0)
        .collect::<Vec<_>>();
    if recovery_plan.is_none() {
        if let Err(error) = verify_legacy_canonical_locks(&blocks_to_check) {
            warn!(
                "p2p",
                "Rejecting service block batch that conflicts with canonical block lock",
                "error" => error
            );
            return 0;
        }
    } else {
        warn!(
            "p2p",
            "Accepted source-majority service batch for local fork recovery",
            "common_height" => recovery_plan.as_ref().unwrap().common_height,
            "conflict_height" => recovery_plan.as_ref().unwrap().conflict_height
        );
    }
    if let Err(error) = preflight_validator_activation_transactions(blocks.iter()) {
        warn!(
            "p2p",
            "Rejecting service block batch because validator activation preflight failed",
            "error" => error
        );
        return 0;
    }

    let mut confirmed_hashes = HashSet::new();
    for block in &blocks {
        confirmed_hashes.extend(transaction_hashes(&block.transactions));
    }

    let (applied, applied_blocks, rollback_height, tip_height, snapshot) = {
        let mut chain = blockchain.lock().unwrap();
        let local_tip_height = chain.last().map(|entry| entry.block_index).unwrap_or(0);

        if let Some(remote_tip) = blocks.last() {
            if remote_tip.block_index <= local_tip_height
                && chain
                    .block_at_height(remote_tip.block_index)
                    .map(|local| local.hash == remote_tip.hash)
                    .unwrap_or(false)
            {
                return 0;
            }
        }

        if let Some(plan) = recovery_plan.as_ref() {
            if let Err(error) = quarantine_local_suffix_for_recovery(plan, "service_block_batch") {
                warn!(
                    "p2p",
                    "Rejecting service block batch because local fork quarantine could not be persisted",
                    "error" => error
                );
                return 0;
            }
        }

        let rollback_height = blocks.iter().rev().find_map(|block| {
            if block.block_index > local_tip_height {
                return None;
            }
            chain
                .block_at_height(block.block_index)
                .filter(|local| local.hash == block.hash)
                .map(|_| block.block_index)
        });
        let rollback_height = rollback_height.filter(|height| *height < local_tip_height);

        let mut staged_chain = chain.clone();
        if let Some(common_height) = rollback_height {
            staged_chain.truncate_to_height(common_height);
        }

        let mut applied_blocks = Vec::new();
        let mut applied_qcs = Vec::new();
        for block in blocks {
            let Some(tip) = staged_chain.last() else {
                break;
            };
            if block.block_index <= tip.block_index {
                continue;
            }
            if block.block_index != tip.block_index + 1 || block.previous_hash != tip.hash {
                break;
            }
            if block.block_index > 0 {
                let Some(qc) = qc_by_hash.get(&block.hash) else {
                    break;
                };
                applied_qcs.push(qc.clone());
            }
            if staged_chain.add_block_extending_tip(block.clone()).is_err() {
                break;
            }
            applied_blocks.push(block);
        }

        if applied_blocks.is_empty() {
            return 0;
        }

        let durable_blocks = applied_blocks
            .iter()
            .filter(|block| block.block_index > 0)
            .cloned()
            .collect::<Vec<_>>();
        if let Err(error) = append_committed_block_bodies(&durable_blocks) {
            warn!(
                "p2p",
                "Rejecting service block batch because durable committed block bodies could not be written",
                "error" => error
            );
            return 0;
        }
        if let Err(error) = DualQuorumConsensus::record_committed_qcs_checked(&applied_qcs) {
            warn!(
                "p2p",
                "Rejecting service block batch because durable committed QCs could not be written",
                "error" => error
            );
            return 0;
        }
        let canonical_entries = durable_blocks
            .iter()
            .zip(applied_qcs.iter())
            .map(|(block, qc)| (block, qc))
            .collect::<Vec<_>>();
        if let Err(error) = write_legacy_canonical_locks(&canonical_entries) {
            warn!(
                "p2p",
                "Rejecting service block batch because canonical locks could not be written",
                "error" => error
            );
            return 0;
        }

        *chain = staged_chain;
        compact_hot_chain_state_from_env(&mut chain, "p2p_apply_block_batch_service");
        if let Some(tip) = chain.last() {
            cache_last_known_good_chain_tip(tip);
        }
        let tip_height = chain.last().map(|entry| entry.block_index).unwrap_or(0);
        let should_snapshot = rollback_height.is_some() || should_persist_chain_tip(tip_height);
        let snapshot = if should_snapshot {
            if rollback_height.is_some() {
                Some(chain.clone())
            } else {
                note_chain_persist(tip_height);
                if can_clone_chain_for_snapshot(tip_height) {
                    Some(chain.clone())
                } else {
                    None
                }
            }
        } else {
            None
        };

        (
            applied_blocks.len() as u64,
            applied_blocks,
            rollback_height,
            tip_height,
            snapshot,
        )
    };

    if let Some(common_height) = rollback_height {
        warn!(
            "p2p",
            "Rolled back divergent local tip to common ancestor",
            "common_height" => common_height,
            "new_tip_height" => tip_height
        );
        if let Some(snapshot) = snapshot.as_ref() {
            crate::dag::rebuild_global_from_chain(snapshot);
        }
    } else {
        crate::dag::commit_blocks(&applied_blocks);
    }

    if let Some(snapshot) = snapshot {
        let chain_path = crate::utils::resolve_data_path("data/chain.json");
        persist_chain_snapshot_async(snapshot, chain_path, tip_height);
    }

    prune_transaction_hashes_from_pool(&confirmed_hashes);
    if let Err(error) = apply_token_state_for_blocks(&applied_blocks) {
        if let Some(block) = applied_blocks.last() {
            quarantine_after_validator_activation_failure(block, &error);
        }
        return 0;
    }
    applied
}

fn apply_block_batch_legacy(
    blockchain: &BlockchainArc,
    mut blocks: Vec<Block>,
    quorum_certificates: Vec<QuorumCertificate>,
) -> u64 {
    if blocks.is_empty() {
        return 0;
    }

    blocks.sort_by_key(|block| block.block_index);
    blocks.dedup_by(|left, right| left.block_index == right.block_index && left.hash == right.hash);

    let qc_by_hash = quorum_certificates
        .into_iter()
        .map(|qc| (qc.block_hash.clone(), qc))
        .collect::<HashMap<_, _>>();

    let locally_matching_prefix = {
        let chain = blockchain.lock().unwrap();
        let local_tip_height = chain.last().map(|entry| entry.block_index).unwrap_or(0);
        blocks
            .iter()
            .filter(|block| {
                chain
                    .block_at_height(block.block_index)
                    .map(|local| local.hash == block.hash)
                    .unwrap_or_else(|| {
                        block.block_index <= local_tip_height
                            && block_matches_legacy_canonical_lock(block)
                    })
            })
            .map(|block| block.hash.clone())
            .collect::<HashSet<_>>()
    };

    let blocks_to_verify = blocks
        .iter()
        .filter(|block| !locally_matching_prefix.contains(&block.hash))
        .collect::<Vec<_>>();
    let verification_results = if blocks_to_verify.is_empty() {
        Vec::new()
    } else {
        let commit_verifier = commit_verifier_validator_manager();
        verify_batch_with_bounded_parallelism(
            &blocks_to_verify,
            thread::available_parallelism()
                .map(|parallelism| parallelism.get())
                .unwrap_or(1)
                .min(MAX_BLOCK_BATCH_VERIFY_WORKERS),
            |block| {
                let block = *block;
                verify_network_commit_certificate_with_manager(
                    block,
                    qc_by_hash.get(&block.hash),
                    &commit_verifier,
                )
                .map(|_| ())
            },
        )
    };

    for (block, verification_result) in blocks_to_verify.iter().zip(verification_results) {
        if let Err(error) = verification_result {
            warn!(
                "p2p",
                "Rejecting block batch without valid Aegis PQC quorum certificate",
                "height" => block.block_index,
                "hash" => block.hash.clone(),
                "error" => error
            );
            return 0;
        }
    }
    let verified_source_hashes = blocks_to_verify
        .iter()
        .map(|block| block.hash.clone())
        .collect::<HashSet<_>>();
    let recovery_plan = match source_majority_canonical_lock_recovery_plan(
        blockchain,
        &blocks,
        &verified_source_hashes,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            warn!(
                "p2p",
                "Rejecting block batch because canonical lock recovery could not be evaluated",
                "error" => error
            );
            return 0;
        }
    };
    if recovery_plan.is_none() {
        for block in &blocks_to_verify {
            if block.block_index > 0 {
                if let Err(error) = verify_legacy_canonical_lock(block) {
                    record_canonical_lock_conflict_from_peer(blockchain, block, &error);
                    warn!(
                        "p2p",
                        "Rejecting block batch that conflicts with canonical block lock",
                        "height" => block.block_index,
                        "hash" => block.hash.clone(),
                        "error" => error
                    );
                    return 0;
                }
            }
        }
    } else {
        warn!(
            "p2p",
            "Accepted source-majority batch for local fork recovery",
            "common_height" => recovery_plan.as_ref().unwrap().common_height,
            "conflict_height" => recovery_plan.as_ref().unwrap().conflict_height
        );
    }
    if let Err(error) = preflight_validator_activation_transactions(blocks.iter()) {
        warn!(
            "p2p",
            "Rejecting block batch because validator activation preflight failed",
            "error" => error
        );
        return 0;
    }

    let mut confirmed_hashes = HashSet::new();
    for block in &blocks {
        confirmed_hashes.extend(transaction_hashes(&block.transactions));
    }

    let (applied, applied_blocks, rollback_height, tip_height, snapshot) = {
        let mut chain = blockchain.lock().unwrap();
        let local_tip_height = chain.last().map(|entry| entry.block_index).unwrap_or(0);
        let mut rollback_height = None;
        let mut applied_blocks = Vec::new();

        // Late duplicate sync responses should never rewind a chain that has already
        // advanced beyond the batch tip. Only consider rollback when the incoming batch
        // actually diverges from the local chain at its highest advertised height.
        if let Some(remote_tip) = blocks.last() {
            if remote_tip.block_index <= local_tip_height
                && chain
                    .block_at_height(remote_tip.block_index)
                    .map(|local| local.hash == remote_tip.hash)
                    .unwrap_or(false)
            {
                return 0;
            }
        }

        if let Some(plan) = recovery_plan.as_ref() {
            if let Err(error) = quarantine_local_suffix_for_recovery(plan, "legacy_block_batch") {
                warn!(
                    "p2p",
                    "Rejecting block batch because local fork quarantine could not be persisted",
                    "error" => error
                );
                return 0;
            }
        }

        let highest_common_ancestor = blocks.iter().rev().find_map(|block| {
            if block.block_index > local_tip_height {
                return None;
            }
            chain
                .block_at_height(block.block_index)
                .filter(|local| local.hash == block.hash)
                .map(|_| block.block_index)
        });

        if let Some(common_height) = highest_common_ancestor {
            if common_height < local_tip_height {
                chain.truncate_to_height(common_height);
                rollback_height = Some(common_height);
            }
        }

        let mut applied = 0u64;
        for block in blocks.into_iter() {
            let Some(tip) = chain.last() else {
                break;
            };

            if block.block_index <= tip.block_index {
                continue;
            }

            if block.block_index != tip.block_index + 1 || block.previous_hash != tip.hash {
                break;
            }

            if block.block_index > 0 {
                if qc_by_hash.contains_key(&block.hash) {
                    if let Err(error) = append_committed_block_body(&block) {
                        warn!(
                            "p2p",
                            "Rejecting block batch because durable committed block body could not be written",
                            "height" => block.block_index,
                            "hash" => block.hash.clone(),
                            "error" => error
                        );
                        break;
                    }
                }
            }

            if chain.add_block_extending_tip(block.clone()).is_err() {
                warn!(
                    "p2p",
                    "Rejecting block batch entry because it could not be materialized on the local chain tip after durable body write",
                    "height" => block.block_index,
                    "hash" => block.hash.clone()
                );
                break;
            }
            if block.block_index > 0 {
                if let Some(qc) = qc_by_hash.get(&block.hash) {
                    if let Err(error) = DualQuorumConsensus::record_committed_qc_checked(qc.clone())
                    {
                        warn!(
                            "p2p",
                            "Rejecting block batch because durable committed QC could not be written",
                            "height" => block.block_index,
                            "hash" => block.hash.clone(),
                            "error" => error
                        );
                        break;
                    }
                    if let Err(error) = write_legacy_canonical_lock(&block, qc) {
                        record_canonical_lock_conflict_from_peer(blockchain, &block, &error);
                        warn!(
                            "p2p",
                            "Rejecting block batch because canonical lock could not be written",
                            "height" => block.block_index,
                            "hash" => block.hash.clone(),
                            "error" => error
                        );
                        break;
                    }
                }
            }
            applied_blocks.push(block.clone());
            applied += 1;
        }

        compact_hot_chain_state_from_env(&mut chain, "p2p_apply_block_batch");
        if let Some(tip) = chain.last() {
            cache_last_known_good_chain_tip(tip);
        }
        let tip_height = chain.last().map(|entry| entry.block_index).unwrap_or(0);
        let should_snapshot = rollback_height.is_some() || should_persist_chain_tip(tip_height);
        let snapshot = if should_snapshot {
            if rollback_height.is_some() {
                Some(chain.clone())
            } else {
                note_chain_persist(tip_height);
                if can_clone_chain_for_snapshot(tip_height) {
                    Some(chain.clone())
                } else {
                    None
                }
            }
        } else {
            None
        };

        (
            applied,
            applied_blocks,
            rollback_height,
            tip_height,
            snapshot,
        )
    };

    if let Some(common_height) = rollback_height {
        warn!(
            "p2p",
            "Rolled back divergent local tip to common ancestor",
            "common_height" => common_height,
            "new_tip_height" => tip_height
        );
    }

    if rollback_height.is_some() {
        if let Some(snapshot) = snapshot.as_ref() {
            crate::dag::rebuild_global_from_chain(snapshot);
        }
    } else {
        crate::dag::commit_blocks(&applied_blocks);
    }

    if let Some(snapshot) = snapshot {
        let chain_path = crate::utils::resolve_data_path("data/chain.json");
        persist_chain_snapshot_async(snapshot, chain_path, tip_height);
    }

    prune_transaction_hashes_from_pool(&confirmed_hashes);
    if let Err(error) = apply_token_state_for_blocks(&applied_blocks) {
        if let Some(block) = applied_blocks.last() {
            quarantine_after_validator_activation_failure(block, &error);
        }
        return 0;
    }

    applied
}

fn block_matches_legacy_canonical_lock(block: &Block) -> bool {
    legacy_canonical_commit_record(block.block_index)
        .ok()
        .flatten()
        .map(|record| record.block_hash == block.hash)
        .unwrap_or(false)
}

fn quarantine_after_validator_activation_failure(block: &Block, error: &str) {
    let reason = format!(
        "validator activation state application failed at finalized height {}: {error}",
        block.block_index
    );
    if let Err(quarantine_error) = record_self_quarantine_for_canonical_lock_conflict(
        block.block_index,
        None,
        &block.hash,
        &reason,
    ) {
        warn!(
            "p2p",
            "Validator activation failure could not persist self-quarantine; refusing consensus participation in-process",
            "height" => block.block_index,
            "block_hash" => block.hash.clone(),
            "error" => error.to_string(),
            "quarantine_error" => quarantine_error
        );
    } else {
        warn!(
            "p2p",
            "Validator activation failure self-quarantined node",
            "height" => block.block_index,
            "block_hash" => block.hash.clone(),
            "error" => error.to_string()
        );
    }
}

fn apply_token_state_for_blocks(blocks: &[Block]) -> Result<(), String> {
    if blocks.is_empty() {
        return Ok(());
    }

    let token_manager = crate::token::TOKEN_MANAGER.clone();
    let validator_manager = VALIDATOR_MANAGER.clone();
    let mut applied_txs = 0u64;
    let mut failed_txs = 0u64;
    let mut applied_validator_activations = 0u64;

    for block in blocks {
        for tx in &block.transactions {
            match token_manager.process_transaction_in_finalized_block_with_fee_market(
                tx,
                block.block_index,
                &block.hash,
                block.applied_fee_market_base_fee(),
            ) {
                Ok(_) => applied_txs += 1,
                Err(error) => {
                    failed_txs += 1;
                    warn!(
                        "p2p",
                        "Failed to apply synced block transaction state",
                        "block_height" => block.block_index,
                        "tx_hash" => tx.hash(),
                        "error" => error
                    );
                }
            }
            if is_validator_activation_transaction(tx) {
                match apply_validator_activation_transaction(
                    tx,
                    &token_manager,
                    &validator_manager,
                    block.block_index,
                ) {
                    Ok(message) => {
                        applied_validator_activations += 1;
                        info!(
                            "p2p",
                            "Applied synced validator activation",
                            "block_height" => block.block_index,
                            "tx_hash" => tx.hash(),
                            "message" => message
                        );
                    }
                    Err(error) => {
                        let failure = format!(
                            "activation transaction {} could not be applied: {error}",
                            tx.hash()
                        );
                        warn!(
                            "p2p",
                            "Failed to apply synced validator activation; refusing consensus participation",
                            "block_height" => block.block_index,
                            "tx_hash" => tx.hash(),
                            "error" => failure.clone()
                        );
                        return Err(failure);
                    }
                }
            }
        }
        let activated_validators =
            validator_manager.apply_pending_shadow_activations(block.block_index);
        if !activated_validators.is_empty() {
            applied_validator_activations += activated_validators.len() as u64;
            info!(
                "p2p",
                "Activated shadow validators after synced finalized boundary",
                "block_height" => block.block_index,
                "activated_validators" => activated_validators.join(",")
            );
        }
        if let Err(error) = crate::sts::note_finalized_sts_block(block.block_index, &block.hash) {
            warn!(
                "p2p",
                "Failed to persist synced finalized STS state",
                "block_height" => block.block_index,
                "error" => error.to_string()
            );
        }
    }

    if applied_txs > 0 || failed_txs > 0 {
        info!(
            "p2p",
            "Processed token state for synced blocks",
            "blocks" => blocks.len(),
            "applied_transactions" => applied_txs,
            "failed_transactions" => failed_txs
        );
    }

    if applied_txs > 0 {
        if let Err(error) = token_manager.save_state(crate::token::token_state_path()) {
            warn!(
                "p2p",
                "Failed to persist synced token state",
                "error" => error.to_string()
            );
        }
    }
    if applied_validator_activations > 0 {
        validator_manager
            .save_registry("data/validator_registry.json")
            .map_err(|error| {
                format!("validator registry persistence failed after activation: {error}")
            })?;
    }

    Ok(())
}

fn should_persist_chain_tip(tip_height: u64) -> bool {
    if tip_height <= 32 {
        return true;
    }

    let gap_blocks = chain_persist_gap_blocks();
    let elapsed_secs = chain_persist_elapsed_secs();
    let state = LAST_CHAIN_PERSIST.lock().unwrap();
    match *state {
        Some((last_height, last_at)) => {
            // Chain bodies are appended to the committed block log before locks/QCs.
            // Full chain snapshots are restart accelerators, not the hot durability path.
            let gap = tip_height.saturating_sub(last_height);
            let elapsed = last_at.elapsed();
            gap >= gap_blocks || elapsed >= Duration::from_secs(elapsed_secs)
        }
        None => tip_height % gap_blocks == 0,
    }
}

fn chain_persist_gap_blocks() -> u64 {
    std::env::var("SYNERGY_CHAIN_PERSIST_GAP_BLOCKS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(250)
}

fn chain_persist_elapsed_secs() -> u64 {
    std::env::var("SYNERGY_CHAIN_PERSIST_MIN_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(600)
}

fn chain_snapshot_max_clone_height() -> u64 {
    std::env::var("SYNERGY_CHAIN_SNAPSHOT_MAX_CLONE_HEIGHT")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_CHAIN_SNAPSHOT_CLONE_HEIGHT)
}

fn chain_snapshot_clone_allowed(tip_height: u64, max_clone_height: u64) -> bool {
    tip_height <= max_clone_height
}

fn can_clone_chain_for_snapshot(tip_height: u64) -> bool {
    let max_clone_height = chain_snapshot_max_clone_height();
    if chain_snapshot_clone_allowed(tip_height, max_clone_height) {
        return true;
    }

    warn!(
        "p2p",
        "Skipping full-chain snapshot persistence because chain height exceeds clone safety limit",
        "height" => tip_height,
        "max_clone_height" => max_clone_height,
        "override_env" => "SYNERGY_CHAIN_SNAPSHOT_MAX_CLONE_HEIGHT"
    );
    false
}

fn note_chain_persist(tip_height: u64) {
    let mut state = LAST_CHAIN_PERSIST.lock().unwrap();
    *state = Some((tip_height, Instant::now()));
}

fn persist_chain_snapshot_async(
    snapshot: BlockChain,
    chain_path: std::path::PathBuf,
    tip_height: u64,
) {
    if CHAIN_PERSIST_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        debug!(
            "p2p",
            "Skipping chain persistence because a previous save is still running",
            "height" => tip_height
        );
        return;
    }

    thread::spawn(move || {
        snapshot.save_to_file(chain_path.to_str().unwrap_or("data/chain.json"));
        CHAIN_PERSIST_IN_FLIGHT.store(false, Ordering::SeqCst);
    });
}

/// Best-effort dial for a discovered peer.
fn dial_peer_async(
    peer_address: String,
    blockchain: BlockchainArc,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    dial_registry: DialRegistryArc,
    message_sender: mpsc::Sender<PeerMessage>,
    config: NodeConfig,
    source_session: Option<(String, u64)>,
) -> Result<(), ()> {
    let peer_address = normalize_peer_target(&config, &peer_address)
        .unwrap_or_else(|| peer_address.trim().to_string());
    if let Some((source_peer, source_session_id)) = source_session.as_ref() {
        if !peer_session_is_current(source_peer, *source_session_id) {
            return Ok(());
        }
    }
    let Some(transport_address) = resolve_peer_transport_address(&config, &peer_address) else {
        debug!(
            "p2p",
            "Skipping discovered peer without transport route",
            "peer" => peer_address
        );
        return Ok(());
    };
    if !reserve_outbound_dial(
        &dial_registry,
        &connected_peers,
        &peer_address,
        config.network.max_peers as usize,
    ) {
        return Ok(());
    }

    let cleanup_address = peer_address.clone();
    let cleanup_address_for_thread = cleanup_address.clone();
    let dial_registry_for_thread = Arc::clone(&dial_registry);
    let spawned = spawn_named_thread("p2p-discovery-dial", move || {
        if let Some((source_peer, source_session_id)) = source_session.as_ref() {
            if !peer_session_is_current(source_peer, *source_session_id) {
                release_outbound_dial(&dial_registry_for_thread, &cleanup_address_for_thread);
                return;
            }
        }
        match dial_with_timeout(&transport_address, std::time::Duration::from_secs(5)) {
            Ok(stream) => {
                if let Err(e) = handle_outgoing_connection(
                    stream,
                    peer_address,
                    blockchain,
                    connected_peers,
                    peer_state_cache,
                    message_sender,
                    config,
                ) {
                    warn!("p2p", "Discovered peer dial failed", "error" => e.to_string());
                }
            }
            Err(e) => {
                debug!(
                    "p2p",
                    "Discovered peer dial error",
                    "peer" => peer_address,
                    "transport" => transport_address,
                    "error" => e.to_string()
                );
            }
        }
        release_outbound_dial(&dial_registry_for_thread, &cleanup_address_for_thread);
    });
    if !spawned {
        release_outbound_dial(&dial_registry, &cleanup_address);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        apply_block_batch, apply_block_batch_for_role, apply_block_if_new, apply_status_to_peer,
        authorize_chain_requester_for_session, background_poll_interval, begin_peer_session,
        best_connected_validator_height, block_sync_min_serve_interval_secs,
        block_sync_request_range, block_sync_request_range_with_overlap,
        block_sync_response_policy, build_local_handshake,
        build_local_handshake_with_extra_capabilities, build_local_status_message,
        bypasses_shared_message_queue, cache_peer_state, cache_pending_block,
        canonical_chain_incarnation, canonical_genesis_hash, canonical_validator_address_for_slot,
        canonical_validator_public_address, chain_has_block_sync_overlap,
        chain_snapshot_clone_allowed, claim_status_rate_limit, collect_known_peer_addresses,
        configured_public_address_for_validator_in_set, configured_seed_server_dial_targets,
        configured_validator_p2p_dials, configured_validator_public_address_map,
        connected_endpoint_host_matches_configured_address,
        connected_endpoint_matches_configured_address, connected_peer_key_for_address,
        connected_validator_participants, current_bootstrap_refresh_interval, current_timestamp,
        dial_with_timeout, disconnect_peer_after_poisoned_write, disconnect_peer_entry,
        dispatch_peer_message, ensure_peer_status_allows_chain_data,
        etdag_ingress_peer_for_session, handle_get_blocks_message, handle_status_message,
        handshake_version_mismatch_reason, hydrate_peer_from_cache, insert_seed_server_target,
        is_validator_vpn_dial_address, is_validator_vpn_relayer_dial_address,
        local_consensus_handshake_required, local_consensus_version,
        local_is_typed_finality_relayer, local_is_typed_finality_service_observer,
        local_node_runs_validator_consensus, local_node_uses_service_batch_durability,
        local_peer_identity, merge_peer_state_from_existing, normalize_peer_target,
        parse_block_sync_busy_retry, parse_bootnode_dial_address, peer_has_identifying_metadata,
        peer_identity_key, peer_is_authorized_block_sync_requester,
        peer_is_designated_support_sync_source, peer_is_eligible_block_sync_source,
        peer_is_eligible_block_sync_source_for_local, peer_is_validator_vpn_relayer,
        peer_matches_address, peer_readiness_exclusion_reason_at, peer_write_gate,
        pending_incoming_connections_from_host, preferred_connection_direction,
        preflight_validator_activation_transactions, receive_message,
        recover_peer_validator_address_for_vote_target, register_typed_consensus_peer_session,
        register_validator_consensus_handshake_key, release_block_sync_apply_slot_after_worker,
        release_block_sync_peer, reserve_block_sync_peer, reset_service_sync_coordinator_for_tests,
        resolve_bootstrap_dial_targets, resolve_duplicate_connection,
        resolve_peer_transport_address, select_block_sync_response_blocks,
        service_sync_claim_response, service_sync_identity, service_sync_release_and_reassign,
        service_sync_request_from_status, should_canonicalize_validator_public_address,
        should_disconnect_for_status_genesis_mismatch, should_prune_stale_peer,
        should_request_missing_blocks, should_resolve_duplicate_session,
        status_peer_is_eligible_block_sync_source, status_ready_validator_addresses,
        status_ready_validator_addresses_with_local_duty_gate, status_ready_validator_participants,
        status_sync_batch, support_peer_sync_request_is_too_deep, sync_batch_limit_for_role,
        typed_consensus_peer_for_session, validate_outbound_frame_length,
        validate_simplified_consensus_target_identity, validate_simplified_predecode_frame_length,
        validate_vote_request_extends_local_tip, validator_consensus_capability,
        validator_status_genesis_grace_remaining_secs,
        validator_status_genesis_within_grace_window, verify_batch_with_bounded_parallelism,
        verify_handshake_pq_signature, vote_request_parent_sync_range,
        with_peer_stream_outside_peers_lock, ConnectionDirection, DialTargetsArc,
        DuplicateResolution, P2PNetwork, PeerConnection, PeerEntryGuard,
        TypedFinalityObserverMessage, BACKGROUND_SYNC_POLL_MILLIS, BLOCK_SYNC_APPLY_ACTIVE,
        BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS, COORDINATED_ROUND_ROBIN_V1,
        DEFAULT_BOOTSTRAP_REFRESH_SECS, DUTY_DISABLED_TTL_SECS, IMMEDIATE_STATUS_SYNC_BATCH,
        MAX_P2P_FRAME_BYTES, MAX_STATUS_SYNC_BATCH, MAX_SUPPORT_NODE_BLOCK_SYNC_RESPONSE_BLOCKS,
        MAX_VALIDATOR_SUPPORT_SYNC_RESPONSE_BLOCKS, NORMAL_BOOTSTRAP_REFRESH_SECS,
        PEER_SESSION_IDS, PEER_WRITE_GATES, PENDING_BLOCKS, POSY_SIMPLIFIED_PROTOCOL_VERSION,
        QUARANTINE_STATUS_TTL_SECS, SERVICE_BLOCK_SYNC_RESPONSE_TIMEOUT_SECS,
        SERVICE_SYNC_COORDINATOR, SIMPLIFIED_POSY_VALIDATOR_CAPABILITY,
        STALE_UNIDENTIFIED_PEER_SECS, STALE_VALIDATOR_STATUS_SECS, STATUS_READY_TTL_SECS,
        STATUS_REQUEST_MIN_INTERVAL_SECS, STATUS_RESPONSE_MIN_INTERVAL_SECS,
        SUPPORT_NODE_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS, TEST_COMMIT_VERIFIER_VALIDATOR_MANAGER,
        TYPED_CONSENSUS_PEER_SESSIONS, VALIDATOR_SUPPORT_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS,
    };
    use crate::block::{Block, BlockChain};
    use crate::config::{NodeConfig, ValidatorVpnTransportConfig};
    use crate::consensus::dual_quorum::{DualQuorumConsensus, QuorumCertificate, Vote};
    use crate::consensus::simplified_posy::AuthenticatedSimplifiedConsensusPeer;
    use crate::consensus::typed_coordinator::AuthenticatedTypedConsensusPeer;
    use crate::consensus::validator_keys::{
        consensus_algorithm_label, load_local_validator_keypair,
        register_test_validator_signing_key,
    };
    use crate::consensus::{
        anti_divergence::{
            current_self_quarantine_record, record_self_quarantine_for_canonical_lock_conflict,
        },
        legacy_canonical_lock::{
            clear_legacy_canonical_locks_for_tests, write_legacy_canonical_lock,
        },
    };
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCSignature};
    use crate::p2p::messages::NetworkMessage;
    use crate::p2p::messages::{
        MAX_SIMPLIFIED_CONSENSUS_CERTIFICATE_FRAME_BYTES,
        MAX_SIMPLIFIED_CONSENSUS_CONTROL_FRAME_BYTES,
        MAX_SIMPLIFIED_CONSENSUS_PROPOSAL_FRAME_BYTES,
        MAX_SIMPLIFIED_CONSENSUS_STATE_SYNC_FRAME_BYTES, MAX_SIMPLIFIED_CONSENSUS_VOTE_FRAME_BYTES,
        MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CANDIDATE_FRAME_BYTES,
        MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CONTROL_FRAME_BYTES,
        MAX_SIMPLIFIED_TARGET_ADMISSION_PACKAGE_FRAME_BYTES,
        MAX_SIMPLIFIED_TARGET_ADMISSION_VOTE_FRAME_BYTES,
    };
    use crate::synergy_types::{AegisPqKeyId, AegisPqKeyRole, Epoch, UmaId, ValidatorId};
    use crate::transaction::Transaction;
    use crate::validator::{
        Validator, ValidatorManager, ValidatorRegistration, ValidatorStatus, VALIDATOR_MANAGER,
    };
    use base64::{engine::general_purpose, Engine as _};
    use lazy_static::lazy_static;
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::io;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{mpsc, Arc, Barrier, Mutex, MutexGuard};

    #[test]
    fn simplified_vote_frame_is_bounded_before_full_payload_allocation() {
        let prefix = br#"{"SimplifiedConsensus":{"message":{"Vote":{"vote":{}}}}}"#;
        validate_simplified_predecode_frame_length(
            MAX_SIMPLIFIED_CONSENSUS_VOTE_FRAME_BYTES - 4,
            prefix,
        )
        .unwrap();
        assert!(validate_simplified_predecode_frame_length(
            MAX_SIMPLIFIED_CONSENSUS_VOTE_FRAME_BYTES - 3,
            prefix,
        )
        .is_err());
    }

    #[test]
    fn simplified_material_chunk_is_bounded_before_full_payload_allocation() {
        let prefix = br#"{"SimplifiedConsensus":{"message":{"MaterialChunk":{"chunk":{}}}}}"#;
        validate_simplified_predecode_frame_length(
            MAX_SIMPLIFIED_CONSENSUS_STATE_SYNC_FRAME_BYTES - 4,
            prefix,
        )
        .unwrap();
        assert!(validate_simplified_predecode_frame_length(
            MAX_SIMPLIFIED_CONSENSUS_STATE_SYNC_FRAME_BYTES - 3,
            prefix,
        )
        .is_err());
    }

    #[test]
    fn target_admission_variants_are_bounded_before_full_payload_allocation() {
        let vote = br#"{"SimplifiedTargetAdmission":{"message":{"Vote":{"request":{}}}}}"#;
        validate_simplified_predecode_frame_length(
            MAX_SIMPLIFIED_TARGET_ADMISSION_VOTE_FRAME_BYTES - 4,
            vote,
        )
        .unwrap();
        assert!(validate_simplified_predecode_frame_length(
            MAX_SIMPLIFIED_TARGET_ADMISSION_VOTE_FRAME_BYTES - 3,
            vote,
        )
        .is_err());

        let package =
            br#"{"SimplifiedTargetAdmission":{"message":{"CertifiedPackage":{"package":{}}}}}"#;
        validate_simplified_predecode_frame_length(
            MAX_SIMPLIFIED_TARGET_ADMISSION_PACKAGE_FRAME_BYTES - 4,
            package,
        )
        .unwrap();
        assert!(validate_simplified_predecode_frame_length(
            MAX_SIMPLIFIED_TARGET_ADMISSION_PACKAGE_FRAME_BYTES - 3,
            package,
        )
        .is_err());
    }

    #[test]
    fn empty_etdag_assembly_variants_are_bounded_before_full_payload_allocation() {
        let cases: &[(&[u8], usize)] = &[
            (
                br#"{"SimplifiedEtdagAssembly":{"message":{"Marker":{}}}}"#,
                MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CONTROL_FRAME_BYTES,
            ),
            (
                br#"{"SimplifiedEtdagAssembly":{"message":{"VacVote":{}}}}"#,
                MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CONTROL_FRAME_BYTES,
            ),
            (
                br#"{"SimplifiedEtdagAssembly":{"message":{"DccVote":{}}}}"#,
                MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CONTROL_FRAME_BYTES,
            ),
            (
                br#"{"SimplifiedEtdagAssembly":{"message":{"BvcVote":{}}}}"#,
                MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CONTROL_FRAME_BYTES,
            ),
            (
                br#"{"SimplifiedEtdagAssembly":{"message":{"BocVote":{}}}}"#,
                MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CONTROL_FRAME_BYTES,
            ),
            (
                br#"{"SimplifiedEtdagAssembly":{"message":{"DccCandidate":{}}}}"#,
                MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CANDIDATE_FRAME_BYTES,
            ),
            (
                br#"{"SimplifiedEtdagAssembly":{"message":{"BvcCandidate":{}}}}"#,
                MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CANDIDATE_FRAME_BYTES,
            ),
            (
                br#"{"SimplifiedEtdagAssembly":{"message":{"BocCandidate":{}}}}"#,
                MAX_SIMPLIFIED_ETDAG_ASSEMBLY_CANDIDATE_FRAME_BYTES,
            ),
        ];

        for &(prefix, maximum) in cases {
            validate_simplified_predecode_frame_length(maximum - 4, prefix)
                .expect("empty-ETDAG assembly frame at the exact cap must pass");
            assert!(validate_simplified_predecode_frame_length(maximum - 3, prefix).is_err());
        }
    }

    #[test]
    fn empty_etdag_assembly_rejects_unknown_inner_variant_before_allocation() {
        let prefix = br#"{"SimplifiedEtdagAssembly":{"message":{"Unbounded":{}}}}"#;

        let error = validate_simplified_predecode_frame_length(1024, prefix)
            .expect_err("unknown empty-ETDAG assembly variants must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn empty_etdag_assembly_requires_canonical_message_first_encoding() {
        let prefix =
            br#"{"SimplifiedEtdagAssembly":{"chain_incarnation":5,"message":{"Marker":{}}}}"#;

        let error = validate_simplified_predecode_frame_length(1024, prefix)
            .expect_err("assembly envelope must expose its bounded kind before other fields");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn simplified_predecode_applies_every_exact_kind_budget() {
        let cases: &[(&[u8], usize)] = &[
            (
                br#"{"SimplifiedConsensus":{"message":{"Proposal":{}}}}"#,
                MAX_SIMPLIFIED_CONSENSUS_PROPOSAL_FRAME_BYTES,
            ),
            (
                br#"{"SimplifiedConsensus":{"message":{"ReliableDelivery":{}}}}"#,
                MAX_SIMPLIFIED_CONSENSUS_VOTE_FRAME_BYTES,
            ),
            (
                br#"{"SimplifiedConsensus":{"message":{"QuorumCertificate":{}}}}"#,
                MAX_SIMPLIFIED_CONSENSUS_CERTIFICATE_FRAME_BYTES,
            ),
            (
                br#"{"SimplifiedConsensus":{"message":{"MaterialRequest":{}}}}"#,
                MAX_SIMPLIFIED_CONSENSUS_CONTROL_FRAME_BYTES,
            ),
            (
                br#"{"SimplifiedConsensus":{"message":{"StateSyncChunk":{}}}}"#,
                MAX_SIMPLIFIED_CONSENSUS_STATE_SYNC_FRAME_BYTES,
            ),
        ];

        for &(prefix, maximum) in cases {
            validate_simplified_predecode_frame_length(maximum - 4, prefix)
                .expect("exact simplified wire budget must be accepted");
            assert!(validate_simplified_predecode_frame_length(maximum - 3, prefix).is_err());
        }
    }

    #[test]
    fn simplified_predecode_accepts_only_complete_unit_control_frames() {
        for frame in [
            br#""GetPeers""#.as_slice(),
            br#""Ping""#,
            br#""Pong""#,
            br#""GetStatus""#,
        ] {
            validate_simplified_predecode_frame_length(frame.len(), frame)
                .expect("known unit NetworkMessage control frame must pass");
        }

        assert!(validate_simplified_predecode_frame_length(9, br#""Unknown""#).is_err());
        assert!(validate_simplified_predecode_frame_length(13, br#""GetStatus" x"#).is_err());
    }

    #[test]
    fn simplified_predecode_rejects_padding_that_hides_the_outer_kind() {
        let prefix = vec![b' '; 4 * 1024];

        let error = validate_simplified_predecode_frame_length(
            MAX_SIMPLIFIED_CONSENSUS_VOTE_FRAME_BYTES,
            &prefix,
        )
        .expect_err("padded envelope must not bypass bounded kind discovery");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn simplified_predecode_uses_exact_kind_instead_of_payload_substrings() {
        let prefix = br#"{"SimplifiedConsensus":{"message":{"MaterialChunk":{"note":"Vote"}}}}"#;

        validate_simplified_predecode_frame_length(
            MAX_SIMPLIFIED_CONSENSUS_VOTE_FRAME_BYTES - 3,
            prefix,
        )
        .expect("payload text must not change the exact material-chunk bound");
    }

    #[test]
    fn simplified_predecode_does_not_decode_unrelated_partial_utf8_payload() {
        let mut prefix =
            br#"{"SimplifiedConsensus":{"message":{"MaterialChunk":{"chunk":{"payload":"#.to_vec();
        prefix.resize((4 * 1024) - 1, b'a');
        prefix.push(0xc3);

        validate_simplified_predecode_frame_length(
            MAX_SIMPLIFIED_CONSENSUS_STATE_SYNC_FRAME_BYTES - 4,
            &prefix,
        )
        .expect("bounded tag parsing must not reject a prefix ending inside UTF-8 payload");
    }

    #[test]
    fn simplified_target_routing_rejects_an_address_rebound_to_another_validator() {
        let expected_validator_id = ValidatorId("expected-validator".to_string());
        let rebound_validator_id = ValidatorId("rebound-validator".to_string());
        let identity = AuthenticatedSimplifiedConsensusPeer {
            validator_id: rebound_validator_id.clone(),
            validator_uma_id: UmaId("uma:rebound-validator".to_string()),
            consensus_key_id: AegisPqKeyId("rebound-validator-key".to_string()),
        };
        let frozen = [expected_validator_id.clone(), rebound_validator_id]
            .into_iter()
            .collect();

        let error = validate_simplified_consensus_target_identity(
            &identity,
            &expected_validator_id,
            &frozen,
        )
        .expect_err("rebound address must not receive another validator's targeted response");

        assert!(error.contains("rebound to another validator"));
    }
    use std::thread;
    use std::time::{Duration, Instant};

    // Session and write-gate registries are process-global; serialize tests that exercise them.
    /// One lock for all p2p shared-state tests.
    ///
    /// Peer sessions, write gates and the service-sync coordinator are a single
    /// entangled global: ending a peer session releases that peer's service-sync
    /// reservation. Guarding them with two independent mutexes let a
    /// peer-session-only test run alongside a service-sync test and knock out
    /// its reservation, which is why
    /// `completed_service_apply_does_not_release_next_batch_slot` failed
    /// intermittently on its very first request while passing 5/5 alone.
    static PEER_SESSION_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn peer_session_test_guard() -> MutexGuard<'static, ()> {
        PEER_SESSION_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Takes the shared p2p lock and resets the coordinator state, so callers
    /// must NOT also call [`peer_session_test_guard`] — that would deadlock.
    fn service_sync_test_guard() -> MutexGuard<'static, ()> {
        let guard = peer_session_test_guard();
        reset_service_sync_coordinator_for_tests();
        BLOCK_SYNC_APPLY_ACTIVE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        PEER_SESSION_IDS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        PEER_WRITE_GATES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        guard
    }

    fn service_sync_test_connection() -> Option<(std::net::TcpStream, std::net::TcpStream)> {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return None,
            Err(error) => panic!("failed to bind service sync test listener: {error}"),
        };
        let address = listener
            .local_addr()
            .expect("service sync listener should have an address");
        let client = match std::net::TcpStream::connect(address) {
            Ok(stream) => stream,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return None,
            Err(error) => panic!("failed to connect service sync test stream: {error}"),
        };
        let (server, _) = listener
            .accept()
            .expect("service sync test stream should be accepted");
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("service sync test stream should set a read timeout");
        Some((client, server))
    }

    fn service_sync_test_config() -> NodeConfig {
        let mut config = NodeConfig::default();
        config.identity.role = "relayer".to_string();
        config.network.additional_dial_targets = vec!["127.0.0.1:5622".to_string()];
        config
    }

    fn service_sync_test_peer(
        client: std::net::TcpStream,
        address: &str,
        validator_address: &str,
        height: u64,
    ) -> PeerConnection {
        let mut peer = test_peer_with_validator_address(Some(validator_address));
        peer.address = if address.ends_with('b') {
            "relay2.synergynode.xyz:5622".to_string()
        } else {
            "relay1.synergynode.xyz:5622".to_string()
        };
        peer.stream = Some(client);
        peer.connected_endpoint = Some("127.0.0.1:5622".to_string());
        peer.node_id = Some(address.to_string());
        peer.handshake_role = Some("relayer".to_string());
        peer.public_address = Some(peer.address.clone());
        peer.last_known_height = height;
        peer.status_received_at = Some(current_timestamp());
        peer.genesis_hash = canonical_genesis_hash();
        peer
    }

    /// Deterministic Testnet-v3 unit-test genesis (chain 1266, 6 validators).
    /// This fixture is marked `TEST_FIXTURE_NOT_FOR_PRODUCTION` and is rejected
    /// by the production loader, so unit tests never depend on the unsigned
    /// production candidate or on the BLOCKED placeholder.
    fn configure_canonical_genesis_path_for_tests() {
        std::env::set_var(
            "SYNERGY_GENESIS_FILE",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../config/genesis.testnet-v3.test-fixture.json"
            ),
        );
    }

    #[test]
    fn p2p_snapshot_clone_guard_blocks_large_live_chains() {
        assert!(chain_snapshot_clone_allowed(50_000, 50_000));
        assert!(!chain_snapshot_clone_allowed(50_001, 50_000));
    }

    fn test_peer_with_validator_address(validator_address: Option<&str>) -> PeerConnection {
        PeerConnection {
            address: "peer-a".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: Some("peer-a.synergy-network.io:5622".to_string()),
            validator_address: validator_address.map(str::to_string),
            connected_at: 0,
            last_seen: 0,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            connected_endpoint: None,
            node_id: Some("peer-a".to_string()),
            handshake_role: None,
            version: Some("1.0.0".to_string()),
            capabilities: vec!["blocks".to_string()],
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: canonical_genesis_hash(),
            status_received_at: Some(current_timestamp()),
            status_reported_at: None,
            status_validator_address: None,
            status_source_session_id: None,
            active_validator_set_hash: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        }
    }

    #[test]
    fn typed_finality_observer_sources_are_scoped_to_the_intended_transport_tiers() {
        let mut vpn_relayer = test_peer_with_validator_address(None);
        vpn_relayer.handshake_role = Some("relayer".to_string());
        vpn_relayer.connected_endpoint = Some("10.70.20.1:5622".to_string());
        assert!(peer_is_validator_vpn_relayer(&vpn_relayer));

        let mut inbound_vpn_relayer = test_peer_with_validator_address(None);
        inbound_vpn_relayer.handshake_role = Some("relayer".to_string());
        inbound_vpn_relayer.direction = ConnectionDirection::Incoming;
        inbound_vpn_relayer.connected_endpoint = Some("10.70.20.1:49152".to_string());
        assert!(
            peer_is_validator_vpn_relayer(&inbound_vpn_relayer),
            "a signed relayer arriving from its canonical VPN host may use an ephemeral TCP source port"
        );

        let mut public_relayer = vpn_relayer;
        public_relayer.connected_endpoint = Some("73.79.66.255:5622".to_string());
        assert!(
            !peer_is_validator_vpn_relayer(&public_relayer),
            "a public endpoint must not pull a validator's typed finality journal"
        );

        let mut config = NodeConfig::default();
        config.identity.role = "relayer".to_string();
        assert!(local_is_typed_finality_relayer(&config));
        assert!(!local_is_typed_finality_service_observer(&config));

        let mut canonical_indexer = test_peer_with_validator_address(None);
        canonical_indexer.handshake_role = Some("indexer_explorer".to_string());
        canonical_indexer.connected_endpoint = Some("74.208.227.23:5622".to_string());
        canonical_indexer.public_address = Some("74.208.227.23:5622".to_string());
        assert!(
            peer_is_designated_support_sync_source(&config, &canonical_indexer),
            "the canonical Atlas indexer must be allowed to pull only verified relayer finality"
        );

        canonical_indexer.connected_endpoint = Some("74.208.227.23:49152".to_string());
        assert!(
            peer_is_designated_support_sync_source(&config, &canonical_indexer),
            "a signed canonical support endpoint may use an ephemeral TCP source port on an inbound connection"
        );

        canonical_indexer.public_address = Some("74.208.227.23:5623".to_string());
        assert!(
            !peer_is_designated_support_sync_source(&config, &canonical_indexer),
            "a source-host match without the signed canonical listener must fail closed"
        );

        config.identity.role = "rpc_gateway".to_string();
        assert!(!local_is_typed_finality_relayer(&config));
        assert!(local_is_typed_finality_service_observer(&config));
    }

    #[test]
    fn typed_finality_observer_messages_bypass_background_queue() {
        assert!(bypasses_shared_message_queue(
            &NetworkMessage::TypedFinalityObserver {
                chain_incarnation: canonical_chain_incarnation(),
                genesis_hash: canonical_genesis_hash(),
                message: TypedFinalityObserverMessage::Request {
                    next_height: crate::synergy_types::Height(1),
                },
            }
        ));
    }

    #[test]
    fn peer_address_matching_uses_validator_identity_for_vpn_connections() {
        let validator_address = "synv11validatorxxxxxxxxxxxxxxxxxxxx";
        let mut peer = test_peer_with_validator_address(Some(validator_address));
        peer.address = "10.69.10.5:58352".to_string();
        peer.public_address = None;

        assert!(peer_matches_address(&peer, validator_address));

        let mut peers = HashMap::new();
        peers.insert(peer.address.clone(), peer);

        assert_eq!(
            connected_peer_key_for_address(&peers, validator_address),
            Some("10.69.10.5:58352".to_string())
        );
    }

    #[test]
    fn status_ready_excludes_quarantined_and_duty_disabled_validators() {
        let mut config = NodeConfig::default();
        config.node.validator_address = "synv1local".to_string();
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));

        let mut healthy_peer = test_peer_with_validator_address(Some("synv1healthy"));
        healthy_peer.status_received_at = Some(current_timestamp());

        let mut quarantined_peer = test_peer_with_validator_address(Some("synv1quarantined"));
        quarantined_peer.address = "peer-quarantined".to_string();
        quarantined_peer.status_received_at = Some(current_timestamp());
        quarantined_peer.quarantined = true;
        quarantined_peer.consensus_duties_disabled = true;
        quarantined_peer.recovery_state = Some("OPERATOR_QUARANTINE".to_string());

        let mut shadow_peer = test_peer_with_validator_address(Some("synv1shadow"));
        shadow_peer.address = "peer-shadow".to_string();
        shadow_peer.status_received_at = Some(current_timestamp());
        shadow_peer.consensus_duties_disabled = true;
        shadow_peer.recovery_state = Some("SHADOW_OBSERVING".to_string());

        {
            let mut peers = connected_peers.lock().unwrap();
            peers.insert("peer-healthy".to_string(), healthy_peer);
            peers.insert("peer-quarantined".to_string(), quarantined_peer);
            peers.insert("peer-shadow".to_string(), shadow_peer);
        }

        let addresses =
            status_ready_validator_addresses_with_local_duty_gate(&config, &connected_peers, false);
        assert!(addresses.contains(&"synv1local".to_string()));
        assert!(addresses.contains(&"synv1healthy".to_string()));
        assert!(!addresses.contains(&"synv1quarantined".to_string()));
        assert!(!addresses.contains(&"synv1shadow".to_string()));

        let local_disabled =
            status_ready_validator_addresses_with_local_duty_gate(&config, &connected_peers, true);
        assert!(!local_disabled.contains(&"synv1local".to_string()));
        assert!(local_disabled.contains(&"synv1healthy".to_string()));
    }

    #[test]
    fn stale_peer_status_expires_from_status_ready_snapshot() {
        let mut config = NodeConfig::default();
        config.node.validator_address = "synv1local".to_string();
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let now = current_timestamp();

        let mut stale_peer = test_peer_with_validator_address(Some("synv1stale"));
        stale_peer.address = "peer-stale".to_string();
        stale_peer.status_received_at =
            Some(now.saturating_sub(STATUS_READY_TTL_SECS.saturating_add(1)));
        let stale_reason = peer_readiness_exclusion_reason_at(&stale_peer, now, None);

        let mut fresh_peer = test_peer_with_validator_address(Some("synv1fresh"));
        fresh_peer.address = "peer-fresh".to_string();
        fresh_peer.status_received_at = Some(now);

        {
            let mut peers = connected_peers.lock().unwrap();
            peers.insert("peer-stale".to_string(), stale_peer);
            peers.insert("peer-fresh".to_string(), fresh_peer);
        }

        let addresses =
            status_ready_validator_addresses_with_local_duty_gate(&config, &connected_peers, false);
        assert!(addresses.contains(&"synv1fresh".to_string()));
        assert!(!addresses.contains(&"synv1stale".to_string()));
        assert_eq!(stale_reason, Some("stale-status"));
    }

    #[test]
    fn fresh_status_overwrites_stale_quarantine_and_duty_flags() {
        let mut peer = test_peer_with_validator_address(Some("synv1peer"));
        let now = current_timestamp();
        peer.status_received_at =
            Some(now.saturating_sub(DUTY_DISABLED_TTL_SECS.saturating_add(1)));
        peer.quarantined = true;
        peer.consensus_duties_disabled = true;
        peer.recovery_state = Some("STALE_QUARANTINE".to_string());

        apply_status_to_peer(
            &mut peer,
            77,
            "fresh-hash",
            "genesis-hash",
            Some(now),
            Some("synv1peer"),
            Some("peer-session"),
            Some("validator-set-hash"),
            false,
            false,
            None,
            now,
        );

        assert_eq!(peer.last_known_height, 77);
        assert_eq!(peer.best_block_hash, "fresh-hash");
        assert!(!peer.quarantined);
        assert!(!peer.consensus_duties_disabled);
        assert_eq!(peer.status_validator_address.as_deref(), Some("synv1peer"));
        assert_eq!(
            peer.status_source_session_id.as_deref(),
            Some("peer-session")
        );
        assert_eq!(
            peer.active_validator_set_hash.as_deref(),
            Some("validator-set-hash")
        );
        assert_eq!(
            peer_readiness_exclusion_reason_at(&peer, now, Some("validator-set-hash")),
            None
        );
    }

    #[test]
    fn status_metadata_cannot_establish_validator_identity() {
        let mut peer = test_peer_with_validator_address(None);
        let now = current_timestamp();

        apply_status_to_peer(
            &mut peer,
            77,
            "fresh-hash",
            "genesis-hash",
            Some(now),
            Some("synv1status-only"),
            Some("peer-session"),
            Some("validator-set-hash"),
            false,
            false,
            None,
            now,
        );

        assert!(peer.validator_address.is_none());
        assert_eq!(
            peer.status_validator_address.as_deref(),
            Some("synv1status-only")
        );
    }

    #[test]
    fn reconnect_hydration_does_not_inherit_stale_quarantine() {
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let now = current_timestamp();
        let mut existing = test_peer_with_validator_address(Some("synv1peer"));
        existing.status_received_at =
            Some(now.saturating_sub(QUARANTINE_STATUS_TTL_SECS.saturating_add(1)));
        existing.quarantined = true;
        existing.consensus_duties_disabled = true;
        existing.recovery_state = Some("STALE_QUARANTINE".to_string());
        cache_peer_state(&cache, &existing);

        let mut replacement = test_peer_with_validator_address(Some("synv1peer"));
        replacement.status_received_at = None;
        replacement.genesis_hash.clear();
        replacement.quarantined = false;
        replacement.consensus_duties_disabled = false;
        let peer_identity = peer_identity_key("peer-a", Some("synv1peer"));
        hydrate_peer_from_cache(&cache, &peer_identity, &mut replacement);

        assert_eq!(replacement.status_received_at, None);
        assert!(!replacement.quarantined);
        assert!(!replacement.consensus_duties_disabled);
        assert_eq!(
            peer_readiness_exclusion_reason_at(&replacement, now, None),
            Some("stale-status")
        );
    }

    #[test]
    fn peer_info_uses_canonical_peer_snapshot_readiness_reason() {
        let config = NodeConfig::default();
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let network = P2PNetwork::new(blockchain, &config);
        let now = current_timestamp();
        let mut peer = test_peer_with_validator_address(Some("synv1peer"));
        peer.address = "peer-stale".to_string();
        peer.status_received_at = Some(now.saturating_sub(STATUS_READY_TTL_SECS.saturating_add(1)));
        network
            .connected_peers
            .lock()
            .unwrap()
            .insert("peer-stale".to_string(), peer);

        let snapshot = network
            .collect_peer_snapshots()
            .into_iter()
            .next()
            .expect("peer snapshot");
        let info = network
            .get_peer_info()
            .into_iter()
            .next()
            .expect("peer info");

        assert_eq!(
            snapshot.readiness_exclusion_reason.as_deref(),
            Some("stale-status")
        );
        assert_eq!(
            info.get("readiness_exclusion_reason")
                .and_then(serde_json::Value::as_str),
            Some("stale-status")
        );
        assert_eq!(
            info.get("status_fresh")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn peer_readiness_reports_wrong_validator_set_hash() {
        let now = current_timestamp();
        let mut peer = test_peer_with_validator_address(Some("synv1peer"));
        peer.status_received_at = Some(now);
        peer.active_validator_set_hash = Some("wrong-set".to_string());

        assert_eq!(
            peer_readiness_exclusion_reason_at(&peer, now, Some("expected-set")),
            Some("wrong-validator-set-hash")
        );
    }

    #[test]
    fn block_sync_source_accepts_duty_disabled_support_peer_but_not_shadow_validator() {
        let mut config = NodeConfig::default();
        config.network.additional_dial_targets = vec!["127.0.0.1:5622".to_string()];
        let mut relayer_peer =
            test_peer_with_validator_address(Some("synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632"));
        relayer_peer.node_id = Some("sentry1".to_string());
        relayer_peer.handshake_role = Some("relayer".to_string());
        relayer_peer.address = "relay1.synergynode.xyz:5622".to_string();
        relayer_peer.public_address = Some("relay1.synergynode.xyz:5622".to_string());
        relayer_peer.connected_endpoint = Some("127.0.0.1:5622".to_string());
        relayer_peer.consensus_duties_disabled = true;
        relayer_peer.last_known_height = 195_000;
        assert!(peer_is_eligible_block_sync_source(&config, &relayer_peer));

        let mut shadow_validator = test_peer_with_validator_address(Some("synv1shadow"));
        shadow_validator.consensus_duties_disabled = true;
        shadow_validator.last_known_height = 195_000;
        assert!(!peer_is_eligible_block_sync_source(
            &config,
            &shadow_validator
        ));
    }

    lazy_static! {
        static ref TEST_VALIDATOR_KEY_LOCK: Mutex<()> = Mutex::new(());
        static ref TEST_BLOCK_APPLICATION_LOCK: Mutex<()> = Mutex::new(());
    }

    struct TestCommitVerifierGuard {
        previous: Option<Arc<ValidatorManager>>,
    }

    impl Drop for TestCommitVerifierGuard {
        fn drop(&mut self) {
            let previous = self.previous.take();
            TEST_COMMIT_VERIFIER_VALIDATOR_MANAGER.with(|slot| {
                *slot.borrow_mut() = previous;
            });
        }
    }

    struct BlockApplicationTestGuard {
        _block_guard: MutexGuard<'static, ()>,
        _vote_guard: MutexGuard<'static, ()>,
        _commit_verifier_guard: TestCommitVerifierGuard,
    }

    fn block_application_test_guard() -> BlockApplicationTestGuard {
        let block_guard = TEST_BLOCK_APPLICATION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let vote_guard = DualQuorumConsensus::test_vote_tracking_guard();
        let commit_verifier = Arc::new(ValidatorManager::new());
        let previous =
            TEST_COMMIT_VERIFIER_VALIDATOR_MANAGER.with(|slot| slot.replace(Some(commit_verifier)));
        DualQuorumConsensus::reset_test_vote_tracking();
        PENDING_BLOCKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        clear_legacy_canonical_locks_for_tests();
        BlockApplicationTestGuard {
            _block_guard: block_guard,
            _vote_guard: vote_guard,
            _commit_verifier_guard: TestCommitVerifierGuard { previous },
        }
    }

    fn current_test_commit_verifier_manager() -> Option<Arc<ValidatorManager>> {
        TEST_COMMIT_VERIFIER_VALIDATOR_MANAGER.with(|slot| slot.borrow().clone())
    }

    fn register_test_validator_in_manager(
        validator_manager: &Arc<ValidatorManager>,
        address: &str,
        public_key: &crate::crypto::pqc::PQCPublicKey,
    ) {
        let encoded_public_key = format!(
            "{}:{}",
            consensus_algorithm_label(&public_key.algorithm),
            general_purpose::STANDARD.encode(&public_key.key_data)
        );
        if let Ok(mut registry) = validator_manager.registry.lock() {
            let mut validator = Validator::new(
                address.to_string(),
                encoded_public_key,
                format!("Test validator {address}"),
                50_000_000_000_000,
            );
            validator.status = ValidatorStatus::Active;
            validator.synergy_score = 100.0;
            validator.activation_tx_hash = Some(format!("syntxn-test-{address}"));
            registry.validators.insert(address.to_string(), validator);
            registry.pending_registrations.remove(address);
        }
    }

    fn register_current_test_commit_verifier_validator(
        address: &str,
        public_key: &crate::crypto::pqc::PQCPublicKey,
    ) {
        if let Some(validator_manager) = current_test_commit_verifier_manager() {
            register_test_validator_in_manager(&validator_manager, address, public_key);
        }
    }

    fn sign_test_block(block: &mut Block) {
        let _guard = TEST_VALIDATOR_KEY_LOCK
            .lock()
            .expect("test validator key lock should succeed");
        ensure_test_validator_key_locked(&block.validator_id);
        let (public_key, private_key) =
            load_local_validator_keypair(&block.validator_id, &VALIDATOR_MANAGER)
                .expect("test validator signing key should load");
        let mut manager = PQCManager::new();
        let signature = manager
            .sign(&private_key, block.hash.as_bytes())
            .expect("test Aegis PQC block signature should sign");
        block.proposer_public_key = public_key.key_data;
        block.block_signature = signature.signature_data;
        block.block_signature_algorithm =
            consensus_algorithm_label(&public_key.algorithm).to_string();
    }

    fn signed_block(
        height: u64,
        transactions: Vec<crate::transaction::Transaction>,
        previous_hash: String,
        validator: String,
        nonce: u64,
        timestamp: u64,
    ) -> Block {
        let mut block = Block::new_with_timestamp(
            height,
            transactions,
            previous_hash,
            validator,
            nonce,
            timestamp,
        );
        sign_test_block(&mut block);
        block
    }

    fn ensure_test_validator_key(address: &str) {
        let _guard = TEST_VALIDATOR_KEY_LOCK
            .lock()
            .expect("test validator key lock should succeed");
        ensure_test_validator_key_locked(address);
    }

    fn ensure_test_validator_key_locked(address: &str) {
        if let Ok((public_key, _)) = load_local_validator_keypair(address, &VALIDATOR_MANAGER) {
            VALIDATOR_MANAGER.update_synergy_score(address, 100.0);
            register_current_test_commit_verifier_validator(address, &public_key);
            return;
        }

        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::MLDSA65)
            .expect("test Aegis PQC validator key should generate");
        register_test_validator_signing_key(address, public_key.clone(), private_key);
        let encoded_public_key = format!(
            "{}:{}",
            consensus_algorithm_label(&public_key.algorithm),
            general_purpose::STANDARD.encode(&public_key.key_data)
        );

        if let Ok(mut registry) = VALIDATOR_MANAGER.registry.lock() {
            let mut validator = Validator::new(
                address.to_string(),
                encoded_public_key.clone(),
                format!("Test validator {address}"),
                50_000_000_000_000,
            );
            validator.status = ValidatorStatus::Active;
            validator.synergy_score = 100.0;
            validator.activation_tx_hash = Some(format!("syntxn-test-{address}"));
            registry.validators.insert(address.to_string(), validator);
            registry.pending_registrations.remove(address);
        } else if VALIDATOR_MANAGER.get_validator(address).is_none() {
            let _ = VALIDATOR_MANAGER.register_validator(ValidatorRegistration {
                address: address.to_string(),
                public_key: encoded_public_key,
                name: format!("Test validator {address}"),
                stake_amount: 50_000_000_000_000,
                submitted_at: 0,
                registration_tx_hash: format!("test-registration-{address}"),
            });
            let _ = VALIDATOR_MANAGER.approve_validator(address);
        }
        VALIDATOR_MANAGER.update_synergy_score(address, 100.0);
        register_current_test_commit_verifier_validator(address, &public_key);
    }

    fn ensure_test_qc_validators(addresses: &[&str]) {
        for address in addresses {
            ensure_test_validator_key_locked(address);
        }
    }

    fn test_quorum_certificate(block: &Block) -> QuorumCertificate {
        let _guard = TEST_VALIDATOR_KEY_LOCK
            .lock()
            .expect("test validator key lock should succeed");
        let signers = ["synv1qc01", "synv1qc02", "synv1qc03", "synv1qc04"];
        ensure_test_validator_key_locked(&block.validator_id);
        ensure_test_qc_validators(&signers);
        let validator_manager =
            current_test_commit_verifier_manager().unwrap_or_else(|| VALIDATOR_MANAGER.clone());
        let active_before_signing = validator_manager
            .get_active_validators()
            .into_iter()
            .map(|validator| validator.address)
            .collect::<Vec<_>>();
        for address in active_before_signing {
            ensure_test_validator_key_locked(&address);
        }
        let mut signer_addresses = validator_manager
            .get_active_validators()
            .into_iter()
            .map(|validator| validator.address)
            .collect::<Vec<_>>();
        signer_addresses.sort();
        let votes = signer_addresses
            .iter()
            .map(|validator| {
                DualQuorumConsensus::create_vote_for_validator_with_manager(
                    validator,
                    block,
                    0,
                    1,
                    &validator_manager,
                )
                .expect("test vote should sign")
            })
            .collect::<Vec<_>>();
        QuorumCertificate {
            block_hash: block.hash.clone(),
            cluster_id: None,
            epoch_number: 0,
            round_number: 1,
            aggregate_signature: vec![42],
            participant_bitmap: vec![0x0f],
            // Production verifies cumulative_weight as the summed BONDED STAKE of
            // the signers, not the signer count. Declaring the count here made
            // every certified block fail with
            // "QC cumulative_weight mismatch: computed bonded weight ..., declared N".
            cumulative_weight: signer_addresses
                .iter()
                .filter_map(|address| validator_manager.get_validator(address))
                .map(|validator| validator.stake_amount as f64)
                .sum::<f64>(),
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: block.timestamp,
            votes,
        }
    }

    #[test]
    fn dial_with_timeout_keeps_established_peer_streams_blocking() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind test listener: {error}"),
        };
        let addr = listener.local_addr().unwrap();

        let accept_handle = thread::spawn(move || {
            let _ = listener.accept().unwrap();
        });

        let stream = match dial_with_timeout(&addr.to_string(), Duration::from_millis(250)) {
            Ok(stream) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                // The local desktop sandbox can deny loopback dials in tests even
                // though the runtime code path is valid on normal hosts.
                accept_handle.join().unwrap();
                return;
            }
            Err(error) => panic!("dial_with_timeout failed: {error}"),
        };

        assert_eq!(stream.read_timeout().unwrap(), None);
        assert_eq!(stream.write_timeout().unwrap(), None);

        accept_handle.join().unwrap();
    }

    #[test]
    fn lower_node_id_prefers_outgoing_connection() {
        assert_eq!(
            preferred_connection_direction("node-01", "node-02"),
            Some(ConnectionDirection::Outgoing)
        );
    }

    #[test]
    fn higher_node_id_prefers_incoming_connection() {
        assert_eq!(
            preferred_connection_direction("node-02", "node-01"),
            Some(ConnectionDirection::Incoming)
        );
    }

    #[test]
    fn peer_identity_key_prefers_validator_address_over_node_id() {
        assert_eq!(
            peer_identity_key("testnet-random-node-id", Some("synv1validator")),
            "validator:synv1validator".to_string()
        );
        assert_eq!(
            peer_identity_key("testnet-random-node-id", None),
            "node:testnet-random-node-id".to_string()
        );
    }

    #[test]
    fn local_peer_identity_uses_same_validator_namespace_as_remote_peers() {
        let mut config = NodeConfig::default();
        config.node.bootstrap_only = false;
        config.node.validator_address = "synv1local".to_string();
        config.p2p.node_name = "testnet-local".to_string();

        assert_eq!(
            local_peer_identity(&config),
            "validator:synv1local".to_string()
        );
    }

    #[test]
    fn signed_aegis_pqc_handshake_verifies() {
        configure_canonical_genesis_path_for_tests();
        let mut config = NodeConfig::default();
        config.p2p.node_name = "qualification-relay".to_string();
        config.node.bootstrap_only = true;
        config.node.validator_address.clear();

        let handshake = build_local_handshake(&config).expect("handshake should sign");

        verify_handshake_pq_signature(&handshake).expect("handshake signature should verify");
        let NetworkMessage::Handshake {
            aegis_pq_public_key_algorithm,
            ..
        } = handshake
        else {
            panic!("expected handshake");
        };
        assert_eq!(aegis_pq_public_key_algorithm.as_deref(), Some("fndsa"));
    }

    /// The downstream FN-DSA-1024 peer identity must never be substituted for a
    /// validator's Genesis-assigned ML-DSA-65 consensus key. A validator whose
    /// custody key is unavailable must fail closed rather than quietly
    /// generating a weaker non-consensus identity and still advertising the
    /// simplified PoSy validator capability.
    ///
    /// Live ML-DSA-65 handshake verification is proven separately by Ring 1
    /// case `real_mldsa_six_validator_burn_in` and by the Ring 2
    /// `p2p_verified_handshakes_total{algorithm="ML-DSA-65"}` counter; the
    /// canonical Genesis fixture intentionally ships no validator private keys.
    #[test]
    fn validator_handshake_never_falls_back_to_the_fndsa_peer_identity() {
        configure_canonical_genesis_path_for_tests();
        let mut config = NodeConfig::default();
        config.p2p.node_name = "genesisval1".to_string();
        config.node.validator_address = "synv1local".to_string();
        assert!(
            local_consensus_handshake_required(&config),
            "a configured validator address must select the consensus handshake path"
        );

        let error = build_local_handshake(&config)
            .expect_err("a validator without its custody key must fail closed");

        assert!(
            error.contains("ML-DSA-65"),
            "the validator path must demand the assigned ML-DSA-65 consensus key: {error}"
        );
        assert!(
            !error.contains("fndsa"),
            "the validator path must not reach the FN-DSA peer identity generator: {error}"
        );
    }

    #[test]
    fn old_chain_incarnation_handshake_is_rejected_before_pq_verification() {
        configure_canonical_genesis_path_for_tests();
        let mut config = NodeConfig::default();
        config.p2p.node_name = "genesisval1".to_string();
        let mut handshake = build_local_handshake(&config).expect("handshake should sign");
        if let NetworkMessage::Handshake {
            chain_incarnation, ..
        } = &mut handshake
        {
            *chain_incarnation = Some(canonical_chain_incarnation().saturating_sub(1));
        }

        let requests_before =
            crate::crypto::aegis_pqvm::pqc_verification_metrics_snapshot().requests;
        let error = verify_handshake_pq_signature(&handshake)
            .expect_err("an old chain incarnation must fail closed");
        let requests_after =
            crate::crypto::aegis_pqvm::pqc_verification_metrics_snapshot().requests;

        assert!(error.contains("Chain 1266 incarnation"), "{error}");
        assert_eq!(
            requests_after, requests_before,
            "incarnation mismatch must be rejected before PQ verification"
        );
    }

    #[test]
    fn typed_consensus_identity_binding_is_scoped_to_one_live_peer_session() {
        let peer_address = format!("typed-identity-test-{}", std::process::id());
        let first_session = begin_peer_session(&peer_address);
        let identity = AuthenticatedTypedConsensusPeer {
            validator_id: ValidatorId("validator-test".to_string()),
            validator_uma_id: UmaId("uma-test".to_string()),
            consensus_key_id: AegisPqKeyId("consensus-key-test".to_string()),
        };
        register_typed_consensus_peer_session(&peer_address, first_session, identity.clone())
            .expect("current peer session should accept the verified identity binding");
        assert_eq!(
            typed_consensus_peer_for_session(&peer_address, first_session),
            Some(identity)
        );

        let replacement_session = begin_peer_session(&peer_address);
        assert_ne!(replacement_session, first_session);
        assert!(typed_consensus_peer_for_session(&peer_address, first_session).is_none());
        assert!(typed_consensus_peer_for_session(&peer_address, replacement_session).is_none());
        PEER_SESSION_IDS.lock().unwrap().remove(&peer_address);
        TYPED_CONSENSUS_PEER_SESSIONS
            .lock()
            .unwrap()
            .retain(|(address, _), _| address != &peer_address);
    }

    #[test]
    fn empty_etdag_assembly_identity_is_derived_only_from_live_authenticated_session() {
        let peer_address = format!("empty-etdag-identity-test-{}", std::process::id());
        let session_id = begin_peer_session(&peer_address);
        assert!(etdag_ingress_peer_for_session(&peer_address, session_id).is_none());

        let typed_identity = AuthenticatedTypedConsensusPeer {
            validator_id: ValidatorId("validator-test".to_string()),
            validator_uma_id: UmaId("uma-test".to_string()),
            consensus_key_id: AegisPqKeyId("consensus-key-test".to_string()),
        };
        register_typed_consensus_peer_session(&peer_address, session_id, typed_identity.clone())
            .expect("authenticated live session should accept its validator identity");

        let assembly_identity = etdag_ingress_peer_for_session(&peer_address, session_id)
            .expect("assembly ingress must derive from the authenticated session");
        assert_eq!(assembly_identity.validator_id, typed_identity.validator_id);

        let replacement_session = begin_peer_session(&peer_address);
        assert!(etdag_ingress_peer_for_session(&peer_address, session_id).is_none());
        assert!(etdag_ingress_peer_for_session(&peer_address, replacement_session).is_none());
        PEER_SESSION_IDS.lock().unwrap().remove(&peer_address);
        TYPED_CONSENSUS_PEER_SESSIONS
            .lock()
            .unwrap()
            .retain(|(address, _), _| address != &peer_address);
    }

    #[test]
    fn handshake_rejects_retired_posy_consensus_version() {
        let error = handshake_version_mismatch_reason(
            "consensus_version",
            POSY_SIMPLIFIED_PROTOCOL_VERSION,
            Some("posy/2.2"),
        )
        .expect("retired PoSy peers must be rejected");

        assert!(error.contains("consensus_version differs"), "{error}");
        assert!(error.contains(POSY_SIMPLIFIED_PROTOCOL_VERSION));
    }

    #[test]
    fn direct_vote_handshake_capability_is_signed_and_verifiable() {
        configure_canonical_genesis_path_for_tests();
        let mut config = NodeConfig::default();
        config.p2p.node_name = "qualification-relay".to_string();
        config.node.bootstrap_only = true;
        config.node.validator_address.clear();

        let handshake = build_local_handshake_with_extra_capabilities(&config, &["direct-vote"])
            .expect("direct vote handshake should sign");

        verify_handshake_pq_signature(&handshake).expect("direct vote handshake should verify");
        if let NetworkMessage::Handshake { capabilities, .. } = handshake {
            assert!(capabilities
                .iter()
                .any(|capability| capability == "direct-vote"));
        } else {
            panic!("expected handshake");
        }
    }

    #[test]
    fn missing_aegis_pqc_handshake_signature_is_rejected() {
        configure_canonical_genesis_path_for_tests();
        let mut config = NodeConfig::default();
        config.p2p.node_name = "genesisval1".to_string();
        let mut handshake = build_local_handshake(&config).expect("handshake should sign");
        if let NetworkMessage::Handshake {
            aegis_pq_handshake_signature,
            ..
        } = &mut handshake
        {
            *aegis_pq_handshake_signature = None;
        }

        let err = verify_handshake_pq_signature(&handshake)
            .expect_err("missing signature must fail closed");

        assert!(err.contains("missing Aegis PQC peer handshake signature"));
    }

    #[test]
    fn altered_aegis_pqc_handshake_signature_is_rejected() {
        configure_canonical_genesis_path_for_tests();
        let mut config = NodeConfig::default();
        config.p2p.node_name = "genesisval1".to_string();
        let mut handshake = build_local_handshake(&config).expect("handshake should sign");
        if let NetworkMessage::Handshake {
            aegis_pq_handshake_signature: Some(signature),
            ..
        } = &mut handshake
        {
            signature.signature_bytes[0] ^= 0x01;
        }

        let err = verify_handshake_pq_signature(&handshake)
            .expect_err("altered signature must fail closed");

        assert!(err.contains("Aegis PQC peer handshake verification failed"));
    }

    #[test]
    fn handshake_without_testnet_network_name_is_rejected() {
        configure_canonical_genesis_path_for_tests();
        let mut config = NodeConfig::default();
        config.p2p.node_name = "genesisval1".to_string();
        let mut handshake = build_local_handshake(&config).expect("handshake should sign");
        if let NetworkMessage::Handshake {
            network_id_text, ..
        } = &mut handshake
        {
            *network_id_text = None;
        }

        let err = verify_handshake_pq_signature(&handshake)
            .expect_err("missing network name must fail closed");

        assert!(err.contains("network_id testnet"));
    }

    #[test]
    fn simplified_validator_handshake_uses_the_assigned_mldsa65_key_only() {
        let mut key_manager = PQCManager::new();
        let (public_key, private_key) = key_manager
            .generate_keypair(PQCAlgorithm::MLDSA65)
            .expect("generate ML-DSA-65 test key");
        let expected_bytes = public_key.key_data.clone();
        let mut signer = AegisPqvmSigner::initialize_required().expect("initialize signer");
        let key_id = register_validator_consensus_handshake_key(
            &mut signer,
            "synv1validator",
            public_key,
            private_key,
        )
        .expect("register assigned validator key");
        assert_eq!(
            signer.public_key_record(&key_id).unwrap().key_bytes,
            expected_bytes
        );
        assert!(signer.registry.key_is_active_for_epoch(
            "synv1validator",
            &key_id,
            Epoch(0),
            AegisPqKeyRole::PeerIdentity
        ));

        let (wrong_public, wrong_private) = key_manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .expect("generate FN-DSA test key");
        let error = register_validator_consensus_handshake_key(
            &mut signer,
            "synv1wrong",
            wrong_public,
            wrong_private,
        )
        .expect_err("simplified validator handshake must reject FN-DSA");
        assert!(error.contains("ML-DSA-65"));
    }

    #[test]
    fn simplified_validator_handshake_requirement_is_exact_and_excludes_bootstrap() {
        let mut config = NodeConfig::default();
        config.node.validator_address = "synv1validator".to_string();
        config.consensus.algorithm = "unsupported-consensus-profile".to_string();
        assert!(!local_consensus_handshake_required(&config));
        config.consensus.algorithm = POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string();
        assert!(local_consensus_handshake_required(&config));
        config.node.bootstrap_only = true;
        assert!(!local_consensus_handshake_required(&config));
        config.node.bootstrap_only = false;
        config.consensus.algorithm = COORDINATED_ROUND_ROBIN_V1.to_string();
        assert!(local_consensus_handshake_required(&config));
        assert_eq!(local_consensus_version(&config), COORDINATED_ROUND_ROBIN_V1);
    }

    #[test]
    fn simplified_validator_capability_is_the_only_posy_capability() {
        assert_eq!(
            validator_consensus_capability(POSY_SIMPLIFIED_PROTOCOL_VERSION)
                .expect("simplified PoSy must have a validator capability"),
            "posy-simplified-v3-validator"
        );
        assert!(validator_consensus_capability("unsupported-posy-profile").is_err());
    }

    #[test]
    fn duplicate_resolution_keeps_preferred_existing_connection() {
        assert_eq!(
            resolve_duplicate_connection(
                "node-01",
                "node-02",
                ConnectionDirection::Outgoing,
                10,
                ConnectionDirection::Incoming,
                20,
            ),
            DuplicateResolution::KeepExisting
        );
    }

    #[test]
    fn duplicate_resolution_replaces_non_preferred_existing_connection() {
        assert_eq!(
            resolve_duplicate_connection(
                "node-01",
                "node-02",
                ConnectionDirection::Incoming,
                10,
                ConnectionDirection::Outgoing,
                20,
            ),
            DuplicateResolution::ReplaceExisting
        );
    }

    #[test]
    fn duplicate_direct_vote_session_bypasses_stable_connection_resolution() {
        assert!(!should_resolve_duplicate_session(true));
        assert!(should_resolve_duplicate_session(false));
    }

    #[test]
    fn validator_duplicate_resolution_prefers_opposite_directions_on_each_side() {
        let local_a = "validator:synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs";
        let local_b = "validator:synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt";

        let decision_a = resolve_duplicate_connection(
            local_a,
            local_b,
            ConnectionDirection::Outgoing,
            10,
            ConnectionDirection::Incoming,
            20,
        );
        let decision_b = resolve_duplicate_connection(
            local_b,
            local_a,
            ConnectionDirection::Outgoing,
            10,
            ConnectionDirection::Incoming,
            20,
        );

        assert_eq!(decision_a, DuplicateResolution::KeepExisting);
        assert_eq!(decision_b, DuplicateResolution::ReplaceExisting);
    }

    #[test]
    fn reconnect_hydration_preserves_remote_status_for_same_validator_identity() {
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let status_time = current_timestamp();
        let existing = PeerConnection {
            address: "62.146.182.208:5622".to_string(),
            direction: ConnectionDirection::Outgoing,
            public_address: Some("62.146.182.208:5622".to_string()),
            validator_address: Some("synv1peer-b".to_string()),
            connected_at: 10,
            last_seen: 20,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            connected_endpoint: None,
            node_id: Some("testnet-peer-b".to_string()),
            handshake_role: None,
            version: Some("1.0.0".to_string()),
            capabilities: vec!["blocks".to_string()],
            last_known_height: 42,
            best_block_hash: "block-hash".to_string(),
            genesis_hash: "genesis-hash".to_string(),
            status_received_at: Some(status_time),
            status_reported_at: None,
            status_validator_address: None,
            status_source_session_id: None,
            active_validator_set_hash: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };
        cache_peer_state(&cache, &existing);

        let mut replacement = PeerConnection {
            address: "62.146.182.208:64347".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: Some("62.146.182.208:5622".to_string()),
            validator_address: Some("synv1peer-b".to_string()),
            connected_at: 30,
            last_seen: 30,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            connected_endpoint: None,
            node_id: Some("testnet-peer-b".to_string()),
            handshake_role: None,
            version: Some("1.0.0".to_string()),
            capabilities: vec!["blocks".to_string()],
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            status_reported_at: None,
            status_validator_address: None,
            status_source_session_id: None,
            active_validator_set_hash: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };

        let peer_identity = peer_identity_key("testnet-peer-b", Some("synv1peer-b"));
        hydrate_peer_from_cache(&cache, &peer_identity, &mut replacement);

        assert_eq!(replacement.last_known_height, 42);
        assert_eq!(replacement.best_block_hash, "block-hash".to_string());
        assert_eq!(replacement.genesis_hash, "genesis-hash".to_string());
        assert_eq!(replacement.status_received_at, Some(status_time));
    }

    #[test]
    fn replacement_session_inherits_existing_remote_status() {
        let status_time = current_timestamp();
        let existing = PeerConnection {
            address: "62.146.182.208:5622".to_string(),
            direction: ConnectionDirection::Outgoing,
            public_address: Some("62.146.182.208:5622".to_string()),
            validator_address: Some("synv1peer-a".to_string()),
            connected_at: 10,
            last_seen: 15,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            connected_endpoint: None,
            node_id: Some("testnet-peer-a".to_string()),
            handshake_role: None,
            version: Some("1.0.0".to_string()),
            capabilities: vec!["blocks".to_string()],
            last_known_height: 9,
            best_block_hash: "hash-9".to_string(),
            genesis_hash: "genesis-hash".to_string(),
            status_received_at: Some(status_time),
            status_reported_at: None,
            status_validator_address: None,
            status_source_session_id: None,
            active_validator_set_hash: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };
        let mut replacement = PeerConnection {
            address: "62.146.182.208:56733".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: None,
            validator_address: Some("synv1peer-a".to_string()),
            connected_at: 20,
            last_seen: 20,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            connected_endpoint: None,
            node_id: Some("testnet-peer-a".to_string()),
            handshake_role: None,
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            status_reported_at: None,
            status_validator_address: None,
            status_source_session_id: None,
            active_validator_set_hash: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };

        merge_peer_state_from_existing(&existing, &mut replacement);

        assert_eq!(replacement.last_known_height, 9);
        assert_eq!(replacement.genesis_hash, "genesis-hash".to_string());
        assert_eq!(replacement.status_received_at, Some(status_time));
        assert_eq!(
            replacement.public_address,
            Some("62.146.182.208:5622".to_string())
        );
    }

    #[test]
    fn parse_bootnode_dial_address_normalizes_identity_and_ipv6() {
        assert_eq!(
            parse_bootnode_dial_address("snr://peer@74.208.227.23:5620"),
            Some("74.208.227.23:5620".to_string())
        );
        assert_eq!(
            parse_bootnode_dial_address(
                "snr://synv1156xl3ct9cxc4cl9pdn5ww9myxudavl0hxrq7zv@2a02:1812:172a:e900:1497:71dc:d720:e28e:5620",
            ),
            Some("[2a02:1812:172a:e900:1497:71dc:d720:e28e]:5620".to_string())
        );
    }

    #[test]
    fn parse_bootnode_dial_address_rejects_invalid_bare_host_targets() {
        assert_eq!(parse_bootnode_dial_address("snr://peer@test:5620"), None);
        assert_eq!(parse_bootnode_dial_address(""), None);
    }

    #[test]
    fn incoming_host_match_resolves_dns_named_configured_endpoints() {
        // Regression: this helper called `to_socket_addrs()` on a bare host with
        // the port already stripped, which always fails. Every DNS-named
        // allowlist entry was therefore unmatchable on the incoming path, so a
        // support peer advertising a hostname could not be authorized at all:
        // the numeric allowlist entry matched its observed source host but not
        // its advertised address, and the DNS entry matched its advertised
        // address but never resolved. That is why the RPC gateway, which
        // advertises `rpc.synergynode.xyz:5623`, was rejected by every relayer
        // with "typed finality observer request to relayer is not from a
        // configured public service role".
        assert!(connected_endpoint_host_matches_configured_address(
            "127.0.0.1:54321",
            "localhost:5623"
        ));

        // A resolved host that is not the observed source must still fail.
        assert!(!connected_endpoint_host_matches_configured_address(
            "203.0.113.7:54321",
            "localhost:5623"
        ));

        // Numeric entries keep matching on host alone, ignoring the peer's
        // ephemeral inbound source port.
        assert!(connected_endpoint_host_matches_configured_address(
            "167.86.83.83:54321",
            "167.86.83.83:5623"
        ));
        assert!(!connected_endpoint_host_matches_configured_address(
            "167.86.83.84:54321",
            "167.86.83.83:5623"
        ));

        // A self-reported hostname is never transport evidence.
        assert!(!connected_endpoint_host_matches_configured_address(
            "localhost:54321",
            "localhost:5623"
        ));
    }

    #[test]
    fn canonical_validator_public_address_preserves_public_history_gateway_port() {
        assert_eq!(
            canonical_validator_public_address("167.86.83.83:5623", Some("167.86.83.83:5622")),
            Some("167.86.83.83:5623".to_string())
        );
        assert_eq!(
            canonical_validator_public_address(
                "archive.synergynode.xyz:5615",
                Some("archive.synergynode.xyz:5615")
            ),
            Some("archive.synergynode.xyz:5615".to_string())
        );
        assert_eq!(
            canonical_validator_public_address("73.79.66.255:5615", Some("73.79.66.255:5615")),
            Some("73.79.66.255:5615".to_string())
        );
        assert_eq!(
            canonical_validator_public_address("94.72.117.108:62422", Some("94.72.117.108:5622")),
            Some("94.72.117.108:5622".to_string())
        );
    }

    #[test]
    fn canonical_validator_public_address_preserves_stable_validator_identity() {
        let validator_address = "synv11validatorxxxxxxxxxxxxxxxxxxxx";

        assert_eq!(
            canonical_validator_public_address("10.69.10.5:58352", Some(validator_address)),
            Some(validator_address.to_string())
        );
    }

    #[test]
    fn canonical_innernet_routes_are_accepted_and_retired_routes_rejected() {
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: "synv1validator1".to_string(),
            dial_address: "10.70.10.1:5622".to_string(),
        }];

        assert!(is_validator_vpn_dial_address("10.70.10.1:5622"));
        assert!(is_validator_vpn_dial_address("10.70.10.254:5622"));
        assert!(is_validator_vpn_relayer_dial_address("10.70.20.1:5622"));
        assert!(is_validator_vpn_relayer_dial_address("10.70.20.254:5622"));
        assert!(!is_validator_vpn_dial_address("10.69.10.1:5622"));
        assert!(!is_validator_vpn_relayer_dial_address("10.69.0.1:5622"));
        assert!(!is_validator_vpn_dial_address("10.70.10.0:5622"));
        assert!(!is_validator_vpn_relayer_dial_address("10.70.20.255:5622"));

        assert_eq!(
            resolve_peer_transport_address(&config, "10.70.10.1:5622"),
            None
        );
        assert_eq!(normalize_peer_target(&config, "10.70.10.1:5622"), None);
        assert_eq!(
            resolve_peer_transport_address(&config, "10.70.20.1:5622"),
            Some("10.70.20.1:5622".to_string())
        );
        assert_eq!(
            resolve_peer_transport_address(&config, "10.69.10.1:5622"),
            None
        );
    }

    #[test]
    fn relayer_rejects_raw_validator_vpn_targets_and_resolves_validator_identity() {
        let mut config = NodeConfig::default();
        config.identity.role = "relayer".to_string();
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: "synv1validator1".to_string(),
            dial_address: "10.70.10.1:5622".to_string(),
        }];

        assert_eq!(
            resolve_peer_transport_address(&config, "10.70.10.1:5622"),
            None
        );
        assert_eq!(
            resolve_peer_transport_address(&config, "synv1validator1"),
            Some("10.70.10.1:5622".to_string())
        );
    }

    #[test]
    fn synv1_resolution_requires_an_enrolled_validator_transport() {
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: "synv1validator1".to_string(),
            dial_address: "10.70.10.7:5622".to_string(),
        }];

        assert_eq!(
            resolve_peer_transport_address(&config, "synv1validator1"),
            Some("10.70.10.7:5622".to_string())
        );
        assert_eq!(
            resolve_peer_transport_address(&config, "synv1validator2"),
            None
        );

        config.network.validator_vpn_transports[0].dial_address = "10.69.10.7:5622".to_string();
        assert_eq!(
            resolve_peer_transport_address(&config, "synv1validator1"),
            None
        );
    }

    #[test]
    fn validator_activation_preflight_rejects_malformed_activation_before_append() {
        let tx = Transaction::new(
            "synv1invalid".to_string(),
            "synv1invalid".to_string(),
            0,
            0,
            Vec::new(),
            0,
            0,
            Some("validator_activation:{}".to_string()),
            "fndsa".to_string(),
        );
        let block = Block::new_with_timestamp(
            1,
            vec![tx],
            "previous-hash".to_string(),
            "block-hash".to_string(),
            0,
            1_700_000_000,
        );

        let error = preflight_validator_activation_transactions(std::iter::once(&block))
            .expect_err("malformed activation should fail preflight");
        assert!(error.contains("missing validator address"));
    }

    #[test]
    fn validator_public_address_canonicalization_requires_synv_identity() {
        assert!(should_canonicalize_validator_public_address(Some(
            "synv11validatorxxxxxxxxxxxxxxxxxxxx"
        )));
        assert!(!should_canonicalize_validator_public_address(Some(
            "archive-validator-01"
        )));
        assert!(!should_canonicalize_validator_public_address(Some(
            "rpc-gateway-01"
        )));
        assert!(!should_canonicalize_validator_public_address(None));
    }

    #[test]
    fn collect_known_peer_addresses_includes_assigned_synergy_targets() {
        let mut config = NodeConfig::default();
        config.identity.role = "relayer".to_string();
        config.role.compiled_profile = "relayer_node".to_string();
        config.p2p.public_address = "genesisval1.synergy-network.io:5622".to_string();
        config.network.additional_dial_targets =
            vec!["genesisval2.synergy-network.io:5622".to_string()];
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let discovered_targets: DialTargetsArc = Arc::new(Mutex::new(vec![
            "genesisval3.synergy-network.io:5622".to_string(),
        ]));

        let addresses =
            collect_known_peer_addresses(&connected_peers, &discovered_targets, &config);

        assert!(addresses.contains(&"genesisval1.synergy-network.io:5622".to_string()));
        assert!(addresses.contains(&"genesisval2.synergy-network.io:5622".to_string()));
        assert!(addresses.contains(&"genesisval3.synergy-network.io:5622".to_string()));
    }

    #[test]
    fn collect_known_peer_addresses_includes_validator_vpn_targets() {
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.p2p.public_address = "synv1validator7".to_string();
        config.network.additional_dial_targets = vec![
            "synv1validator1".to_string(),
            "10.70.20.1:5622".to_string(),
            "10.70.10.1:5622".to_string(),
            "192.168.1.2:5622".to_string(),
        ];
        config.network.validator_vpn_transports = vec![
            ValidatorVpnTransportConfig {
                validator_address: "synv1validator1".to_string(),
                dial_address: "10.70.10.1:5622".to_string(),
            },
            ValidatorVpnTransportConfig {
                validator_address: "synv1validator2".to_string(),
                dial_address: "10.70.10.2:5622".to_string(),
            },
        ];
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let discovered_targets: DialTargetsArc = Arc::new(Mutex::new(vec![
            "synv1validator2".to_string(),
            "10.70.10.2:5622".to_string(),
            "172.16.1.2:5622".to_string(),
        ]));

        let addresses =
            collect_known_peer_addresses(&connected_peers, &discovered_targets, &config);

        assert!(addresses.contains(&"synv1validator7".to_string()));
        assert!(addresses.contains(&"synv1validator1".to_string()));
        assert!(addresses.contains(&"synv1validator2".to_string()));
        assert!(!addresses.contains(&"10.70.20.1:5622".to_string()));
        assert!(!addresses.contains(&"10.70.10.1:5622".to_string()));
        assert!(!addresses.contains(&"10.70.10.2:5622".to_string()));
        assert!(!addresses.contains(&"192.168.1.2:5622".to_string()));
        assert!(!addresses.contains(&"172.16.1.2:5622".to_string()));
    }

    #[test]
    fn collect_known_peer_addresses_excludes_public_targets_for_vpn_validator() {
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.p2p.public_address = "synv1validator7".to_string();
        config.network.additional_dial_targets = vec![
            "genesisval1.synergy-network.io:5622".to_string(),
            "synv1validator1".to_string(),
            "10.70.10.1:5622".to_string(),
            "10.70.20.1:5622".to_string(),
        ];
        config.network.validator_vpn_transports = vec![
            ValidatorVpnTransportConfig {
                validator_address: "synv1validator1".to_string(),
                dial_address: "10.70.10.1:5622".to_string(),
            },
            ValidatorVpnTransportConfig {
                validator_address: "synv1validator2".to_string(),
                dial_address: "10.70.10.2:5622".to_string(),
            },
        ];

        let mut peers = HashMap::new();
        peers.insert(
            "public-validator".to_string(),
            PeerConnection {
                address: "62.146.182.208:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: Some("genesisval2.synergy-network.io:5622".to_string()),
                validator_address: Some("synv1public".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: Some("testnet-public".to_string()),
                handshake_role: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        let connected_peers = Arc::new(Mutex::new(peers));
        let discovered_targets: DialTargetsArc = Arc::new(Mutex::new(vec![
            "genesisval3.synergy-network.io:5622".to_string(),
            "synv1validator2".to_string(),
            "10.70.10.2:5622".to_string(),
        ]));

        let addresses =
            collect_known_peer_addresses(&connected_peers, &discovered_targets, &config);

        assert!(addresses.contains(&"synv1validator7".to_string()));
        assert!(addresses.contains(&"synv1validator1".to_string()));
        assert!(addresses.contains(&"synv1validator2".to_string()));
        assert!(!addresses.contains(&"10.70.20.1:5622".to_string()));
        assert!(!addresses.contains(&"10.70.10.1:5622".to_string()));
        assert!(!addresses.contains(&"10.70.10.2:5622".to_string()));
        assert!(!addresses.contains(&"genesisval1.synergy-network.io:5622".to_string()));
        assert!(!addresses.contains(&"genesisval2.synergy-network.io:5622".to_string()));
        assert!(!addresses.contains(&"genesisval3.synergy-network.io:5622".to_string()));
    }

    #[test]
    fn configured_validator_dials_exclude_validator_vpn_transport_routes() {
        let mut config = NodeConfig::default();
        config.network.persistent_peers = vec![
            "genesisval1.synergy-network.io:5622".to_string(),
            "10.69.0.1:5622".to_string(),
            "10.69.10.1:5622".to_string(),
            "10.69.11.2:5622".to_string(),
            "10.69.10.3:5623".to_string(),
            "192.168.1.2:5622".to_string(),
        ];

        let dials = configured_validator_p2p_dials(&config);

        assert_eq!(
            dials,
            vec!["genesisval1.synergy-network.io:5622".to_string()]
        );
    }

    #[test]
    fn vote_target_identity_recovers_from_configured_validator_public_address() {
        let validators = vec![
            "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs".to_string(),
            "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt".to_string(),
            "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string(),
            "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5".to_string(),
            "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f".to_string(),
            "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx".to_string(),
        ];
        let active_validator_addresses = validators.iter().cloned().collect::<HashSet<_>>();
        let mut config = NodeConfig::default();
        config.node.allowed_validator_addresses = validators.clone();
        config.network.persistent_peers = vec![
            "relay1.synergynode.xyz:5622".to_string(),
            "relay2.synergynode.xyz:5622".to_string(),
            "rpc.synergynode.xyz:5623".to_string(),
            "archive.synergynode.xyz:5615".to_string(),
            "62.146.182.207:5622".to_string(),
            "62.146.182.208:5622".to_string(),
            "62.146.182.209:5622".to_string(),
            "73.79.66.255:5622".to_string(),
            "194.163.183.166:5622".to_string(),
            "157.173.192.45:5622".to_string(),
        ];
        // Routes alone never identify a node; the topology supplies the explicit
        // endpoint -> `synv...` bindings.
        config.network.validator_vpn_transports = validators
            .iter()
            .cloned()
            .zip([
                "62.146.182.207:5622",
                "62.146.182.208:5622",
                "62.146.182.209:5622",
                "73.79.66.255:5622",
                "194.163.183.166:5622",
                "157.173.192.45:5622",
            ])
            .map(|(validator_address, dial)| ValidatorVpnTransportConfig {
                validator_address,
                dial_address: dial.to_string(),
            })
            .collect();

        let address_map =
            configured_validator_public_address_map(&config, &active_validator_addresses);

        assert_eq!(
            address_map.get("62.146.182.209:5622"),
            Some(&"synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string())
        );

        let peer = PeerConnection {
            address: "62.146.182.209:5622".to_string(),
            direction: ConnectionDirection::Outgoing,
            public_address: None,
            validator_address: None,
            connected_at: 0,
            last_seen: 0,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            connected_endpoint: None,
            node_id: None,
            handshake_role: None,
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            status_reported_at: None,
            status_validator_address: None,
            status_source_session_id: None,
            active_validator_set_hash: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };

        assert_eq!(
            recover_peer_validator_address_for_vote_target(
                &config,
                &peer,
                &active_validator_addresses,
            ),
            Some("synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string())
        );
    }

    /// Testnet-v3 peer identity: endpoints are ROUTES, `synv...` is IDENTITY.
    ///
    /// The retained production topology puts two distinct machines (Val4 and the
    /// archive validator) behind the same public endpoint 73.79.66.255:5622, so
    /// an endpoint may never designate a node on its own. A route resolves to an
    /// identity only through an explicit authenticated binding.
    #[test]
    fn validator_routes_resolve_only_through_explicit_node_identity_bindings() {
        let val1 = "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs".to_string();
        let val4 = "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5".to_string();
        let val6 = "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx".to_string();
        let validators = vec![val1.clone(), val4.clone(), val6.clone()];
        let active = validators.iter().cloned().collect::<HashSet<_>>();

        let mut config = NodeConfig::default();
        config.node.allowed_validator_addresses = validators;
        config.node.validator_address = val1.clone();
        config.p2p.public_address = "62.146.182.207:5622".to_string();
        // Routes only — these must NOT by themselves identify any node.
        config.network.persistent_peers = vec![
            "73.79.66.255:5622".to_string(),
            "157.173.192.45:5622".to_string(),
        ];

        let unbound = configured_validator_public_address_map(&config, &active);
        assert!(
            !unbound.contains_key("73.79.66.255:5622"),
            "a bare endpoint must never resolve to a node identity"
        );
        assert!(
            !unbound.contains_key("157.173.192.45:5622"),
            "a bare endpoint must never resolve to a node identity"
        );

        // Explicit binding: route -> authenticated node identity.
        config.network.validator_vpn_transports = vec![
            ValidatorVpnTransportConfig {
                validator_address: val4.clone(),
                dial_address: "73.79.66.255:5622".to_string(),
            },
            ValidatorVpnTransportConfig {
                validator_address: val6.clone(),
                dial_address: "157.173.192.45:5622".to_string(),
            },
        ];
        let bound = configured_validator_public_address_map(&config, &active);
        assert_eq!(bound.get("73.79.66.255:5622"), Some(&val4));
        assert_eq!(bound.get("157.173.192.45:5622"), Some(&val6));
        // The node identity itself always resolves to itself.
        assert_eq!(bound.get(val4.as_str()), Some(&val4));

        // A route claimed by two different identities is ambiguous and must
        // resolve to neither — this is the Val4 / archive-validator case.
        let mut shared = config.clone();
        shared
            .network
            .validator_vpn_transports
            .push(ValidatorVpnTransportConfig {
                validator_address: val1.clone(),
                dial_address: "73.79.66.255:5622".to_string(),
            });
        let shared_map = configured_validator_public_address_map(&shared, &active);
        assert!(
            !shared_map.contains_key("73.79.66.255:5622"),
            "an endpoint claimed by two identities must resolve to neither"
        );
        assert_eq!(shared_map.get(val1.as_str()), Some(&val1));
        assert_eq!(shared_map.get(val4.as_str()), Some(&val4));

        // Endpoint changes do not change identity.
        let mut moved = config.clone();
        moved.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: val4.clone(),
            dial_address: "203.0.113.77:5622".to_string(),
        }];
        let moved_map = configured_validator_public_address_map(&moved, &active);
        assert_eq!(moved_map.get("203.0.113.77:5622"), Some(&val4));
        assert_eq!(moved_map.get(val4.as_str()), Some(&val4));
        assert!(!moved_map.contains_key("73.79.66.255:5622"));

        // A validator outside the active set is never routable.
        let narrowed = [val1.clone()].into_iter().collect::<HashSet<_>>();
        let narrowed_map = configured_validator_public_address_map(&config, &narrowed);
        assert!(!narrowed_map.values().any(|v| v == &val4));
        assert!(!narrowed_map.contains_key("73.79.66.255:5622"));
    }

    /// The same public endpoint must never let one node impersonate another.
    #[test]
    fn shared_public_endpoint_cannot_impersonate_another_node_identity() {
        let val4 = "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5".to_string();
        let val5 = "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f".to_string();
        let active = [val4.clone(), val5.clone()]
            .into_iter()
            .collect::<HashSet<_>>();

        let mut config = NodeConfig::default();
        config.node.allowed_validator_addresses = vec![val4.clone(), val5.clone()];
        config.node.validator_address = val5.clone();
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: val4.clone(),
            dial_address: "73.79.66.255:5622".to_string(),
        }];

        // Correct route, but the peer asserts a different node identity: the
        // asserted identity wins and the route must not override it.
        let map = configured_validator_public_address_map(&config, &active);
        assert_eq!(map.get("73.79.66.255:5622"), Some(&val4));
        assert_ne!(map.get("73.79.66.255:5622"), Some(&val5));

        // Port reuse / ambiguity on the same host does not create identity.
        assert!(!map.contains_key("73.79.66.255:5615"));
        assert!(!map.contains_key("73.79.66.255"));
    }

    #[test]
    fn vote_target_identity_recovers_from_genesis_validator_node_id() {
        configure_canonical_genesis_path_for_tests();
        // `genesisval5` names genesis validator slot 5; the identity is taken
        // from the canonical genesis, never from the peer's endpoint.
        let validator = canonical_validator_address_for_slot(5)
            .expect("test fixture genesis must define validator slot 5");
        let active_validator_addresses = [validator.clone()].into_iter().collect::<HashSet<_>>();
        let config = NodeConfig::default();
        let peer = PeerConnection {
            address: "194.163.183.166:53988".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: None,
            validator_address: None,
            connected_at: 0,
            last_seen: 0,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            connected_endpoint: None,
            node_id: Some("genesisval5".to_string()),
            handshake_role: None,
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            status_reported_at: None,
            status_validator_address: None,
            status_source_session_id: None,
            active_validator_set_hash: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };

        assert_eq!(
            recover_peer_validator_address_for_vote_target(
                &config,
                &peer,
                &active_validator_addresses,
            ),
            Some(validator)
        );
    }

    #[test]
    fn validator_bootstrap_rejects_unsigned_public_validator_peers() {
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.node.validator_address = "synv1validator1".to_string();
        config.p2p.public_address = "genesisval1.synergy-network.io:5622".to_string();
        config.p2p.listen_address = "0.0.0.0:5622".to_string();
        config.network.persistent_peers = vec![
            "genesisval2.synergy-network.io:5622".to_string(),
            "62.146.182.208:5622".to_string(),
        ];

        let targets = resolve_bootstrap_dial_targets(&config);

        assert!(targets.is_empty());
    }

    #[test]
    fn public_support_nodes_only_dial_canonical_relayers() {
        for role in [
            "observer",
            "rpc_gateway",
            "archive_validator",
            "explorer_indexer",
            "bootnode",
            "seed_server",
        ] {
            let mut config = NodeConfig::default();
            config.identity.role = role.to_string();
            config.role.compiled_profile = role.to_string();
            config.role.services.clear();
            config.network.persistent_peers = vec![
                "relay1.synergynode.xyz:5622".to_string(),
                "relay2.synergynode.xyz:5622".to_string(),
                "relay3.synergynode.xyz:5622".to_string(),
                "62.146.182.207:5622".to_string(),
                "rpc.synergynode.xyz:5623".to_string(),
                "archive.synergynode.xyz:5615".to_string(),
            ];

            assert_eq!(
                resolve_bootstrap_dial_targets(&config),
                vec![
                    "relay1.synergynode.xyz:5622".to_string(),
                    "relay2.synergynode.xyz:5622".to_string(),
                    "relay3.synergynode.xyz:5622".to_string(),
                ],
                "role {role} must not dial validators or sibling support nodes"
            );
        }
    }

    #[test]
    fn relayers_can_dial_validators_and_public_support_nodes() {
        let mut config = NodeConfig::default();
        config.identity.role = "relayer".to_string();
        config.role.compiled_profile = "relayer".to_string();
        config.role.services.clear();
        config.network.persistent_peers = vec![
            "relay2.synergynode.xyz:5622".to_string(),
            "62.146.182.207:5622".to_string(),
            "rpc.synergynode.xyz:5623".to_string(),
            "archive.synergynode.xyz:5615".to_string(),
        ];

        let targets = resolve_bootstrap_dial_targets(&config);

        assert!(targets.contains(&"relay2.synergynode.xyz:5622".to_string()));
        assert!(targets.contains(&"62.146.182.207:5622".to_string()));
        assert!(targets.contains(&"rpc.synergynode.xyz:5623".to_string()));
        assert!(targets.contains(&"archive.synergynode.xyz:5615".to_string()));
    }

    #[test]
    fn http_seed_endpoints_never_become_p2p_dial_targets() {
        let configured_seed_endpoints = configured_seed_server_dial_targets(&[
            "http://seed1.synergy-network.io:5621".to_string(),
            "https://seed2.synergy-network.io:5621/peer-list.json".to_string(),
        ]);
        let mut targets = HashSet::new();

        insert_seed_server_target(
            &mut targets,
            &configured_seed_endpoints,
            "seed1.synergy-network.io:5621".to_string(),
        );
        insert_seed_server_target(
            &mut targets,
            &configured_seed_endpoints,
            "seed2.synergy-network.io:5621".to_string(),
        );
        insert_seed_server_target(
            &mut targets,
            &configured_seed_endpoints,
            "genesisval1.synergy-network.io:5622".to_string(),
        );

        assert_eq!(
            targets,
            HashSet::from(["genesisval1.synergy-network.io:5622".to_string()])
        );
    }

    #[test]
    fn resolve_bootstrap_dial_targets_excludes_self_genesis_alias_but_keeps_other_validators() {
        let temp = crate::utils::test_temp_root(format!(
            "synergy-networking-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be monotonic")
                .as_nanos()
        ));
        fs::create_dir_all(&temp).expect("temp dir");
        let workspace = temp.join("validator-workspace");
        let config_dir = workspace.join("config");
        let data_dir = workspace.join("data");
        fs::create_dir_all(&config_dir).expect("config dir");
        fs::create_dir_all(&data_dir).expect("data dir");

        fs::write(
            config_dir.join("operational-manifest.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "validators": [
                    {"address": "synv1validator1", "slot": 1},
                    {"address": "synv1validator5", "slot": 5}
                ]
            }))
            .expect("manifest should serialize"),
        )
        .expect("manifest should write");

        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.storage.path = data_dir.to_string_lossy().to_string();
        config.network.p2p_port = 5622;
        config.p2p.public_address = "62.146.182.207:5622".to_string();
        config.p2p.listen_address = "0.0.0.0:5622".to_string();
        config.node.validator_address = "synv1validator1".to_string();
        config.network.additional_dial_targets = vec![
            "genesisval1.synergy-network.io:5622".to_string(),
            "genesisval5.synergy-network.io:5622".to_string(),
        ];

        let targets = resolve_bootstrap_dial_targets(&config);

        assert!(!targets.contains(&"genesisval1.synergy-network.io:5622".to_string()));
        assert!(!targets.contains(&"genesisval5.synergy-network.io:5622".to_string()));

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn resolve_bootstrap_dial_targets_keeps_lower_and_higher_vpn_validators() {
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.node.validator_address = "synv1validator2".to_string();
        config.p2p.public_address = "synv1validator2".to_string();
        config.network.validator_vpn_transports = vec![
            ValidatorVpnTransportConfig {
                validator_address: "synv1validator1".to_string(),
                dial_address: "10.70.10.1:5622".to_string(),
            },
            ValidatorVpnTransportConfig {
                validator_address: "synv1validator3".to_string(),
                dial_address: "10.70.10.3:5622".to_string(),
            },
        ];
        config.network.bootnodes = vec![
            "genesisval1.synergy-network.io:5622".to_string(),
            "10.70.10.1:5622".to_string(),
        ];
        config.network.additional_dial_targets = vec![
            "genesisval3.synergy-network.io:5622".to_string(),
            "synv1validator1".to_string(),
            "10.70.20.1:5622".to_string(),
            "synv1validator2".to_string(),
        ];
        config.network.persistent_peers = vec!["synv1validator3".to_string()];

        let targets = resolve_bootstrap_dial_targets(&config);

        assert_eq!(
            targets,
            vec![
                "10.70.20.1:5622".to_string(),
                "synv1validator1".to_string(),
                "synv1validator3".to_string(),
            ]
        );
    }

    #[test]
    fn collect_known_peer_addresses_excludes_unassigned_outgoing_ip_targets() {
        let mut config = NodeConfig::default();
        config.identity.role = "relayer".to_string();
        config.role.compiled_profile = "relayer_node".to_string();
        let mut peers = HashMap::new();
        peers.insert(
            "incoming".to_string(),
            PeerConnection {
                address: "62.146.182.209:54792".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: None,
                validator_address: Some("synv1incoming".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: Some("testnet-incoming".to_string()),
                handshake_role: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "outgoing".to_string(),
            PeerConnection {
                address: "62.146.182.209:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: Some("genesisval3.synergy-network.io:5622".to_string()),
                validator_address: Some("synv1outgoing".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: Some("testnet-outgoing".to_string()),
                handshake_role: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        let connected_peers = Arc::new(Mutex::new(peers));
        let discovered_targets: DialTargetsArc = Arc::new(Mutex::new(Vec::new()));

        let addresses =
            collect_known_peer_addresses(&connected_peers, &discovered_targets, &config);

        assert!(!addresses.contains(&"62.146.182.209:54792".to_string()));
        assert!(!addresses.contains(&"62.146.182.209:5622".to_string()));
        assert!(addresses.contains(&"genesisval3.synergy-network.io:5622".to_string()));
    }

    #[test]
    fn peer_has_identifying_metadata_requires_announced_identity_fields() {
        let unidentified = PeerConnection {
            address: "62.146.182.208:54001".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: None,
            validator_address: None,
            connected_at: 0,
            last_seen: 0,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            connected_endpoint: None,
            node_id: None,
            handshake_role: None,
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            status_reported_at: None,
            status_validator_address: None,
            status_source_session_id: None,
            active_validator_set_hash: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };
        let identified = PeerConnection {
            address: "62.146.182.208:5622".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: Some("genesisval2.synergy-network.io:5622".to_string()),
            validator_address: Some("synv1peer-a".to_string()),
            connected_at: 0,
            last_seen: 0,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            connected_endpoint: None,
            node_id: Some("testnet-peer-a".to_string()),
            handshake_role: None,
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            status_reported_at: None,
            status_validator_address: None,
            status_source_session_id: None,
            active_validator_set_hash: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };

        assert!(!peer_has_identifying_metadata(&unidentified));
        assert!(peer_has_identifying_metadata(&identified));
    }

    #[test]
    fn pending_incoming_connection_limit_ignores_identified_peers_from_same_host() {
        let mut peers = HashMap::new();
        peers.insert(
            "bootnode2".to_string(),
            PeerConnection {
                address: "62.146.182.208:5620".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: Some("bootnode2.synergy-network.io:5620".to_string()),
                validator_address: None,
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: Some("bootnode2".to_string()),
                handshake_role: None,
                version: Some("1.0.0".to_string()),
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "validator2-stable".to_string(),
            PeerConnection {
                address: "62.146.182.208:5622".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: Some("genesisval2.synergy-network.io:5622".to_string()),
                validator_address: Some("synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: Some("genesisval2".to_string()),
                handshake_role: None,
                version: Some("1.0.0".to_string()),
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "validator2-reconnect".to_string(),
            PeerConnection {
                address: "62.146.182.208:54001".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: None,
                validator_address: None,
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: None,
                handshake_role: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );

        assert_eq!(
            pending_incoming_connections_from_host(&peers, "62.146.182.208"),
            1
        );
    }

    #[test]
    fn peer_entry_guard_removes_pending_peer_on_drop() {
        let _session_guard = peer_session_test_guard();
        let peer_address = "62.146.182.208:54001".to_string();
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        connected_peers.lock().unwrap().insert(
            peer_address.clone(),
            PeerConnection {
                address: peer_address.clone(),
                direction: ConnectionDirection::Incoming,
                public_address: None,
                validator_address: None,
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: None,
                handshake_role: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let session_id = super::begin_peer_session(&peer_address);

        {
            let _guard = PeerEntryGuard::new(
                peer_address.clone(),
                session_id,
                Arc::clone(&connected_peers),
                Arc::clone(&peer_state_cache),
            );
        }

        assert!(!connected_peers.lock().unwrap().contains_key(&peer_address));
    }

    #[test]
    fn disconnecting_peer_removes_peer_write_gate() {
        let peer_address = "gate-cleanup-peer".to_string();
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let mut peer = test_peer_with_validator_address(None);
        peer.address = peer_address.clone();
        connected_peers
            .lock()
            .unwrap()
            .insert(peer_address.clone(), peer);
        let _gate = peer_write_gate(&peer_address);
        assert!(PEER_WRITE_GATES.lock().unwrap().contains_key(&peer_address));

        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let mut peers = connected_peers.lock().unwrap();
        disconnect_peer_entry(&peer_state_cache, &mut peers, &peer_address);
        drop(peers);

        assert!(!PEER_WRITE_GATES.lock().unwrap().contains_key(&peer_address));
    }

    #[test]
    fn empty_remote_genesis_hash_is_allowed_for_discovery_peer() {
        assert!(!should_disconnect_for_status_genesis_mismatch(
            "local-hash",
            "",
            None,
        ));
    }

    #[test]
    fn empty_remote_genesis_hash_disconnects_validator_peer() {
        assert!(should_disconnect_for_status_genesis_mismatch(
            "local-hash",
            "",
            Some("synv1validator"),
        ));
    }

    #[test]
    fn mismatched_nonempty_remote_genesis_hash_disconnects_peer() {
        assert!(should_disconnect_for_status_genesis_mismatch(
            "local-hash",
            "remote-hash",
            None,
        ));
    }

    #[test]
    fn matching_remote_genesis_hash_is_allowed_for_validator_peer() {
        assert!(!should_disconnect_for_status_genesis_mismatch(
            "local-hash",
            "local-hash",
            Some("synv1validator"),
        ));
    }

    #[test]
    fn local_status_uses_canonical_genesis_for_compact_chain() {
        configure_canonical_genesis_path_for_tests();
        let canonical_hash = canonical_genesis_hash();
        assert!(!canonical_hash.is_empty());

        let mut chain = BlockChain::new();
        let mut retained = Block::new_with_timestamp(
            123,
            Vec::new(),
            "retained-parent".to_string(),
            "validator".to_string(),
            0,
            1,
        );
        retained.hash = "retained-block-hash".to_string();
        chain.chain.push(retained);

        let blockchain = Arc::new(Mutex::new(chain));
        let config = NodeConfig::default();
        let status = build_local_status_message(&blockchain, &config);

        let NetworkMessage::Status {
            block_height,
            best_block_hash,
            genesis_hash,
            ..
        } = status
        else {
            panic!("local status should build a status message");
        };

        assert_eq!(block_height, 123);
        assert_eq!(best_block_hash, "retained-block-hash");
        assert_eq!(genesis_hash, canonical_hash);
    }

    #[test]
    fn validator_chain_data_waits_for_status_without_disconnect() {
        let _session_guard = peer_session_test_guard();
        configure_canonical_genesis_path_for_tests();
        let mut chain = BlockChain::new();
        chain.genesis().expect("genesis block should load");
        let blockchain = Arc::new(Mutex::new(chain));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));

        connected_peers.lock().unwrap().insert(
            "peer-pending".to_string(),
            PeerConnection {
                address: "peer-pending".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: None,
                validator_address: Some("synv1validator".to_string()),
                connected_at: current_timestamp(),
                last_seen: current_timestamp(),
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: Some("validator-pending".to_string()),
                handshake_role: None,
                version: Some("1.0.0".to_string()),
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        let session_id = super::begin_peer_session("peer-pending");

        assert!(!ensure_peer_status_allows_chain_data(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            "peer-pending",
            session_id,
            "blocks",
        ));
        assert!(connected_peers.lock().unwrap().contains_key("peer-pending"));
    }

    #[test]
    fn chain_data_disconnects_peer_with_mismatched_genesis() {
        let _session_guard = peer_session_test_guard();
        configure_canonical_genesis_path_for_tests();
        let mut chain = BlockChain::new();
        chain.genesis().expect("genesis block should load");
        let blockchain = Arc::new(Mutex::new(chain));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));

        connected_peers.lock().unwrap().insert(
            "peer-mismatch".to_string(),
            PeerConnection {
                address: "peer-mismatch".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: None,
                validator_address: Some("synv1validator".to_string()),
                connected_at: current_timestamp(),
                last_seen: current_timestamp(),
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: Some("validator-mismatch".to_string()),
                handshake_role: None,
                version: Some("1.0.0".to_string()),
                capabilities: Vec::new(),
                last_known_height: 10,
                best_block_hash: "remote-tip".to_string(),
                genesis_hash: "remote-hash".to_string(),
                status_received_at: Some(current_timestamp()),
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        let session_id = super::begin_peer_session("peer-mismatch");

        assert!(!ensure_peer_status_allows_chain_data(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            "peer-mismatch",
            session_id,
            "block",
        ));
        assert!(!connected_peers
            .lock()
            .unwrap()
            .contains_key("peer-mismatch"));
    }

    #[test]
    fn empty_local_genesis_hash_does_not_force_disconnect() {
        assert!(!should_disconnect_for_status_genesis_mismatch(
            "",
            "remote-hash",
            Some("synv1validator"),
        ));
    }

    #[test]
    fn status_sync_batch_only_requests_blocks_for_ahead_peer() {
        let mut validator_config = NodeConfig::default();
        validator_config.identity.role = "validator".to_string();

        assert_eq!(status_sync_batch(&validator_config, 10, 10), None);
        assert_eq!(
            status_sync_batch(&validator_config, 11, 10),
            Some(IMMEDIATE_STATUS_SYNC_BATCH)
        );
        assert_eq!(
            status_sync_batch(&validator_config, 2_500, 1_000),
            Some(MAX_STATUS_SYNC_BATCH)
        );
        assert_eq!(
            status_sync_batch(&validator_config, 7_000, 1_000),
            Some(MAX_STATUS_SYNC_BATCH)
        );
    }

    #[test]
    fn service_sync_batch_uses_support_peer_budget() {
        let service_config = NodeConfig::default();

        assert!(!local_node_runs_validator_consensus(&service_config));
        assert_eq!(
            sync_batch_limit_for_role(&service_config),
            MAX_SUPPORT_NODE_BLOCK_SYNC_RESPONSE_BLOCKS
        );
        assert_eq!(
            status_sync_batch(&service_config, 1_001, 1_000),
            Some(MAX_SUPPORT_NODE_BLOCK_SYNC_RESPONSE_BLOCKS)
        );
    }

    #[test]
    fn service_statuses_admit_only_one_global_block_sync_request() {
        let _service_sync_guard = service_sync_test_guard();
        let Some((client_a, mut server_a)) = service_sync_test_connection() else {
            return;
        };
        let Some((client_b, mut server_b)) = service_sync_test_connection() else {
            return;
        };

        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        connected_peers.lock().unwrap().insert(
            "peer-a".to_string(),
            service_sync_test_peer(client_a, "peer-a", "validator-a", 500),
        );
        connected_peers.lock().unwrap().insert(
            "peer-b".to_string(),
            service_sync_test_peer(client_b, "peer-b", "validator-b", 500),
        );
        let session_a = begin_peer_session("peer-a");
        let session_b = begin_peer_session("peer-b");
        let config = service_sync_test_config();
        let genesis_hash = canonical_genesis_hash();

        {
            let peers = connected_peers.lock().unwrap();
            assert!(peer_is_designated_support_sync_source(
                &config,
                peers.get("peer-a").expect("peer-a should be connected"),
            ));
            assert!(super::peer_is_eligible_block_sync_source_for_local(
                &config,
                peers.get("peer-a").expect("peer-a should be connected"),
            ));
        }
        handle_status_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
            "peer-a",
            session_a,
            500,
            "hash-a",
            &genesis_hash,
            Some(current_timestamp()),
            Some("validator-a"),
            Some("peer-a"),
            Some("test-validator-set"),
            false,
            false,
            None,
        );
        handle_status_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
            "peer-b",
            session_b,
            500,
            "hash-b",
            &genesis_hash,
            Some(current_timestamp()),
            Some("validator-b"),
            Some("peer-b"),
            Some("test-validator-set"),
            false,
            false,
            None,
        );

        assert!(matches!(
            receive_message(&mut server_a).expect("first service status should request blocks"),
            NetworkMessage::GetBlocks { .. }
        ));
        assert!(receive_message(&mut server_b).is_err());
        assert!(service_sync_claim_response("peer-a", session_a, &[]).is_some());
        reset_service_sync_coordinator_for_tests();
    }

    #[test]
    fn service_sync_completion_immediately_requests_the_next_range() {
        let _service_sync_guard = service_sync_test_guard();
        let Some((client_a, mut server_a)) = service_sync_test_connection() else {
            return;
        };

        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        connected_peers.lock().unwrap().insert(
            "peer-a".to_string(),
            service_sync_test_peer(client_a, "peer-a", "validator-a", 500),
        );
        let session_a = begin_peer_session("peer-a");
        let config = service_sync_test_config();
        let started = service_sync_request_from_status(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
        );
        assert!(started);
        assert!(matches!(
            receive_message(&mut server_a).expect("initial request should be sent"),
            NetworkMessage::GetBlocks { .. }
        ));
        let generation = service_sync_claim_response("peer-a", session_a, &[])
            .expect("initial request should hold the service reservation");

        service_sync_release_and_reassign(
            generation,
            Some(service_sync_identity("peer-a", session_a)),
            true,
        );

        assert!(matches!(
            receive_message(&mut server_a).expect("successful apply should continue immediately"),
            NetworkMessage::GetBlocks { .. }
        ));
        reset_service_sync_coordinator_for_tests();
    }

    #[test]
    fn service_block_response_releases_apply_slot_after_ordered_apply() {
        let _service_sync_guard = service_sync_test_guard();
        let Some((client_a, mut server_a)) = service_sync_test_connection() else {
            return;
        };

        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        connected_peers.lock().unwrap().insert(
            "peer-a".to_string(),
            service_sync_test_peer(client_a, "peer-a", "validator-a", 500),
        );
        let session_a = begin_peer_session("peer-a");
        let config = service_sync_test_config();
        assert!(service_sync_request_from_status(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
        ));
        assert!(matches!(
            receive_message(&mut server_a).expect("initial request should be sent"),
            NetworkMessage::GetBlocks { .. }
        ));

        let (message_sender, _message_receiver) = mpsc::channel();
        dispatch_peer_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &message_sender,
            &config,
            "peer-a",
            session_a,
            NetworkMessage::Blocks {
                blocks: Vec::new(),
                quorum_certificates: Vec::new(),
            },
        )
        .expect("service block response should dispatch");

        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            let coordinator_released = SERVICE_SYNC_COORDINATOR.lock().unwrap().in_flight.is_none();
            let apply_slot_released = !BLOCK_SYNC_APPLY_ACTIVE
                .lock()
                .unwrap()
                .contains(&("peer-a".to_string(), session_a));
            if coordinator_released && apply_slot_released {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }

        assert!(SERVICE_SYNC_COORDINATOR.lock().unwrap().in_flight.is_none());
        assert!(!BLOCK_SYNC_APPLY_ACTIVE
            .lock()
            .unwrap()
            .contains(&("peer-a".to_string(), session_a)));
    }

    #[test]
    fn completed_service_apply_does_not_release_next_batch_slot() {
        let _service_sync_guard = service_sync_test_guard();
        let Some((client_a, mut server_a)) = service_sync_test_connection() else {
            return;
        };

        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        connected_peers.lock().unwrap().insert(
            "peer-a".to_string(),
            service_sync_test_peer(client_a, "peer-a", "validator-a", 500),
        );
        let session_a = begin_peer_session("peer-a");
        let config = service_sync_test_config();
        assert!(service_sync_request_from_status(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
        ));
        assert!(matches!(
            receive_message(&mut server_a).expect("initial request should be sent"),
            NetworkMessage::GetBlocks { .. }
        ));
        let generation = service_sync_claim_response("peer-a", session_a, &[])
            .expect("initial response should claim the service flight");
        assert!(reserve_block_sync_peer(
            &BLOCK_SYNC_APPLY_ACTIVE,
            "peer-a",
            session_a
        ));

        release_block_sync_peer(&BLOCK_SYNC_APPLY_ACTIVE, "peer-a", session_a);
        service_sync_release_and_reassign(
            generation,
            Some(service_sync_identity("peer-a", session_a)),
            true,
        );
        assert!(matches!(
            receive_message(&mut server_a).expect("next request should be sent"),
            NetworkMessage::GetBlocks { .. }
        ));
        assert!(service_sync_claim_response("peer-a", session_a, &[]).is_some());
        assert!(reserve_block_sync_peer(
            &BLOCK_SYNC_APPLY_ACTIVE,
            "peer-a",
            session_a
        ));

        release_block_sync_apply_slot_after_worker("peer-a", session_a, Some(generation), true);
        let next_apply_slot_survives_old_worker_release = BLOCK_SYNC_APPLY_ACTIVE
            .lock()
            .unwrap()
            .contains(&("peer-a".to_string(), session_a));
        release_block_sync_peer(&BLOCK_SYNC_APPLY_ACTIVE, "peer-a", session_a);
        reset_service_sync_coordinator_for_tests();

        assert!(
            next_apply_slot_survives_old_worker_release,
            "the completed worker must not clear the next service flight's apply reservation"
        );
    }

    #[test]
    fn service_sync_timeout_releases_and_reassigns_the_source() {
        let _service_sync_guard = service_sync_test_guard();
        let Some((client_a, mut server_a)) = service_sync_test_connection() else {
            return;
        };
        let Some((client_b, mut server_b)) = service_sync_test_connection() else {
            return;
        };

        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        connected_peers.lock().unwrap().insert(
            "peer-a".to_string(),
            service_sync_test_peer(client_a, "peer-a", "validator-a", 500),
        );
        connected_peers.lock().unwrap().insert(
            "peer-b".to_string(),
            service_sync_test_peer(client_b, "peer-b", "validator-b", 500),
        );
        let _session_a = begin_peer_session("peer-a");
        let session_b = begin_peer_session("peer-b");
        let config = service_sync_test_config();
        assert!(service_sync_request_from_status(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
        ));
        assert!(matches!(
            receive_message(&mut server_a).expect("failed source should have the initial request"),
            NetworkMessage::GetBlocks { .. }
        ));
        {
            let mut coordinator = SERVICE_SYNC_COORDINATOR.lock().unwrap();
            let flight = coordinator
                .in_flight
                .as_mut()
                .expect("initial request should hold the service reservation");
            flight.phase_started_at =
                Instant::now() - Duration::from_secs(SERVICE_BLOCK_SYNC_RESPONSE_TIMEOUT_SECS + 1);
        }
        assert!(service_sync_request_from_status(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
        ));

        assert!(matches!(
            receive_message(&mut server_b).expect("timeout should reassign to another source"),
            NetworkMessage::GetBlocks { .. }
        ));
        assert!(service_sync_claim_response("peer-b", session_b, &[]).is_some());
        reset_service_sync_coordinator_for_tests();
    }

    #[test]
    fn service_sync_response_timeout_allows_qc_warmup_without_source_churn() {
        const OBSERVED_QC_WARMUP_SECS: u64 = 70;

        let _service_sync_guard = service_sync_test_guard();
        let Some((client_a, mut server_a)) = service_sync_test_connection() else {
            return;
        };
        let Some((client_b, mut server_b)) = service_sync_test_connection() else {
            return;
        };

        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        connected_peers.lock().unwrap().insert(
            "peer-a".to_string(),
            service_sync_test_peer(client_a, "peer-a", "validator-a", 500),
        );
        connected_peers.lock().unwrap().insert(
            "peer-b".to_string(),
            service_sync_test_peer(client_b, "peer-b", "validator-b", 500),
        );
        let session_a = begin_peer_session("peer-a");
        let session_b = begin_peer_session("peer-b");
        let config = service_sync_test_config();
        assert!(SERVICE_BLOCK_SYNC_RESPONSE_TIMEOUT_SECS > OBSERVED_QC_WARMUP_SECS);

        assert!(service_sync_request_from_status(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
        ));
        assert!(matches!(
            receive_message(&mut server_a).expect("initial request should be sent"),
            NetworkMessage::GetBlocks { .. }
        ));

        {
            let mut coordinator = SERVICE_SYNC_COORDINATOR.lock().unwrap();
            let flight = coordinator
                .in_flight
                .as_mut()
                .expect("initial request should hold the service reservation");
            flight.phase_started_at = Instant::now() - Duration::from_secs(OBSERVED_QC_WARMUP_SECS);
        }
        assert!(!service_sync_request_from_status(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
        ));
        assert!(
            receive_message(&mut server_b).is_err(),
            "a valid response during QC warm-up must not rotate to another source"
        );

        {
            let mut coordinator = SERVICE_SYNC_COORDINATOR.lock().unwrap();
            let flight = coordinator
                .in_flight
                .as_mut()
                .expect("warm-up request should still hold the service reservation");
            flight.phase_started_at =
                Instant::now() - Duration::from_secs(SERVICE_BLOCK_SYNC_RESPONSE_TIMEOUT_SECS + 1);
        }
        assert!(service_sync_request_from_status(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
        ));
        assert!(matches!(
            receive_message(&mut server_b).expect("expired response should fail over"),
            NetworkMessage::GetBlocks { .. }
        ));
        assert!(service_sync_claim_response("peer-b", session_b, &[]).is_some());
        assert!(service_sync_claim_response("peer-a", session_a, &[]).is_none());
        reset_service_sync_coordinator_for_tests();
    }

    #[test]
    fn validator_status_sync_keeps_independent_requests_and_consensus_role() {
        let _service_sync_guard = service_sync_test_guard();
        let Some((client_a, mut server_a)) = service_sync_test_connection() else {
            return;
        };
        let Some((client_b, mut server_b)) = service_sync_test_connection() else {
            return;
        };

        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        connected_peers.lock().unwrap().insert(
            "peer-a".to_string(),
            service_sync_test_peer(client_a, "peer-a", "validator-a", 500),
        );
        connected_peers.lock().unwrap().insert(
            "peer-b".to_string(),
            service_sync_test_peer(client_b, "peer-b", "validator-b", 500),
        );
        let session_a = begin_peer_session("peer-a");
        let session_b = begin_peer_session("peer-b");
        let mut config = service_sync_test_config();
        config.identity.role = "validator".to_string();
        let genesis_hash = canonical_genesis_hash();

        handle_status_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
            "peer-a",
            session_a,
            500,
            "hash-a",
            &genesis_hash,
            Some(current_timestamp()),
            Some("validator-a"),
            Some("peer-a"),
            Some("test-validator-set"),
            false,
            false,
            None,
        );
        handle_status_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
            "peer-b",
            session_b,
            500,
            "hash-b",
            &genesis_hash,
            Some(current_timestamp()),
            Some("validator-b"),
            Some("peer-b"),
            Some("test-validator-set"),
            false,
            false,
            None,
        );

        assert!(local_node_runs_validator_consensus(&config));
        assert!(!local_node_uses_service_batch_durability(&config));
        assert!(matches!(
            receive_message(&mut server_a).expect("validator A should request blocks"),
            NetworkMessage::GetBlocks { .. }
        ));
        assert!(matches!(
            receive_message(&mut server_b)
                .expect("validator B should request blocks independently"),
            NetworkMessage::GetBlocks { .. }
        ));
        reset_service_sync_coordinator_for_tests();
    }

    #[test]
    fn block_sync_request_range_includes_reconciliation_overlap() {
        assert_eq!(block_sync_request_range(10, 10, 500), None);
        assert_eq!(block_sync_request_range(0, 12, 500), Some((0, 13)));
        assert_eq!(
            block_sync_request_range(20_657, 20_735, 500),
            Some((20_655, 81))
        );
        assert_eq!(
            block_sync_request_range(10_000, 20_000, 2_000),
            Some((9_998, 2_003))
        );
    }

    #[test]
    fn block_sync_request_range_progresses_with_support_response_cap() {
        let local_height = 3;
        let (from_height, count) =
            block_sync_request_range(local_height, 1_080, MAX_STATUS_SYNC_BATCH).unwrap();

        assert!(from_height <= local_height);
        assert!(
            from_height + count as u64 - 1 > local_height,
            "first throttled validator response must include at least one block above local height"
        );
        assert!(count <= MAX_VALIDATOR_SUPPORT_SYNC_RESPONSE_BLOCKS);
    }

    #[test]
    fn block_sync_request_range_can_disable_overlap_for_compact_snapshot_chain() {
        assert_eq!(
            block_sync_request_range_with_overlap(743_026, 743_122, 96, false),
            Some((743_026, 97))
        );
    }

    #[test]
    fn block_sync_overlap_requires_contiguous_local_window() {
        let mut compact_chain = BlockChain::new();
        let mut retained_tip = Block::new_with_timestamp(
            743_026,
            Vec::new(),
            "snapshot-parent".to_string(),
            "validator".to_string(),
            0,
            743_026,
        );
        retained_tip.hash = "snapshot-tip".to_string();
        compact_chain.chain.push(retained_tip);

        assert!(!chain_has_block_sync_overlap(&compact_chain, 743_026, 96));

        let mut contiguous_chain = BlockChain::new();
        for height in 743_024..=743_026 {
            let mut block = Block::new_with_timestamp(
                height,
                Vec::new(),
                format!("parent-{height}"),
                "validator".to_string(),
                0,
                height,
            );
            block.hash = format!("hash-{height}");
            contiguous_chain.chain.push(block);
        }

        assert!(chain_has_block_sync_overlap(&contiguous_chain, 743_026, 96));
    }

    #[test]
    fn block_sync_response_selection_seeks_into_compact_chain_window() {
        let mut chain = BlockChain::new();
        for height in 261_825..261_835 {
            let mut block = Block::new_with_timestamp(
                height,
                Vec::new(),
                format!("parent-{height}"),
                "validator".to_string(),
                0,
                height,
            );
            block.hash = format!("hash-{height}");
            chain.chain.push(block);
        }

        let selected = select_block_sync_response_blocks(&chain, 261_829, 4);
        assert_eq!(
            selected
                .iter()
                .map(|block| block.block_index)
                .collect::<Vec<_>>(),
            vec![261_829, 261_830, 261_831, 261_832]
        );

        let before_window = select_block_sync_response_blocks(&chain, 0, 2);
        assert_eq!(
            before_window
                .iter()
                .map(|block| block.block_index)
                .collect::<Vec<_>>(),
            vec![261_825, 261_826]
        );

        assert!(select_block_sync_response_blocks(&chain, 999_999, 4).is_empty());
    }

    #[test]
    fn vote_messages_bypass_the_shared_message_queue() {
        let vote = Vote {
            validator_address: "synv1peer-a".to_string(),
            block_hash: "block-hash".to_string(),
            block_index: 7,
            epoch_number: 2,
            round_number: 1,
            signature: PQCSignature {
                algorithm: PQCAlgorithm::FNDSA,
                signature_data: vec![1, 2, 3],
                message_hash: vec![7, 8, 9],
                public_key_id: "peer-a".to_string(),
                created_at: 123,
            },
            signer_public_key: vec![4, 5, 6],
            timestamp: 123,
        };
        assert!(bypasses_shared_message_queue(&NetworkMessage::Vote {
            vote: vote.clone(),
        }));
        assert!(bypasses_shared_message_queue(
            &NetworkMessage::VoteRequest {
                block_data: Block::new(
                    0,
                    Vec::new(),
                    "genesis".to_string(),
                    "synv1leader".to_string(),
                    0
                ),
                epoch_number: 0,
                round_number: 1,
            }
        ));
        assert!(bypasses_shared_message_queue(&NetworkMessage::GetBlocks {
            from_height: 10,
            count: 25,
        }));
        assert!(bypasses_shared_message_queue(&NetworkMessage::Blocks {
            blocks: vec![Block::new(
                1,
                Vec::new(),
                "genesis".to_string(),
                "synv1leader".to_string(),
                1,
            )],
            quorum_certificates: Vec::new(),
        }));
        assert!(bypasses_shared_message_queue(&NetworkMessage::Block {
            block_data: Block::new(
                1,
                Vec::new(),
                "genesis".to_string(),
                "synv1leader".to_string(),
                1,
            ),
            quorum_certificate: None,
        }));
        assert!(!bypasses_shared_message_queue(&NetworkMessage::Status {
            block_height: 1,
            best_block_hash: "tip".to_string(),
            genesis_hash: "genesis".to_string(),
            status_timestamp: Some(1),
            validator_address: Some("synv1leader".to_string()),
            source_session_id: Some("test-session".to_string()),
            active_validator_set_hash: Some("test-validator-set".to_string()),
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        }));
    }

    #[test]
    fn vote_request_parent_validation_requires_next_canonical_tip() {
        let local_tip = (7, "tip-hash".to_string());
        let valid_proposal = Block::new(
            8,
            Vec::new(),
            "tip-hash".to_string(),
            "synv1leader".to_string(),
            1,
        );
        assert!(validate_vote_request_extends_local_tip(Some(&local_tip), &valid_proposal).is_ok());

        let future_proposal = Block::new(
            9,
            Vec::new(),
            "tip-hash".to_string(),
            "synv1leader".to_string(),
            2,
        );
        assert!(
            validate_vote_request_extends_local_tip(Some(&local_tip), &future_proposal)
                .expect_err("future proposals should be rejected")
                .contains("does not extend local tip")
        );

        let bad_parent = Block::new(
            8,
            Vec::new(),
            "other-parent".to_string(),
            "synv1leader".to_string(),
            3,
        );
        assert!(
            validate_vote_request_extends_local_tip(Some(&local_tip), &bad_parent)
                .expect_err("wrong parents should be rejected")
                .contains("parent hash")
        );
    }

    #[test]
    fn vote_request_parent_sync_range_ignores_stale_vote_requests() {
        assert_eq!(vote_request_parent_sync_range(21102, 21102), None);
        assert_eq!(vote_request_parent_sync_range(21102, 21101), None);
        assert_eq!(vote_request_parent_sync_range(21102, 21103), None);
        assert_eq!(
            vote_request_parent_sync_range(21102, 21110),
            Some((21103, 7))
        );
    }

    #[test]
    fn future_blocks_are_cached_and_applied_when_parent_arrives() {
        let _guard = block_application_test_guard();

        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis".to_string(),
            "synv1leader".to_string(),
            0,
            100,
        );
        let block_one = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            1,
            102,
        );
        let block_two = signed_block(
            2,
            Vec::new(),
            block_one.hash.clone(),
            "synv1leader".to_string(),
            2,
            104,
        );
        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        let blockchain = Arc::new(Mutex::new(chain));

        let block_two_qc = test_quorum_certificate(&block_two);
        assert!(!apply_block_if_new(
            &blockchain,
            block_two.clone(),
            Some(block_two_qc)
        ));
        assert_eq!(blockchain.lock().unwrap().last().unwrap().block_index, 0);

        let block_one_qc = test_quorum_certificate(&block_one);
        assert!(apply_block_if_new(
            &blockchain,
            block_one,
            Some(block_one_qc)
        ));
        let chain = blockchain.lock().unwrap();
        assert_eq!(chain.last().unwrap().block_index, 2);
        assert_eq!(chain.last().unwrap().hash, block_two.hash);
        drop(chain);

        PENDING_BLOCKS.lock().unwrap().clear();
        clear_legacy_canonical_locks_for_tests();
    }

    #[test]
    fn unsigned_network_block_is_rejected() {
        let _guard = block_application_test_guard();

        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis".to_string(),
            "synv1leader".to_string(),
            0,
            100,
        );
        let unsigned_block = Block::new_with_timestamp(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            1,
            102,
        );
        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        let blockchain = Arc::new(Mutex::new(chain));

        assert!(!apply_block_if_new(&blockchain, unsigned_block, None));
        assert_eq!(blockchain.lock().unwrap().last().unwrap().block_index, 0);
    }

    #[test]
    fn unfunded_activation_is_rejected_before_peer_block_append_or_quarantine() {
        let _guard = block_application_test_guard();
        let quarantine_path = crate::utils::resolve_data_path("data/validator_quarantine.json");
        let previous_quarantine = fs::read(&quarantine_path).ok();
        let _ = fs::remove_file(&quarantine_path);

        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis".to_string(),
            "synv1leader".to_string(),
            0,
            100,
        );
        // Address Engine v1 accepts only a canonical raw FN-DSA-1024 identity
        // root. Keep this fixture deterministic while exercising the unfunded
        // activation path; an arbitrary text label must not be treated as a
        // public key.
        let activation_public_key_hex = "42".repeat(crate::address::FN_DSA_1024_PUBLIC_KEY_BYTES);
        let activation_address =
            crate::address::generate_validator_address(&activation_public_key_hex, 1)
                .expect("deterministic FN-DSA fixture derives a validator address");
        let activation_tx = crate::transaction::Transaction::new(
            activation_address.clone(),
            activation_address.clone(),
            0,
            0,
            vec![1, 2, 3],
            1,
            21_000,
            Some(format!(
                "validator_activation:{{\"validator\":\"{}\",\"public_key\":\"{}\",\"name\":\"Unfunded Validator\",\"stake_amount_nwei\":{}}}",
                activation_address,
                activation_public_key_hex,
                crate::validator::TESTNET_MIN_VALIDATOR_STAKE_NWEI
            )),
            "fndsa".to_string(),
        );
        let block = Block::new_with_timestamp(
            1,
            vec![activation_tx],
            genesis.hash.clone(),
            "synv1leader".to_string(),
            1,
            102,
        );
        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        let blockchain = Arc::new(Mutex::new(chain));

        let error = preflight_validator_activation_transactions(std::iter::once(&block))
            .expect_err("unfunded activation must fail before validators sign or append it");
        assert!(error.contains("nWei bonded"));
        assert_eq!(blockchain.lock().unwrap().last().unwrap().block_index, 0);
        assert!(
            current_self_quarantine_record().is_none(),
            "rejecting invalid uncommitted input must not quarantine a healthy validator"
        );

        let _ = fs::remove_file(&quarantine_path);
        if let Some(previous_quarantine) = previous_quarantine {
            fs::write(&quarantine_path, previous_quarantine)
                .expect("previous quarantine record should be restored");
        }
        clear_legacy_canonical_locks_for_tests();
    }

    #[test]
    fn peer_canonical_lock_conflict_does_not_self_quarantine_local_node() {
        let _guard = block_application_test_guard();

        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis".to_string(),
            "synv1leader".to_string(),
            0,
            100,
        );
        let canonical_block = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            1,
            102,
        );
        let conflicting_peer_block = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            2,
            104,
        );
        let next_canonical_block = signed_block(
            2,
            Vec::new(),
            canonical_block.hash.clone(),
            "synv1leader".to_string(),
            3,
            106,
        );
        let canonical_qc = test_quorum_certificate(&canonical_block);
        write_legacy_canonical_lock(&canonical_block, &canonical_qc)
            .expect("test canonical lock should be written");

        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        chain.add_block(canonical_block);
        chain.add_block(next_canonical_block);
        let blockchain = Arc::new(Mutex::new(chain));

        assert!(!apply_block_if_new(
            &blockchain,
            conflicting_peer_block.clone(),
            Some(test_quorum_certificate(&conflicting_peer_block))
        ));
        assert_eq!(blockchain.lock().unwrap().last().unwrap().block_index, 2);
        assert!(
            current_self_quarantine_record().is_none(),
            "rejecting a historical peer block that conflicts with a local canonical lock must not self-quarantine a node that is already past that height"
        );

        clear_legacy_canonical_locks_for_tests();
    }

    #[test]
    fn peer_canonical_lock_conflict_at_local_tip_does_not_self_quarantine_local_node() {
        let _guard = block_application_test_guard();

        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis".to_string(),
            "synv1leader".to_string(),
            0,
            100,
        );
        let local_locked_block = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            1,
            102,
        );
        let conflicting_peer_block = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            2,
            104,
        );
        let local_qc = test_quorum_certificate(&local_locked_block);
        write_legacy_canonical_lock(&local_locked_block, &local_qc)
            .expect("test canonical lock should be written");

        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        chain.add_block(local_locked_block);
        let blockchain = Arc::new(Mutex::new(chain));

        assert!(!apply_block_if_new(
            &blockchain,
            conflicting_peer_block.clone(),
            Some(test_quorum_certificate(&conflicting_peer_block))
        ));
        assert_eq!(blockchain.lock().unwrap().last().unwrap().block_index, 1);
        assert_eq!(
            current_self_quarantine_record(),
            None,
            "peer-supplied canonical lock conflicts must be rejected and recorded as peer evidence, not local self-quarantine"
        );

        clear_legacy_canonical_locks_for_tests();
    }

    #[test]
    fn pending_peer_canonical_lock_conflict_after_tip_apply_does_not_self_quarantine() {
        let _guard = block_application_test_guard();

        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis".to_string(),
            "synv1leader".to_string(),
            0,
            100,
        );
        let block_one = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            1,
            102,
        );
        let local_locked_block_two = signed_block(
            2,
            Vec::new(),
            block_one.hash.clone(),
            "synv1leader".to_string(),
            2,
            104,
        );
        let conflicting_peer_block_two = signed_block(
            2,
            Vec::new(),
            block_one.hash.clone(),
            "synv1leader".to_string(),
            3,
            106,
        );
        write_legacy_canonical_lock(
            &local_locked_block_two,
            &test_quorum_certificate(&local_locked_block_two),
        )
        .expect("test canonical lock should be written");
        cache_pending_block(
            conflicting_peer_block_two.clone(),
            test_quorum_certificate(&conflicting_peer_block_two),
        );

        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        let blockchain = Arc::new(Mutex::new(chain));

        let block_one_qc = test_quorum_certificate(&block_one);
        assert!(apply_block_if_new(
            &blockchain,
            block_one,
            Some(block_one_qc)
        ));
        let chain = blockchain.lock().unwrap();
        assert_eq!(chain.last().unwrap().block_index, 1);
        assert_eq!(
            current_self_quarantine_record(),
            None,
            "pending peer block conflicts discovered after applying the parent must be rejected as peer evidence without local self-quarantine"
        );
        drop(chain);

        PENDING_BLOCKS.lock().unwrap().clear();
        clear_legacy_canonical_locks_for_tests();
    }

    #[test]
    fn signed_network_block_without_qc_is_rejected() {
        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis".to_string(),
            "synv1leader".to_string(),
            0,
            100,
        );
        let signed_block = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            1,
            102,
        );
        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        let blockchain = Arc::new(Mutex::new(chain));

        assert!(!apply_block_if_new(&blockchain, signed_block, None));
        assert_eq!(blockchain.lock().unwrap().last().unwrap().block_index, 0);
    }

    #[test]
    fn background_sync_requests_pause_while_sync_manager_is_active() {
        let config = NodeConfig::default();
        assert!(should_request_missing_blocks(&config, false));
        assert!(!should_request_missing_blocks(&config, true));
    }

    #[test]
    fn validator_role_is_detected_from_identity_profile_or_address() {
        let mut config = NodeConfig::default();
        assert!(!local_node_runs_validator_consensus(&config));
        assert!(!local_node_uses_service_batch_durability(&config));

        config.identity.role = "relayer".to_string();
        assert!(local_node_uses_service_batch_durability(&config));
        config.identity.role = "archive_validator".to_string();
        assert!(local_node_uses_service_batch_durability(&config));
        config.identity.role = "unknown-service".to_string();
        assert!(!local_node_uses_service_batch_durability(&config));

        config.identity.role = "validator".to_string();
        assert!(local_node_runs_validator_consensus(&config));
        assert!(!local_node_uses_service_batch_durability(&config));

        config.identity.role.clear();
        config.role.compiled_profile = "validator_node".to_string();
        assert!(local_node_runs_validator_consensus(&config));

        config.role.compiled_profile = "archive_validator_node".to_string();
        assert!(!local_node_runs_validator_consensus(&config));
        assert!(local_node_uses_service_batch_durability(&config));

        config.role.compiled_profile.clear();
        config.node.validator_address = "synv1local".to_string();
        assert!(!local_node_runs_validator_consensus(&config));

        config.role.services = vec!["consensus".to_string()];
        assert!(local_node_runs_validator_consensus(&config));
    }

    #[test]
    fn validator_nodes_throttle_support_peer_block_sync_responses() {
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        let support_peer = test_peer_with_validator_address(Some("synv1support"));

        let policy = block_sync_response_policy(&config, Some(&support_peer));

        assert_eq!(
            policy.max_blocks,
            MAX_VALIDATOR_SUPPORT_SYNC_RESPONSE_BLOCKS
        );
        assert_eq!(policy.write_timeout, Duration::from_millis(500));
        assert_eq!(
            block_sync_min_serve_interval_secs(&config, Some(&support_peer)),
            VALIDATOR_SUPPORT_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS
        );
    }

    #[test]
    fn validator_nodes_serve_active_validator_sync_without_slow_recovery_throttle() {
        configure_canonical_genesis_path_for_tests();
        let active_validator = "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs";
        ensure_test_validator_key(active_validator);

        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: active_validator.to_string(),
            dial_address: "10.70.10.7:5622".to_string(),
        }];
        let mut active_peer = test_peer_with_validator_address(Some(active_validator));
        active_peer.connected_endpoint = Some("10.70.10.7:5622".to_string());

        assert_eq!(
            block_sync_min_serve_interval_secs(&config, Some(&active_peer)),
            BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS
        );
    }

    #[test]
    fn non_validator_nodes_serve_large_public_onboarding_block_sync_batches() {
        let mut config = NodeConfig::default();
        config.identity.role = "relayer".to_string();
        let support_peer = test_peer_with_validator_address(Some("synv1support"));

        let policy = block_sync_response_policy(&config, Some(&support_peer));

        assert_eq!(
            policy.max_blocks,
            MAX_SUPPORT_NODE_BLOCK_SYNC_RESPONSE_BLOCKS
        );
        assert_eq!(policy.write_timeout, Duration::from_secs(2));
        assert_eq!(
            block_sync_min_serve_interval_secs(&config, Some(&support_peer)),
            SUPPORT_NODE_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS
        );
    }

    #[test]
    fn deep_support_peer_sync_request_is_refused() {
        configure_canonical_genesis_path_for_tests();
        let active_validator = "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs";
        ensure_test_validator_key(active_validator);
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: active_validator.to_string(),
            dial_address: "10.70.10.1:5622".to_string(),
        }];

        let support_peer = test_peer_with_validator_address(Some("synv1support"));
        let active_peer = test_peer_with_validator_address(Some(active_validator));
        let mut active_peer = active_peer;
        active_peer.connected_endpoint = Some("10.70.10.1:5622".to_string());

        assert!(support_peer_sync_request_is_too_deep(
            &config,
            Some(&support_peer),
            250_000,
            11_666
        ));
        assert!(!support_peer_sync_request_is_too_deep(
            &config,
            Some(&support_peer),
            50_000,
            11_666
        ));
        assert!(!support_peer_sync_request_is_too_deep(
            &config,
            Some(&support_peer),
            50_000,
            49_500
        ));
        assert!(!support_peer_sync_request_is_too_deep(
            &config,
            Some(&active_peer),
            50_000,
            11_666
        ));
    }

    #[test]
    fn oversized_p2p_frame_is_rejected_before_body_read() {
        let len = (MAX_P2P_FRAME_BYTES as u32).saturating_add(1);
        let mut input = std::io::Cursor::new(len.to_le_bytes().to_vec());
        let error = receive_message(&mut input).expect_err("oversized frame must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn oversized_outbound_p2p_frame_is_rejected() {
        assert_eq!(
            validate_outbound_frame_length(MAX_P2P_FRAME_BYTES).unwrap(),
            MAX_P2P_FRAME_BYTES as u32
        );
        let error = validate_outbound_frame_length(MAX_P2P_FRAME_BYTES + 1)
            .expect_err("oversized outbound frame must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn block_sync_admission_allows_only_one_job_per_peer_session() {
        let active = Mutex::new(HashSet::new());

        assert!(reserve_block_sync_peer(&active, "peer-a", 7));
        assert!(!reserve_block_sync_peer(&active, "peer-a", 7));
        assert!(reserve_block_sync_peer(&active, "peer-a", 8));
        assert!(reserve_block_sync_peer(&active, "peer-b", 7));

        release_block_sync_peer(&active, "peer-a", 7);
        assert!(reserve_block_sync_peer(&active, "peer-a", 7));
    }

    #[test]
    fn status_rate_limit_suppresses_feedback_until_the_session_window_expires() {
        let last_sent = Mutex::new(HashMap::new());

        assert!(claim_status_rate_limit(
            &last_sent,
            "peer-a",
            7,
            100,
            STATUS_REQUEST_MIN_INTERVAL_SECS,
        ));
        assert!(!claim_status_rate_limit(
            &last_sent,
            "peer-a",
            7,
            104,
            STATUS_REQUEST_MIN_INTERVAL_SECS,
        ));
        assert!(claim_status_rate_limit(
            &last_sent,
            "peer-a",
            7,
            105,
            STATUS_REQUEST_MIN_INTERVAL_SECS,
        ));
        assert!(claim_status_rate_limit(
            &last_sent,
            "peer-a",
            8,
            101,
            STATUS_RESPONSE_MIN_INTERVAL_SECS,
        ));
    }

    #[test]
    fn canonical_validators_only_serve_active_or_designated_sync_requesters() {
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.network.additional_dial_targets = vec!["127.0.0.1:5622".to_string()];
        let mut onboarding_peer = test_peer_with_validator_address(Some("synv1onboarding"));
        onboarding_peer.node_id = Some("validator-onboarding".to_string());
        onboarding_peer.quarantined = true;
        onboarding_peer.consensus_duties_disabled = true;
        assert!(!peer_is_authorized_block_sync_requester(
            &config,
            &onboarding_peer
        ));

        let active_validator = "synv1recoveringactivexxxxxxxxxxxxxxxxxxxx";
        ensure_test_validator_key(active_validator);
        config.node.allowed_validator_addresses = vec![active_validator.to_string()];
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: active_validator.to_string(),
            dial_address: "10.70.10.5:5622".to_string(),
        }];

        let mut quarantined_active_peer = test_peer_with_validator_address(Some(active_validator));
        quarantined_active_peer.node_id = Some("recovering-validator".to_string());
        quarantined_active_peer.quarantined = true;
        quarantined_active_peer.consensus_duties_disabled = true;
        quarantined_active_peer.connected_endpoint = Some("10.70.10.5:49152".to_string());
        quarantined_active_peer.direction = ConnectionDirection::Incoming;
        assert!(
            peer_is_authorized_block_sync_requester(&config, &quarantined_active_peer),
            "a verified active validator on its signed VPN transport must be allowed to request recovery blocks while quarantined"
        );

        let mut support_peer = test_peer_with_validator_address(None);
        support_peer.node_id = Some("sentry1".to_string());
        support_peer.handshake_role = Some("relayer".to_string());
        support_peer.address = "relay1.synergynode.xyz:5622".to_string();
        support_peer.public_address = Some("relay1.synergynode.xyz:5622".to_string());
        support_peer.connected_endpoint = Some("127.0.0.1:5622".to_string());
        assert!(peer_is_designated_support_sync_source(
            &config,
            &support_peer
        ));
        assert!(peer_is_authorized_block_sync_requester(
            &config,
            &support_peer
        ));

        let mut spoofed_support = test_peer_with_validator_address(None);
        spoofed_support.handshake_role = Some("relayer".to_string());
        spoofed_support.public_address = Some("relay1.synergynode.xyz:5622".to_string());
        spoofed_support.node_id = Some("sentry1".to_string());
        assert!(
            !peer_is_designated_support_sync_source(&config, &spoofed_support),
            "a self-reported public support address must not override the connected endpoint"
        );

        support_peer.consensus_duties_disabled = true;
        assert!(!peer_is_authorized_block_sync_requester(
            &config,
            &support_peer
        ));
    }

    #[test]
    fn forged_active_validator_address_without_matching_transport_is_not_authorized() {
        configure_canonical_genesis_path_for_tests();
        let active_validator = "synv1forgedtransportxxxxxxxxxxxxxxxxxxxx";
        ensure_test_validator_key(active_validator);

        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.node.allowed_validator_addresses = vec![active_validator.to_string()];
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: active_validator.to_string(),
            dial_address: "10.70.10.7:5622".to_string(),
        }];

        let mut forged = test_peer_with_validator_address(Some(active_validator));
        forged.node_id = Some("peer-a".to_string());
        forged.connected_endpoint = Some("10.70.10.8:5622".to_string());

        assert!(!super::peer_is_active_consensus_validator(&config, &forged));
        assert!(!peer_is_authorized_block_sync_requester(&config, &forged));
    }

    #[test]
    fn active_validator_from_signed_transport_ip_is_authorized_on_incoming_ephemeral_port() {
        configure_canonical_genesis_path_for_tests();
        let active_validator = "synv1incomingtransportxxxxxxxxxxxxxxxxxx";
        ensure_test_validator_key(active_validator);

        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.node.allowed_validator_addresses = vec![active_validator.to_string()];
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: active_validator.to_string(),
            dial_address: "10.70.10.8:5622".to_string(),
        }];

        let mut peer = test_peer_with_validator_address(Some(active_validator));
        peer.connected_endpoint = Some("10.70.10.8:49152".to_string());
        peer.direction = ConnectionDirection::Incoming;

        assert!(super::configured_validator_transport_matches_peer(
            &config,
            &peer,
            active_validator
        ));
        assert!(super::peer_is_active_consensus_validator(&config, &peer));
    }

    #[test]
    fn quarantined_local_validator_can_recover_from_active_validator_source() {
        configure_canonical_genesis_path_for_tests();
        let active_validator = "synv1recoverysourcexxxxxxxxxxxxxxxxxxxx";
        ensure_test_validator_key(active_validator);
        record_self_quarantine_for_canonical_lock_conflict(
            42,
            Some("local-fork-hash".to_string()),
            "majority-hash",
            "test local fork",
        )
        .expect("test quarantine record should write");

        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.node.validator_address = "synv1localrecoveringxxxxxxxxxxxxxxxxxxx".to_string();
        config.node.allowed_validator_addresses = vec![active_validator.to_string()];
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: active_validator.to_string(),
            dial_address: "10.70.10.6:5622".to_string(),
        }];

        let mut source = test_peer_with_validator_address(Some(active_validator));
        source.connected_endpoint = Some("10.70.10.6:5622".to_string());
        source.direction = ConnectionDirection::Outgoing;
        source.last_known_height = 100;
        source.status_received_at = Some(current_timestamp());

        assert!(super::current_validator_quarantine_duty_block().is_some());
        assert!(
            peer_is_eligible_block_sync_source_for_local(&config, &source),
            "a locally quarantined validator must keep a recovery-only block sync path to healthy active validators"
        );

        source.quarantined = true;
        source.consensus_duties_disabled = true;
        assert!(
            !peer_is_eligible_block_sync_source_for_local(&config, &source),
            "recovery must not trust a quarantined source validator"
        );
    }

    #[test]
    fn validator_transport_binding_rejects_wrong_ip_and_wrong_outgoing_port() {
        let validator = "synv1endpointbindingxxxxxxxxxxxxxxxxxxxx";
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: validator.to_string(),
            dial_address: "10.70.10.8:5622".to_string(),
        }];

        let mut peer = test_peer_with_validator_address(Some(validator));
        peer.direction = ConnectionDirection::Incoming;
        peer.connected_endpoint = Some("10.70.10.9:49152".to_string());
        assert!(!super::configured_validator_transport_matches_peer(
            &config, &peer, validator
        ));

        peer.direction = ConnectionDirection::Outgoing;
        peer.connected_endpoint = Some("10.70.10.8:49152".to_string());
        assert!(!super::configured_validator_transport_matches_peer(
            &config, &peer, validator
        ));
    }

    #[test]
    fn production_transport_resolution_rejects_unsigned_static_fallback() {
        let validator = "synv1unsignedstaticxxxxxxxxxxxxxxxxxxxxxx";
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: validator.to_string(),
            dial_address: "10.70.10.8:5622".to_string(),
        }];

        assert_eq!(
            super::validator_vpn_transport_for_target_with_static_fallback(
                &config, validator, false,
            ),
            None
        );
    }

    #[test]
    fn private_qualification_static_transport_requires_the_isolated_overlay() {
        let validator = "synv1privatequalificationxxxxxxxxxxxxxxxxxx";
        let mut config = NodeConfig::default();
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: validator.to_string(),
            dial_address: "10.126.10.8:5622".to_string(),
        }];

        assert_eq!(
            super::configured_validator_vpn_transport_for_target(&config, validator, true),
            Some("10.126.10.8:5622".to_string())
        );

        config.network.validator_vpn_transports[0].dial_address = "10.70.10.8:5622".to_string();
        assert_eq!(
            super::configured_validator_vpn_transport_for_target(&config, validator, true),
            None
        );

        assert!(super::is_private_qualification_innernet_dial_address(
            "10.126.10.8:5622",
            10,
        ));
        assert!(super::is_private_qualification_innernet_dial_address(
            "10.126.20.8:5622",
            20,
        ));
        assert!(!super::is_private_qualification_innernet_dial_address(
            "10.70.20.8:5622",
            20,
        ));
        assert!(!super::is_private_qualification_innernet_dial_address(
            "10.126.20.8:5621",
            20,
        ));
    }

    #[test]
    fn transport_enrollment_does_not_activate_an_unbonded_validator() {
        configure_canonical_genesis_path_for_tests();
        let unactivated_validator = "synv1transportonlyxxxxxxxxxxxxxxxxxxxxx";
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: unactivated_validator.to_string(),
            dial_address: "10.70.10.8:5622".to_string(),
        }];

        let mut peer = test_peer_with_validator_address(Some(unactivated_validator));
        peer.connected_endpoint = Some("10.70.10.8:49152".to_string());
        peer.direction = ConnectionDirection::Incoming;

        assert!(super::configured_validator_transport_matches_peer(
            &config,
            &peer,
            unactivated_validator
        ));
        assert!(!super::peer_is_active_consensus_validator(&config, &peer));
    }

    #[test]
    fn configured_support_endpoint_matches_dns_and_ip_only_at_exact_port() {
        assert!(connected_endpoint_matches_configured_address(
            "127.0.0.1:5623",
            "localhost:5623"
        ));
        assert!(!connected_endpoint_matches_configured_address(
            "127.0.0.1:5622",
            "localhost:5623"
        ));
        assert!(!connected_endpoint_matches_configured_address(
            "127.0.0.1:5624",
            "localhost:5623"
        ));
        assert!(!connected_endpoint_matches_configured_address(
            "RPC.SYNERGYNODE.XYZ:5623",
            "rpc.synergynode.xyz:5623"
        ));
        assert!(!connected_endpoint_matches_configured_address(
            "rpc.synergynode.xyz:5624",
            "rpc.synergynode.xyz:5623"
        ));
    }

    #[test]
    fn authenticated_support_classification_propagates_without_public_address_trust() {
        let config = NodeConfig::default();
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let network = P2PNetwork::new(blockchain, &config);

        let mut authenticated = test_peer_with_validator_address(None);
        authenticated.address = "rpc.synergynode.xyz:5623".to_string();
        authenticated.public_address = Some("relay1.synergynode.xyz:9999".to_string());
        authenticated.node_id = Some("untrusted-looking-name".to_string());
        authenticated.handshake_role = Some("rpc_gateway_node".to_string());
        authenticated.connected_endpoint = Some("167.86.83.83:5623".to_string());
        network
            .connected_peers
            .lock()
            .unwrap()
            .insert(authenticated.address.clone(), authenticated);

        let snapshot = network
            .collect_peer_snapshots()
            .into_iter()
            .next()
            .expect("peer snapshot");
        assert!(snapshot.authenticated_designated_support);
        assert!(!snapshot.authenticated_designated_relayer);

        let mut spoofed = test_peer_with_validator_address(None);
        spoofed.address = "peer-a:5622".to_string();
        spoofed.public_address = Some("rpc.synergynode.xyz:5623".to_string());
        spoofed.handshake_role = Some("rpc_gateway_node".to_string());
        assert!(!peer_is_designated_support_sync_source(
            &NodeConfig::default(),
            &spoofed
        ));

        let mut vpn_spoof = test_peer_with_validator_address(None);
        vpn_spoof.address = "relay1.synergynode.xyz:5622".to_string();
        vpn_spoof.public_address = Some("relay1.synergynode.xyz:5622".to_string());
        vpn_spoof.handshake_role = Some("relayer".to_string());
        vpn_spoof.connected_endpoint = Some("10.70.20.77:5622".to_string());
        assert!(!peer_is_designated_support_sync_source(
            &NodeConfig::default(),
            &vpn_spoof
        ));
    }

    #[test]
    fn authoritative_support_policy_fails_closed_for_unactivated_validator() {
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.node.validator_address = "synv1notactive".to_string();
        config.validator.state_sync_before_join = false;

        assert!(super::local_sync_requires_support_sources_authoritatively(
            &config
        ));
    }

    #[test]
    fn active_consensus_membership_overrides_stale_static_allowlist() {
        let active_validator = "synv1activewithoutlegacyallowlistxxxxxxxxx";
        ensure_test_validator_key(active_validator);

        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.node.validator_address = active_validator.to_string();
        config.node.strict_validator_allowlist = true;
        config.node.allowed_validator_addresses = vec!["synv1legacyvalidator".to_string()];
        config.validator.state_sync_before_join = false;

        assert!(!super::local_sync_requires_support_sources_authoritatively(
            &config
        ));
    }

    #[test]
    fn canonical_get_blocks_disconnects_unactivated_requester_before_serving_history() {
        let _session_guard = peer_session_test_guard();
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();

        let mut peer = test_peer_with_validator_address(Some("synv1onboarding"));
        peer.node_id = Some("validator-onboarding".to_string());
        peer.quarantined = true;
        peer.consensus_duties_disabled = true;
        connected_peers
            .lock()
            .unwrap()
            .insert(peer.address.clone(), peer);
        let session_id = super::begin_peer_session("peer-a");

        handle_get_blocks_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
            "peer-a",
            session_id,
            0,
            MAX_STATUS_SYNC_BATCH,
        );

        assert!(!connected_peers.lock().unwrap().contains_key("peer-a"));
    }

    #[test]
    fn canonical_chain_request_gate_disconnects_ordinary_unactivated_requesters() {
        let _session_guard = peer_session_test_guard();
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();

        for request_kind in ["block-headers", "block-bodies"] {
            let mut peer =
                test_peer_with_validator_address(Some("synv1ordinaryunactivatedrequester"));
            peer.node_id = Some("validator-onboarding".to_string());
            connected_peers
                .lock()
                .unwrap()
                .insert("peer-a".to_string(), peer);
            let session_id = begin_peer_session("peer-a");

            assert!(!authorize_chain_requester_for_session(
                &connected_peers,
                &peer_state_cache,
                &config,
                "peer-a",
                session_id,
                request_kind,
            ));
            assert!(!connected_peers.lock().unwrap().contains_key("peer-a"));
        }
    }

    #[test]
    fn status_exchange_accepts_verified_peer_before_readiness() {
        let _session_guard = peer_session_test_guard();
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let mut peer = test_peer_with_validator_address(Some("synv1onboarding"));
        peer.handshake_role = None;
        peer.status_received_at = None;
        peer.genesis_hash.clear();
        connected_peers
            .lock()
            .unwrap()
            .insert("peer-a".to_string(), peer);
        let session_id = begin_peer_session("peer-a");

        assert!(super::authorize_status_exchange_for_session(
            &connected_peers,
            &peer_state_cache,
            "peer-a",
            session_id,
            "status-request",
        ));
        assert!(connected_peers.lock().unwrap().contains_key("peer-a"));
    }

    #[test]
    fn status_exchange_disconnects_peer_without_verified_handshake() {
        let _session_guard = peer_session_test_guard();
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let mut peer = test_peer_with_validator_address(Some("synv1onboarding"));
        peer.version = None;
        connected_peers
            .lock()
            .unwrap()
            .insert("peer-a".to_string(), peer);
        let session_id = begin_peer_session("peer-a");

        assert!(!super::authorize_status_exchange_for_session(
            &connected_peers,
            &peer_state_cache,
            "peer-a",
            session_id,
            "status",
        ));
        assert!(!connected_peers.lock().unwrap().contains_key("peer-a"));
    }

    #[test]
    fn validator_status_identity_must_match_verified_handshake() {
        let _session_guard = peer_session_test_guard();
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();

        let mut peer = test_peer_with_validator_address(Some("synv1handshake"));
        peer.handshake_role = Some("validator".to_string());
        peer.status_received_at = None;
        connected_peers
            .lock()
            .unwrap()
            .insert("peer-a".to_string(), peer);
        let session_id = begin_peer_session("peer-a");

        handle_status_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
            "peer-a",
            session_id,
            12,
            "best-hash",
            &canonical_genesis_hash(),
            Some(current_timestamp()),
            Some("synv1spoofed"),
            Some("peer-a"),
            Some("validator-set-hash"),
            false,
            false,
            None,
        );

        assert!(!connected_peers.lock().unwrap().contains_key("peer-a"));
    }

    #[test]
    fn role_omitted_verified_handshake_accepts_matching_status() {
        let _session_guard = peer_session_test_guard();
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();

        let mut peer = test_peer_with_validator_address(Some("synv1handshake"));
        peer.handshake_role = None;
        peer.status_received_at = None;
        connected_peers
            .lock()
            .unwrap()
            .insert("peer-a".to_string(), peer);
        let session_id = begin_peer_session("peer-a");

        handle_status_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
            "peer-a",
            session_id,
            12,
            "best-hash",
            &canonical_genesis_hash(),
            Some(current_timestamp()),
            Some("synv1handshake"),
            Some("peer-a"),
            Some("validator-set-hash"),
            false,
            false,
            None,
        );

        let peers = connected_peers.lock().unwrap();
        let peer = peers.get("peer-a").expect("peer should remain connected");
        assert_eq!(peer.validator_address.as_deref(), Some("synv1handshake"));
        assert_eq!(
            peer.status_validator_address.as_deref(),
            Some("synv1handshake")
        );
        assert!(peer.status_received_at.is_some());
    }

    #[test]
    fn duty_disabled_anonymous_status_is_not_a_block_sync_source() {
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        assert!(!status_peer_is_eligible_block_sync_source(
            &config, None, false, false, false, false, true,
        ));
        assert!(!status_peer_is_eligible_block_sync_source(
            &config,
            Some("synv1support"),
            false,
            false,
            false,
            false,
            true,
        ));
        assert!(status_peer_is_eligible_block_sync_source(
            &config,
            Some("synv1support"),
            false,
            true,
            false,
            false,
            true,
        ));
    }

    #[test]
    fn failed_block_sync_write_disconnects_peer_to_preserve_framing() {
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let mut peers = HashMap::new();
        peers.insert(
            "peer-a".to_string(),
            test_peer_with_validator_address(Some("synv1support")),
        );

        disconnect_peer_after_poisoned_write(
            &peer_state_cache,
            &mut peers,
            "peer-a",
            "block-sync-send-failed: timed out",
        );

        assert!(!peers.contains_key("peer-a"));
        assert!(peer_state_cache
            .lock()
            .unwrap()
            .contains_key("validator:synv1support"));
    }

    #[test]
    fn background_poll_interval_uses_heartbeat_during_active_sync() {
        let heartbeat = Duration::from_secs(7);
        assert_eq!(background_poll_interval(100, heartbeat, true), heartbeat);
        assert_eq!(
            background_poll_interval(100, heartbeat, false),
            Duration::from_millis(BACKGROUND_SYNC_POLL_MILLIS)
        );
        assert_eq!(
            background_poll_interval(5, heartbeat, false),
            Duration::from_millis(BACKGROUND_SYNC_POLL_MILLIS)
        );
        assert_eq!(background_poll_interval(0, heartbeat, false), heartbeat);
    }

    #[test]
    fn dispatch_peer_message_keeps_votes_off_the_background_queue() {
        let _session_guard = peer_session_test_guard();
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        connected_peers.lock().unwrap().insert(
            "peer-a".to_string(),
            PeerConnection {
                address: "peer-a".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: Some("genesisval2.synergy-network.io:5622".to_string()),
                validator_address: Some("synv1peer-a".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: Some("testnet-peer-a".to_string()),
                handshake_role: None,
                version: Some("1.0.0".to_string()),
                capabilities: vec!["blocks".to_string()],
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        let session_id = super::begin_peer_session("peer-a");

        let (sender, receiver) = mpsc::channel();
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let config = NodeConfig::default();
        let vote = Vote {
            validator_address: "synv1peer-a".to_string(),
            block_hash: "block-hash".to_string(),
            block_index: 7,
            epoch_number: 2,
            round_number: 1,
            signature: PQCSignature {
                algorithm: PQCAlgorithm::FNDSA,
                signature_data: vec![1, 2, 3],
                message_hash: vec![7, 8, 9],
                public_key_id: "peer-a".to_string(),
                created_at: 123,
            },
            signer_public_key: vec![4, 5, 6],
            timestamp: 123,
        };

        dispatch_peer_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &sender,
            &config,
            "peer-a",
            session_id,
            NetworkMessage::Vote { vote },
        )
        .expect("vote dispatch should succeed");

        assert!(
            receiver.recv_timeout(Duration::from_millis(50)).is_err(),
            "vote dispatch should bypass the shared background queue"
        );

        let replacement_session_id = super::begin_peer_session("peer-a");
        assert_ne!(replacement_session_id, session_id);
        dispatch_peer_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &sender,
            &config,
            "peer-a",
            session_id,
            NetworkMessage::Ping,
        )
        .expect("stale message dispatch should fail closed without a queue error");
        assert!(
            receiver.recv_timeout(Duration::from_millis(50)).is_err(),
            "stale peer session must not enqueue background messages"
        );
    }

    #[test]
    fn status_handler_records_genesis_hash_and_requests_blocks_without_deadlocking() {
        let _service_sync_guard = service_sync_test_guard();
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind test listener: {error}"),
        };
        let addr = listener.local_addr().expect("listener address");
        let client = match std::net::TcpStream::connect(addr) {
            Ok(stream) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to connect test stream: {error}"),
        };
        let (mut server, _) = listener.accept().expect("accept peer stream");
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set read timeout");

        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        config.node.validator_address = "synv1local".to_string();
        config.network.additional_dial_targets = vec!["127.0.0.1:5622".to_string()];

        connected_peers.lock().unwrap().insert(
            "peer-a".to_string(),
            PeerConnection {
                address: "relay1.synergynode.xyz:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: Some("relay1.synergynode.xyz:5622".to_string()),
                validator_address: Some("synv1peer-a".to_string()),
                connected_at: 100,
                last_seen: 100,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: Some(client),
                connected_endpoint: Some("127.0.0.1:5622".to_string()),
                node_id: Some("testnet-peer-a".to_string()),
                handshake_role: Some("relayer".to_string()),
                version: Some("1.0.0".to_string()),
                capabilities: vec!["blocks".to_string()],
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        let session_id = super::begin_peer_session("peer-a");

        let genesis_hash = canonical_genesis_hash();
        let (done_tx, done_rx) = mpsc::channel();
        let blockchain_for_thread = Arc::clone(&blockchain);
        let connected_peers_for_thread = Arc::clone(&connected_peers);
        let peer_state_cache_for_thread = Arc::clone(&peer_state_cache);
        let config_for_thread = config.clone();
        let genesis_hash_for_thread = genesis_hash.clone();

        thread::spawn(move || {
            handle_status_message(
                &blockchain_for_thread,
                &connected_peers_for_thread,
                &peer_state_cache_for_thread,
                &config_for_thread,
                "peer-a",
                session_id,
                12,
                "best-hash",
                &genesis_hash_for_thread,
                Some(current_timestamp()),
                Some("synv1peer-a"),
                Some("peer-a"),
                Some("test-validator-set"),
                false,
                false,
                None,
            );
            let _ = done_tx.send(());
        });

        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("status handler should complete without deadlocking");

        {
            let peers = connected_peers.lock().unwrap();
            let peer = peers.get("peer-a").expect("peer should remain connected");
            assert_eq!(peer.last_known_height, 12);
            assert_eq!(peer.best_block_hash, "best-hash".to_string());
            assert_eq!(peer.genesis_hash, genesis_hash);
            assert!(peer.status_received_at.is_some());
        }

        match receive_message(&mut server).expect("status handling should request blocks") {
            NetworkMessage::GetBlocks { from_height, count } => {
                assert_eq!(from_height, 0);
                assert_eq!(count, 13);
            }
            other => panic!("expected GetBlocks request, got {other:?}"),
        }
    }

    #[test]
    fn canonical_status_handler_disconnects_quarantined_unactivated_peer() {
        let _session_guard = peer_session_test_guard();
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();

        let mut peer = test_peer_with_validator_address(Some("synv1onboarding"));
        peer.node_id = Some("validator-onboarding".to_string());
        peer.handshake_role = Some("validator".to_string());
        connected_peers
            .lock()
            .unwrap()
            .insert(peer.address.clone(), peer);
        let session_id = super::begin_peer_session("peer-a");

        handle_status_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
            "peer-a",
            session_id,
            9_300,
            "stale-snapshot-tip",
            "canonical-genesis",
            Some(current_timestamp()),
            Some("synv1onboarding"),
            Some("validator-onboarding"),
            None,
            true,
            true,
            Some("malformed_quarantine_marker"),
        );

        assert!(!connected_peers.lock().unwrap().contains_key("peer-a"));
    }

    #[test]
    fn status_handler_requests_blocks_from_duty_disabled_support_peer() {
        let _service_sync_guard = service_sync_test_guard();
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind test listener: {error}"),
        };
        let addr = listener.local_addr().expect("listener address");
        let client = match std::net::TcpStream::connect(addr) {
            Ok(stream) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to connect test stream: {error}"),
        };
        let (mut server, _) = listener.accept().expect("accept peer stream");
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set read timeout");

        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let mut config = NodeConfig::default();
        config.network.additional_dial_targets = vec!["127.0.0.1:5622".to_string()];

        let mut support_peer =
            test_peer_with_validator_address(Some("synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632"));
        support_peer.node_id = Some("sentry1".to_string());
        support_peer.handshake_role = Some("relayer".to_string());
        support_peer.address = "relay1.synergynode.xyz:5622".to_string();
        support_peer.public_address = Some("relay1.synergynode.xyz:5622".to_string());
        support_peer.connected_endpoint = Some("127.0.0.1:5622".to_string());
        support_peer.stream = Some(client);
        support_peer.status_received_at = None;
        support_peer.consensus_duties_disabled = true;
        connected_peers
            .lock()
            .unwrap()
            .insert("relayer-a".to_string(), support_peer);
        let session_id = super::begin_peer_session("relayer-a");

        let genesis_hash = canonical_genesis_hash();
        handle_status_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
            "relayer-a",
            session_id,
            195_000,
            "best-hash",
            &genesis_hash,
            Some(current_timestamp()),
            Some("synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632"),
            Some("sentry1"),
            Some("test-validator-set"),
            false,
            true,
            Some("SUPPORT_RELAY"),
        );

        let local_height = blockchain
            .lock()
            .unwrap()
            .last()
            .map(|block| block.block_index)
            .unwrap_or(0);
        let (expected_from_height, expected_count) =
            block_sync_request_range(local_height, 195_000, sync_batch_limit_for_role(&config))
                .expect("support peer should advertise blocks above the local tip");

        match receive_message(&mut server).expect("status handling should request blocks") {
            NetworkMessage::GetBlocks { from_height, count } => {
                assert_eq!(from_height, expected_from_height);
                assert_eq!(count, expected_count);
            }
            other => panic!("expected GetBlocks request from support peer, got {other:?}"),
        }
    }

    #[test]
    fn block_sync_busy_retry_preserves_range_and_delay() {
        assert_eq!(
            parse_block_sync_busy_retry(
                "block-sync-busy: a block response is pending; retry-after-millis=1000; from-height=973360; count=128"
            ),
            Some((Duration::from_secs(1), 973_360, 128))
        );
        assert_eq!(
            parse_block_sync_busy_retry(
                "block-sync-busy: legacy response; retry-after-millis=1000"
            ),
            None
        );
    }

    #[test]
    fn validator_status_genesis_grace_window_expires_after_threshold() {
        assert!(validator_status_genesis_within_grace_window(100, 120));
        assert_eq!(validator_status_genesis_grace_remaining_secs(100, 120), 10);
        assert!(!validator_status_genesis_within_grace_window(100, 130));
        assert_eq!(validator_status_genesis_grace_remaining_secs(100, 130), 0);
    }

    #[test]
    fn bootstrap_refresh_uses_configured_fast_interval_until_validator_mesh_is_complete() {
        let mut config = NodeConfig::default();
        config.consensus.min_validators = 4;
        config.node.validator_address = "synv1local".to_string();
        config.p2p.bootstrap_refresh_secs = 61;
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));

        let interval = current_bootstrap_refresh_interval(&config, &connected_peers);
        assert_eq!(interval, Duration::from_secs(61));
        assert_eq!(
            connected_validator_participants(&config, &connected_peers),
            1
        );
    }

    #[test]
    fn bootstrap_refresh_defaults_to_legacy_fast_interval() {
        let mut config = NodeConfig::default();
        config.consensus.min_validators = 4;
        config.node.validator_address = "synv1local".to_string();
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));

        let interval = current_bootstrap_refresh_interval(&config, &connected_peers);
        assert_eq!(
            interval,
            Duration::from_secs(DEFAULT_BOOTSTRAP_REFRESH_SECS)
        );
    }

    #[test]
    fn bootstrap_refresh_relaxes_after_validator_mesh_is_complete() {
        let mut config = NodeConfig::default();
        config.consensus.min_validators = 4;
        config.node.validator_address = "synv1local".to_string();

        let mut peers = HashMap::new();
        for (index, validator_address) in ["synv1peer-a", "synv1peer-b", "synv1peer-c"]
            .iter()
            .enumerate()
        {
            peers.insert(
                format!("peer-{index}"),
                PeerConnection {
                    address: format!("127.0.0.1:56{:02}", index + 20),
                    direction: ConnectionDirection::Outgoing,
                    public_address: None,
                    validator_address: Some((*validator_address).to_string()),
                    connected_at: 0,
                    last_seen: 0,
                    blocks_sent: 0,
                    blocks_received: 0,
                    txs_sent: 0,
                    txs_received: 0,
                    stream: None,
                    connected_endpoint: None,
                    node_id: None,
                    handshake_role: None,
                    version: None,
                    capabilities: Vec::new(),
                    last_known_height: 0,
                    best_block_hash: String::new(),
                    genesis_hash: "genesis-hash".to_string(),
                    status_received_at: Some(current_timestamp()),
                    status_reported_at: None,
                    status_validator_address: None,
                    status_source_session_id: None,
                    active_validator_set_hash: None,
                    quarantined: false,
                    consensus_duties_disabled: false,
                    recovery_state: None,
                },
            );
        }

        let connected_peers = Arc::new(Mutex::new(peers));
        let interval = current_bootstrap_refresh_interval(&config, &connected_peers);

        assert_eq!(
            connected_validator_participants(&config, &connected_peers),
            4
        );
        assert_eq!(interval, Duration::from_secs(NORMAL_BOOTSTRAP_REFRESH_SECS));
    }

    #[test]
    fn status_ready_validator_participants_requires_peer_status_exchange() {
        let mut config = NodeConfig::default();
        config.consensus.min_validators = 4;
        config.node.validator_address = "synv1local".to_string();

        let mut peers = HashMap::new();
        peers.insert(
            "peer-a".to_string(),
            PeerConnection {
                address: "127.0.0.1:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-a".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: None,
                handshake_role: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "peer-b".to_string(),
            PeerConnection {
                address: "127.0.0.2:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-b".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: None,
                handshake_role: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: "genesis-hash".to_string(),
                status_received_at: Some(current_timestamp()),
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );

        let connected_peers = Arc::new(Mutex::new(peers));
        assert_eq!(
            connected_validator_participants(&config, &connected_peers),
            3
        );
        assert_eq!(
            status_ready_validator_participants(&config, &connected_peers),
            2
        );
    }

    #[test]
    fn status_ready_validator_addresses_exclude_non_allowlisted_peer_validator_identity() {
        let local_validator = "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs";
        let support_identity = "synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632";
        let mut config = NodeConfig::default();
        config.node.validator_address = local_validator.to_string();
        config.node.allowed_validator_addresses = vec![local_validator.to_string()];

        let mut support_peer = test_peer_with_validator_address(Some(support_identity));
        support_peer.status_received_at = Some(current_timestamp());
        support_peer.genesis_hash = "test-genesis".to_string();

        let mut peers = HashMap::new();
        peers.insert("support-peer".to_string(), support_peer);
        let connected_peers = Arc::new(Mutex::new(peers));

        let addresses = status_ready_validator_addresses(&config, &connected_peers);
        assert!(addresses.contains(&local_validator.to_string()));
        assert!(!addresses.contains(&support_identity.to_string()));
        assert_eq!(addresses.len(), 1);
    }

    #[test]
    fn best_connected_validator_height_ignores_unknown_validator_status() {
        let mut peers = HashMap::new();
        peers.insert(
            "peer-a".to_string(),
            PeerConnection {
                address: "127.0.0.1:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-a".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: None,
                handshake_role: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 99,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "peer-b".to_string(),
            PeerConnection {
                address: "127.0.0.2:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-b".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                connected_endpoint: None,
                node_id: None,
                handshake_role: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 7,
                best_block_hash: String::new(),
                genesis_hash: "genesis-hash".to_string(),
                status_received_at: Some(current_timestamp()),
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );

        let connected_peers = Arc::new(Mutex::new(peers));
        assert_eq!(best_connected_validator_height(&connected_peers), 7);
    }

    #[test]
    fn best_connected_validator_height_with_support_ignores_single_higher_fork() {
        let mut peers = HashMap::new();
        peers.insert(
            "peer-a".to_string(),
            PeerConnection {
                address: "127.0.0.1:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-a".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: None,
                connected_endpoint: None,
                handshake_role: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 12,
                best_block_hash: "hash-12".to_string(),
                genesis_hash: "genesis-hash".to_string(),
                status_received_at: Some(current_timestamp()),
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "peer-b".to_string(),
            PeerConnection {
                address: "127.0.0.2:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-b".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: None,
                connected_endpoint: None,
                handshake_role: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 12,
                best_block_hash: "hash-12".to_string(),
                genesis_hash: "genesis-hash".to_string(),
                status_received_at: Some(current_timestamp()),
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "peer-c".to_string(),
            PeerConnection {
                address: "127.0.0.3:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-c".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: None,
                connected_endpoint: None,
                handshake_role: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 20,
                best_block_hash: "fork-20".to_string(),
                genesis_hash: "genesis-hash".to_string(),
                status_received_at: Some(current_timestamp()),
                status_reported_at: None,
                status_validator_address: None,
                status_source_session_id: None,
                active_validator_set_hash: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );

        let connected_peers = Arc::new(Mutex::new(peers));
        assert_eq!(
            super::best_connected_validator_height_with_support(&connected_peers, 2),
            12
        );
    }

    #[test]
    fn best_connected_validator_height_with_support_uses_supported_moving_head_floor() {
        let mut peers = HashMap::new();
        for (peer_id, validator, height) in [
            ("peer-a", "synv1peer-a", 105),
            ("peer-b", "synv1peer-b", 104),
            ("peer-c", "synv1peer-c", 103),
            ("peer-d", "synv1peer-d", 101),
        ] {
            let mut peer = test_peer_with_validator_address(Some(validator));
            peer.address = peer_id.to_string();
            peer.last_known_height = height;
            peer.best_block_hash = format!("hash-{height}");
            peer.status_received_at = Some(current_timestamp());
            peers.insert(peer_id.to_string(), peer);
        }

        let connected_peers = Arc::new(Mutex::new(peers));
        assert_eq!(
            super::best_connected_validator_height_with_support(&connected_peers, 3),
            103
        );
    }

    #[test]
    fn best_connected_validator_height_with_support_excludes_quarantined_sources() {
        let mut peers = HashMap::new();
        for (peer_id, validator, height, quarantined, duty_disabled) in [
            ("peer-a", "synv1peer-a", 200, true, true),
            ("peer-b", "synv1peer-b", 180, false, true),
            ("peer-c", "synv1peer-c", 100, false, false),
            ("peer-d", "synv1peer-d", 99, false, false),
            ("peer-e", "synv1peer-e", 98, false, false),
        ] {
            let mut peer = test_peer_with_validator_address(Some(validator));
            peer.address = peer_id.to_string();
            peer.last_known_height = height;
            peer.best_block_hash = format!("hash-{height}");
            peer.status_received_at = Some(current_timestamp());
            peer.quarantined = quarantined;
            peer.consensus_duties_disabled = duty_disabled;
            peers.insert(peer_id.to_string(), peer);
        }

        let connected_peers = Arc::new(Mutex::new(peers));
        assert_eq!(
            super::best_connected_validator_height_with_support(&connected_peers, 3),
            98
        );
    }

    fn test_block(previous: &Block, height: u64, validator: &str, nonce: u64) -> Block {
        signed_block(
            height,
            Vec::new(),
            previous.hash.clone(),
            validator.to_string(),
            nonce,
            1_700_000_000 + height,
        )
    }

    #[test]
    fn apply_block_batch_rolls_back_to_common_ancestor_before_replaying() {
        let _guard = block_application_test_guard();
        let mut chain = BlockChain::new();
        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis-parent".to_string(),
            "genesis".to_string(),
            0,
            1_700_000_000,
        );
        chain.add_block(genesis.clone());
        let block1 = test_block(&genesis, 1, "validator-a", 1);
        let block2 = test_block(&block1, 2, "validator-b", 2);
        let local_block3 = test_block(&block2, 3, "validator-c", 3);
        write_legacy_canonical_lock(&local_block3, &test_quorum_certificate(&local_block3))
            .expect("local fork lock should be written before peer recovery");
        chain.add_block(block1.clone());
        chain.add_block(block2.clone());
        chain.add_block(local_block3.clone());

        let blockchain = Arc::new(Mutex::new(chain));

        let remote_block3 = signed_block(
            3,
            Vec::new(),
            block2.hash.clone(),
            "validator-d".to_string(),
            99,
            1_700_000_099,
        );
        let remote_block4 = test_block(&remote_block3, 4, "validator-e", 4);
        let block2_qc = test_quorum_certificate(&block2);
        let remote_block3_qc = test_quorum_certificate(&remote_block3);
        let remote_block4_qc = test_quorum_certificate(&remote_block4);

        let applied = apply_block_batch(
            &blockchain,
            vec![block2.clone(), remote_block3.clone(), remote_block4.clone()],
            vec![block2_qc, remote_block3_qc, remote_block4_qc],
        );
        assert_eq!(applied, 2);

        let chain = blockchain.lock().unwrap();
        assert_eq!(chain.last().map(|block| block.block_index), Some(4));
        assert_eq!(
            chain.block_at_height(3).map(|block| block.hash.clone()),
            Some(remote_block3.hash.clone())
        );
        assert_eq!(
            chain.block_at_height(4).map(|block| block.hash.clone()),
            Some(remote_block4.hash.clone())
        );
        drop(chain);
        assert_eq!(
            crate::consensus::legacy_canonical_lock::legacy_canonical_commit_record(3)
                .unwrap()
                .map(|record| record.block_hash),
            Some(remote_block3.hash.clone())
        );
        assert!(
            super::current_validator_quarantine_duty_block().is_some(),
            "source-majority fork recovery must keep consensus duties disabled"
        );
        clear_legacy_canonical_locks_for_tests();
    }

    #[test]
    fn apply_block_batch_rejects_entire_batch_when_one_certificate_is_invalid() {
        let _guard = block_application_test_guard();
        let mut chain = BlockChain::new();
        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis-parent".to_string(),
            "genesis".to_string(),
            0,
            1_700_000_000,
        );
        chain.add_block(genesis.clone());
        let block1 = test_block(&genesis, 1, "validator-a", 1);
        let block2 = test_block(&block1, 2, "validator-b", 2);
        let blockchain = Arc::new(Mutex::new(chain));

        let valid_qc = test_quorum_certificate(&block1);
        let mut invalid_qc = test_quorum_certificate(&block2);
        invalid_qc.block_hash = "not-the-block-hash".to_string();

        let applied = apply_block_batch_for_role(
            &blockchain,
            vec![block1, block2],
            vec![valid_qc, invalid_qc],
            true,
        );

        assert_eq!(applied, 0);
        assert_eq!(
            blockchain
                .lock()
                .unwrap()
                .last()
                .map(|block| block.block_index),
            Some(0)
        );
    }

    #[test]
    fn service_batch_matches_validator_chain_result() {
        let _guard = block_application_test_guard();
        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis-parent".to_string(),
            "genesis".to_string(),
            0,
            1_700_000_000,
        );
        let block1 = test_block(&genesis, 1, "validator-service", 1);
        let block2 = test_block(&block1, 2, "validator-service", 2);
        let qcs = vec![
            test_quorum_certificate(&block1),
            test_quorum_certificate(&block2),
        ];

        let validator_chain = Arc::new(Mutex::new(BlockChain {
            chain: vec![genesis.clone()],
        }));
        assert_eq!(
            apply_block_batch(
                &validator_chain,
                vec![block1.clone(), block2.clone()],
                qcs.clone(),
            ),
            2
        );

        clear_legacy_canonical_locks_for_tests();
        let service_chain = Arc::new(Mutex::new(BlockChain {
            chain: vec![genesis],
        }));
        assert_eq!(
            apply_block_batch_for_role(&service_chain, vec![block1, block2], qcs, true),
            2
        );
        let service_hashes = service_chain
            .lock()
            .unwrap()
            .chain
            .iter()
            .map(|block| block.hash.clone())
            .collect::<Vec<_>>();
        let validator_hashes = validator_chain
            .lock()
            .unwrap()
            .chain
            .iter()
            .map(|block| block.hash.clone())
            .collect::<Vec<_>>();
        assert_eq!(service_hashes, validator_hashes);
    }

    #[test]
    fn service_batch_write_failure_does_not_advance_tip() {
        let _guard = block_application_test_guard();
        let root = crate::utils::test_temp_root(format!(
            "synergy-service-batch-write-failure-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let previous_log = std::env::var("SYNERGY_COMMITTED_BLOCK_LOG_FILE").ok();
        std::env::set_var("SYNERGY_COMMITTED_BLOCK_LOG_FILE", &root);

        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis-parent".to_string(),
            "genesis".to_string(),
            0,
            1_700_000_000,
        );
        let block1 = test_block(&genesis, 1, "validator-failure", 1);
        let blockchain = Arc::new(Mutex::new(BlockChain {
            chain: vec![genesis],
        }));
        let applied = apply_block_batch_for_role(
            &blockchain,
            vec![block1.clone()],
            vec![test_quorum_certificate(&block1)],
            true,
        );

        assert_eq!(applied, 0);
        assert_eq!(
            blockchain
                .lock()
                .unwrap()
                .last()
                .map(|block| block.block_index),
            Some(0)
        );

        match previous_log {
            Some(value) => std::env::set_var("SYNERGY_COMMITTED_BLOCK_LOG_FILE", value),
            None => std::env::remove_var("SYNERGY_COMMITTED_BLOCK_LOG_FILE"),
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn bounded_batch_verifier_caps_workers_and_keeps_result_order() {
        let items = (0..8).collect::<Vec<_>>();
        let active_workers = Arc::new(AtomicUsize::new(0));
        let peak_workers = Arc::new(AtomicUsize::new(0));
        let active_workers_for_verify = active_workers.clone();
        let peak_workers_for_verify = peak_workers.clone();

        let results = verify_batch_with_bounded_parallelism(&items, 2, move |item| {
            let active = active_workers_for_verify.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            peak_workers_for_verify.fetch_max(active, AtomicOrdering::SeqCst);
            thread::sleep(Duration::from_millis(5));
            active_workers_for_verify.fetch_sub(1, AtomicOrdering::SeqCst);

            if *item == 3 {
                panic!("deterministic verifier panic");
            } else if *item == 5 {
                Err("deterministic test failure".to_string())
            } else {
                Ok(())
            }
        });

        assert!(peak_workers.load(AtomicOrdering::SeqCst) <= 2);
        assert_eq!(results.len(), items.len());
        assert!(results[..3].iter().all(Result::is_ok));
        assert!(matches!(
            results[3].as_ref(),
            Err(error) if error == "batch verifier panicked for item 3"
        ));
        assert!(results[4].is_ok());
        assert!(matches!(
            results[5].as_ref(),
            Err(error) if error == "deterministic test failure"
        ));
        assert!(results[6..].iter().all(Result::is_ok));
    }

    #[test]
    fn get_blocks_write_does_not_hold_connected_peers_lock() {
        let _session_guard = peer_session_test_guard();
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
        let address = listener
            .local_addr()
            .expect("test listener should expose its address");
        let accept_handle = thread::spawn(move || {
            listener
                .accept()
                .expect("test listener should accept the sync connection")
                .0
        });
        let _client =
            std::net::TcpStream::connect(address).expect("test sync client should connect");
        let server_stream = accept_handle
            .join()
            .expect("test accept thread should join");

        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let mut peer = test_peer_with_validator_address(None);
        peer.address = "sync-peer".to_string();
        peer.connected_at = 42;
        peer.stream = Some(server_stream);
        connected_peers
            .lock()
            .unwrap()
            .insert(peer.address.clone(), peer);
        let session_id = super::begin_peer_session("sync-peer");

        let write_started = Arc::new(Barrier::new(2));
        let release_write = Arc::new(Barrier::new(2));
        let peers_for_write = Arc::clone(&connected_peers);
        let started_for_write = Arc::clone(&write_started);
        let release_for_write = Arc::clone(&release_write);
        let write_handle = thread::spawn(move || {
            with_peer_stream_outside_peers_lock(
                &peers_for_write,
                "sync-peer",
                session_id,
                move |_stream| {
                    started_for_write.wait();
                    release_for_write.wait();
                },
            )
            .expect("sync peer stream should be captured")
        });

        write_started.wait();
        assert!(connected_peers.try_lock().is_ok());
        let (replacement_tx, replacement_rx) = mpsc::channel();
        let replacement_handle = thread::spawn(move || {
            let session_id = super::begin_peer_session("sync-peer");
            replacement_tx
                .send(session_id)
                .expect("replacement session result should be observed");
        });
        assert!(
            replacement_rx
                .recv_timeout(Duration::from_millis(25))
                .is_err(),
            "replacement session must wait for the in-flight session-bound write"
        );
        release_write.wait();
        let (session_identity, ()) = write_handle
            .join()
            .expect("blocked sync write thread should join");

        let replacement_session_id = replacement_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("replacement session should start after the write completes");
        replacement_handle
            .join()
            .expect("replacement session thread should join");
        assert_ne!(replacement_session_id, session_identity.session_id);
        let peers = connected_peers.lock().unwrap();
        let peer = peers
            .get("sync-peer")
            .expect("replacement peer should remain present");
        assert!(!super::peer_stream_matches_identity(
            "sync-peer",
            peer,
            &session_identity
        ));
    }

    #[test]
    fn apply_block_batch_ignores_stale_matching_prefix_batches() {
        let _guard = block_application_test_guard();
        let mut chain = BlockChain::new();
        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis-parent".to_string(),
            "genesis".to_string(),
            0,
            1_700_000_000,
        );
        chain.add_block(genesis.clone());
        let block1 = test_block(&genesis, 1, "validator-a", 1);
        let block2 = test_block(&block1, 2, "validator-b", 2);
        let block3 = test_block(&block2, 3, "validator-c", 3);
        let block4 = test_block(&block3, 4, "validator-d", 4);
        let block5 = test_block(&block4, 5, "validator-e", 5);
        chain.add_block(block1.clone());
        chain.add_block(block2.clone());
        chain.add_block(block3.clone());
        chain.add_block(block4.clone());
        chain.add_block(block5.clone());

        let blockchain = Arc::new(Mutex::new(chain));
        let applied = apply_block_batch(
            &blockchain,
            vec![block2.clone(), block3.clone(), block4.clone()],
            vec![
                test_quorum_certificate(&block2),
                test_quorum_certificate(&block3),
                test_quorum_certificate(&block4),
            ],
        );
        assert_eq!(applied, 0);

        let chain = blockchain.lock().unwrap();
        assert_eq!(chain.last().map(|block| block.block_index), Some(5));
        assert_eq!(
            chain.block_at_height(5).map(|block| block.hash.clone()),
            Some(block5.hash.clone())
        );
    }

    #[test]
    fn apply_block_batch_accepts_qc_less_matching_overlap_before_new_blocks() {
        let _guard = block_application_test_guard();
        let mut chain = BlockChain::new();
        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis-parent".to_string(),
            "genesis".to_string(),
            0,
            1_700_000_000,
        );
        chain.add_block(genesis.clone());
        let block1 = test_block(&genesis, 1, "validator-a", 1);
        let block2 = test_block(&block1, 2, "validator-b", 2);
        let block3 = test_block(&block2, 3, "validator-c", 3);
        let block4 = test_block(&block3, 4, "validator-d", 4);
        chain.add_block(block1.clone());
        chain.add_block(block2.clone());
        chain.add_block(block3.clone());

        let blockchain = Arc::new(Mutex::new(chain));
        let applied = apply_block_batch(
            &blockchain,
            vec![block2.clone(), block3.clone(), block4.clone()],
            vec![test_quorum_certificate(&block4)],
        );
        assert_eq!(applied, 1);

        let chain = blockchain.lock().unwrap();
        assert_eq!(chain.last().map(|block| block.block_index), Some(4));
        assert_eq!(
            chain.block_at_height(4).map(|block| block.hash.clone()),
            Some(block4.hash.clone())
        );
        drop(chain);
        clear_legacy_canonical_locks_for_tests();
    }

    #[test]
    fn stale_unidentified_peers_are_pruned_after_grace_window() {
        let peer = PeerConnection {
            address: "10.69.0.5:55354".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: None,
            validator_address: None,
            connected_at: 100,
            last_seen: 100,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            connected_endpoint: None,
            node_id: None,
            handshake_role: None,
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            status_reported_at: None,
            status_validator_address: None,
            status_source_session_id: None,
            active_validator_set_hash: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };
        let config = NodeConfig::default();
        let active_validator_addresses = HashSet::new();

        assert!(!should_prune_stale_peer(
            &config,
            &peer,
            100 + STALE_UNIDENTIFIED_PEER_SECS - 1,
            &active_validator_addresses,
        ));
        assert!(should_prune_stale_peer(
            &config,
            &peer,
            100 + STALE_UNIDENTIFIED_PEER_SECS,
            &active_validator_addresses,
        ));
    }

    #[test]
    fn configured_validator_dial_is_not_status_ready_until_status_exchange() {
        let validators = vec![
            "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs".to_string(),
            "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt".to_string(),
            "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string(),
            "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5".to_string(),
            "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f".to_string(),
            "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx".to_string(),
        ];
        let active_validator_addresses = validators.iter().cloned().collect::<HashSet<_>>();
        let mut config = NodeConfig::default();
        config.node.allowed_validator_addresses = validators;
        config.node.validator_address = "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string();
        config.network.persistent_peers = vec![
            "62.146.182.207:5622".to_string(),
            "62.146.182.208:5622".to_string(),
            "73.79.66.255:5622".to_string(),
            "194.163.183.166:5622".to_string(),
            "157.173.192.45:5622".to_string(),
        ];
        // A bare endpoint no longer identifies a peer: identity comes from an
        // explicit route -> `synv...` binding. Without this the dialed peer is
        // (correctly) "unidentified" and would be pruned as stale.
        config.network.validator_vpn_transports = vec![ValidatorVpnTransportConfig {
            validator_address: "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5".to_string(),
            dial_address: "73.79.66.255:5622".to_string(),
        }];
        let now = current_timestamp();
        let peer = PeerConnection {
            address: "73.79.66.255:5622".to_string(),
            direction: ConnectionDirection::Outgoing,
            public_address: None,
            validator_address: None,
            connected_at: now,
            last_seen: now,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            connected_endpoint: None,
            node_id: None,
            handshake_role: None,
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            status_reported_at: None,
            status_validator_address: None,
            status_source_session_id: None,
            active_validator_set_hash: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };
        let connected_peers = Arc::new(Mutex::new(HashMap::from([(
            "73.79.66.255:5622".to_string(),
            peer,
        )])));

        let status_ready = status_ready_validator_addresses(&config, &connected_peers);

        assert!(status_ready.contains(&"synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string()));
        assert!(!status_ready.contains(&"synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5".to_string()));
        let peers = connected_peers.lock().expect("peer map should lock");
        let peer = peers
            .get("73.79.66.255:5622")
            .expect("configured validator peer should exist");
        assert!(!should_prune_stale_peer(
            &config,
            peer,
            now + STALE_UNIDENTIFIED_PEER_SECS,
            &active_validator_addresses,
        ));
        assert!(!should_prune_stale_peer(
            &config,
            peer,
            now + STALE_VALIDATOR_STATUS_SECS,
            &active_validator_addresses,
        ));
        assert!(should_prune_stale_peer(
            &config,
            peer,
            now + STALE_VALIDATOR_STATUS_SECS + 1,
            &active_validator_addresses,
        ));
    }

    #[test]
    fn validator_peers_missing_status_are_pruned_after_status_timeout() {
        let peer = PeerConnection {
            address: "10.69.0.2:5622".to_string(),
            direction: ConnectionDirection::Outgoing,
            public_address: Some("10.69.0.2:5622".to_string()),
            validator_address: Some("synv1peer-b".to_string()),
            connected_at: 200,
            last_seen: 200,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: Some("synv1peer-b".to_string()),
            connected_endpoint: None,
            handshake_role: None,
            version: Some("1.0.0".to_string()),
            capabilities: vec!["blocks".to_string()],
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            status_reported_at: None,
            status_validator_address: None,
            status_source_session_id: None,
            active_validator_set_hash: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };
        let config = NodeConfig::default();
        let active_validator_addresses = HashSet::new();

        assert!(!should_prune_stale_peer(
            &config,
            &peer,
            200 + STALE_VALIDATOR_STATUS_SECS - 1,
            &active_validator_addresses,
        ));
        assert!(!should_prune_stale_peer(
            &config,
            &peer,
            200 + STALE_VALIDATOR_STATUS_SECS,
            &active_validator_addresses,
        ));
        assert!(should_prune_stale_peer(
            &config,
            &peer,
            200 + STALE_VALIDATOR_STATUS_SECS + 1,
            &active_validator_addresses,
        ));
    }
}
