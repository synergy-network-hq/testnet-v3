use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::block::{Block, BlockChain, HOT_CHAIN_RETENTION_BLOCKS_ENV};
use crate::cluster::{fault_tolerance_f, quorum_threshold, EpochClusterAssignmentSnapshot};
use crate::config::ResolvedConsensusMode;
use crate::consensus::chain_durability::recover_chain_and_validate_canonical;
#[cfg(test)]
use crate::consensus::consensus_algorithm::reconcile_validator_registry_clusters_for_height;
use crate::consensus::consensus_algorithm::{
    reconcile_validator_registry_clusters_from_finalized_chain, ProofOfSynergy,
    CLUSTER_RANDOMNESS_V3_ACTIVATION_EPOCH, CLUSTER_RANDOMNESS_V3_ACTIVATION_HEIGHT,
    EPOCH_RANDOMNESS_V3_ACTIVATION_EPOCH, EPOCH_RANDOMNESS_V3_ACTIVATION_HEIGHT,
};
use crate::consensus::consensus_fork;
use crate::consensus::coordinated_finality_store::{
    configured_coordinated_finality_path, CoordinatedFinalityRecord, CoordinatedFinalityStore,
};
use crate::consensus::coordinated_round_robin::CoordinatedConsensusVerifier;
use crate::consensus::dual_quorum::{required_validator_quorum, DualQuorumConsensus};
use crate::consensus::legacy_canonical_lock::{
    legacy_canonical_commit_record, write_legacy_canonical_lock,
};
use crate::consensus::synergy_score::SynergyScoreCalculator;
use crate::consensus::testnet_v3_bootstrap::load_testnet_v3_genesis_bootstrap;
use crate::consensus::typed_finality_store::{
    configured_typed_finality_path, TypedFinalityRecord, TypedFinalityStore,
};
use crate::crypto::pqc::PQCManager;
use crate::epoch::{epoch_for_block_height, TESTNET_EPOCH_LENGTH_BLOCKS};
use crate::genesis::canonical_genesis;
use crate::role_profiles::{resolve_configured_role, AuthorityPlane, RoleProfile};
use crate::sxcp;
use crate::sync::{SyncManager, SyncState};
use crate::synergy_types::{CanonicalSerialize, Hash, TxId};
use crate::synq_execution::{
    execute_synq_static_call, execute_synq_transaction_at, SynQArtifactKey, SynQContractArtifact,
    SynQDeploymentRecord, SynQExecutionContext,
};
use crate::synq_receipts::{
    configured_synq_receipt_index_path, SynQIndexedReceipt, SynQReceiptIndex,
};
use crate::token::TOKEN_MANAGER;
use crate::transaction::Transaction;
use crate::validator::{
    balanced_validator_cluster_id, canonical_active_validator_set_hash,
    canonical_validator_cluster_address, canonical_validator_clusters_for_height,
    canonical_validator_clusters_for_height_with_seed, consensus_membership_validators_for_height,
    effective_cluster_epoch_for_height, replay_validator_activation_transactions,
    replay_validator_activation_transactions_for_service, target_validator_cluster_count,
    validator_set_effective_height_for_height, Validator, ValidatorManager, ValidatorRegistry,
    ValidatorStatus, INITIAL_VALIDATOR_SYNERGY_SCORE, TESTNET_MIN_VALIDATOR_STAKE_NWEI,
    VALIDATOR_MANAGER,
};
use crate::wallet::WALLET_MANAGER;
use crate::{info, warn};
use aivm_core::state::StateKey;
// Temporarily disabled for quick compile
// use crate::aivm::AIVMRuntime;
// use crate::aivm::runtime::{ContractType, AIVMExecutionContext};
use hex;
use lazy_static::lazy_static;
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use tungstenite::handshake::server::{Request as WsRequest, Response as WsResponse};
use tungstenite::{accept_hdr, Error as WsError, Message as WsMessage};

const VALIDATOR_REGISTRY_PATH: &str = "data/validator_registry.json";

fn compact_hot_chain_state_from_env(chain: &mut BlockChain, context: &str) {
    if let Some((retain_recent_blocks, removed_blocks)) = chain.compact_from_env() {
        if removed_blocks > 0 {
            info!(
                "rpc",
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

fn compact_boundary_has_or_rebuilds_canonical_lock(block: &Block) -> Result<bool, String> {
    match legacy_canonical_commit_record(block.block_index)? {
        Some(record) if record.block_hash == block.hash && record.parent_hash == block.previous_hash => {
            Ok(true)
        }
        Some(record) => Err(format!(
            "compact chain boundary h{} does not match canonical lock: chain_hash={} chain_parent={} lock_hash={} lock_parent={}",
            block.block_index,
            block.hash,
            block.previous_hash,
            record.block_hash,
            record.parent_hash
        )),
        None => {
            let Some(qc) = DualQuorumConsensus::committed_qc_for_block_hash(&block.hash) else {
                return Err(format!(
                    "compact chain starts at h{} but canonical lock is missing and no committed QC can rebuild it",
                    block.block_index
                ));
            };
            write_legacy_canonical_lock(block, &qc).map_err(|error| {
                format!(
                    "compact chain starts at h{} but canonical lock rebuild failed: {error}",
                    block.block_index
                )
            })?;
            Ok(true)
        }
    }
}

lazy_static! {
    pub static ref TX_POOL: Arc<Mutex<Vec<Transaction>>> = Arc::new(Mutex::new(Vec::new()));
}

lazy_static! {
    static ref NODE_START_TIME: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
}

lazy_static! {
    static ref LAST_KNOWN_GOOD_CHAIN_TIP: Mutex<Option<Block>> = Mutex::new(None);
}

lazy_static! {
    static ref SIMULATION_CACHE: Mutex<HashMap<String, CachedSimulation>> =
        Mutex::new(HashMap::new());
}

static SUBSCRIPTION_COUNTER: AtomicU64 = AtomicU64::new(1);
static QRPC_FALLBACK_COUNT: AtomicU64 = AtomicU64::new(0);
const MAX_HTTP_HEADER_BYTES: usize = 32 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 4 * 1024 * 1024;
const QRPC_CHAIN_TIP_RETRY_ATTEMPTS: usize = 40;
const QRPC_CHAIN_TIP_RETRY_DELAY_MILLIS: u64 = 25;
const QRPC_STATUS_CHAIN_SNAPSHOT_RETRY_ATTEMPTS: usize = 8;
const QRPC_STATUS_CHAIN_SNAPSHOT_RETRY_DELAY_MILLIS: u64 = 25;
const QRPC_CHAIN_UNAVAILABLE_ERROR: &str = "consensus chain state unavailable without blocking";

#[derive(Debug, Clone)]
struct ChainTipSnapshot {
    available: bool,
    height: Option<u64>,
    hash: Option<String>,
    timestamp: Option<u64>,
    error: Option<String>,
}

pub(crate) fn cache_last_known_good_chain_tip(block: &Block) {
    if let Ok(mut cached_tip) = LAST_KNOWN_GOOD_CHAIN_TIP.lock() {
        *cached_tip = Some(block.clone());
    }
}

fn cached_last_known_good_chain_tip() -> Option<Block> {
    LAST_KNOWN_GOOD_CHAIN_TIP
        .lock()
        .ok()
        .and_then(|cached_tip| cached_tip.clone())
}

pub fn qrpc_fallback_count() -> u64 {
    QRPC_FALLBACK_COUNT.load(Ordering::Relaxed)
}

fn record_qrpc_fallback(reason: &str) {
    QRPC_FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
    warn!(
        "rpc",
        "qRPC served read from fallback state",
        "reason" => reason.to_string()
    );
}

fn persisted_chain_tip() -> Option<Block> {
    let chain_path = crate::utils::resolve_data_path("data/chain.json");
    BlockChain::load_last_from_file(chain_path.to_str().unwrap_or("data/chain.json"))
}

fn cached_or_load_chain_tip<F>(cached: Option<Block>, load_persisted: F) -> Option<Block>
where
    F: FnOnce() -> Option<Block>,
{
    cached.or_else(load_persisted)
}

fn cached_or_persisted_chain_tip() -> Option<Block> {
    // The canonical startup path primes this cache before the RPC listener starts, and every
    // committed block refreshes it while holding the chain lock. Reparsing the full chain file
    // here can stall a simple height request for tens of seconds during catch-up.
    let best_tip =
        cached_or_load_chain_tip(cached_last_known_good_chain_tip(), persisted_chain_tip);
    if let Some(block) = best_tip.as_ref() {
        cache_last_known_good_chain_tip(block);
    }
    best_tip
}

fn try_live_chain_tip_block(chain: &Arc<Mutex<BlockChain>>) -> Result<Option<Block>, ()> {
    match chain.try_lock() {
        Ok(chain_guard) => {
            let latest_block = chain_guard.last().cloned();
            if let Some(block) = latest_block.as_ref() {
                cache_last_known_good_chain_tip(block);
            }
            Ok(latest_block)
        }
        Err(TryLockError::WouldBlock) | Err(TryLockError::Poisoned(_)) => Err(()),
    }
}

fn read_through_chain_tip_block(chain: &Arc<Mutex<BlockChain>>) -> Option<Block> {
    for attempt in 0..QRPC_CHAIN_TIP_RETRY_ATTEMPTS {
        if let Ok(latest_block) = try_live_chain_tip_block(chain) {
            return latest_block;
        }
        if attempt + 1 < QRPC_CHAIN_TIP_RETRY_ATTEMPTS {
            thread::sleep(Duration::from_millis(QRPC_CHAIN_TIP_RETRY_DELAY_MILLIS));
        }
    }

    let fallback = cached_or_persisted_chain_tip();
    if fallback.is_some() {
        record_qrpc_fallback("chain_tip_lock_unavailable");
    }
    fallback
}

fn chain_tip_snapshot_from_block(block: &Block) -> ChainTipSnapshot {
    ChainTipSnapshot {
        available: true,
        height: Some(block.block_index),
        hash: Some(block.hash.clone()),
        timestamp: Some(block.timestamp),
        error: None,
    }
}

fn find_http_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

#[derive(Debug, Clone)]
struct RpcError {
    code: i64,
    message: String,
    data: Option<Value>,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    fn with_data(code: i64, message: impl Into<String>, data: Value) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }
}

#[derive(Debug, Clone)]
struct CachedSimulation {
    simulation_hash: String,
    created_at: u64,
}

#[derive(Debug, Clone)]
struct StsReplayReport {
    source: &'static str,
    state: crate::sts::StsState,
    chain_start_height: u64,
    latest_height: u64,
    snapshot_block_hash: Option<String>,
    snapshot_updated_at: Option<u64>,
    scanned_blocks: usize,
    scanned_transactions: usize,
    applied_transactions: usize,
    skipped_payloads: usize,
    errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpcTransport {
    Http,
    WebSocket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpcMethodExposure {
    PublicRead,
    PublicClient,
    AuthorityPlane,
    NonPublicWrite,
    Operator,
}

impl RpcMethodExposure {
    fn label(self) -> &'static str {
        match self {
            Self::PublicRead => "public-read",
            Self::PublicClient => "public-client",
            Self::AuthorityPlane => "authority-plane",
            Self::NonPublicWrite => "non-public-write",
            Self::Operator => "operator",
        }
    }
}

#[derive(Debug, Clone)]
struct RpcRequestContext {
    transport: RpcTransport,
    peer_addr: Option<SocketAddr>,
    headers: HashMap<String, String>,
    role_profile: Option<&'static RoleProfile>,
}

impl RpcRequestContext {
    fn new(
        transport: RpcTransport,
        peer_addr: Option<SocketAddr>,
        headers: HashMap<String, String>,
    ) -> Self {
        Self {
            transport,
            peer_addr,
            headers,
            role_profile: current_rpc_role_profile(),
        }
    }

    fn effective_client_ip(&self) -> Option<IpAddr> {
        self.trusted_forwarded_client_ip()
            .or_else(|| self.peer_addr.map(|addr| addr.ip()))
    }

    fn forwarded_client_ip_header(&self) -> Option<&str> {
        self.headers
            .get("cf-connecting-ip")
            .map(String::as_str)
            .or_else(|| self.headers.get("true-client-ip").map(String::as_str))
            .or_else(|| self.headers.get("x-forwarded-for").map(String::as_str))
            .or_else(|| self.headers.get("x-real-ip").map(String::as_str))
    }

    fn trusted_forwarded_client_ip(&self) -> Option<IpAddr> {
        let peer_ip = self.peer_addr.map(|addr| addr.ip())?;
        if !trusted_rpc_proxy_peer(peer_ip) {
            return None;
        }
        parse_forwarded_ip(self.forwarded_client_ip_header())
    }

    fn is_public_request(&self) -> bool {
        if self.trusted_forwarded_client_ip().is_some() {
            return true;
        }
        self.effective_client_ip()
            .map(|ip| !ip.is_loopback())
            .unwrap_or(false)
    }

    fn transport_label(&self) -> &'static str {
        match self.transport {
            RpcTransport::Http => "http",
            RpcTransport::WebSocket => "ws",
        }
    }
}

#[derive(Debug, Clone)]
enum SubscriptionCursor {
    NewHeads {
        last_block: u64,
    },
    Logs {
        last_block: u64,
        address: Option<String>,
        topics: Vec<String>,
    },
    PendingTransactions {
        seen_hashes: HashSet<String>,
    },
    ValidatorEvents {
        last_block: u64,
    },
}

#[derive(Debug, Clone, serde::Deserialize)]
struct RpcTransactionEnvelope {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    sender: Option<String>,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    receiver: Option<String>,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    amount: Option<Value>,
    #[serde(default)]
    nonce: Option<u64>,
    #[serde(default)]
    signature: Option<Value>,
    #[serde(rename = "signerPublicKey", default)]
    signer_public_key_alias: Option<Value>,
    #[serde(default)]
    signer_public_key: Option<Value>,
    #[serde(rename = "publicKey", default)]
    public_key_alias: Option<Value>,
    #[serde(default)]
    timestamp: Option<u64>,
    #[serde(default)]
    gas_price: Option<Value>,
    #[serde(rename = "gasPrice", default)]
    gas_price_alias: Option<Value>,
    #[serde(rename = "maxFee", default)]
    max_fee: Option<Value>,
    #[serde(default)]
    gas_limit: Option<Value>,
    #[serde(rename = "gasLimit", default)]
    gas_limit_alias: Option<Value>,
    #[serde(rename = "maxPriorityFeePerGas", default)]
    max_priority_fee_per_gas: Option<Value>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    signature_algorithm: Option<String>,
    #[serde(rename = "signatureAlgorithm", default)]
    signature_algorithm_alias: Option<String>,
    #[serde(rename = "chainId", default)]
    chain_id: Option<Value>,
    #[serde(default)]
    network_id: Option<String>,
    #[serde(rename = "networkId", default)]
    network_id_alias: Option<String>,
    #[serde(default)]
    tx_type: Option<String>,
    #[serde(rename = "type", default)]
    envelope_type: Option<String>,
    #[serde(default)]
    delegation: Option<Value>,
    #[serde(default)]
    delegations: Option<Value>,
    #[serde(rename = "authorizationList", default)]
    authorization_list: Option<Value>,
}

#[derive(Debug, Clone)]
struct NormalizedRpcTransaction {
    chain_id: u64,
    network_id: String,
    sender: String,
    receiver: String,
    amount: u64,
    nonce: u64,
    signature: Vec<u8>,
    signer_public_key: Vec<u8>,
    timestamp: u64,
    gas_price: u64,
    gas_limit: u64,
    data: Option<String>,
    signature_algorithm: String,
}

#[derive(Debug, Clone)]
struct NormalizedEnvelopeResult {
    transaction: Transaction,
    warnings: Vec<String>,
    chain_id: Option<u64>,
}

// Global shared blockchain instance - will be used by both RPC and consensus
lazy_static! {
    pub static ref SHARED_CHAIN: Arc<Mutex<BlockChain>> = {
        let chain_path = crate::utils::resolve_data_path("data/chain.json");
        let canonical_genesis = canonical_genesis()
            .unwrap_or_else(|error| panic!("failed to load canonical genesis: {error}"));
        Arc::new(Mutex::new(
            match BlockChain::load_from_file(chain_path.to_str().unwrap_or("data/chain.json")) {
                Some(chain) => {
                    let mut chain = chain;
                    if let Err(error) = chain.ensure_expected_genesis_hash(canonical_genesis.hash())
                    {
                        let compact_boundary = chain
                            .chain
                            .first()
                            .filter(|block| block.block_index > 0)
                            .map(compact_boundary_has_or_rebuilds_canonical_lock)
                            .transpose()
                            .unwrap_or_else(|boundary_error| {
                                panic!(
                                    "compact chain boundary preflight failed for {}: {}",
                                    chain_path.display(),
                                    boundary_error
                                )
                            })
                            .unwrap_or(false);
                        if compact_boundary {
                            info!(
                                "rpc",
                                "Accepted compact chain state with canonical lock boundary",
                                "path" => chain_path.display().to_string(),
                                "first_height" => chain.chain.first().map(|block| block.block_index).unwrap_or(0),
                                "first_hash" => chain.chain.first().map(|block| block.hash.clone()).unwrap_or_default(),
                                "canonical_genesis" => canonical_genesis.hash().to_string()
                            );
                        } else {
                            #[cfg(test)]
                            {
                                eprintln!(
                                    "ignoring incompatible test chain state at {}: {}",
                                    chain_path.display(),
                                    error
                                );
                                let mut chain = BlockChain::new();
                                chain.genesis().unwrap_or_else(|error| {
                                    panic!("failed to bootstrap genesis block: {error}")
                                });
                                return Arc::new(Mutex::new(chain));
                            }
                            #[cfg(not(test))]
                            {
                                panic!(
                                "existing chain state at {} does not match canonical genesis {}: {}",
                                chain_path.display(),
                                canonical_genesis.hash(),
                                error
                            )
                            }
                        }
                    }
                    recover_chain_and_validate_canonical(&mut chain, &chain_path).unwrap_or_else(
                        |error| {
                            panic!(
                                "chain body durability preflight failed for {}: {}",
                                chain_path.display(),
                                error
                            )
                        },
                    );
                    compact_hot_chain_state_from_env(&mut chain, "startup_existing_chain");
                    chain
                }
                None => {
                    let mut chain = BlockChain::new();
                    chain.genesis().unwrap_or_else(|error| {
                        panic!("failed to bootstrap genesis block: {error}")
                    });
                    compact_hot_chain_state_from_env(&mut chain, "startup_new_chain");
                    chain.save_to_file(chain_path.to_str().unwrap_or("data/chain.json"));
                    chain
                }
            },
        ))
    };
}

lazy_static! {
    pub static ref SYNC_MANAGER: Arc<Mutex<SyncManager>> =
        Arc::new(Mutex::new(SyncManager::new(Arc::clone(&SHARED_CHAIN))));
}

// For backward compatibility
pub use self::SHARED_CHAIN as CHAIN;

// Temporarily disabled for quick compile
// lazy_static! {
//     pub static ref AIVM_RUNTIME: Arc<AIVMRuntime> = Arc::new(AIVMRuntime::new());
// }

fn replay_validator_activations_from_canonical_chain(
    canonical_chain: &BlockChain,
    token_manager: &crate::token::TokenManager,
    validator_manager: &Arc<ValidatorManager>,
) -> (u64, u64) {
    replay_validator_activation_transactions(canonical_chain, token_manager, validator_manager)
}

fn rpc_startup_uses_service_safe_replay(role_profile: Option<&RoleProfile>) -> bool {
    role_profile
        .map(|profile| !profile.service_surface.contains(&"consensus"))
        .unwrap_or(false)
}

fn replay_validator_activations_for_rpc_startup(
    canonical_chain: &BlockChain,
    token_manager: &crate::token::TokenManager,
    validator_manager: &Arc<ValidatorManager>,
    role_profile: Option<&RoleProfile>,
) -> (u64, u64) {
    if rpc_startup_uses_service_safe_replay(role_profile) {
        replay_validator_activation_transactions_for_service(
            canonical_chain,
            token_manager,
            validator_manager,
        )
    } else {
        replay_validator_activations_from_canonical_chain(
            canonical_chain,
            token_manager,
            validator_manager,
        )
    }
}

/// Reconcile registry-only cluster state from the canonical finalized tip.
///
/// Service roles may expose validator-set state but never run consensus duties. Every non-empty
/// membership uses the same finalized-boundary evidence as validators, regardless of cluster
/// count. A partial or unverified chain therefore fails closed instead of publishing a divergent
/// bootstrap map.
fn reconcile_validator_registry_from_finalized_chain(
    canonical_chain: &BlockChain,
    validator_manager: &Arc<ValidatorManager>,
) -> Result<bool, String> {
    let finalized_height = canonical_chain
        .last()
        .map(|block| block.block_index)
        .ok_or_else(|| "canonical finalized chain tip is unavailable".to_string())?;
    let canonical_epoch = epoch_for_block_height(finalized_height, TESTNET_EPOCH_LENGTH_BLOCKS);
    let registry_validators = validator_manager
        .registry
        .lock()
        .map_err(|_| "failed to lock validator registry for finalized reconciliation".to_string())?
        .validators
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let active = consensus_membership_validators_for_height(registry_validators, finalized_height)?;
    if active.is_empty() {
        let mut registry = validator_manager.registry.lock().map_err(|_| {
            "failed to lock validator registry for finalized reconciliation".to_string()
        })?;
        let mut changed = registry.normalize_testnet_epoch_contract();
        if registry.current_epoch != canonical_epoch || !registry.clusters.is_empty() {
            registry.current_epoch = canonical_epoch;
            registry.clear_cluster_assignments();
            changed = true;
        }
        return Ok(changed);
    }

    {
        return reconcile_validator_registry_clusters_from_finalized_chain(
            validator_manager,
            canonical_chain,
            finalized_height,
        );
    }
}

pub fn start_rpc_server(
    bind_address: &str,
    ws_bind_address: Option<String>,
    cors_enabled: bool,
    cors_origins: Vec<String>,
) {
    println!("📡 RPC server running on {}", bind_address);
    {
        let mut start_time = NODE_START_TIME.lock().unwrap();
        if start_time.is_none() {
            *start_time = Some(current_timestamp());
        }
    }

    // Load the registry first so replay can repair stale entries as well as rebuild a missing file.
    if let Err(e) = VALIDATOR_MANAGER.load_registry(VALIDATOR_REGISTRY_PATH) {
        println!("ℹ️ No validator registry found at startup: {}", e);
    }
    let role_profile = current_rpc_role_profile();

    // SHARED_CHAIN has already passed canonical genesis and chain-body validation during
    // initialization. Keep the validated chain locked while replay scans it by reference so a
    // missing or stale registry cannot suppress an activated validator or double chain memory.
    let (activation_replayed, activation_failed, cluster_reconciliation) = {
        let canonical_chain = SHARED_CHAIN
            .lock()
            .expect("canonical startup chain lock should not be poisoned");
        let replay_result = replay_validator_activations_for_rpc_startup(
            &canonical_chain,
            &TOKEN_MANAGER,
            &VALIDATOR_MANAGER,
            role_profile,
        );
        if let Some(block) = canonical_chain.last() {
            cache_last_known_good_chain_tip(block);
        }
        let cluster_reconciliation = if rpc_startup_uses_service_safe_replay(role_profile) {
            reconcile_validator_registry_from_finalized_chain(&canonical_chain, &VALIDATOR_MANAGER)
        } else {
            Ok(false)
        };
        (replay_result.0, replay_result.1, cluster_reconciliation)
    };
    if activation_replayed > 0 {
        println!(
            "🔁 Replayed {} validator activation transaction(s) at startup",
            activation_replayed
        );
    }
    if activation_failed > 0 {
        eprintln!(
            "⚠️ Rejected {} validator activation transaction(s) at startup; fail-closed validation left them unapplied",
            activation_failed
        );
    }
    if let Err(error) = &cluster_reconciliation {
        eprintln!(
            "⚠️ Failed to reconcile validator clusters from finalized chain; validator-set RPC will fail closed: {}",
            error
        );
    }

    let validators = VALIDATOR_MANAGER.get_active_validators();
    println!(
        "✅ Loaded {} validators from registry at startup",
        validators.len()
    );
    if activation_replayed > 0
        || cluster_reconciliation
            .as_ref()
            .is_ok_and(|changed| *changed)
    {
        if let Err(error) = VALIDATOR_MANAGER.save_registry(VALIDATOR_REGISTRY_PATH) {
            println!(
                "⚠️ Failed to persist startup validator registry replay: {}",
                error
            );
        }
    }

    if let Some(ws_bind_address) = ws_bind_address {
        let tx_pool = Arc::clone(&TX_POOL);
        let chain = Arc::clone(&CHAIN);
        let validator_manager = Arc::clone(&VALIDATOR_MANAGER);
        thread::spawn(move || {
            start_ws_rpc_server(&ws_bind_address, &tx_pool, &chain, &validator_manager);
        });
    }

    for stream in TcpListener::bind(bind_address)
        .expect("Failed to bind RPC server")
        .incoming()
    {
        let tx_pool = Arc::clone(&TX_POOL);
        let chain = Arc::clone(&CHAIN);
        let validator_manager = Arc::clone(&VALIDATOR_MANAGER);
        let cors_enabled_for_conn = cors_enabled;
        let cors_origins_for_conn = cors_origins.clone();
        thread::spawn(move || {
            if let Ok(mut stream) = stream {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let mut buffer = [0; 16384];
                if let Ok(bytes_read) = stream.read(&mut buffer) {
                    let mut request_bytes = buffer[..bytes_read].to_vec();
                    while find_http_header_end(&request_bytes).is_none()
                        && request_bytes.len() < MAX_HTTP_HEADER_BYTES
                    {
                        match stream.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(next_read) => request_bytes.extend_from_slice(&buffer[..next_read]),
                            Err(_) => break,
                        }
                    }

                    let Some(header_end) = find_http_header_end(&request_bytes) else {
                        send_json_rpc_error(
                            &mut stream,
                            None,
                            &RpcError::new(-32700, "Malformed HTTP request"),
                            cors_enabled_for_conn,
                            &cors_origins_for_conn,
                        );
                        return;
                    };

                    let header_bytes = &request_bytes[..header_end];
                    let request_headers = String::from_utf8_lossy(header_bytes);
                    let request_line = request_headers.lines().next().unwrap_or_default();
                    let mut request_line_parts = request_line.split_whitespace();
                    let http_method = request_line_parts.next().unwrap_or_default();
                    let request_path = request_line_parts.next().unwrap_or("/");

                    // Handle CORS preflight
                    if http_method == "OPTIONS" {
                        let response_str = format_cors_preflight_response(
                            cors_enabled_for_conn,
                            &cors_origins_for_conn,
                        );
                        write_http_response_and_close(&mut stream, &response_str);
                        return;
                    }

                    if http_method == "GET" {
                        let response_str = match request_path {
                            "/" | "/healthz" => format_text_response(
                                "ok\n",
                                cors_enabled_for_conn,
                                &cors_origins_for_conn,
                            ),
                            "/readyz" => format_text_response(
                                "ready\n",
                                cors_enabled_for_conn,
                                &cors_origins_for_conn,
                            ),
                            _ => format_not_found_response(
                                cors_enabled_for_conn,
                                &cors_origins_for_conn,
                            ),
                        };
                        let _ = stream.write(response_str.as_bytes());
                        let _ = stream.flush();
                        return;
                    }

                    let headers = parse_http_headers(&request_headers);
                    let request_context = RpcRequestContext::new(
                        RpcTransport::Http,
                        stream.peer_addr().ok(),
                        headers.clone(),
                    );
                    let mut body = request_bytes[header_end + 4..].to_vec();

                    if http_method == "POST" {
                        if !request_is_json(&headers) {
                            send_json_rpc_error(
                                &mut stream,
                                None,
                                &RpcError::new(-32700, "Content-Type must be application/json"),
                                cors_enabled_for_conn,
                                &cors_origins_for_conn,
                            );
                            return;
                        }

                        let content_length = headers
                            .get("content-length")
                            .and_then(|value| value.parse::<usize>().ok());
                        if matches!(content_length, Some(length) if length > MAX_HTTP_BODY_BYTES) {
                            send_json_rpc_error(
                                &mut stream,
                                None,
                                &RpcError::new(-32600, "HTTP request body too large"),
                                cors_enabled_for_conn,
                                &cors_origins_for_conn,
                            );
                            return;
                        }
                        if let Some(content_length) = content_length {
                            while body.len() < content_length {
                                match stream.read(&mut buffer) {
                                    Ok(0) => break,
                                    Ok(next_read) => body.extend_from_slice(&buffer[..next_read]),
                                    Err(_) => break,
                                }
                            }
                            body.truncate(content_length);
                        }

                        match serde_json::from_slice::<Value>(&body) {
                            Ok(parsed) => match process_json_rpc_payload(
                                &parsed,
                                &tx_pool,
                                &chain,
                                &validator_manager,
                                None,
                                &request_context,
                            ) {
                                Ok(Some(response)) => {
                                    let response_str = format_response(
                                        &response.to_string(),
                                        cors_enabled_for_conn,
                                        &cors_origins_for_conn,
                                    );
                                    write_http_response_and_close(&mut stream, &response_str);
                                }
                                Ok(None) => {
                                    let response_str = format_http_response(
                                        "204 No Content",
                                        "application/json",
                                        "",
                                        cors_enabled_for_conn,
                                        &cors_origins_for_conn,
                                    );
                                    write_http_response_and_close(&mut stream, &response_str);
                                }
                                Err(error) => send_json_rpc_error(
                                    &mut stream,
                                    None,
                                    &error,
                                    cors_enabled_for_conn,
                                    &cors_origins_for_conn,
                                ),
                            },
                            Err(_) => send_json_rpc_error(
                                &mut stream,
                                None,
                                &RpcError::new(-32700, "Malformed JSON in body"),
                                cors_enabled_for_conn,
                                &cors_origins_for_conn,
                            ),
                        }
                    } else {
                        send_json_rpc_error(
                            &mut stream,
                            None,
                            &RpcError::new(-32600, "Unsupported HTTP method"),
                            cors_enabled_for_conn,
                            &cors_origins_for_conn,
                        );
                    }
                }
            }
        });
    }
}

pub fn transaction_hashes(transactions: &[Transaction]) -> HashSet<String> {
    transactions
        .iter()
        .map(|transaction| transaction.hash())
        .collect()
}

pub fn prune_transaction_hashes_from_pool(confirmed_hashes: &HashSet<String>) -> usize {
    if confirmed_hashes.is_empty() {
        return 0;
    }

    let mut pool = TX_POOL.lock().unwrap();
    let before = pool.len();
    pool.retain(|transaction| !confirmed_hashes.contains(&transaction.hash()));
    before.saturating_sub(pool.len())
}

fn prune_invalid_transactions_from_pool() -> usize {
    let pending_transactions = TX_POOL.lock().unwrap().clone();
    let invalid_transactions = pending_transactions
        .iter()
        .filter_map(|transaction| {
            ProofOfSynergy::validate_transaction_for_mempool(transaction)
                .err()
                .map(|reason| (transaction.hash(), transaction.sender.clone(), reason))
        })
        .collect::<Vec<_>>();

    if invalid_transactions.is_empty() {
        return 0;
    }

    let invalid_hashes = invalid_transactions
        .iter()
        .map(|(tx_hash, _, _)| tx_hash.clone())
        .collect::<HashSet<_>>();
    let pruned = prune_transaction_hashes_from_pool(&invalid_hashes);

    for (tx_hash, sender, reason) in invalid_transactions {
        warn!(
            "rpc",
            "Pruned runtime-invalid transaction from mempool",
            "tx_hash" => tx_hash,
            "sender" => sender,
            "reason" => reason
        );
    }

    pruned
}

fn default_cluster_id(index: usize, active_validator_count: usize) -> Option<u64> {
    balanced_validator_cluster_id(index, active_validator_count)
}

fn synthesize_validator(
    address: String,
    public_key: String,
    name: String,
    stake_amount: u64,
    registered_at: u64,
) -> Validator {
    Validator {
        address,
        public_key,
        name,
        website: None,
        description: None,
        email: None,
        registered_at,
        last_active: 0,
        total_blocks_produced: 0,
        total_transactions_validated: 0,
        uptime_percentage: 0.0,
        average_block_time: 0.0,
        missed_blocks: 0,
        double_signs: 0,
        consecutive_missed_votes: 0,
        missed_vote_window: 0,
        last_vote_timestamp: 0,
        equivocation_evidence_count: 0,
        synergy_score: 0.0,
        finalized_synergy_score_bps: 0,
        task_accuracy: 0.0,
        collaboration_score: 0.0,
        reputation_score: 0.0,
        slashing_penalty: 0.0,
        stake_amount,
        min_stake_required: stake_amount.max(1),
        cluster_id: None,
        cluster_address: None,
        cluster_assignment_epoch: None,
        cluster_assignment_seed: None,
        cluster_assignment_effective_height: None,
        status: ValidatorStatus::Inactive,
        version: env!("CARGO_PKG_VERSION").to_string(),
        activation_tx_hash: None,
        shadow_started_at_height: None,
        activation_recorded_height: None,
        activation_effective_height: None,
    }
}

fn assign_canonical_cluster_memberships(
    validators: &mut [Validator],
    epoch: u64,
    height: u64,
) -> Result<(), String> {
    let active_validators = validators
        .iter()
        .filter(|validator| validator.status == ValidatorStatus::Active)
        .cloned()
        .collect::<Vec<_>>();
    let cluster_members =
        canonical_validator_clusters_for_height(active_validators, epoch, height)?;
    let mut assignments = HashMap::new();
    for (cluster_id, members) in cluster_members {
        let cluster_address = canonical_validator_cluster_address(cluster_id, &members);
        for member in members {
            assignments.insert(member.address, (cluster_id, cluster_address.clone()));
        }
    }

    for validator in validators {
        if let Some((cluster_id, cluster_address)) = assignments.get(&validator.address) {
            validator.cluster_id = Some(*cluster_id);
            validator.cluster_address = Some(cluster_address.clone());
        } else {
            validator.cluster_id = None;
            validator.cluster_address = None;
        }
    }
    Ok(())
}

fn canonical_epoch_cluster_assignments(
    registry: &ValidatorRegistry,
    epoch: u64,
    height: u64,
    randomness_source: &str,
) -> Result<Vec<EpochClusterAssignmentSnapshot>, String> {
    let validator_candidates = registry.validators.values().cloned().collect::<Vec<_>>();
    let effective_epoch = effective_cluster_epoch_for_height(epoch, height)?;
    let height_scoped_membership =
        consensus_membership_validators_for_height(validator_candidates, height)?;
    let cluster_plan = canonical_validator_clusters_for_height_with_seed(
        height_scoped_membership,
        effective_epoch,
        height,
        randomness_source,
    )?;
    let assignment_hash = canonical_validator_cluster_plan_digest(&cluster_plan, effective_epoch);
    Ok(cluster_plan
        .into_iter()
        .map(|(cluster_id, members)| EpochClusterAssignmentSnapshot {
            epoch_id: effective_epoch,
            cluster_address: canonical_validator_cluster_address(cluster_id, &members),
            validator_ids: members
                .iter()
                .map(|validator| validator.address.clone())
                .collect(),
            quorum_threshold: quorum_threshold(members.len()),
            fault_tolerance_f: fault_tolerance_f(members.len()),
            assignment_hash: assignment_hash.clone(),
            rotation_mode: crate::cluster::RotationMode::RoutineRotation,
            created_block_height: height,
        })
        .collect())
}

fn epoch_cluster_assignments_for_rpc(
    registry: &ValidatorRegistry,
    ledger: &crate::cluster::ClusterLedger,
    epoch: u64,
    height: u64,
    current_randomness_source: Option<&str>,
) -> Result<Vec<EpochClusterAssignmentSnapshot>, String> {
    let supplied_epoch = epoch_for_block_height(height, TESTNET_EPOCH_LENGTH_BLOCKS);
    let effective_epoch = effective_cluster_epoch_for_height(supplied_epoch, height)?;
    if epoch == effective_epoch {
        let randomness_source = current_randomness_source.ok_or_else(|| {
            "verified current-epoch cluster randomness is unavailable".to_string()
        })?;
        canonical_epoch_cluster_assignments(registry, effective_epoch, height, randomness_source)
    } else {
        Ok(ledger.get_epoch_cluster_assignments(epoch))
    }
}

fn canonical_cluster_status(
    registry: &ValidatorRegistry,
    cluster_address: &str,
    ledger_status: Option<&crate::cluster::ClusterStatusResponse>,
) -> Value {
    let Some(cluster) = registry
        .clusters
        .values()
        .find(|cluster| cluster.address == cluster_address)
    else {
        return Value::Null;
    };
    let ledger_status =
        ledger_status
            .cloned()
            .unwrap_or_else(|| crate::cluster::ClusterStatusResponse {
                cluster_address: cluster.address.clone(),
                status: crate::cluster::ClusterStatus::Active,
                current_epoch: registry.current_epoch,
                current_validator_ids: Vec::new(),
                previous_validator_ids: Vec::new(),
                current_quorum_threshold: 0,
                current_fault_tolerance_f: 0,
                current_rotation_mode: crate::cluster::RotationMode::RoutineRotation,
                last_rotation_epoch: None,
                last_full_rotation_epoch: None,
                total_rewards_earned_nwei: 0,
                total_rewards_settled_nwei: 0,
                recent_performance_score_bps: 0,
                recent_finality_success_rate_bps: 0,
                recent_missed_rounds: 0,
                recent_slashing_events: 0,
                cartel_risk_score_bps: None,
                co_cluster_repetition_summary: None,
            });
    json!(crate::cluster::ClusterStatusResponse {
        cluster_address: cluster.address.clone(),
        status: ledger_status.status,
        current_epoch: registry.current_epoch,
        current_validator_ids: cluster.validators.clone(),
        previous_validator_ids: ledger_status.previous_validator_ids,
        current_quorum_threshold: quorum_threshold(cluster.validators.len()),
        current_fault_tolerance_f: fault_tolerance_f(cluster.validators.len()),
        current_rotation_mode: ledger_status.current_rotation_mode,
        last_rotation_epoch: ledger_status.last_rotation_epoch,
        last_full_rotation_epoch: ledger_status.last_full_rotation_epoch,
        total_rewards_earned_nwei: ledger_status.total_rewards_earned_nwei,
        total_rewards_settled_nwei: ledger_status.total_rewards_settled_nwei,
        recent_performance_score_bps: ledger_status.recent_performance_score_bps,
        recent_finality_success_rate_bps: ledger_status.recent_finality_success_rate_bps,
        recent_missed_rounds: ledger_status.recent_missed_rounds,
        recent_slashing_events: ledger_status.recent_slashing_events,
        cartel_risk_score_bps: ledger_status.cartel_risk_score_bps,
        co_cluster_repetition_summary: ledger_status.co_cluster_repetition_summary,
    })
}

fn recent_active_validator_addresses(
    chain: &BlockChain,
    total_known_validators: usize,
    validator_id_to_address: &HashMap<String, String>,
) -> HashSet<String> {
    let window = total_known_validators.max(10).saturating_mul(12);
    chain
        .chain
        .iter()
        .rev()
        .filter(|block| block.block_index > 0 && block.validator_id != "genesis")
        .take(window)
        .map(|block| {
            validator_id_to_address
                .get(&block.validator_id)
                .cloned()
                .unwrap_or_else(|| block.validator_id.clone())
        })
        .collect()
}

fn configured_validator_addresses() -> HashSet<String> {
    if let Ok(Some(addresses)) = consensus_fork::active_consensus_validator_addresses() {
        if !addresses.is_empty() {
            return addresses.into_iter().collect();
        }
    }

    canonical_genesis()
        .map(|genesis| {
            genesis
                .validators()
                .iter()
                .map(|entry| entry.operator_address.clone())
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default()
}

fn network_validator_snapshot(
    chain: &BlockChain,
    validator_manager: &ValidatorManager,
) -> Vec<Validator> {
    let mut validators = validator_manager
        .get_all_validators()
        .into_iter()
        .map(|validator| (validator.address.clone(), validator))
        .collect::<HashMap<_, _>>();
    let genesis_timestamp = canonical_genesis()
        .map(|genesis| genesis.timestamp())
        .unwrap_or(0);
    let configured_addresses = configured_validator_addresses();
    let mut validator_id_to_address = HashMap::new();

    if let Ok(genesis) = canonical_genesis() {
        let configured_validator_count = configured_addresses.len().max(genesis.validators().len());
        for (index, entry) in genesis.validators().iter().enumerate() {
            let address = entry.operator_address.clone();
            validator_id_to_address.insert(entry.validator_id.clone(), address.clone());
            let validator = validators.entry(address.clone()).or_insert_with(|| {
                synthesize_validator(
                    address.clone(),
                    entry.consensus_public_key.clone(),
                    entry.moniker.clone(),
                    entry.stake_nwei,
                    genesis.timestamp(),
                )
            });
            if validator.public_key.is_empty() {
                validator.public_key = entry.consensus_public_key.clone();
            }
            if validator.name.trim().is_empty() {
                validator.name = entry.moniker.clone();
            }
            if validator.stake_amount == 0 {
                validator.stake_amount = entry.stake_nwei;
            }
            if validator.min_stake_required == 0 {
                validator.min_stake_required = entry.stake_nwei.max(1);
            }
            if validator.cluster_id.is_none() {
                validator.cluster_id = default_cluster_id(index, configured_validator_count);
            }
            if validator.registered_at == 0 {
                validator.registered_at = genesis.timestamp();
            }
        }
    }

    for address in &configured_addresses {
        validators.entry(address.clone()).or_insert_with(|| {
            synthesize_validator(
                address.clone(),
                String::new(),
                format!("Validator-{}", &address[..8.min(address.len())]),
                TESTNET_MIN_VALIDATOR_STAKE_NWEI,
                genesis_timestamp,
            )
        });
    }

    // Testnet-v3 finality lives in one durable finality store. The inherited
    // `BlockChain` remains at Genesis on read-only roles, so deriving activity
    // from it made every live validator appear to have produced zero blocks.
    // Once a supported finality store exists it is the sole finalized
    // authority, matching the block/explorer RPC paths below.
    let finality_records = finality_records_for_rpc().ok().flatten();
    let total_observed_blocks = finality_records
        .as_ref()
        .map(|records| records.len() as u64)
        .unwrap_or_else(|| {
            chain
                .chain
                .iter()
                .filter(|block| block.block_index > 0)
                .count() as u64
        });
    let activity_window = validators.len().max(10).saturating_mul(12);
    let recent_active = finality_records
        .as_ref()
        .map(|records| {
            records
                .iter()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .take(activity_window)
                .map(|record| {
                    let validator_id = record.proposer_validator_id();
                    validator_id_to_address
                        .get(validator_id)
                        .cloned()
                        .unwrap_or_else(|| validator_id.to_string())
                })
                .collect::<HashSet<_>>()
        })
        .unwrap_or_else(|| {
            recent_active_validator_addresses(chain, validators.len(), &validator_id_to_address)
        });

    if let Some(records) = finality_records.as_ref() {
        for record in records.iter() {
            let validator_id = record.proposer_validator_id();
            let address = validator_id_to_address
                .get(validator_id)
                .cloned()
                .unwrap_or_else(|| validator_id.to_string());
            let validator = validators.entry(address.clone()).or_insert_with(|| {
                synthesize_validator(
                    address.clone(),
                    String::new(),
                    format!("Validator-{}", &address[..8.min(address.len())]),
                    0,
                    genesis_timestamp,
                )
            });
            validator.total_blocks_produced = validator.total_blocks_produced.saturating_add(1);
            validator.total_transactions_validated = validator
                .total_transactions_validated
                .saturating_add(record.transaction_count() as u64);
            let timestamp = record.timestamp_ms() / 1_000;
            validator.last_active = validator.last_active.max(timestamp);
            validator.last_vote_timestamp = validator.last_vote_timestamp.max(timestamp);
        }
    } else {
        for block in chain.chain.iter().filter(|block| block.block_index > 0) {
            let address = validator_id_to_address
                .get(&block.validator_id)
                .cloned()
                .unwrap_or_else(|| block.validator_id.clone());
            let validator = validators.entry(address.clone()).or_insert_with(|| {
                synthesize_validator(
                    address.clone(),
                    String::new(),
                    format!("Validator-{}", &address[..8.min(address.len())]),
                    0,
                    genesis_timestamp,
                )
            });
            validator.total_blocks_produced = validator.total_blocks_produced.saturating_add(1);
            validator.total_transactions_validated = validator
                .total_transactions_validated
                .saturating_add(block.transactions.len() as u64);
            validator.last_active = validator.last_active.max(block.timestamp);
            validator.last_vote_timestamp = validator.last_vote_timestamp.max(block.timestamp);
        }
    }

    let mut ordered = validators.into_values().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.address.cmp(&right.address));
    let observed_validator_count = ordered.len();
    for (index, validator) in ordered.iter_mut().enumerate() {
        let is_recently_active = recent_active.contains(&validator.address);
        let is_configured_validator = configured_addresses.contains(&validator.address);
        let registry_active = matches!(
            validator.status,
            ValidatorStatus::Active | ValidatorStatus::Pending
        );
        let disciplined = matches!(
            validator.status,
            ValidatorStatus::Jailed | ValidatorStatus::Slashed
        );
        if validator.cluster_id.is_none() {
            validator.cluster_id = default_cluster_id(index, observed_validator_count);
        }
        if validator.min_stake_required == 0 {
            validator.min_stake_required = validator.stake_amount.max(1);
        }
        validator.average_block_time = calculate_average_block_time(chain);
        validator.uptime_percentage = if total_observed_blocks > 0 {
            (validator.total_blocks_produced as f64 / total_observed_blocks as f64) * 100.0
        } else if is_recently_active {
            100.0
        } else {
            0.0
        };
        if disciplined {
            // Preserve explicit jail/slash state.
        } else if is_configured_validator || registry_active || is_recently_active {
            validator.status = ValidatorStatus::Active;
        } else {
            validator.status = ValidatorStatus::Inactive;
        }
        if validator.synergy_score <= 0.0 && matches!(validator.status, ValidatorStatus::Active) {
            validator.synergy_score = INITIAL_VALIDATOR_SYNERGY_SCORE;
        }
        if validator.task_accuracy <= 0.0 && matches!(validator.status, ValidatorStatus::Active) {
            validator.task_accuracy = 100.0;
        }
        if validator.reputation_score <= 0.0 && matches!(validator.status, ValidatorStatus::Active)
        {
            validator.reputation_score = 100.0;
        }
    }
    let current_height = chain.last().map(|block| block.block_index).unwrap_or(0);
    if assign_canonical_cluster_memberships(
        &mut ordered,
        validator_manager.get_current_epoch(),
        current_height,
    )
    .is_err()
    {
        for validator in &mut ordered {
            validator.cluster_id = None;
            validator.cluster_address = None;
        }
    }

    ordered
}

#[derive(Debug, Clone)]
struct LocalValidatorNickname {
    address: String,
    nickname: String,
}

fn configured_local_validator_nickname() -> Option<LocalValidatorNickname> {
    let config = crate::config::load_node_config(None).ok()?;
    let address = if !config.node.validator_address.trim().is_empty() {
        config.node.validator_address.trim().to_string()
    } else {
        config.identity.address.trim().to_string()
    };
    let nickname = config.identity.label.trim().to_string();
    if address.is_empty() || nickname.is_empty() {
        return None;
    }
    Some(LocalValidatorNickname { address, nickname })
}

fn validator_display_metadata(
    validator: &Validator,
    local_nickname: Option<&LocalValidatorNickname>,
) -> (String, Option<String>) {
    if let Some(local) = local_nickname {
        if local.address.eq_ignore_ascii_case(&validator.address)
            && !local.nickname.trim().is_empty()
        {
            return (local.nickname.clone(), Some(local.nickname.clone()));
        }
    }
    (validator.name.clone(), None)
}

fn validator_to_rpc_json(
    validator: Validator,
    local_nickname: Option<&LocalValidatorNickname>,
) -> Value {
    let moniker = validator.name.clone();
    let (display_name, nickname) = validator_display_metadata(&validator, local_nickname);
    let mut value = serde_json::to_value(&validator).unwrap_or_else(|_| json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("name".to_string(), json!(display_name));
        object.insert("moniker".to_string(), json!(moniker));
        object.insert("nickname".to_string(), json!(nickname));
    }
    value
}

fn validator_set_snapshot_json(
    chain: &Arc<Mutex<BlockChain>>,
    validator_manager: &Arc<ValidatorManager>,
) -> Value {
    let finalized_height = match chain.lock() {
        Ok(canonical_chain) => match canonical_chain.last() {
            Some(block) => block.block_index,
            None => {
                return json!({
                    "error": "canonical finalized chain tip is unavailable",
                    "chain_id": 1266,
                    "fail_closed": true,
                    "is_latest": false,
                });
            }
        },
        Err(_) => {
            return json!({
                "error": "canonical finalized chain lock is unavailable",
                "chain_id": 1266,
                "fail_closed": true,
                "is_latest": false,
            });
        }
    };

    let canonical_epoch = epoch_for_block_height(finalized_height, TESTNET_EPOCH_LENGTH_BLOCKS);
    let registry_validators = match validator_manager.registry.lock() {
        Ok(registry) => registry.validators.values().cloned().collect::<Vec<_>>(),
        Err(_) => {
            return json!({
                "error": "validator registry is temporarily unavailable",
                "chain_id": 1266,
                "fail_closed": true,
                "is_latest": false,
            });
        }
    };
    let _height_scoped_active = match consensus_membership_validators_for_height(
        registry_validators.clone(),
        finalized_height,
    ) {
        Ok(active) => active,
        Err(error) => {
            return json!({
                "error": format!("validator membership is unavailable at finalized height {finalized_height}: {error}"),
                "chain_id": 1266,
                "current_finalized_height": finalized_height,
                "fail_closed": true,
                "is_latest": false,
            });
        }
    };
    let reconciliation = match chain.lock() {
        Ok(canonical_chain) => reconcile_validator_registry_clusters_from_finalized_chain(
            validator_manager,
            &canonical_chain,
            finalized_height,
        ),
        Err(_) => Err("canonical finalized chain lock is unavailable".to_string()),
    };
    match reconciliation {
        Ok(true) => {
            if let Err(error) = validator_manager.save_registry(VALIDATOR_REGISTRY_PATH) {
                return json!({
                    "error": format!("canonical validator cluster reconciliation could not be persisted at finalized height {finalized_height}: {error}"),
                    "chain_id": 1266,
                    "current_finalized_height": finalized_height,
                    "epoch_id": canonical_epoch,
                    "fail_closed": true,
                    "is_latest": false,
                });
            }
        }
        Ok(false) => {}
        Err(error) => {
            return json!({
                "error": format!("canonical validator cluster seed is unavailable at finalized height {finalized_height}: {error}"),
                "chain_id": 1266,
                "current_finalized_height": finalized_height,
                "epoch_id": canonical_epoch,
                "fail_closed": true,
                "is_latest": false,
            });
        }
    }

    // QC reconciliation may update assignment epoch, seed, and cluster membership. Refresh the
    // authoritative clone before deriving the published membership and cluster plan.
    let registry_validators = match validator_manager.registry.lock() {
        Ok(registry) => registry.validators.values().cloned().collect::<Vec<_>>(),
        Err(_) => {
            return json!({
                "error": "validator registry is temporarily unavailable after reconciliation",
                "chain_id": 1266,
                "current_finalized_height": finalized_height,
                "fail_closed": true,
                "is_latest": false,
            });
        }
    };

    let registry = match validator_manager.registry.lock() {
        Ok(registry) => registry.clone(),
        Err(_) => {
            return json!({
                "error": "validator registry is temporarily unavailable",
                "chain_id": 1266,
                "fail_closed": true,
                "is_latest": false,
            });
        }
    };

    let active = match consensus_membership_validators_for_height(
        registry_validators.clone(),
        finalized_height,
    ) {
        Ok(active) => active,
        Err(error) => {
            return json!({
                "error": format!("validator membership is unavailable at finalized height {finalized_height}: {error}"),
                "chain_id": 1266,
                "current_finalized_height": finalized_height,
                "fail_closed": true,
                "is_latest": false,
            });
        }
    };
    let effective_epoch = match effective_cluster_epoch_for_height(
        canonical_epoch,
        finalized_height,
    ) {
        Ok(epoch) => epoch,
        Err(error) => {
            return json!({
                "error": format!("validator cluster epoch is unavailable at finalized height {finalized_height}: {error}"),
                "chain_id": 1266,
                "current_finalized_height": finalized_height,
                "fail_closed": true,
                "is_latest": false,
            });
        }
    };
    let randomness_evidence = match chain.lock() {
        Ok(canonical_chain) => ProofOfSynergy::cluster_epoch_randomness_evidence(
            &canonical_chain,
            effective_epoch,
            TESTNET_EPOCH_LENGTH_BLOCKS,
            validator_manager,
        ),
        Err(_) => Err("canonical finalized chain lock is unavailable".to_string()),
    };
    let randomness_evidence = match randomness_evidence {
        Ok(evidence) => evidence,
        Err(error) => {
            return json!({
                "error": format!("canonical epoch randomness evidence is unavailable at finalized height {finalized_height}: {error}"),
                "chain_id": 1266,
                "current_finalized_height": finalized_height,
                "epoch_id": effective_epoch,
                "fail_closed": true,
                "is_latest": false,
            });
        }
    };
    let canonical_assignment_effective_height = randomness_evidence.assignment_effective_height;
    let cluster_count = target_validator_cluster_count(active.len());
    let expected_assignment_seed = hex::encode(&randomness_evidence.randomness);
    let seeds = active
        .iter()
        .filter_map(|validator| validator.cluster_assignment_seed.as_deref())
        .filter(|seed| !seed.trim().is_empty())
        .collect::<HashSet<_>>();
    if seeds.len() != 1 || !seeds.contains(expected_assignment_seed.as_str()) {
        return json!({
            "error": format!("canonical validator cluster seed does not match verified {} evidence at finalized height {finalized_height}", randomness_evidence.scheme),
            "chain_id": 1266,
            "current_finalized_height": finalized_height,
            "epoch_id": effective_epoch,
            "fail_closed": true,
            "is_latest": false,
        });
    }
    let cluster_plan = match canonical_validator_clusters_for_height_with_seed(
        registry_validators.clone(),
        effective_epoch,
        finalized_height,
        &expected_assignment_seed,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return json!({
                "error": format!("canonical validator cluster assignment is unavailable at finalized height {finalized_height}: {error}"),
                "chain_id": 1266,
                "current_finalized_height": finalized_height,
                "fail_closed": true,
                "is_latest": false,
            });
        }
    };
    let validator_set_hash = canonical_active_validator_set_hash(&active);
    let cluster_map_hash = canonical_validator_cluster_plan_digest(&cluster_plan, effective_epoch);
    let manifest_effective_height = match validator_set_effective_height_for_height(
        finalized_height,
    ) {
        Ok(height) => height,
        Err(error) => {
            return json!({
                "error": format!("validator-set transition metadata is unavailable at finalized height {finalized_height}: {error}"),
                "chain_id": 1266,
                "current_finalized_height": finalized_height,
                "is_latest": false,
            });
        }
    };
    let activation_effective_height = active
        .iter()
        .filter_map(|validator| validator.activation_effective_height)
        .max();
    let effective_from_height = manifest_effective_height
        .into_iter()
        .chain(activation_effective_height)
        .max()
        .unwrap_or(0);
    let effective_height_source = match (manifest_effective_height, activation_effective_height) {
        (Some(_), Some(_)) => "epoch_manifest_and_activation_replay",
        (Some(_), None) => "epoch_validator_set_manifest",
        (None, Some(_)) => "activation_replay",
        (None, None) => "genesis_or_legacy_registry",
    };
    let effective_height_verified =
        manifest_effective_height.is_some() || activation_effective_height.is_some();
    let assignment_epochs = active
        .iter()
        .filter_map(|validator| validator.cluster_assignment_epoch)
        .collect::<HashSet<_>>();
    let assignment_seeds = active
        .iter()
        .filter_map(|validator| validator.cluster_assignment_seed.as_deref())
        .filter(|seed| !seed.trim().is_empty())
        .collect::<HashSet<_>>();
    let assignment_effective_heights = active
        .iter()
        .filter_map(|validator| validator.cluster_assignment_effective_height)
        .collect::<HashSet<_>>();
    let persisted_assignments_match_plan = cluster_plan.len() == registry.clusters.len()
        && cluster_plan.iter().all(|(cluster_id, members)| {
            let expected_address = canonical_validator_cluster_address(*cluster_id, members);
            let expected_validators = members
                .iter()
                .map(|validator| validator.address.clone())
                .collect::<Vec<_>>();
            let registry_cluster_matches =
                registry.clusters.get(cluster_id).is_some_and(|cluster| {
                    cluster.id == *cluster_id
                        && cluster.address == expected_address
                        && cluster.validators == expected_validators
                });
            registry_cluster_matches
                && members.iter().all(|validator| {
                    validator.cluster_id == Some(*cluster_id)
                        && validator.cluster_address.as_deref() == Some(expected_address.as_str())
                        && validator.cluster_assignment_epoch == Some(effective_epoch)
                        && validator
                            .cluster_assignment_seed
                            .as_deref()
                            .is_some_and(|seed| seed == expected_assignment_seed)
                        && validator.cluster_assignment_effective_height
                            == Some(canonical_assignment_effective_height)
                })
        });
    let cluster_assignments_complete = !active.is_empty()
        && registry.current_epoch == effective_epoch
        && registry.epoch_length == TESTNET_EPOCH_LENGTH_BLOCKS
        && active
            .iter()
            .all(|validator| validator.cluster_id.is_some())
        && assignment_epochs == HashSet::from([effective_epoch])
        && assignment_seeds == HashSet::from([expected_assignment_seed.as_str()])
        && assignment_effective_heights.len() == 1
        && persisted_assignments_match_plan;
    let cluster_assignment_epoch = cluster_assignments_complete.then_some(effective_epoch);
    let cluster_randomness_source =
        cluster_assignments_complete.then(|| expected_assignment_seed.clone());
    let cluster_assignment_effective_height = cluster_assignments_complete.then(|| {
        assignment_effective_heights
            .iter()
            .next()
            .copied()
            .unwrap_or_default()
    });
    if !cluster_assignments_complete {
        return json!({
            "error": format!("canonical validator cluster assignments are not proven at finalized height {finalized_height}"),
            "chain_id": 1266,
            "epoch_id": effective_epoch,
            "current_finalized_height": finalized_height,
            "active_validators": active.iter().map(|validator| validator.address.clone()).collect::<Vec<_>>(),
            "cluster_assignments_complete": false,
            "fail_closed": true,
            "is_latest": false,
        });
    }
    let cluster_assignments = cluster_plan
        .iter()
        .map(|(cluster_id, members)| {
            json!({
                "cluster_id": cluster_id,
                "cluster_address": canonical_validator_cluster_address(*cluster_id, members),
                "validator_ids": members.iter().map(|validator| validator.address.clone()).collect::<Vec<_>>(),
                "quorum_threshold": quorum_threshold(members.len()),
                "fault_tolerance_f": fault_tolerance_f(members.len()),
                "assignment_epoch": cluster_assignment_epoch,
                "assignment_effective_height": cluster_assignment_effective_height,
                    "validators": members.iter().map(|validator| json!({
                        "address": validator.address,
                        "public_key": validator.public_key,
                        "stake_amount": validator.stake_amount,
                        "cluster_id": validator.cluster_id,
                        "status": format!("{:?}", validator.status),
                        "activation_tx_hash": validator.activation_tx_hash,
                        "activation_recorded_height": validator.activation_recorded_height,
                        "activation_effective_height": validator.activation_effective_height,
                        "finalized_synergy_score_bps": validator.finalized_synergy_score_bps,
                    })).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let membership_bundle_hash = validator_membership_bundle_hash(
        &active,
        effective_epoch,
        &validator_set_hash,
        &cluster_map_hash,
        cluster_randomness_source.as_deref(),
        cluster_assignment_effective_height,
    );
    let addresses_for_status = |status: ValidatorStatus| {
        let mut addresses = registry
            .validators
            .values()
            .filter(|validator| validator.status == status)
            .map(|validator| validator.address.clone())
            .collect::<Vec<_>>();
        addresses.sort();
        addresses
    };
    let active_addresses = active
        .iter()
        .map(|validator| validator.address.clone())
        .collect::<Vec<_>>();
    let mut syncing_addresses = registry
        .validators
        .values()
        .filter(|validator| {
            validator.status == ValidatorStatus::Shadow
                && !validator
                    .activation_effective_height
                    .is_some_and(|height| height <= finalized_height)
        })
        .map(|validator| validator.address.clone())
        .collect::<Vec<_>>();
    syncing_addresses.sort();
    let network_quorum_threshold = required_validator_quorum(active.len());
    let cluster_quorum_thresholds = cluster_plan
        .iter()
        .map(|(cluster_id, members)| {
            json!({
                "cluster_id": cluster_id,
                "validator_count": members.len(),
                "quorum_threshold": quorum_threshold(members.len()),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "chain_id": 1266,
        "network_id": current_network_id(),
        "snapshot_format_version": 1,
        "protocol_version": current_protocol_version(),
        "binary_version": env!("CARGO_PKG_VERSION"),
        "epoch_id": effective_epoch,
        "validator_set_version": registry.validator_set_version,
        "effective_from_height": effective_from_height,
        "validator_set_effective_height": effective_from_height,
        "effective_height_source": effective_height_source,
        "effective_height_verified": effective_height_verified,
        "current_finalized_height": finalized_height,
        "active_validators": active_addresses.clone(),
        "pending_validators": addresses_for_status(ValidatorStatus::Pending),
        "syncing_validators": syncing_addresses,
        "eligible_validators": active_addresses,
        "jailed_validators": addresses_for_status(ValidatorStatus::Jailed),
        "removed_validators": addresses_for_status(ValidatorStatus::Slashed),
        "quorum_threshold": network_quorum_threshold,
        "network_quorum_threshold": network_quorum_threshold,
        "quorum_scope": "network_aggregate_not_cluster_finality",
        "cluster_quorum_scope": if cluster_count > 1 { "independent_per_cluster" } else { "single_cluster" },
        "cluster_quorum_thresholds": cluster_quorum_thresholds,
        "validator_set_hash": validator_set_hash,
        "local_validator_set_hash": validator_set_hash,
        "network_validator_set_hash": validator_set_hash,
        "cluster_count": cluster_count,
        "cluster_assignments_complete": cluster_assignments_complete,
        "cluster_assignment_epoch": cluster_assignment_epoch,
        "cluster_assignment_effective_height": cluster_assignment_effective_height,
        "cluster_assignment_boundary_height": randomness_evidence.boundary_height,
        "cluster_assignment_boundary_hash": randomness_evidence.boundary_block_hash.clone(),
        "cluster_assignment_evidence": {
            "chain_id": 1266,
            "next_epoch": randomness_evidence.next_epoch,
            "boundary_height": randomness_evidence.boundary_height,
            "boundary_block_hash": randomness_evidence.boundary_block_hash,
            "assignment_effective_height": randomness_evidence.assignment_effective_height,
            "randomness_scheme": randomness_evidence.scheme,
            "boundary_qc_verified": randomness_evidence.boundary_qc_verified,
            "cluster_v3_activation_epoch": CLUSTER_RANDOMNESS_V3_ACTIVATION_EPOCH,
            "cluster_v3_activation_height": CLUSTER_RANDOMNESS_V3_ACTIVATION_HEIGHT,
            "leader_v3_activation_epoch": EPOCH_RANDOMNESS_V3_ACTIVATION_EPOCH,
            "leader_v3_activation_height": EPOCH_RANDOMNESS_V3_ACTIVATION_HEIGHT,
        },
        "cluster_randomness_scheme": randomness_evidence.scheme,
        "cluster_randomness_boundary_qc_verified": randomness_evidence.boundary_qc_verified,
        "cluster_randomness_v3_activation_epoch": CLUSTER_RANDOMNESS_V3_ACTIVATION_EPOCH,
        "cluster_randomness_v3_activation_height": CLUSTER_RANDOMNESS_V3_ACTIVATION_HEIGHT,
        "cluster_randomness_source": cluster_randomness_source,
        "cluster_map_hash": cluster_map_hash,
        "cluster_assignments": cluster_assignments,
        "membership_bundle_format_version": 2,
        "membership_bundle_hash": membership_bundle_hash,
        "is_latest": true,
        "generated_at_utc": current_timestamp(),
    })
}

fn canonical_validator_cluster_plan_digest(
    cluster_plan: &[(u64, Vec<Validator>)],
    epoch: u64,
) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(epoch.to_be_bytes());
    for (cluster_id, members) in cluster_plan {
        hasher.update(cluster_id.to_be_bytes());
        hasher.update((members.len() as u64).to_be_bytes());
        for validator in members {
            let address = validator.address.as_bytes();
            hasher.update((address.len() as u64).to_be_bytes());
            hasher.update(address);
        }
    }
    hex::encode(hasher.finalize())
}

fn validator_membership_bundle_hash(
    active_validators: &[Validator],
    epoch: u64,
    validator_set_hash: &str,
    cluster_map_hash: &str,
    cluster_randomness_source: Option<&str>,
    cluster_assignment_effective_height: Option<u64>,
) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b"synergy-validator-membership-bundle-v2");
    hasher.update(1264_u64.to_be_bytes());
    hasher.update(epoch.to_be_bytes());
    hasher.update(
        cluster_assignment_effective_height
            .unwrap_or_default()
            .to_be_bytes(),
    );
    for value in [
        current_network_id(),
        current_protocol_version(),
        validator_set_hash.to_string(),
        cluster_map_hash.to_string(),
        cluster_randomness_source.unwrap_or_default().to_string(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let mut validators = active_validators.iter().collect::<Vec<_>>();
    validators.sort_by(|left, right| left.address.cmp(&right.address));
    for validator in validators {
        for value in [
            validator.address.as_str(),
            validator.public_key.as_str(),
            validator.activation_tx_hash.as_deref().unwrap_or_default(),
        ] {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        hasher.update(validator.stake_amount.to_be_bytes());
        hasher.update(validator.cluster_id.unwrap_or(u64::MAX).to_be_bytes());
    }
    hex::encode(hasher.finalize())
}

fn network_cluster_summary(validators: &[Validator]) -> Value {
    let mut validators_by_cluster = BTreeMap::<u64, Vec<&Validator>>::new();
    for validator in validators {
        let Some(cluster_id) = validator.cluster_id else {
            continue;
        };
        validators_by_cluster
            .entry(cluster_id)
            .or_default()
            .push(validator);
    }

    let mut clusters = Vec::with_capacity(validators_by_cluster.len());
    for (cluster_id, members) in validators_by_cluster {
        let validator_count = members.len();
        let active_validator_count = members
            .iter()
            .filter(|validator| validator.status == ValidatorStatus::Active)
            .count();
        let quorum_threshold = quorum_threshold(validator_count);
        let fault_tolerance_f = fault_tolerance_f(validator_count);
        let can_finalize = validator_count > 0 && active_validator_count >= quorum_threshold;
        let validators_until_liveness_risk =
            active_validator_count.saturating_sub(quorum_threshold);
        let health = if validator_count == 0 {
            "empty"
        } else if can_finalize && active_validator_count == validator_count {
            "healthy"
        } else if can_finalize {
            "degraded"
        } else {
            "halted_safely"
        };
        let mut status_counts = BTreeMap::<String, usize>::new();
        for validator in &members {
            *status_counts
                .entry(format!("{:?}", validator.status))
                .or_default() += 1;
        }
        let cluster_address = members
            .iter()
            .find_map(|validator| validator.cluster_address.clone())
            .unwrap_or_else(|| format!("cluster-{cluster_id}"));
        let validator_details = members
            .iter()
            .map(|validator| {
                json!({
                    "address": validator.address,
                    "name": validator.name,
                    "status": format!("{:?}", validator.status),
                    "cluster_id": cluster_id,
                    "cluster_address": validator.cluster_address,
                    "last_vote_timestamp": validator.last_vote_timestamp,
                    "missed_vote_window": validator.missed_vote_window,
                    "consecutive_missed_votes": validator.consecutive_missed_votes
                })
            })
            .collect::<Vec<_>>();

        clusters.push(json!({
            "cluster_id": cluster_id,
            "cluster_address": cluster_address,
            "validator_count": validator_count,
            "active_validator_count": active_validator_count,
            "fault_tolerance_f": fault_tolerance_f,
            "quorum_threshold": quorum_threshold,
            "can_finalize": can_finalize,
            "validators_until_liveness_risk": validators_until_liveness_risk,
            "health": health,
            "status_counts": status_counts,
            "validators": validator_details
        }));
    }

    let active_validators = validators
        .iter()
        .filter(|validator| validator.status == ValidatorStatus::Active)
        .count();
    let all_clusters_can_finalize = clusters
        .iter()
        .all(|cluster| cluster["can_finalize"].as_bool().unwrap_or(false));
    let consensus_mode = if clusters.len() <= 1 {
        "single_cluster_testnet"
    } else {
        "multi_cluster_posy"
    };

    json!({
        "total_validators": validators.len(),
        "active_validators": active_validators,
        "cluster_count": clusters.len(),
        "consensus_mode": consensus_mode,
        "all_clusters_can_finalize": all_clusters_can_finalize,
        "clusters": clusters
    })
}

fn start_ws_rpc_server(
    bind_address: &str,
    tx_pool: &Arc<Mutex<Vec<Transaction>>>,
    chain: &Arc<Mutex<BlockChain>>,
    validator_manager: &Arc<ValidatorManager>,
) {
    println!("📡 RPC WebSocket server running on {}", bind_address);

    for stream in TcpListener::bind(bind_address)
        .expect("Failed to bind RPC WebSocket server")
        .incoming()
    {
        let tx_pool = Arc::clone(tx_pool);
        let chain = Arc::clone(chain);
        let validator_manager = Arc::clone(validator_manager);
        thread::spawn(move || {
            if let Ok(stream) = stream {
                handle_ws_connection(stream, &tx_pool, &chain, &validator_manager);
            }
        });
    }
}

fn handle_ws_connection(
    stream: std::net::TcpStream,
    tx_pool: &Arc<Mutex<Vec<Transaction>>>,
    chain: &Arc<Mutex<BlockChain>>,
    validator_manager: &Arc<ValidatorManager>,
) {
    let peer_addr = stream.peer_addr().ok();
    let captured_headers: Arc<Mutex<HashMap<String, String>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let header_sink = Arc::clone(&captured_headers);
    let mut websocket = match accept_hdr(stream, |request: &WsRequest, response: WsResponse| {
        if let Ok(mut headers) = header_sink.lock() {
            headers.clear();
            for (name, value) in request.headers() {
                headers.insert(
                    name.as_str().to_ascii_lowercase(),
                    value.to_str().unwrap_or_default().to_string(),
                );
            }
        }
        Ok(response)
    }) {
        Ok(websocket) => websocket,
        Err(error) => {
            eprintln!("WebSocket handshake failed: {}", error);
            return;
        }
    };

    let _ = websocket
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(250)));

    let mut subscriptions: HashMap<String, SubscriptionCursor> = HashMap::new();
    let request_context = RpcRequestContext::new(
        RpcTransport::WebSocket,
        peer_addr,
        captured_headers
            .lock()
            .map(|headers| headers.clone())
            .unwrap_or_default(),
    );

    loop {
        emit_subscription_notifications(&mut websocket, &mut subscriptions, tx_pool, chain);

        match websocket.read() {
            Ok(WsMessage::Text(body)) => {
                match serde_json::from_str::<Value>(&body)
                    .map_err(|_| RpcError::new(-32700, "Malformed JSON in WebSocket payload"))
                {
                    Ok(parsed) => match process_json_rpc_payload(
                        &parsed,
                        tx_pool,
                        chain,
                        validator_manager,
                        Some(&mut subscriptions),
                        &request_context,
                    ) {
                        Ok(Some(response)) => {
                            if websocket
                                .send(WsMessage::Text(response.to_string()))
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            let response = json_rpc_error_response(None, &error);
                            if websocket
                                .send(WsMessage::Text(response.to_string()))
                                .is_err()
                            {
                                break;
                            }
                        }
                    },
                    Err(error) => {
                        let response = json_rpc_error_response(None, &error);
                        if websocket
                            .send(WsMessage::Text(response.to_string()))
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            Ok(WsMessage::Ping(payload)) => {
                if websocket.send(WsMessage::Pong(payload)).is_err() {
                    break;
                }
            }
            Ok(WsMessage::Close(_)) => break,
            Ok(_) => {}
            Err(WsError::ConnectionClosed) | Err(WsError::AlreadyClosed) => break,
            Err(WsError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                eprintln!("WebSocket RPC error: {}", error);
                break;
            }
        }
    }
}

fn process_json_rpc_payload(
    parsed: &Value,
    tx_pool: &Arc<Mutex<Vec<Transaction>>>,
    chain: &Arc<Mutex<BlockChain>>,
    validator_manager: &Arc<ValidatorManager>,
    subscriptions: Option<&mut HashMap<String, SubscriptionCursor>>,
    request_context: &RpcRequestContext,
) -> Result<Option<Value>, RpcError> {
    match parsed {
        Value::Array(items) => {
            if items.is_empty() {
                return Ok(Some(json_rpc_error_response(
                    None,
                    &RpcError::new(-32600, "Invalid request"),
                )));
            }

            let mut responses = Vec::new();
            let mut subscriptions = subscriptions;
            for item in items {
                if let Some(response) = process_json_rpc_request_object(
                    item,
                    tx_pool,
                    chain,
                    validator_manager,
                    subscriptions.as_deref_mut(),
                    request_context,
                )? {
                    responses.push(response);
                }
            }

            if responses.is_empty() {
                Ok(None)
            } else {
                Ok(Some(Value::Array(responses)))
            }
        }
        Value::Object(_) => process_json_rpc_request_object(
            parsed,
            tx_pool,
            chain,
            validator_manager,
            subscriptions,
            request_context,
        )
        .map(|response| response.map(|value| json!(value))),
        _ => Ok(Some(json_rpc_error_response(
            None,
            &RpcError::new(-32600, "Invalid request"),
        ))),
    }
}

fn process_json_rpc_request_object(
    request: &Value,
    tx_pool: &Arc<Mutex<Vec<Transaction>>>,
    chain: &Arc<Mutex<BlockChain>>,
    validator_manager: &Arc<ValidatorManager>,
    subscriptions: Option<&mut HashMap<String, SubscriptionCursor>>,
    request_context: &RpcRequestContext,
) -> Result<Option<Value>, RpcError> {
    let request_object = request
        .as_object()
        .ok_or_else(|| RpcError::new(-32600, "Invalid request"))?;

    let method = request_object
        .get("method")
        .and_then(|value| value.as_str())
        .ok_or_else(|| RpcError::new(-32600, "Missing method"))?;
    let params = request_object
        .get("params")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let id = request_object.get("id").cloned();

    enforce_rpc_exposure_policy(method, request_context)?;

    if id.is_none() && method != "synergy_subscribe" && method != "synergy_unsubscribe" {
        let _ = execute_rpc_method(
            method,
            params,
            tx_pool,
            chain,
            validator_manager,
            subscriptions,
            request_context,
        )?;
        return Ok(None);
    }

    let result = execute_rpc_method(
        method,
        params,
        tx_pool,
        chain,
        validator_manager,
        subscriptions,
        request_context,
    );

    match result {
        Ok(value) => Ok(Some(json!({
            "jsonrpc": "2.0",
            "id": id.clone().unwrap_or(Value::Null),
            "result": value,
            "chain_context": rpc_chain_context_json()
        }))),
        Err(error) => Ok(Some(json_rpc_error_response(id, &error))),
    }
}

fn execute_rpc_method(
    method: &str,
    params: Value,
    tx_pool: &Arc<Mutex<Vec<Transaction>>>,
    chain: &Arc<Mutex<BlockChain>>,
    validator_manager: &Arc<ValidatorManager>,
    subscriptions: Option<&mut HashMap<String, SubscriptionCursor>>,
    _request_context: &RpcRequestContext,
) -> Result<Value, RpcError> {
    if method == "synergy_simulateTransaction" {
        return Err(RpcError::new(
            -32072,
            "ERR_CONFIDENTIAL_SIMULATION_REQUIRED: public plaintext simulation is disabled after ETDAG activation",
        ));
    }
    match method {
        "synergy_getAccountNonce" | "synergy_getAccountAuthNonce" => {
            get_account_nonce(&params, tx_pool, chain)
        }
        "synergy_subscribe" => {
            let subscriptions = subscriptions
                .ok_or_else(|| RpcError::new(-32601, "synergy_subscribe is WebSocket-only"))?;
            register_subscription(&params, chain, tx_pool, subscriptions)
        }
        "synergy_unsubscribe" => {
            let subscriptions = subscriptions
                .ok_or_else(|| RpcError::new(-32601, "synergy_unsubscribe is WebSocket-only"))?;
            unregister_subscription(&params, subscriptions)
        }
        _ => translate_legacy_rpc_result(handle_json_rpc(
            method,
            params,
            tx_pool,
            chain,
            validator_manager,
        )),
    }
}

fn submit_etdag_transaction_envelope(_envelope_value: &Value) -> Value {
    if !crate::etdag::etdag_certified_input_ingress_is_active() {
        return json!({
            "success": false,
            "code": "ERR_ETDAG_NOT_ACTIVATED",
            "error": "Encrypted transaction admission is unavailable until a finalized ETDAG activation permit and authenticated ingress are installed",
            "automatic_plaintext_fallback": false,
        });
    }
    etdag_distributed_admission_unavailable_json()
}

/// A raw sealed envelope is not an executable transaction.  It needs the
/// validator-distributed availability, DAG-cut, batch-order, and ordered
/// reveal certificates before a typed proposal may consume it.
fn etdag_distributed_admission_unavailable_json() -> Value {
    // Earlier code retained envelopes in a process-local pool but had no
    // producer to advance them, returning a misleading success response. Do
    // not retain or forward client data until that scheduler is installed.
    json!({
        "success": false,
        "code": "ERR_ETDAG_DISTRIBUTED_ADMISSION_UNAVAILABLE",
        "error": "ETDAG is activation-permitted, but the validator-distributed admission scheduler is not installed; the sealed envelope was not retained or forwarded",
        "admission_status": "NOT_ACCEPTED",
        "plaintext_exposed": false,
        "automatic_plaintext_fallback": false,
    })
}

fn etdag_admission_package_json(params: &Value) -> Value {
    let Some(height) = params
        .get(0)
        .and_then(|value| value.as_u64())
        .map(crate::synergy_types::Height)
    else {
        return json!({
            "success": false,
            "code": "ERR_MISSING_TARGET_HEIGHT",
            "error": "A positive target height is required",
        });
    };
    if height.0 == 0 {
        return json!({
            "success": false,
            "code": "ERR_INVALID_TARGET_HEIGHT",
            "error": "Target height must be positive",
        });
    }
    match crate::etdag::EtdagAdmissionPackageStore::process_wide().get(height) {
        Ok(Some(package)) => match package.package_digest() {
            Ok(package_digest) => json!({
                "success": true,
                "target_height": height.0,
                "package_digest": package_digest.0,
                "package": package,
                "contains_secret_key_material": false,
                "client_must_verify_certificate": true,
            }),
            Err(error) => json!({
                "success": false,
                "code": "ERR_TARGET_ADMISSION_PACKAGE_INVALID",
                "error": error,
            }),
        },
        Ok(None) => json!({
            "success": false,
            "code": "ERR_TARGET_ADMISSION_PACKAGE_UNAVAILABLE",
            "error": "No certified target-admission package is installed for that height",
            "target_height": height.0,
        }),
        Err(error) => json!({
            "success": false,
            "code": "ERR_TARGET_ADMISSION_PACKAGE_STORE",
            "error": error,
        }),
    }
}

fn etdag_status_json() -> Value {
    let activated = crate::etdag::etdag_certified_input_ingress_is_active();
    json!({
        "profile_id": crate::etdag::ETDAG_PROFILE_ID,
        "enabled": activated,
        "activation_status": if activated { "ACTIVE_CERTIFIED_INPUT_INGRESS" } else { "FINALIZED_ACTIVATION_PERMIT_REQUIRED" },
        "plaintext_user_tx_allowed": false,
        "automatic_plaintext_fallback_allowed": false,
        "encrypted_submission_available": false,
        "submission_status": "VALIDATOR_DISTRIBUTED_ADMISSION_SCHEDULER_REQUIRED",
        "raw_envelopes_retained": false,
        "target_admission_package_method": "synergy_getEtdagAdmissionPackage",
        "target_admission_context_requires_future_qc": false,
        "public_pending_content_before_reveal_gate": false,
        "public_ordered_reveal_required": true,
    })
}

fn consensus_safety_halt_status_json() -> Value {
    consensus_safety_halt_status_for(
        &crate::consensus::signing_authority::DurableConsensusSigningAuthority::process_wide(),
    )
}

fn consensus_safety_halt_status_for(
    authority: &crate::consensus::signing_authority::DurableConsensusSigningAuthority,
) -> Value {
    match authority.safety_halt_incidents() {
        Ok(incidents) => json!({
            "status": if incidents.is_empty() { "SIGNING_ALLOWED" } else { "SAFETY_HALT" },
            "signing_allowed": incidents.is_empty(),
            "incident_count": incidents.len(),
            "incidents": incidents,
            "clearable_by_runtime": false,
        }),
        Err(error) => json!({
            "status": "SAFETY_HALT_STATUS_UNAVAILABLE",
            "signing_allowed": false,
            "incident_count": Value::Null,
            "incidents": [],
            "clearable_by_runtime": false,
            "error": error,
        }),
    }
}

fn submit_aegis_transaction_envelope(
    envelope_value: &Value,
    tx_pool: &Arc<Mutex<Vec<Transaction>>>,
) -> Value {
    match serde_json::from_value::<crate::aegis_tx_tool::AegisTxSubmissionEnvelope>(
        envelope_value.clone(),
    ) {
        Ok(envelope) => {
            match crate::aegis_tx_tool::legacy_transaction_from_aegis_envelope(&envelope) {
                Ok(transaction) => {
                    if transaction.chain_id != current_chain_id() {
                        return json!({
                            "error": format!(
                                "Aegis transaction chainId {} does not match local chain {}",
                                transaction.chain_id,
                                current_chain_id()
                            )
                        });
                    }
                    let tx_id = match envelope.transaction.canonical_bytes() {
                        Ok(bytes) => crate::crypto::aegis_pqvm::AegisPqvmDomainSeparatedHash::hash_transaction(
                            crate::crypto::aegis_pqvm::SYNERGY_TX_V1,
                            envelope.transaction.chain_id,
                            &envelope.transaction.network_id,
                            &bytes,
                        )
                        .0,
                        Err(error) => {
                            return json!({
                                "error": format!(
                                    "Aegis transaction canonicalization failed: {error}"
                                )
                            });
                        }
                    };
                    let tx_hash = transaction.hash();
                    if let Err(error) =
                        ProofOfSynergy::validate_transaction_for_mempool(&transaction)
                    {
                        let pruned = prune_transaction_hashes_from_pool(&transaction_hashes(
                            std::slice::from_ref(&transaction),
                        ));
                        return json!({
                            "error": format!("Transaction failed runtime validation: {error}"),
                            "tx_hash": tx_hash,
                            "mempool_status": "rejected",
                            "pruned_count": pruned,
                        });
                    }
                    {
                        let mut pool = tx_pool.lock().unwrap();
                        pool.push(transaction.clone());
                    }
                    if let Some(p2p) = crate::p2p::get_p2p_network() {
                        p2p.broadcast_transaction(&transaction);
                    }
                    json!({
                        "success": true,
                        "tx_id": tx_id,
                        "tx_hash": tx_hash,
                        "dag_node_id": tx_id,
                        "mempool_status": "queued",
                        "dag_admission_status": "queued_for_proposal_dag",
                        "dependency_status": "verified_or_ancestor_pending",
                        "aegis_pqvm_verification": "verified",
                        "wallet_cli_used": false,
                        "message": "Aegis PQVM DAG transaction submitted"
                    })
                }
                Err(error) => json!({"error": error}),
            }
        }
        Err(error) => json!({"error": format!("Invalid Aegis transaction envelope: {error}")}),
    }
}

fn rpc_u64_param(params: &Value, object_key: &str, array_index: usize) -> Option<u64> {
    params
        .get(object_key)
        .or_else(|| params.get(array_index))
        .and_then(|value| {
            value.as_u64().or_else(|| {
                value.as_str().and_then(|text| {
                    let trimmed = text.trim();
                    trimmed
                        .strip_prefix("0x")
                        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                        .or_else(|| trimmed.parse::<u64>().ok())
                })
            })
        })
}

fn rpc_string_param(params: &Value, object_key: &str, array_index: usize) -> Option<String> {
    params
        .get(object_key)
        .or_else(|| params.get(array_index))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn rpc_bool_param(params: &Value, object_key: &str, array_index: usize) -> Option<bool> {
    params
        .get(object_key)
        .or_else(|| params.get(array_index))
        .and_then(|value| {
            value.as_bool().or_else(|| {
                value.as_str().map(|text| {
                    matches!(
                        text.trim().to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes" | "y" | "on"
                    )
                })
            })
        })
}

fn handle_json_rpc(
    method: &str,
    params: Value,
    tx_pool: &Arc<Mutex<Vec<Transaction>>>,
    chain: &Arc<Mutex<BlockChain>>,
    validator_manager: &Arc<ValidatorManager>,
    // Temporarily disabled AIVM for quick compile
    // aivm_runtime: &Arc<AIVMRuntime>,
) -> Value {
    if matches!(
        method,
        "synergy_sendTransaction"
            | "synergy_submitAegisTransaction"
            | "synergy_submitAegisDagTransaction"
            | "synergy_submitAegisDagTransactionBatch"
            | "synergy_submitAegisTransactionBatch"
    ) {
        return json!({
            "success": false,
            "code": crate::etdag::ERR_PLAINTEXT_USER_TX_DISABLED,
            "error": "Ordinary plaintext transaction submission is disabled after Testnet-v3 ETDAG activation",
            "required_method": "synergy_submitEncryptedTransaction",
            "automatic_plaintext_fallback": false,
        });
    }
    if matches!(
        method,
        "synergy_getTransactionPool"
            | "synergy_getTransaction"
            | "synergy_getTransactionStatus"
            | "synergy_getPendingTransaction"
            | "synergy_getPendingTransactions"
            | "synergy_getDagVertices"
            | "synergy_getDagFrontier"
            | "synergy_getDagVertex"
            | "synergy_getDagNode"
            | "synergy_getDagTransactionStatus"
            | "synergy_getDagTopology"
            | "synergy_getDagGraph"
            | "synergy_getDagDependencies"
            | "synergy_getDagTxOrderRoot"
    ) {
        return json!({
            "success": false,
            "code": "ERR_PRE_REVEAL_PENDING_CONTENT_DISABLED",
            "error": "Pre-RevealGate pending transaction content and legacy plaintext DAG views are disabled",
        });
    }
    match method {
        // Blockchain queries
        "synergy_chainId" | "synergy_networkId" | "synergy_genesisHash" => {
            chain_identity_json()
        }

        "synergy_protocolVersion" => {
            json!({
                "protocol_version": current_protocol_version(),
                "identity": chain_identity_json(),
            })
        }

        "synergy_syncing" => sync_status_json(chain),

        "synergy_startSync" => start_live_sync_json(),

        "synergy_getHealth" => node_health_json(chain),

        "synergy_getReadiness" => node_readiness_json(chain),

        "synergy_getPeers" => peer_info_json(),

        "synergy_blockNumber" => block_number_json(chain),

        "synergy_getBlockNumber" => block_number_json(chain),

        "synergy_getBlockByNumber" => match params.get(0).and_then(|v| v.as_u64()) {
            Some(block_num) => block_by_number_json(chain, block_num),
            None => json!("Invalid block number"),
        },

        "synergy_getBlockByHash" => match params.get(0).and_then(|v| v.as_str()) {
            Some(block_hash) => block_by_hash_json(chain, block_hash),
            None => json!("Invalid block hash"),
        },

        "synergy_getLatestBlock" => latest_block_json(chain),

        "synergy_getFinalizedHead" => latest_finalized_head_json(chain),

        "synergy_getCanonicalLock" => latest_canonical_lock_json(),

        "synergy_getCommittedQC" => latest_committed_qc_json(),

        "synergy_getDivergenceStatus" => {
            crate::consensus::diagnostics::divergence_status(chain)
        }

        "synergy_getQuarantineStatus" => crate::consensus::diagnostics::quarantine_status(),

        "synergy_getReconciliationPlan" => {
            crate::consensus::diagnostics::reconciliation_plan(chain)
        }

        "synergy_getSelfHealStatus" => crate::consensus::diagnostics::self_heal_status(),

        "synergy_listSnapshots" => crate::consensus::diagnostics::list_snapshots(),

        "synergy_getSnapshotCatalog" => crate::consensus::diagnostics::snapshot_catalog(),

        "synergy_createSnapshot" => {
            let options = crate::consensus::diagnostics::CreateSnapshotOptions {
                source_node_majority_branch_proven: rpc_bool_param(
                    &params,
                    "source_node_majority_branch_proven",
                    0,
                )
                .unwrap_or(false),
                source_role: rpc_string_param(&params, "source_role", 1),
                conflict_height_hash: rpc_string_param(&params, "conflict_height_hash", 2),
                snapshot_class: rpc_string_param(&params, "snapshot_class", 3),
                allowed_restore_roles: Vec::new(),
            };
            match crate::consensus::diagnostics::create_snapshot_with_options(options) {
                Ok(report) => report,
                Err(error) => json!({
                    "success": false,
                    "typed_status": "FAILED_CLOSED",
                    "fail_closed": true,
                    "error": error,
                    "next_required_action": "prove majority branch and call synergy_createSnapshot with source_node_majority_branch_proven=true"
                }),
            }
        }

        "synergy_verifySnapshot" => {
            let manifest_path = rpc_string_param(&params, "manifest_path", 0)
                .or_else(|| rpc_string_param(&params, "manifest", 0))
                .unwrap_or_default();
            let snapshot_root = rpc_string_param(&params, "snapshot_root", 1);
            if manifest_path.trim().is_empty() {
                json!({"success": false, "fail_closed": true, "error": "synergy_verifySnapshot requires manifest_path"})
            } else {
                match crate::consensus::diagnostics::verify_snapshot(
                    &manifest_path,
                    snapshot_root.as_deref(),
                ) {
                    Ok(report) => report,
                    Err(error) => json!({"success": false, "fail_closed": true, "error": error}),
                }
            }
        }

        "synergy_diagnoseConsensusStall" => {
            crate::consensus::diagnostics::diagnose_consensus_stall(chain)
        }

        "synergy_diagnoseVoteLocks" => {
            let finalized_height = rpc_u64_param(&params, "finalized_height", 0);
            crate::consensus::diagnostics::diagnose_vote_locks(finalized_height)
        }

        "synergy_recoverTransientVoteLocks" => {
            let finalized_height = rpc_u64_param(&params, "finalized_height", 0);
            let min_age_secs = rpc_u64_param(&params, "min_age_secs", 1).unwrap_or(0);
            let reason = rpc_string_param(&params, "reason", 2)
                .unwrap_or_else(|| "operator_rpc_recover_transient_vote_locks".to_string());
            match crate::consensus::diagnostics::recover_transient_vote_locks(
                finalized_height,
                min_age_secs,
                &reason,
            ) {
                Ok(report) => report,
                Err(error) => json!({"success": false, "fail_closed": true, "error": error}),
            }
        }

        "synergy_startSelfHeal" => match crate::consensus::diagnostics::start_self_heal() {
            Ok(report) => report,
            Err(error) => json!({"success": false, "fail_closed": true, "error": error}),
        },

        "synergy_syncFromCanonicalPeer" => {
            let options = crate::consensus::diagnostics::SyncFromCanonicalPeerOptions {
                canonical_height: rpc_u64_param(&params, "canonical_height", 0),
                canonical_hash: rpc_string_param(&params, "canonical_hash", 1),
                source_peer: rpc_string_param(&params, "source_peer", 2),
                source_qc_aegis_pqc_verified: rpc_bool_param(
                    &params,
                    "source_qc_aegis_pqc_verified",
                    3,
                )
                .unwrap_or(false),
                parent_continuity_verified: rpc_bool_param(
                    &params,
                    "parent_continuity_verified",
                    4,
                )
                .unwrap_or(false),
                state_root_matches: rpc_bool_param(&params, "state_root_matches", 5)
                    .unwrap_or(false),
                source_peer_quarantined: rpc_bool_param(&params, "source_peer_quarantined", 6)
                    .unwrap_or(true),
            };
            match crate::consensus::diagnostics::sync_from_canonical_peer_with_options(options) {
                Ok(report) => report,
                Err(error) => json!({"success": false, "fail_closed": true, "error": error}),
            }
        }

        "synergy_selfHealFromArchive" => {
            match crate::consensus::diagnostics::self_heal_from_archive() {
                Ok(report) => report,
                Err(error) => json!({"success": false, "fail_closed": true, "error": error}),
            }
        }

        "synergy_selfHealFromSnapshot" => {
            let manifest_path = rpc_string_param(&params, "manifest_path", 0)
                .or_else(|| rpc_string_param(&params, "manifest", 0))
                .unwrap_or_default();
            let snapshot_root = rpc_string_param(&params, "snapshot_root", 1);
            if manifest_path.trim().is_empty() {
                json!({"success": false, "fail_closed": true, "error": "synergy_selfHealFromSnapshot requires manifest_path"})
            } else {
                match crate::consensus::diagnostics::self_heal_from_snapshot(
                    &manifest_path,
                    snapshot_root.as_deref(),
                ) {
                    Ok(report) => report,
                    Err(error) => json!({"success": false, "fail_closed": true, "error": error}),
                }
            }
        }

        "synergy_getShadowStatus" => crate::consensus::diagnostics::shadow_status(),

        "synergy_startShadowObserve" => {
            let options = crate::consensus::diagnostics::StartShadowObserveOptions {
                required_blocks: rpc_u64_param(&params, "required_blocks", 0),
            };
            match crate::consensus::diagnostics::start_shadow_observe_with_options(options) {
                Ok(report) => report,
                Err(error) => json!({"success": false, "fail_closed": true, "error": error}),
            }
        }

        "synergy_getRejoinEligibility" => crate::consensus::diagnostics::rejoin_eligibility(),

        "synergy_requestRejoin" => {
            let options = crate::consensus::diagnostics::RejoinRequestOptions {
                common_height: rpc_u64_param(&params, "common_height", 0),
                common_hash: rpc_string_param(&params, "common_hash", 1),
                exact_common_height_match: rpc_bool_param(&params, "exact_common_height_match", 2)
                    .unwrap_or(false),
                latest_finalized_qc_aegis_pqc_verified: rpc_bool_param(
                    &params,
                    "latest_finalized_qc_aegis_pqc_verified",
                    3,
                )
                .unwrap_or(false),
                state_root_matches: rpc_bool_param(&params, "state_root_matches", 4)
                    .unwrap_or(false),
                rejoin_at_finalized_safe_boundary: rpc_bool_param(
                    &params,
                    "rejoin_at_finalized_safe_boundary",
                    5,
                )
                .unwrap_or(false),
                cluster_marks_pending_reactivation: rpc_bool_param(
                    &params,
                    "cluster_marks_pending_reactivation",
                    6,
                )
                .unwrap_or(false),
                operator_approved_reactivation: rpc_bool_param(
                    &params,
                    "operator_approved_reactivation",
                    7,
                )
                .unwrap_or(false),
                operator_approved_emergency_leader_stall_recovery: rpc_bool_param(
                    &params,
                    "operator_approved_emergency_leader_stall_recovery",
                    8,
                )
                .unwrap_or(false),
            };
            match crate::consensus::diagnostics::request_rejoin_with_options(options) {
                Ok(report) => report,
                Err(error) => json!({"success": false, "fail_closed": true, "error": error}),
            }
        }

        "synergy_getValidatorSet" => {
            let chain = chain.lock().unwrap();
            json!(network_validator_snapshot(&chain, validator_manager))
        }

        "synergy_getProtocolConfig" => protocol_config_json(),

        "synergy_getAegisStatus" => aegis_status_json(),

        "synergy_getAegisCapabilities" => aegis_capabilities_json(),

        "synergy_getAegisKeyStatus" => aegis_fail_closed_json(
            "synergy_getAegisKeyStatus",
            "Aegis key status requires a key lifecycle record; public RPC does not expose private key material",
        ),

        "synergy_verifyAegisSignature" => aegis_fail_closed_json(
            "synergy_verifyAegisSignature",
            "Use a typed Aegis artifact verifier; raw signature verification without lifecycle context is rejected",
        ),

        "synergy_verifyAegisTransaction" => {
            if let Some(envelope_value) = params.get(0) {
                verify_aegis_transaction_envelope(envelope_value)
            } else {
                aegis_fail_closed_json(
                    "synergy_verifyAegisTransaction",
                    "Missing Aegis transaction envelope",
                )
            }
        }

        "synergy_verifyAegisQC" => aegis_fail_closed_json(
            "synergy_verifyAegisQC",
            "QC verification requires a typed quorum certificate and validator-set context",
        ),

        "synergy_verifyAegisSnapshotManifest" => aegis_fail_closed_json(
            "synergy_verifyAegisSnapshotManifest",
            "Snapshot manifest verification requires the signed archive manifest payload",
        ),

        "synergy_verifyAegisSnapshotCatalog" => aegis_fail_closed_json(
            "synergy_verifyAegisSnapshotCatalog",
            "Snapshot catalog verification requires the signed archive catalog payload",
        ),

        // PoSy v2.2 encrypted transaction DAG methods.
        "synergy_submitEncryptedTransaction" | "synergy_submitEtdagTransaction" => {
            if let Some(envelope_value) = params.get(0) {
                submit_etdag_transaction_envelope(envelope_value)
            } else {
                json!({
                    "success": false,
                    "code": "ERR_MISSING_ETDAG_ENVELOPE",
                    "error": "Missing encrypted transaction submission envelope",
                })
            }
        }

        "synergy_getEtdagStatus" | "synergy_getDagStatus" => etdag_status_json(),

        "synergy_getEtdagAdmissionPackage" => etdag_admission_package_json(&params),

        "synergy_getConsensusSafetyHalt" => consensus_safety_halt_status_json(),

        // Legacy plaintext DAG query routes below remain unreachable after
        // activation through the fail-closed policy above.

        "synergy_getDagFrontier" => crate::dag::frontier_json(),

        "synergy_getDagVertices" => {
            let limit = dag_rpc_limit(&params, 100, 1_000);
            let status = dag_rpc_status_filter(&params);
            crate::dag::vertices_json(limit, status)
        }

        "synergy_getDagVertex" | "synergy_getDagNode" => {
            if let Some(hash) = params.get(0).and_then(|value| value.as_str()) {
                crate::dag::vertex_json(hash)
            } else {
                json!("Missing DAG vertex hash")
            }
        }

        "synergy_getDagTransactionStatus" => {
            if let Some(tx_id_or_hash) = params.get(0).and_then(|value| value.as_str()) {
                crate::dag::transaction_status_json(tx_id_or_hash)
            } else {
                json!("Missing DAG transaction id or hash")
            }
        }

        "synergy_getDagTopology" => {
            let limit = dag_rpc_limit(&params, 100, 1_000);
            crate::dag::topology_json(limit)
        }

        "synergy_getDagGraph" => {
            let limit = dag_rpc_limit(&params, 100, 1_000);
            crate::dag::topology_json(limit)
        }

        "synergy_getDagDependencies" => dag_dependencies_json(&params),

        "synergy_getDagTxOrderRoot" => dag_tx_order_root_json(&params),

        // Transaction methods
        "synergy_sendTransaction" => {
            if let Some(tx_data) = params.get(0) {
                match normalize_rpc_transaction(tx_data, true) {
                    Ok(normalized) => {
                        let configured_chain_id = current_chain_id();
                        if let Some(chain_id) = normalized.chain_id {
                            if chain_id != configured_chain_id {
                                return json!({
                                    "error": format!("Transaction chainId {} does not match local chain {}", chain_id, configured_chain_id)
                                });
                            }
                        }

                        if let Some(simulation_hash) =
                            params.get(2).and_then(|value| value.as_str())
                        {
                            let tx_digest = canonical_value_digest(tx_data)
                                .unwrap_or_else(|| normalized.transaction.hash());
                            let cache = SIMULATION_CACHE.lock().unwrap();
                            match cache.get(&tx_digest) {
                                Some(cached) if cached.simulation_hash == simulation_hash => {}
                                Some(_) => {
                                    return json!({"error": "simulationHash does not match the current transaction envelope"});
                                }
                                None => {
                                    return json!({"error": "simulationHash is unknown or expired"});
                                }
                            }
                        }

                        match normalized.transaction.validate_for_admission() {
                            crate::transaction::TransactionValidationResult {
                                is_valid: true,
                                ..
                            } => match ProofOfSynergy::validate_transaction_for_mempool(
                                &normalized.transaction,
                            ) {
                                Ok(()) => {
                                let mut pool = tx_pool.lock().unwrap();
                                let tx_hash = normalized.transaction.hash();
                                pool.push(normalized.transaction.clone());

                                if let Some(p2p) = crate::p2p::get_p2p_network() {
                                    p2p.broadcast_transaction(&normalized.transaction);
                                }

                                json!({
                                    "success": true,
                                    "tx_hash": tx_hash,
                                    "mempool_status": "queued",
                                    "policy_warnings": normalized.warnings,
                                    "message": "Transaction submitted"
                                })
                            }
                                Err(error) => {
                                    let tx_hash = normalized.transaction.hash();
                                    let pruned = prune_transaction_hashes_from_pool(
                                        &transaction_hashes(std::slice::from_ref(
                                            &normalized.transaction,
                                        )),
                                    );
                                    json!({
                                        "error": format!(
                                            "Transaction failed runtime validation: {error}"
                                        ),
                                        "tx_hash": tx_hash,
                                        "mempool_status": "rejected",
                                        "policy_warnings": normalized.warnings,
                                        "pruned_count": pruned,
                                    })
                                }
                            },
                            crate::transaction::TransactionValidationResult {
                                error_message: Some(msg),
                                ..
                            } => json!({"error": msg}),
                            _ => json!("Invalid transaction"),
                        }
                    }
                    Err(error) => {
                        json!({"error": error.message, "code": error.code, "data": error.data})
                    }
                }
            } else {
                json!("Missing transaction data")
            }
        }

        "synergy_submitAegisTransaction" | "synergy_submitAegisDagTransaction" => {
            if let Some(envelope_value) = params.get(0) {
                submit_aegis_transaction_envelope(envelope_value, tx_pool)
            } else {
                json!("Missing Aegis transaction envelope")
            }
        }

        "synergy_submitAegisDagTransactionBatch" => {
            if let Some(envelopes) = params.get(0).and_then(|value| value.as_array()) {
                let results = envelopes
                    .iter()
                    .map(|envelope_value| {
                        submit_aegis_transaction_envelope(envelope_value, tx_pool)
                    })
                    .collect::<Vec<_>>();
                let success = results
                    .iter()
                    .all(|result| result.get("success").and_then(Value::as_bool) == Some(true));
                json!({
                    "success": success,
                    "wallet_cli_used": false,
                    "results": results,
                })
            } else {
                json!("Missing Aegis transaction envelope batch")
            }
        }

        "synergy_submitAegisTransactionBatch" => {
            if let Some(envelopes) = params.get(0).and_then(|value| value.as_array()) {
                let results = envelopes
                    .iter()
                    .map(|envelope_value| {
                        submit_aegis_transaction_envelope(envelope_value, tx_pool)
                    })
                    .collect::<Vec<_>>();
                let success = results
                    .iter()
                    .all(|result| result.get("success").and_then(Value::as_bool) == Some(true));
                json!({
                    "success": success,
                    "wallet_cli_used": false,
                    "results": results,
                })
            } else {
                json!("Missing Aegis transaction envelope batch")
            }
        }

        "synergy_getTransaction" | "synergy_getPendingTransaction" => {
            transaction_lookup_json(&params, tx_pool, chain)
        }

        "synergy_getTransactionStatus" => transaction_status_json(&params, tx_pool, chain),

        "synergy_getTransactionPool" => {
            let pool = tx_pool.lock().unwrap();
            let txs: Vec<Value> = pool
                .iter()
                .map(|tx| tx_to_explorer_json(tx, "pending", None, None))
                .collect();
            json!(txs)
        }

        // ---------------------------------------------------------------------
        // SXCP (Synergy Cross-Chain Protocol) – Testnet RPC surface
        // ---------------------------------------------------------------------
        "synergy_registerRelayer" => {
            if let (Some(address), Some(public_key)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
            ) {
                sxcp::register_relayer(address, public_key)
            } else {
                json!({"success": false, "error": "Missing required parameters: address, public_key"})
            }
        }

        "synergy_unregisterRelayer" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                sxcp::unregister_relayer(address)
            } else {
                json!({"success": false, "error": "Missing required parameter: address"})
            }
        }

        "synergy_relayerHeartbeat" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                sxcp::heartbeat_relayer(address)
            } else {
                json!({"success": false, "error": "Missing required parameter: address"})
            }
        }

        "synergy_getRelayerSet" => sxcp::get_relayer_set(),

        "synergy_getRelayerHealth" => sxcp::get_relayer_health(),

        "synergy_getSxcpStatus" => sxcp::get_sxcp_status(),

        "synergy_submitAttestation" => {
            if let (Some(submitted_by), Some(event_hash), Some(aggregate_sig)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_str()),
            ) {
                let metadata = params.get(3).cloned().unwrap_or(json!({}));
                sxcp::submit_attestation(submitted_by, event_hash, aggregate_sig, metadata)
            } else {
                json!({"success": false, "error": "Missing required parameters: submitted_by, event_hash, aggregate_sig"})
            }
        }

        "synergy_getEventAttestation" => {
            if let Some(event_hash) = params.get(0).and_then(|v| v.as_str()) {
                sxcp::get_event_attestation(event_hash)
            } else {
                json!({"success": false, "error": "Missing required parameter: event_hash"})
            }
        }

        "synergy_getAttestations" => {
            let limit = params.get(0).and_then(|v| v.as_u64()).map(|v| v as usize);
            sxcp::get_attestations(limit)
        }

        "synergy_slashRelayer" => {
            if let (Some(address), Some(reason)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
            ) {
                let penalty = params.get(2).and_then(|v| v.as_i64());
                sxcp::slash_relayer(address, reason, penalty)
            } else {
                json!({"success": false, "error": "Missing required parameters: address, reason"})
            }
        }

        "synergy_setSxcpHeartbeatTimeout" => {
            if let Some(timeout_secs) = params.get(0).and_then(|v| v.as_u64()) {
                sxcp::set_heartbeat_timeout(timeout_secs)
            } else {
                json!({"success": false, "error": "Missing required parameter: timeout_secs"})
            }
        }

        "synergy_resetSxcpState" => {
            if params
                .get(0)
                .and_then(|v| v.as_str())
                .map(|token| token == "TESTNET_RESET_SXCP_STATE")
                .unwrap_or(false)
            {
                sxcp::reset_state()
            } else {
                json!({
                    "success": false,
                    "error": "Confirmation token required as first parameter: TESTNET_RESET_SXCP_STATE"
                })
            }
        }

        // Node status
        "synergy_nodeInfo" => {
            let tip = chain_tip_snapshot_for_status(chain);
            let config = crate::config::load_node_config(None).ok();
            let node_name = config
                .as_ref()
                .map(|cfg| cfg.p2p.node_name.clone())
                .filter(|name| !name.is_empty())
                .or_else(|| config.as_ref().map(|cfg| cfg.network.name.clone()));
            let network_id = config.as_ref().map(|cfg| cfg.network.id);
            let chain_id = config.as_ref().map(|cfg| cfg.blockchain.chain_id);
            let consensus = config.as_ref().map(|cfg| cfg.consensus.algorithm.clone());
            let syncing = SYNC_MANAGER.try_lock().ok().map(|manager| {
                !matches!(manager.get_state(), SyncState::Synced | SyncState::Idle)
            });
            let sync_manager_available = syncing.is_some();
            json!({
                "name": node_name,
                "version": env!("CARGO_PKG_VERSION"),
                "protocolVersion": null,
                "networkId": network_id,
                "chainId": chain_id,
                "consensus": consensus,
                "syncing": syncing,
                "syncManagerAvailable": sync_manager_available,
                "currentBlock": tip.height,
                "latestHash": tip.hash,
                "chainStateAvailable": tip.available,
                "chainStateError": tip.error,
                "failClosed": !tip.available,
                "timestamp": current_timestamp()
            })
        }

        "synergy_getDeterminismDigest" => {
            let chain = chain.lock().unwrap();
            let latest_block = chain.last().cloned();
            let latest_height = latest_block.as_ref().map(|b| b.block_index).unwrap_or(0);
            let latest_hash = latest_block
                .as_ref()
                .map(|b| b.hash.clone())
                .unwrap_or_default();

            let token_state_hash = stable_json_file_digest(crate::token::token_state_path());
            let sts_state_hash = stable_json_file_digest(crate::sts::STS_STATE_SNAPSHOT_PATH);
            let validator_registry_hash = stable_json_file_digest("data/validator_registry.json");
            let chain_state_hash =
                canonical_value_digest(&serde_json::to_value(&chain.chain).unwrap_or(json!([])));
            let receipt_hash = compute_receipt_hash(&chain);

            let mut state_hasher = blake3::Hasher::new();
            state_hasher.update(latest_hash.as_bytes());
            if let Some(hash) = token_state_hash.as_ref() {
                state_hasher.update(hash.as_bytes());
            }
            if let Some(hash) = sts_state_hash.as_ref() {
                state_hasher.update(hash.as_bytes());
            }
            if let Some(hash) = validator_registry_hash.as_ref() {
                state_hasher.update(hash.as_bytes());
            }
            if let Some(hash) = chain_state_hash.as_ref() {
                state_hasher.update(hash.as_bytes());
            }
            let state_root = hex::encode(state_hasher.finalize().as_bytes());

            json!({
                "block_height": latest_height,
                "block_hash": latest_hash,
                "state_root": state_root,
                "receipt_hash": receipt_hash,
                "token_state_hash": token_state_hash,
                "sts_state_hash": sts_state_hash,
                "validator_registry_hash": validator_registry_hash,
                "chain_state_hash": chain_state_hash
            })
        }

        "synergy_getConsensusForkStatus" => consensus_fork::active_consensus_fork_status(),

        // Validator management
        "synergy_getValidators" => {
            let chain = chain.lock().unwrap();
            let local_nickname = configured_local_validator_nickname();
            let validators = network_validator_snapshot(&chain, &validator_manager)
                .into_iter()
                .filter(|validator| validator.status == ValidatorStatus::Active)
                .map(|validator| validator_to_rpc_json(validator, local_nickname.as_ref()))
                .collect::<Vec<_>>();
            println!(
                "🔍 [RPC] synergy_getValidators called, returning {} validators",
                validators.len()
            );
            json!(validators)
        }

        "synergy_getValidator" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                let chain = chain.lock().unwrap();
                let local_nickname = configured_local_validator_nickname();
                match network_validator_snapshot(&chain, &validator_manager)
                    .into_iter()
                    .find(|validator| validator.address.eq_ignore_ascii_case(address))
                {
                    Some(validator) => validator_to_rpc_json(validator, local_nickname.as_ref()),
                    None => json!(null),
                }
            } else {
                json!("Missing validator address")
            }
        }

        "synergy_stsGetNativeAsset" | "sts_getNativeAsset" => sts_native_asset_json(),

        "synergy_stsGetTokens" | "sts_getTokens" => sts_tokens_json(chain),

        "synergy_stsGetToken" | "sts_getToken" => sts_token_json(&params, chain),

        "synergy_stsGetBalance" | "sts_getBalance" => sts_balance_json(&params, chain),

        "synergy_stsGetBalances" | "sts_getBalances" => sts_balances_json(&params, chain),

        "synergy_stsGetNftCollection" | "sts_getNftCollection" | "sts_get_nft_collection" => {
            sts_nft_collection_json(&params, chain)
        }

        "synergy_stsGetNft" | "sts_getNft" | "sts_get_nft" => sts_nft_json(&params, chain),

        "synergy_stsGetNftsByOwner" | "sts_getNftsByOwner" | "sts_get_nfts_by_owner" => {
            sts_nfts_by_owner_json(&params, chain)
        }

        "synergy_stsGetNftsByCollection"
        | "sts_getNftsByCollection"
        | "sts_get_nfts_by_collection" => sts_nfts_by_collection_json(&params, chain),

        "synergy_stsGetMultiAssetCollection"
        | "sts_getMultiAssetCollection"
        | "sts_get_multi_asset_collection" => sts_multi_asset_collection_json(&params, chain),

        "synergy_stsGetMultiAssetItem"
        | "sts_getMultiAssetItem"
        | "sts_get_multi_asset_item" => sts_multi_asset_item_json(&params, chain),

        "synergy_stsGetMultiAssetBalance"
        | "sts_getMultiAssetBalance"
        | "sts_get_multi_asset_balance" => sts_multi_asset_balance_json(&params, chain),

        "synergy_stsGetMultiAssetBalances"
        | "sts_getMultiAssetBalances"
        | "sts_get_multi_asset_balances" => sts_multi_asset_balances_json(&params, chain),

        "synergy_stsGetCredentialSchema"
        | "sts_getCredentialSchema"
        | "sts_get_credential_schema" => sts_credential_schema_json(&params, chain),

        "synergy_stsGetCredential" | "sts_getCredential" | "sts_get_credential" => {
            sts_credential_json(&params, chain)
        }

        "synergy_stsGetCredentialsBySubject"
        | "sts_getCredentialsBySubject"
        | "sts_get_credentials_by_subject" => sts_credentials_by_subject_json(&params, chain),

        "synergy_stsVerifyCredential" | "sts_verifyCredential" | "sts_verify_credential" => {
            sts_verify_credential_json(&params, chain)
        }

        "synergy_stsGetCredentialStatus"
        | "sts_getCredentialStatus"
        | "sts_get_credential_status" => sts_credential_status_json(&params, chain),

        "synergy_stsGetEvents" | "sts_getEvents" => sts_events_json(&params, chain),

        // Token methods
        "synergy_getTokenBalance" => {
            if let (Some(address), Some(token)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
            ) {
                let token_manager = TOKEN_MANAGER.clone();
                json!(token_manager.get_balance(address, token))
            } else {
                json!("Missing address or token symbol")
            }
        }

        "synergy_getTokens" => {
            let token_manager = TOKEN_MANAGER.clone();
            json!(token_manager.get_all_tokens())
        }

        "synergy_resolveSynID" => {
            if let Some(syn_id) = params.get(0).and_then(|v| v.as_str()) {
                match crate::synid::resolve_syn_id(syn_id) {
                    Ok(Some(record)) => json!({
                        "success": true,
                        "synId": record.syn_id,
                        "address": record.address,
                        "displayName": record.display_name,
                        "createdAt": record.created_at,
                        "updatedAt": record.updated_at
                    }),
                    Ok(None) => json!(null),
                    Err(error) => json!({"success": false, "error": error}),
                }
            } else {
                json!({"success": false, "error": "Missing SynID parameter"})
            }
        }

        "synergy_reverseResolveSynID" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                match crate::synid::reverse_resolve_syn_id(address) {
                    Ok(records) => json!({
                        "success": true,
                        "address": address,
                        "records": records
                    }),
                    Err(error) => json!({"success": false, "error": error}),
                }
            } else {
                json!({"success": false, "error": "Missing address parameter"})
            }
        }

        "synergy_getAddressBook" => {
            json!({
                "success": true,
                "records": crate::synid::list_syn_ids()
            })
        }

        "synergy_registerSynID" => {
            let object = params.get(0).and_then(|v| v.as_object());
            let syn_id = object
                .and_then(|obj| obj.get("synId").or_else(|| obj.get("syn_id")))
                .and_then(|v| v.as_str())
                .or_else(|| params.get(0).and_then(|v| v.as_str()));
            let address = object
                .and_then(|obj| obj.get("address").or_else(|| obj.get("walletAddress")))
                .and_then(|v| v.as_str())
                .or_else(|| params.get(1).and_then(|v| v.as_str()));
            let display_name = object
                .and_then(|obj| obj.get("displayName").or_else(|| obj.get("name")))
                .and_then(|v| v.as_str())
                .or_else(|| params.get(2).and_then(|v| v.as_str()));

            if let (Some(syn_id), Some(address)) = (syn_id, address) {
                match crate::synid::register_syn_id(syn_id, address, display_name) {
                    Ok(record) => json!({
                        "success": true,
                        "synId": record.syn_id,
                        "address": record.address,
                        "displayName": record.display_name,
                        "createdAt": record.created_at,
                        "updatedAt": record.updated_at
                    }),
                    Err(error) => json!({"success": false, "error": error}),
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: synId, address"})
            }
        }

        "synergy_createWallet" => {
            if let Ok(mut wallet_manager) = WALLET_MANAGER.lock() {
                let address = wallet_manager.create_wallet();
                json!({"address": address, "message": "Wallet created successfully"})
            } else {
                json!({"error": "Failed to create wallet"})
            }
        }

        "synergy_getWallet" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                if let Ok(wallet_manager) = WALLET_MANAGER.lock() {
                    match wallet_manager.get_wallet(address) {
                        Some(wallet) => json!(wallet),
                        None => json!(null),
                    }
                } else {
                    json!({"error": "Failed to access wallet"})
                }
            } else {
                json!("Missing address")
            }
        }

        "synergy_createWalletFromKeypair" => {
            if let (Some(public_key), Some(private_key)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
            ) {
                if let Ok(mut wallet_manager) = WALLET_MANAGER.lock() {
                    let address = wallet_manager.create_wallet_from_keypair(
                        public_key.to_string(),
                        private_key.to_string(),
                    );
                    json!({"success": true, "address": address, "message": "Wallet created successfully"})
                } else {
                    json!({"success": false, "error": "Failed to access wallet manager"})
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: public_key, private_key"})
            }
        }

        "synergy_getAllWallets" => {
            if let Ok(wallet_manager) = WALLET_MANAGER.lock() {
                json!(wallet_manager.get_all_wallets())
            } else {
                json!({"error": "Failed to access wallet manager"})
            }
        }

        "synergy_signTransaction" => {
            if let (Some(address), Some(tx_data)) =
                (params.get(0).and_then(|v| v.as_str()), params.get(1))
            {
                if let Ok(mut transaction) = serde_json::from_value::<Transaction>(tx_data.clone())
                {
                    if let Ok(wallet_manager) = WALLET_MANAGER.lock() {
                        match wallet_manager.sign_transaction(address, &mut transaction) {
                            Ok(result) => {
                                json!({"success": true, "message": result, "transaction": transaction})
                            }
                            Err(error) => json!({"success": false, "error": error}),
                        }
                    } else {
                        json!({"success": false, "error": "Failed to access wallet manager"})
                    }
                } else {
                    json!({"success": false, "error": "Invalid transaction format"})
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: address, transaction"})
            }
        }

        "synergy_sendTokens" => {
            if let (Some(from), Some(to), Some(token_symbol), Some(amount)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_str()),
                params.get(3).and_then(|v| v.as_u64()),
            ) {
                let memo = params.get(4).and_then(|v| v.as_str());
                // Convert SNRG amount to nWei (per SNTS-04: 1 SNRG = 1,000,000,000 nWei)
                // The RPC accepts amounts in SNRG for user-friendliness, but internally stores as nWei
                use crate::gas::constants::NWEI_PER_SNRG;
                let amount_nwei = amount.saturating_mul(NWEI_PER_SNRG as u64);
                let next_nonce = next_account_nonce_value(from, tx_pool, chain);

                if let Ok(mut wallet_manager) = WALLET_MANAGER.lock() {
                    if let Some(wallet) = wallet_manager.get_wallet_mut(from) {
                        wallet.nonce = wallet.nonce.max(next_nonce);
                    }
                    let token_manager = TOKEN_MANAGER.clone();
                    match wallet_manager.send_tokens(
                        from,
                        to,
                        token_symbol,
                        amount_nwei,
                        memo,
                        &token_manager,
                    ) {
                        Ok(transaction) => {
                            let tx_hash = transaction.hash();
                            if let Ok(mut pool) = tx_pool.lock() {
                                pool.push(transaction.clone());
                            }

                            // Best-effort gossip to peers.
                            if let Some(p2p) = crate::p2p::get_p2p_network() {
                                p2p.broadcast_transaction(&transaction);
                            }

                            json!({"success": true, "tx_hash": tx_hash, "transaction": transaction, "message": "Transaction submitted"})
                        }
                        Err(error) => json!({"success": false, "error": error}),
                    }
                } else {
                    json!({"success": false, "error": "Failed to access wallet manager"})
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: from, to, token_symbol, amount"})
            }
        }

        "synergy_stakeTokens" => {
            if let (Some(staker), Some(validator), Some(token_symbol), Some(amount)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_str()),
                params.get(3).and_then(|v| v.as_u64()),
            ) {
                // Convert SNRG amount to nWei (per SNTS-04: 1 SNRG = 1,000,000,000 nWei)
                use crate::gas::constants::NWEI_PER_SNRG;
                let amount_nwei = amount.saturating_mul(NWEI_PER_SNRG as u64);
                let next_nonce = next_account_nonce_value(staker, tx_pool, chain);

                if let Ok(mut wallet_manager) = WALLET_MANAGER.lock() {
                    if let Some(wallet) = wallet_manager.get_wallet_mut(staker) {
                        wallet.nonce = wallet.nonce.max(next_nonce);
                    }
                    let token_manager = TOKEN_MANAGER.clone();
                    match wallet_manager.stake_tokens(
                        staker,
                        validator,
                        token_symbol,
                        amount_nwei,
                        &token_manager,
                    ) {
                        Ok(transaction) => {
                            let tx_hash = transaction.hash();
                            if let Ok(mut pool) = tx_pool.lock() {
                                pool.push(transaction.clone());
                            }

                            if let Some(p2p) = crate::p2p::get_p2p_network() {
                                p2p.broadcast_transaction(&transaction);
                            }

                            json!({"success": true, "tx_hash": tx_hash, "transaction": transaction, "message": "Staking transaction submitted"})
                        }
                        Err(error) => json!({"success": false, "error": error}),
                    }
                } else {
                    json!({"success": false, "error": "Failed to access wallet manager"})
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: staker, validator, token_symbol, amount"})
            }
        }

        "synergy_stakeTokensDirect" => {
            if let (Some(staker), Some(validator), Some(token_symbol), Some(amount)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_str()),
                params.get(3).and_then(|v| v.as_u64()),
            ) {
                // Convert SNRG amount to nWei (per SNTS-04: 1 SNRG = 1,000,000,000 nWei)
                use crate::gas::constants::NWEI_PER_SNRG;
                let amount_nwei = amount.saturating_mul(NWEI_PER_SNRG as u64);

                let token_manager = TOKEN_MANAGER.clone();
                match token_manager.stake_tokens(staker, validator, token_symbol, amount_nwei) {
                    Ok(result) => json!({"success": true, "message": result}),
                    Err(error) => json!({"success": false, "error": error}),
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: staker, validator, token_symbol, amount"})
            }
        }

        "synergy_unstakeTokens" => {
            if let (Some(staker), Some(validator), Some(token_symbol), Some(amount)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_str()),
                params.get(3).and_then(|v| v.as_u64()),
            ) {
                let token_manager = TOKEN_MANAGER.clone();
                match token_manager.unstake_tokens(staker, validator, token_symbol, amount) {
                    Ok(result) => json!({"success": true, "message": result}),
                    Err(error) => json!({"success": false, "error": error}),
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: staker, validator, token_symbol, amount"})
            }
        }

        "synergy_getStakedBalance" => {
            if let (Some(address), Some(token_symbol)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
            ) {
                let token_manager = TOKEN_MANAGER.clone();
                json!({"balance": token_manager.get_staked_balance(address, token_symbol)})
            } else {
                json!("Missing address or token_symbol parameter")
            }
        }

        "synergy_getStakingInfo" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                let token_manager = TOKEN_MANAGER.clone();
                json!(token_manager.get_staking_info(address))
            } else {
                json!("Missing address parameter")
            }
        }

        "synergy_activateValidator" => {
            if let (Some(validator), Some(name), Some(amount)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_u64()),
            ) {
                use crate::gas::constants::NWEI_PER_SNRG;
                let amount_nwei = amount.saturating_mul(NWEI_PER_SNRG as u64);
                let next_nonce = next_account_nonce_value(validator, tx_pool, chain);

                if let Ok(mut wallet_manager) = WALLET_MANAGER.lock() {
                    if let Some(wallet) = wallet_manager.get_wallet_mut(validator) {
                        wallet.nonce = wallet.nonce.max(next_nonce);
                    }
                    match wallet_manager.activate_validator(validator, name, amount_nwei) {
                        Ok(transaction) => {
                            let tx_hash = transaction.hash();
                            if let Ok(mut pool) = tx_pool.lock() {
                                pool.push(transaction.clone());
                            }

                            if let Some(p2p) = crate::p2p::get_p2p_network() {
                                p2p.broadcast_transaction(&transaction);
                            }

                            json!({
                                "success": true,
                                "tx_hash": tx_hash,
                                "transaction": transaction,
                                "message": "Validator activation transaction submitted"
                            })
                        }
                        Err(error) => json!({"success": false, "error": error}),
                    }
                } else {
                    json!({"success": false, "error": "Failed to access wallet manager"})
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: validator, name, amount"})
            }
        }

        "synergy_registerValidator" => {
            json!({
                "success": false,
                "error": "Legacy direct validator registration is disabled on Synergy Testnet chain 1266. Submit the validator activation transaction after Aegis PQC key binding and a finalized 50,000 SNRG stake lock."
            })
        }

        "synergy_approveValidator" => {
            json!({
                "success": false,
                "error": "Legacy direct validator approval is disabled on Synergy Testnet chain 1266. Activation must be finalized by the epoch-gated staking/onboarding path."
            })
        }

        "synergy_getTopValidators" => {
            let count = params.get(0).and_then(|v| v.as_u64()).unwrap_or(10) as usize;
            let chain = chain.lock().unwrap();
            let mut validators = network_validator_snapshot(&chain, &validator_manager);
            validators.sort_by(|left, right| {
                right
                    .synergy_score
                    .partial_cmp(&left.synergy_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| right.stake_amount.cmp(&left.stake_amount))
                    .then_with(|| left.address.cmp(&right.address))
            });
            json!(validators.into_iter().take(count).collect::<Vec<_>>())
        }

        "synergy_getValidatorSetSnapshot" => validator_set_snapshot_json(chain, validator_manager),

        "synergy_slashValidator" => {
            if let (Some(address), Some(reason)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
            ) {
                match validator_manager.slash_validator(address, reason) {
                    Ok(_) => json!({"success": true, "message": "Validator slashed successfully"}),
                    Err(error) => json!({"success": false, "error": error}),
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: address, reason"})
            }
        }

        "synergy_getBlockRange" => match (
            params.get(0).and_then(|v| v.as_u64()),
            params.get(1).and_then(|v| v.as_u64()),
        ) {
            (Some(start), Some(end)) => block_range_json(chain, start, end),
            _ => json!("Missing start or end parameter"),
        },

        "synergy_getTransactionByHash" => {
            if let Some(tx_hash) = params.get(0).and_then(|v| v.as_str()) {
                // Normalize hash: handle multiple formats
                // 1. Remove "0x" prefix if present (EVM format)
                // 2. Remove Synergy prefixes (syntxn-, synxxn-) to get raw hash
                // 3. Convert to lowercase for comparison
                let normalized = tx_hash.strip_prefix("0x").unwrap_or(tx_hash).to_lowercase();

                // Extract raw hash (without prefix) for comparison
                let raw_hash_search = if normalized.starts_with("syntxn-") {
                    normalized.strip_prefix("syntxn-").unwrap_or(&normalized)
                } else if normalized.starts_with("synxxn-") {
                    normalized.strip_prefix("synxxn-").unwrap_or(&normalized)
                } else {
                    &normalized // Assume it's already a raw hash
                };

                // Helper function to check if a transaction matches
                let matches_tx = |tx: &Transaction| -> bool {
                    let tx_hash_formatted = tx.hash().to_lowercase();
                    let tx_hash_raw = tx.raw_hash().to_lowercase();

                    // Match against:
                    // 1. Full formatted hash (with prefix)
                    // 2. Raw hash (without prefix)
                    // 3. Normalized input (might have prefix or not)
                    tx_hash_formatted == normalized
                        || tx_hash_raw == normalized
                        || tx_hash_raw == raw_hash_search
                        || (tx_hash_formatted.starts_with("syntxn-")
                            && tx_hash_formatted.strip_prefix("syntxn-").unwrap_or("")
                                == raw_hash_search)
                        || (tx_hash_formatted.starts_with("synxxn-")
                            && tx_hash_formatted.strip_prefix("synxxn-").unwrap_or("")
                                == raw_hash_search)
                };

                // First, search in confirmed transactions (blocks)
                let chain = chain.lock().unwrap();
                for block in &chain.chain {
                    for (idx, tx) in block.transactions.iter().enumerate() {
                        if matches_tx(tx) {
                            return tx_to_explorer_json(
                                tx,
                                "confirmed",
                                Some(block.block_index),
                                Some(idx),
                            );
                        }
                    }
                }

                // If not found in blocks, search in transaction pool (pending transactions)
                let pool = tx_pool.lock().unwrap();
                for tx in pool.iter() {
                    if matches_tx(tx) {
                        return tx_to_explorer_json(tx, "pending", None, None);
                    }
                }

                json!(null)
            } else {
                json!("Missing transaction hash parameter")
            }
        }

        "synergy_getTransactionsInBlock" => {
            if let Some(block_number) = params.get(0).and_then(|v| v.as_u64()) {
                let chain = chain.lock().unwrap();
                if let Some(block) = chain.chain.iter().find(|b| b.block_index == block_number) {
                    let txs: Vec<Value> = block
                        .transactions
                        .iter()
                        .enumerate()
                        .map(|(idx, tx)| {
                            tx_to_explorer_json(tx, "confirmed", Some(block.block_index), Some(idx))
                        })
                        .collect();
                    json!(txs)
                } else {
                    json!([])
                }
            } else {
                json!("Missing block number parameter")
            }
        }

        "synergy_getValidatorStats" => {
            let chain = chain.lock().unwrap();
            let mut validators = network_validator_snapshot(&chain, &validator_manager);
            let active_validators = validators
                .iter()
                .filter(|validator| validator.status == ValidatorStatus::Active)
                .cloned()
                .collect::<Vec<_>>();
            let total_validators = validators.len();
            validators.sort_by(|left, right| {
                right
                    .synergy_score
                    .partial_cmp(&left.synergy_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| right.stake_amount.cmp(&left.stake_amount))
                    .then_with(|| left.address.cmp(&right.address))
            });
            let cluster_summary = network_cluster_summary(&validators);
            let top_validators = validators.into_iter().take(20).collect::<Vec<_>>();

            json!({
                "total_validators": total_validators,
                "active_validators": active_validators,
                "cluster_summary": cluster_summary,
                "top_validators": top_validators,
                "epoch_rewards": validator_manager.calculate_epoch_rewards(0)
            })
        }

        "synergy_getTokenStats" => {
            let token_manager = TOKEN_MANAGER.clone();
            let tokens = token_manager.get_all_tokens();

            let mut token_stats = Vec::new();
            for token in tokens {
                let total_staked = token_manager.get_staked_balance("*", &token.symbol);
                let holders = {
                    let balances = token_manager.balances.lock().unwrap();
                    balances
                        .values()
                        .filter(|addr_balances| {
                            addr_balances.get(&token.symbol).copied().unwrap_or(0) > 0
                        })
                        .count()
                };
                token_stats.push(json!({
                    "symbol": token.symbol,
                    "name": token.name,
                    "total_supply": token.total_supply,
                    "total_staked": total_staked,
                    "holders": holders
                }));
            }

            json!(token_stats)
        }

        // TEMPORARILY DISABLED:         // AIVM - Artificial Intelligence Virtual Machine Methods
        // TEMPORARILY DISABLED:         "synergy_deployAIVMContract" => {
        // TEMPORARILY DISABLED:             if let (Some(bytecode), Some(abi), Some(contract_type)) = (
        // TEMPORARILY DISABLED:                 params.get(0).and_then(|v| v.as_str()),
        // TEMPORARILY DISABLED:                 params.get(1).and_then(|v| v.as_str()),
        // TEMPORARILY DISABLED:                 params.get(2).and_then(|v| v.as_str()),
        // TEMPORARILY DISABLED:             ) {
        // TEMPORARILY DISABLED:                 let bytecode_vec = hex::decode(bytecode).unwrap_or_default();
        // TEMPORARILY DISABLED:                 let contract_type_enum = match contract_type {
        // TEMPORARILY DISABLED:                     "ai" => ContractType::AIEnhanced,
        // TEMPORARILY DISABLED:                     "cross_chain" => ContractType::CrossChain,
        // TEMPORARILY DISABLED:                     "oracle" => ContractType::Oracle,
        // TEMPORARILY DISABLED:                     _ => ContractType::Standard,
        // TEMPORARILY DISABLED:                 };
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:                 match aivm_runtime.deploy_contract(
        // TEMPORARILY DISABLED:                     bytecode_vec,
        // TEMPORARILY DISABLED:                     abi.to_string(),
        // TEMPORARILY DISABLED:                     "system".to_string(),
        // TEMPORARILY DISABLED:                     contract_type_enum,
        // TEMPORARILY DISABLED:                 ) {
        // TEMPORARILY DISABLED:                     Ok(address) => json!({"success": true, "contract_address": address, "message": "AIVM contract deployed successfully"}),
        // TEMPORARILY DISABLED:                     Err(error) => json!({"success": false, "error": error}),
        // TEMPORARILY DISABLED:                 }
        // TEMPORARILY DISABLED:             } else {
        // TEMPORARILY DISABLED:                 json!({"success": false, "error": "Missing required parameters: bytecode, abi, contract_type"})
        // TEMPORARILY DISABLED:             }
        // TEMPORARILY DISABLED:         }
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:         "synergy_executeAIVMContract" => {
        // TEMPORARILY DISABLED:             if let (Some(contract_address), Some(input_data)) = (
        // TEMPORARILY DISABLED:                 params.get(0).and_then(|v| v.as_str()),
        // TEMPORARILY DISABLED:                 params.get(1).and_then(|v| v.as_str()),
        // TEMPORARILY DISABLED:             ) {
        // TEMPORARILY DISABLED:                 let input_bytes = hex::decode(input_data).unwrap_or_default();
        // TEMPORARILY DISABLED:                 let context = AIVMExecutionContext {
        // TEMPORARILY DISABLED:                     transaction_hash: "manual_execution".to_string(),
        // TEMPORARILY DISABLED:                     block_height: 0,
        // TEMPORARILY DISABLED:                     timestamp: current_timestamp(),
        // TEMPORARILY DISABLED:                     sender: "manual".to_string(),
        // TEMPORARILY DISABLED:                     contract_address: Some(contract_address.to_string()),
        // TEMPORARILY DISABLED:                     input_data: input_bytes,
        // TEMPORARILY DISABLED:                     gas_limit: 1000000,
        // TEMPORARILY DISABLED:                     gas_price: 1000,
        // TEMPORARILY DISABLED:                 };
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:                 match aivm_runtime.execute_contract(contract_address, context) {
        // TEMPORARILY DISABLED:                     Ok(result) => json!({"success": true, "result": result, "message": "AIVM contract executed successfully"}),
        // TEMPORARILY DISABLED:                     Err(error) => json!({"success": false, "error": error}),
        // TEMPORARILY DISABLED:                 }
        // TEMPORARILY DISABLED:             } else {
        // TEMPORARILY DISABLED:                 json!({"success": false, "error": "Missing required parameters: contract_address, input_data"})
        // TEMPORARILY DISABLED:             }
        // TEMPORARILY DISABLED:         }
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:         "synergy_initiateDistributedAI" => {
        // TEMPORARILY DISABLED:             if let (Some(model_id), Some(input_data)) = (
        // TEMPORARILY DISABLED:                 params.get(0).and_then(|v| v.as_str()),
        // TEMPORARILY DISABLED:                 params.get(1).and_then(|v| v.as_str()),
        // TEMPORARILY DISABLED:             ) {
        // TEMPORARILY DISABLED:                 let input_bytes = hex::decode(input_data).unwrap_or_default();
        // TEMPORARILY DISABLED:                 let cluster_id = params.get(2).and_then(|v| v.as_u64());
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:                 match aivm_runtime.distributed_ai.initiate_distributed_computation(
        // TEMPORARILY DISABLED:                     model_id.to_string(),
        // TEMPORARILY DISABLED:                     input_bytes,
        // TEMPORARILY DISABLED:                     cluster_id,
        // TEMPORARILY DISABLED:                 ) {
        // TEMPORARILY DISABLED:                     Ok(computation_id) => json!({"success": true, "computation_id": computation_id, "message": "Distributed AI computation initiated"}),
        // TEMPORARILY DISABLED:                     Err(error) => json!({"success": false, "error": error}),
        // TEMPORARILY DISABLED:                 }
        // TEMPORARILY DISABLED:             } else {
        // TEMPORARILY DISABLED:                 json!({"success": false, "error": "Missing required parameters: model_id, input_data"})
        // TEMPORARILY DISABLED:             }
        // TEMPORARILY DISABLED:         }
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:         "synergy_getDistributedAIStatus" => {
        // TEMPORARILY DISABLED:             if let Some(computation_id) = params.get(0).and_then(|v| v.as_str()) {
        // TEMPORARILY DISABLED:                 match aivm_runtime.distributed_ai.get_computation_status(computation_id) {
        // TEMPORARILY DISABLED:                     Some(status) => json!({"status": format!("{:?}", status), "computation_id": computation_id}),
        // TEMPORARILY DISABLED:                     None => json!({"error": "Computation not found"}),
        // TEMPORARILY DISABLED:                 }
        // TEMPORARILY DISABLED:             } else {
        // TEMPORARILY DISABLED:                 json!("Missing computation_id parameter")
        // TEMPORARILY DISABLED:             }
        // TEMPORARILY DISABLED:         }
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:         "synergy_getDistributedAIResult" => {
        // TEMPORARILY DISABLED:             if let Some(computation_id) = params.get(0).and_then(|v| v.as_str()) {
        // TEMPORARILY DISABLED:                 match aivm_runtime.distributed_ai.get_computation_result(computation_id) {
        // TEMPORARILY DISABLED:                     Some(result) => json!({"success": true, "result": hex::encode(result), "computation_id": computation_id}),
        // TEMPORARILY DISABLED:                     None => json!({"error": "Result not available or computation not completed"}),
        // TEMPORARILY DISABLED:                 }
        // TEMPORARILY DISABLED:             } else {
        // TEMPORARILY DISABLED:                 json!("Missing computation_id parameter")
        // TEMPORARILY DISABLED:             }
        // TEMPORARILY DISABLED:         }
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:         "synergy_submitAIPartialResult" => {
        // TEMPORARILY DISABLED:             if let (Some(task_id), Some(validator_address), Some(partial_result)) = (
        // TEMPORARILY DISABLED:                 params.get(0).and_then(|v| v.as_str()),
        // TEMPORARILY DISABLED:                 params.get(1).and_then(|v| v.as_str()),
        // TEMPORARILY DISABLED:                 params.get(2).and_then(|v| v.as_str()),
        // TEMPORARILY DISABLED:             ) {
        // TEMPORARILY DISABLED:                 let result_bytes = hex::decode(partial_result).unwrap_or_default();
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:                 match aivm_runtime.distributed_ai.submit_partial_result(
        // TEMPORARILY DISABLED:                     task_id,
        // TEMPORARILY DISABLED:                     validator_address,
        // TEMPORARILY DISABLED:                     result_bytes,
        // TEMPORARILY DISABLED:                 ) {
        // TEMPORARILY DISABLED:                     Ok(_) => json!({"success": true, "message": "Partial result submitted successfully"}),
        // TEMPORARILY DISABLED:                     Err(error) => json!({"success": false, "error": error}),
        // TEMPORARILY DISABLED:                 }
        // TEMPORARILY DISABLED:             } else {
        // TEMPORARILY DISABLED:                 json!({"success": false, "error": "Missing required parameters: task_id, validator_address, partial_result"})
        // TEMPORARILY DISABLED:             }
        // TEMPORARILY DISABLED:         }
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:         "synergy_getValidatorAITasks" => {
        // TEMPORARILY DISABLED:             if let Some(validator_address) = params.get(0).and_then(|v| v.as_str()) {
        // TEMPORARILY DISABLED:                 let tasks = aivm_runtime.distributed_ai.get_pending_tasks_for_validator(validator_address);
        // TEMPORARILY DISABLED:                 json!(tasks)
        // TEMPORARILY DISABLED:             } else {
        // TEMPORARILY DISABLED:                 json!("Missing validator_address parameter")
        // TEMPORARILY DISABLED:             }
        // TEMPORARILY DISABLED:         }
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:         "synergy_getValidatorAIRewards" => {
        // TEMPORARILY DISABLED:             if let Some(validator_address) = params.get(0).and_then(|v| v.as_str()) {
        // TEMPORARILY DISABLED:                 let rewards = aivm_runtime.distributed_ai.get_validator_ai_rewards(validator_address);
        // TEMPORARILY DISABLED:                 json!({"validator_address": validator_address, "total_rewards": rewards})
        // TEMPORARILY DISABLED:             } else {
        // TEMPORARILY DISABLED:                 json!("Missing validator_address parameter")
        // TEMPORARILY DISABLED:             }
        // TEMPORARILY DISABLED:         }
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:         "synergy_getAIDistributedStats" => {
        // TEMPORARILY DISABLED:             json!(aivm_runtime.distributed_ai.get_ai_network_stats())
        // TEMPORARILY DISABLED:         }
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:         "synergy_chatWithAIVM" => {
        // TEMPORARILY DISABLED:             if let Some(message) = params.get(0).and_then(|v| v.as_str()) {
        // TEMPORARILY DISABLED:                 let context = AIVMExecutionContext {
        // TEMPORARILY DISABLED:                     transaction_hash: "chat_interaction".to_string(),
        // TEMPORARILY DISABLED:                     block_height: 0,
        // TEMPORARILY DISABLED:                     timestamp: current_timestamp(),
        // TEMPORARILY DISABLED:                     sender: "user".to_string(),
        // TEMPORARILY DISABLED:                     contract_address: None,
        // TEMPORARILY DISABLED:                     input_data: message.as_bytes().to_vec(),
        // TEMPORARILY DISABLED:                     gas_limit: 10000,
        // TEMPORARILY DISABLED:                     gas_price: 100,
        // TEMPORARILY DISABLED:                 };
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:                 // This would need async support in the RPC handler
        // TEMPORARILY DISABLED:                 json!({"success": true, "message": "Chat functionality requires async support - use direct AIVM runtime calls", "context": context})
        // TEMPORARILY DISABLED:             } else {
        // TEMPORARILY DISABLED:                 json!({"success": false, "error": "Missing message parameter"})
        // TEMPORARILY DISABLED:             }
        // TEMPORARILY DISABLED:         }
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:         "synergy_getAIVMContracts" => {
        // TEMPORARILY DISABLED:             json!(aivm_runtime.get_all_contracts())
        // TEMPORARILY DISABLED:         }
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:         "synergy_getAIVMContract" => {
        // TEMPORARILY DISABLED:             if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
        // TEMPORARILY DISABLED:                 match aivm_runtime.get_contract(address) {
        // TEMPORARILY DISABLED:                     Some(contract) => json!(contract),
        // TEMPORARILY DISABLED:                     None => json!(null),
        // TEMPORARILY DISABLED:                 }
        // TEMPORARILY DISABLED:             } else {
        // TEMPORARILY DISABLED:                 json!("Missing contract address parameter")
        // TEMPORARILY DISABLED:             }
        // TEMPORARILY DISABLED:         }
        // TEMPORARILY DISABLED:
        // TEMPORARILY DISABLED:         "synergy_getAIVMStats" => {
        // TEMPORARILY DISABLED:             let distributed_stats = aivm_runtime.distributed_ai.get_ai_network_stats();
        // TEMPORARILY DISABLED:             json!({
        // TEMPORARILY DISABLED:                 "total_contracts": aivm_runtime.get_all_contracts().len(),
        // TEMPORARILY DISABLED:                 "supported_features": ["ai_enhanced", "cross_chain", "oracle", "standard", "distributed_ai"],
        // TEMPORARILY DISABLED:                 "ai_models": ["distributed_ai_model"],
        // TEMPORARILY DISABLED:                 "supported_chains": ["ethereum", "polygon", "solana"],
        // TEMPORARILY DISABLED:                 "distributed_computations": distributed_stats.get("total_computations").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0),
        // TEMPORARILY DISABLED:                 "completed_computations": distributed_stats.get("completed_computations").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0),
        // TEMPORARILY DISABLED:                 "active_validators": distributed_stats.get("active_validators").unwrap_or(&"0".to_string()).parse::<u64>().unwrap_or(0),
        // TEMPORARILY DISABLED:                 "total_ai_rewards_distributed": distributed_stats.get("total_ai_rewards_distributed").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
        // TEMPORARILY DISABLED:             })
        // TEMPORARILY DISABLED:         }
        // TEMPORARILY DISABLED:
        "synergy_getNetworkStats" => {
            let chain = chain.lock().unwrap();
            let token_manager = TOKEN_MANAGER.clone();
            let validators = network_validator_snapshot(&chain, &validator_manager);
            let active_validator_count = validators
                .iter()
                .filter(|validator| validator.status == ValidatorStatus::Active)
                .count();

            let total_supply = token_manager
                .get_all_tokens()
                .iter()
                .filter_map(|token| token.total_supply.parse::<u128>().ok())
                .sum::<u128>();

            json!({
                "block_height": chain.last().map_or(0, |b| b.block_index),
                "total_transactions": chain.chain.iter().map(|b| b.transactions.len()).sum::<usize>(),
                "total_validators": validators.len(),
                "active_validators": active_validator_count,
                "cluster_summary": network_cluster_summary(&validators),
                "total_supply": total_supply.to_string(),
                "tokens": token_manager.get_all_tokens().len(),
                "network_uptime": "99.9%",
                "current_epoch": validator_manager.calculate_epoch_rewards(0).len(),
                "total_staked": token_manager.get_all_tokens().iter().map(|t| t.symbol.clone()).collect::<Vec<_>>()
                    .iter().map(|symbol| token_manager.get_staked_balance("*", symbol)).sum::<u64>()
            })
        }

        // Enhanced Token Operations
        "synergy_createToken" => {
            if let (Some(symbol), Some(name), Some(decimals), Some(total_supply), Some(creator)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_u64()),
                params.get(3).and_then(|v| v.as_u64()),
                params.get(4).and_then(|v| v.as_str()),
            ) {
                let token_manager = TOKEN_MANAGER.clone();
                match token_manager.create_token(
                    symbol.to_string(),
                    name.to_string(),
                    decimals as u8,
                    total_supply,
                    Some(total_supply * 2), // max_supply = 2x total_supply
                    true,                   // mintable
                    true,                   // burnable
                    creator.to_string(),
                ) {
                    Ok(result) => json!({"success": true, "message": result}),
                    Err(error) => json!({"success": false, "error": error}),
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: symbol, name, decimals, total_supply, creator"})
            }
        }

        "synergy_mintTokens" => {
            if let (Some(to), Some(token_symbol), Some(amount)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_u64()),
            ) {
                let token_manager = TOKEN_MANAGER.clone();
                match token_manager.mint_tokens(to, token_symbol, amount) {
                    Ok(result) => json!({"success": true, "message": result}),
                    Err(error) => json!({"success": false, "error": error}),
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: to, token_symbol, amount"})
            }
        }

        "synergy_burnTokens" => {
            if let (Some(from), Some(token_symbol), Some(amount)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_u64()),
            ) {
                let token_manager = TOKEN_MANAGER.clone();
                match token_manager.burn_tokens(from, token_symbol, amount) {
                    Ok(result) => json!({"success": true, "message": result}),
                    Err(error) => json!({"success": false, "error": error}),
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: from, token_symbol, amount"})
            }
        }

        "synergy_getBurnLedger" => {
            let asset_id = params
                .get(0)
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty());
            let token_manager = TOKEN_MANAGER.clone();
            let records = token_manager.get_burn_records(asset_id);
            let total_burned_raw = if let Some(asset_id) = asset_id {
                token_manager.get_burned_total(asset_id)
            } else {
                records
                    .iter()
                    .fold(0u128, |acc, record| acc.saturating_add(record.amount as u128))
            };
            let total_burned_nwei = (asset_id == Some(crate::token::SNRG_SYMBOL))
                .then(|| u128_rpc_value(total_burned_raw))
                .unwrap_or(Value::Null);
            json!({
                "assetId": asset_id.unwrap_or("*"),
                "burnAddress": crate::address::NETWORK_BURN_ADDRESS,
                "totalBurnedRaw": u128_rpc_value(total_burned_raw),
                "totalBurnedNwei": total_burned_nwei,
                "records": records,
                "chain": chain_identity_json(),
            })
        }

        "synergy_transferTokens" => {
            if let (Some(from), Some(to), Some(token_symbol), Some(amount)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_str()),
                params.get(3).and_then(|v| v.as_u64()),
            ) {
                let token_manager = TOKEN_MANAGER.clone();
                match token_manager.transfer_tokens(from, to, token_symbol, amount, 1000) {
                    Ok(result) => json!({"success": true, "message": result}),
                    Err(error) => json!({"success": false, "error": error}),
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: from, to, token_symbol, amount"})
            }
        }

        "synergy_getAllBalances" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                let token_manager = TOKEN_MANAGER.clone();
                json!(token_manager.get_all_balances(address))
            } else {
                json!("Missing address parameter")
            }
        }

        "synergy_getTransferHistory" => {
            let address = params.get(0).and_then(|v| v.as_str());
            let limit = params.get(1).and_then(|v| v.as_u64()).unwrap_or(50);
            if let Some(address) = address {
                let token_manager = TOKEN_MANAGER.clone();
                json!(token_manager.get_transfer_history(address, limit as usize))
            } else {
                json!("Missing address parameter")
            }
        }

        // Node monitoring methods for control panel
        "synergy_getNodeStatus" => {
            let (last_block, avg_block_time) = {
                let chain = chain.lock().unwrap();
                (
                    chain.last().map_or(0, |b| b.block_index),
                    calculate_average_block_time(&chain),
                )
            };
            let peer_count = crate::p2p::get_p2p_network()
                .map(|p2p| p2p.get_peer_count() as u64)
                .unwrap_or(0);
            let config = crate::config::load_node_config(None).ok();
            let network_name = config.as_ref().map(|cfg| cfg.network.name.clone());
            let uptime_seconds = NODE_START_TIME
                .lock()
                .ok()
                .and_then(|start| start.map(|s| current_timestamp().saturating_sub(s)));
            let uptime_percentage =
                uptime_seconds.map(|secs| ((secs as f64 / 86400.0) * 100.0).min(100.0));
            let sync_status = SYNC_MANAGER
                .lock()
                .ok()
                .map(|manager| {
                    let highest_block =
                        manager.get_network_height().max(best_observed_sync_source_height());
                    if last_block < highest_block {
                        "syncing"
                    } else {
                        match manager.get_state() {
                            SyncState::Synced | SyncState::Idle => "synced",
                            SyncState::Discovering
                            | SyncState::Downloading
                            | SyncState::Validating
                            | SyncState::Applying => "syncing",
                        }
                    }
                })
                .unwrap_or("unknown");
            let highest_block = SYNC_MANAGER
                .lock()
                .ok()
                .map(|manager| manager.get_network_height())
                .unwrap_or(0)
                .max(best_observed_sync_source_height());
            json!({
                "node_type": null,
                "status": "running",
                "uptime": uptime_percentage.map(|p| format!("{:.1}%", p)),
                "uptime_seconds": uptime_seconds,
                "version": env!("CARGO_PKG_VERSION"),
                "network": network_name,
                "sync_status": sync_status,
                "last_block": last_block,
                "highest_block": highest_block,
                "avg_block_time": avg_block_time,
                "average_block_time": avg_block_time,
                "peers_connected": peer_count,
                "peer_count": peer_count,
                "peers": peer_count,
                "timestamp": current_timestamp()
            })
        }

        "synergy_getSyncStatus" => {
            let tip = chain_tip_snapshot_for_status(chain);
            let current_block = tip.height.unwrap_or(0);
            if let Ok(manager) = SYNC_MANAGER.try_lock() {
                let state = manager.get_state();
                let syncing = !matches!(state, SyncState::Synced | SyncState::Idle);
                json!({
                    "syncing": syncing,
                    "current_block": current_block,
                    "highest_block": manager.get_network_height(),
                    "starting_block": manager.get_sync_start_height(),
                    "sync_percentage": manager.get_progress_percentage(),
                    "state": format!("{:?}", state),
                    "chain_state_available": tip.available,
                    "chain_state_error": tip.error,
                })
            } else {
                record_qrpc_fallback("sync_manager_lock_unavailable");
                json!({
                    "syncing": true,
                    "current_block": current_block,
                    "highest_block": best_observed_sync_source_height(),
                    "sync_manager_available": false,
                    "chain_state_available": tip.available,
                    "chain_state_error": tip.error,
                    "fallback": true,
                    "fail_closed": false
                })
            }
        }

        "synergy_getBlockValidationStatus" => {
            let chain = chain.lock().unwrap();
            let validators = network_validator_snapshot(&chain, &validator_manager);
            let active_validators = validators
                .iter()
                .filter(|validator| validator.status == ValidatorStatus::Active)
                .count();
            let active_clusters = validators
                .iter()
                .filter(|validator| validator.status == ValidatorStatus::Active)
                .filter_map(|validator| validator.cluster_id)
                .collect::<HashSet<_>>()
                .len();
            let total_stake = validators
                .iter()
                .map(|validator| validator.stake_amount)
                .sum::<u64>();
            let recent_blocks: Vec<_> = chain
                .chain
                .iter()
                .rev()
                .take(10)
                .map(|block| {
                    json!({
                        "block_number": block.block_index,
                        "validator": block.validator_id,
                        "timestamp": block.timestamp,
                        "transactions": block.transactions.len(),
                        "status": "validated" // All blocks in chain are validated
                    })
                })
                .collect();

            json!({
                "current_block_height": chain.last().map_or(0, |b| b.block_index),
                "recent_blocks": recent_blocks,
                "validation_queue": [], // Add pending validation queue
                "active_validators": active_validators,
                "total_validators": validators.len(),
                "cluster_info": {
                    "active_clusters": active_clusters,
                    "total_stake": total_stake
                }
            })
        }

        "synergy_getValidatorActivity" => {
            let chain = chain.lock().unwrap();
            let local_nickname = configured_local_validator_nickname();
            let active_validators = network_validator_snapshot(&chain, &validator_manager)
                .into_iter()
                .filter(|validator| validator.status == ValidatorStatus::Active)
                .collect::<Vec<_>>();
            let mut validator_activity = Vec::new();

            for validator in active_validators {
                let moniker = validator.name.clone();
                let (display_name, nickname) =
                    validator_display_metadata(&validator, local_nickname.as_ref());
                validator_activity.push(json!({
                    "address": validator.address,
                    "name": display_name,
                    "nickname": nickname,
                    "moniker": moniker,
                    "synergy_score": validator.synergy_score,
                    "blocks_produced": validator.total_blocks_produced,
                    "uptime": format!("{:.1}%", validator.uptime_percentage),
                    "cluster_id": validator.cluster_id,
                    "cluster_address": validator.cluster_address,
                    "stake_amount": validator.stake_amount,
                    "last_active": validator.last_active
                }));
            }

            json!({
                "validators": validator_activity,
                "total_active": validator_activity.len(),
                "average_synergy_score": if validator_activity.is_empty() { 0.0 } else {
                    validator_activity.iter()
                        .map(|v| v["synergy_score"].as_f64().unwrap_or(0.0))
                        .sum::<f64>() / validator_activity.len() as f64
                }
            })
        }

        "synergy_getSynergyScoreBreakdown" => {
            let address = params.get(0).and_then(|v| v.as_str());
            if let Some(address) = address {
                if let Some(validator) = validator_manager.get_validator(address) {
                    let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
                    let calculator =
                        SynergyScoreCalculator::new(Arc::clone(validator_manager), pqc_manager);
                    let components = calculator.calculate_synergy_score(&validator);
                    json!({
                        "address": address,
                        "total_score": validator.synergy_score,
                        "components": components
                    })
                } else {
                    json!({"error": "Validator not found"})
                }
            } else {
                json!({"error": "Missing address parameter"})
            }
        }

        "synergy_getPeerInfo" => {
            peer_info_json()
        }

        // =====================================================================
        // Phase 1: Core Blockchain Functionality (New RPC Methods)
        // =====================================================================

        // 1. synergy_getTransactionReceipt
        // Get a transaction receipt with execution details.
        "synergy_getTransactionReceipt" => transaction_receipt_json(&params, chain),

        // 2. synergy_getTransactionCount
        // Get the transaction count (nonce) for an address.
        "synergy_getTransactionCount" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                let _block_tag = params.get(1).and_then(|v| v.as_str()).unwrap_or("latest");

                // Count confirmed transactions sent by this address
                let chain = chain.lock().unwrap();
                let mut count: u64 = 0;
                for block in &chain.chain {
                    for tx in &block.transactions {
                        if tx.sender.eq_ignore_ascii_case(address) {
                            count += 1;
                        }
                    }
                }

                // If block_tag is "pending", also count pending txs
                if _block_tag == "pending" {
                    let pool = tx_pool.lock().unwrap();
                    for tx in pool.iter() {
                        if tx.sender.eq_ignore_ascii_case(address) {
                            count += 1;
                        }
                    }
                }

                json!(count)
            } else {
                json!({"error": "Missing address parameter"})
            }
        }

        // 3. synergy_getBalance
        // Get the SNRG balance for an address (standardized method).
        "synergy_getBalance" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                let token_manager = TOKEN_MANAGER.clone();
                let balance = token_manager.get_balance(address, "SNRG");
                json!(balance)
            } else {
                json!({"error": "Missing address parameter"})
            }
        }

        "synergy_getAccount" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                let balance = TOKEN_MANAGER.get_balance(address, "SNRG");
                let nonce = get_account_nonce(&params, tx_pool, chain).unwrap_or_else(|error| {
                    json!({
                        "error": error.message,
                        "code": error.code,
                    })
                });
                json!({
                    "address": address,
                    "balance_nwei": balance,
                    "nonce": nonce,
                    "chain": chain_identity_json(),
                })
            } else {
                json!({"error": "Missing address parameter"})
            }
        }

        "synergy_getNonce" => get_account_nonce(&params, tx_pool, chain).unwrap_or_else(|error| {
            json!({
                "error": error.message,
                "code": error.code,
            })
        }),

        // 4. synergy_gasPrice
        // Deterministic, protocol-formula next-block base fee (Canonical
        // Live Gas Pricing; see `docs/fee-market.md` and
        // `canonical_fee_market_state`'s doc comment for the important
        // architecture note about this RPC's legacy chain data source).
        // This is never a floating-point calculation or a historical
        // average/percentile -- both are explicitly forbidden by the fee
        // market design.
        "synergy_gasPrice" => {
            let state = current_fee_market_state_from_chain(chain);
            json!({
                "baseFeePerGas": state.base_fee_per_gas_nwei,
                "effectivePqGasPrice": state.effective_pq_gas_price_nwei,
                "pqGasMultiplier": state.params.pq_gas_multiplier,
                "feeAsset": "SNRG",
                "source": "protocol",
                "feeMarketVersion": state.params.fee_market_version,
                "blockNumber": state.last_block_height,
                "forBlock": state.last_block_height.saturating_add(1),
            })
        }

        // 5. synergy_call
        // Execute a verified public view call against the finalized SynQ
        // execution snapshot.  This never mutates consensus state.
        "synergy_call" => {
            if let Some(call_obj) = params.get(0) {
                synq_static_call_json(call_obj, chain)
            } else {
                json!({"error": "Missing call object parameter"})
            }
        }

        // 6. synergy_estimateGas
        // Estimate the gas required for a transaction.
        "synergy_estimateGas" => {
            if let Some(tx_obj) = params.get(0) {
                match normalize_rpc_transaction(tx_obj, false) {
                    Ok(normalized) => {
                        let gas = estimate_gas_for_transaction(&normalized.transaction);
                        let gas_price = current_gas_price_from_chain(chain);
                        let safe_breakdown = normalized
                            .transaction
                            .network_fee_breakdown_with_gas(gas, gas_price)
                            .ok();
                        let max_breakdown = normalized
                            .transaction
                            .network_fee_breakdown_with_gas(gas, normalized.transaction.gas_price)
                            .ok();
                        let safe_fee = safe_breakdown
                            .as_ref()
                            .map(|breakdown| breakdown.total_network_fee_nwei)
                            .unwrap_or_else(|| (gas as u128).saturating_mul(gas_price as u128));
                        let max_fee = max_breakdown
                            .as_ref()
                            .map(|breakdown| breakdown.total_network_fee_nwei)
                            .unwrap_or_else(|| {
                                (gas as u128)
                                    .saturating_mul(normalized.transaction.gas_price as u128)
                            });
                        json!({
                            "gas": gas,
                            "safeFee": u128_rpc_value(safe_fee),
                            "maxFee": u128_rpc_value(max_fee),
                            "feeBreakdown": safe_breakdown.as_ref().map(fee_breakdown_json).unwrap_or(Value::Null),
                            "maxFeeBreakdown": max_breakdown.as_ref().map(fee_breakdown_json).unwrap_or(Value::Null),
                            "warnings": normalized.warnings
                        })
                    }
                    Err(error) => {
                        json!({"error": error.message, "code": error.code, "data": error.data})
                    }
                }
            } else {
                json!({"error": "Missing transaction object parameter"})
            }
        }

        "synergy_estimateFee" => estimate_fee_json(&params, chain),

        "synergy_getFeeSchedule" => fee_schedule_json(chain),

        // synergy_getFeeMarket
        // Preferred, structured fee-market API for Forge/Atlas/wallets/SDKs
        // (see `docs/fee-market.md`). Combines the current and next-block
        // authoritative base fee, PQ gas pricing, priority-fee status, and
        // the fee-market's protocol parameters into one response so
        // callers never have to reconstruct fee-market state from several
        // separate RPC calls.
        "synergy_getFeeMarket" => fee_market_json(chain),

        "synergy_getFeeCollector" => fee_collector_json(),

        "synergy_getReceipt" => transaction_receipt_json(&params, chain),

        "synergy_getTransactionFees" => transaction_fees_json(&params, chain),

        "synergy_getFeeCollectorBalance" => {
            match crate::token::fee_collector_address() {
                Ok(collector) => json!({
                    "fee_collector": collector,
                    "balance_nwei": TOKEN_MANAGER.get_balance(&collector, "SNRG"),
                    "chain": chain_identity_json(),
                }),
                Err(error) => json!({"error": error, "chain": chain_identity_json()}),
            }
        }

        "synergy_getFeeCollectorDeposits" => match crate::token::fee_collector_address() {
            Ok(collector) => json!({
                "fee_collector": collector,
                "deposits": [],
                "indexing_status": "not_available_in_runtime_rpc",
                "chain": chain_identity_json(),
            }),
            Err(error) => json!({"error": error, "chain": chain_identity_json()}),
        },

        // 7. synergy_getLogs
        // Get event logs matching filters.
        "synergy_getLogs" => {
            if let Some(filter) = params.get(0) {
                let from_block = filter
                    .get("fromBlock")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let to_block = filter.get("toBlock").and_then(|v| v.as_u64());
                let filter_address = filter.get("address").and_then(|v| v.as_str());
                let _topics = filter.get("topics").and_then(|v| v.as_array());
                let block_hash = filter.get("blockHash").and_then(|v| v.as_str());

                let chain = chain.lock().unwrap();
                let to_block =
                    to_block.unwrap_or_else(|| chain.last().map_or(0, |b| b.block_index));

                let mut logs: Vec<Value> = Vec::new();
                let mut log_index: u64 = 0;

                for block in &chain.chain {
                    // Filter by block hash if specified
                    if let Some(bh) = block_hash {
                        if !block.hash.eq_ignore_ascii_case(bh) {
                            continue;
                        }
                    } else if block.block_index < from_block || block.block_index > to_block {
                        continue;
                    }

                    for (tx_idx, tx) in block.transactions.iter().enumerate() {
                        // Filter by address if specified
                        if let Some(addr) = filter_address {
                            if !tx.sender.eq_ignore_ascii_case(addr)
                                && !tx.receiver.eq_ignore_ascii_case(addr)
                            {
                                continue;
                            }
                        }

                        // Generate a log entry for each transaction
                        // (full EVM-style event logs will be available when AIVM is re-enabled)
                        if tx.data.is_some() || filter_address.is_some() {
                            logs.push(json!({
                                "logIndex": log_index,
                                "transactionIndex": tx_idx,
                                "transactionHash": tx.hash(),
                                "blockHash": block.hash.clone(),
                                "blockNumber": block.block_index,
                                "address": tx.receiver.clone(),
                                "data": tx.data.clone().unwrap_or_else(|| "0x".to_string()),
                                "topics": [],
                                "removed": false
                            }));
                            log_index += 1;
                        }
                    }
                }

                json!(logs)
            } else {
                // No filter provided - return empty logs
                json!([])
            }
        }

        // 8. synergy_getCode
        // Get verified AIVM bytecode at a deployed SynQ address.
        "synergy_getCode" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                match finalized_synq_query_state() {
                    Ok(state) => {
                        let Some(deployment) = state.synq_contracts.get(address) else {
                            return json!("0x");
                        };
                        match state.synq_artifacts.get(&deployment.artifact_key) {
                            Some(artifact) => json!(format!("0x{}", hex::encode(&artifact.bytecode))),
                            None => json!({
                                "error": "Deployed SynQ contract artifact is missing from finalized execution state",
                                "code": "SYNQ_CODE_ARTIFACT_MISSING"
                            }),
                        }
                    }
                    Err(error) => json!({"error": error, "code": "SYNQ_CODE_STATE_UNAVAILABLE"}),
                }
            } else {
                json!({"error": "Missing address parameter"})
            }
        }

        // 9. synergy_getStorageAt
        // Get a raw physical AIVM storage value. SynQ storage uses the
        // deployed address as namespace; `position` is its exact 0x-encoded
        // storage-key byte sequence.
        "synergy_getStorageAt" => {
            if let (Some(address), Some(position)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
            ) {
                let block_tag = params.get(2).and_then(|v| v.as_str()).unwrap_or("latest");
                if block_tag != "latest" {
                    json!({
                        "error": "Historical SynQ storage queries are unavailable; only finalized latest state is supported",
                        "code": "SYNQ_STORAGE_HISTORICAL_UNAVAILABLE"
                    })
                } else if !position.starts_with("0x") {
                    json!({"error": "SynQ storage position must be 0x-prefixed hex", "code": "SYNQ_STORAGE_POSITION"})
                } else {
                    match hex::decode(&position[2..]) {
                        Ok(key) => match finalized_synq_query_state() {
                            Ok(state) => {
                                if !state.synq_contracts.contains_key(address) {
                                    json!("0x")
                                } else {
                                    let storage_key = StateKey::new(address.as_bytes().to_vec(), key);
                                    json!(state
                                        .synq_aivm_state
                                        .get(&storage_key)
                                        .map(|value| format!("0x{}", hex::encode(value)))
                                        .unwrap_or_else(|| "0x".to_string()))
                                }
                            }
                            Err(error) => json!({"error": error, "code": "SYNQ_STORAGE_STATE_UNAVAILABLE"}),
                        },
                        Err(_) => json!({"error": "SynQ storage position must contain valid hex", "code": "SYNQ_STORAGE_POSITION"}),
                    }
                }
            } else {
                json!({"error": "Missing required parameters: address, position"})
            }
        }

        // =====================================================================
        // Additional Phase 1 utility methods
        // =====================================================================

        // synergy_getBlockTransactionCount
        "synergy_getBlockTransactionCount" => {
            let chain = chain.lock().unwrap();
            if let Some(block_num) = params.get(0).and_then(|v| v.as_u64()) {
                if let Some(block) = chain.chain.iter().find(|b| b.block_index == block_num) {
                    json!(block.transactions.len())
                } else {
                    json!(null)
                }
            } else if let Some(block_hash) = params.get(0).and_then(|v| v.as_str()) {
                if let Some(block) = chain
                    .chain
                    .iter()
                    .find(|b| b.hash.eq_ignore_ascii_case(block_hash))
                {
                    json!(block.transactions.len())
                } else {
                    json!(null)
                }
            } else {
                json!({"error": "Missing block number or block hash parameter"})
            }
        }

        // synergy_getBlockReceipts
        "synergy_getBlockReceipts" => block_receipts_json(&params, chain),

        // synergy_getPendingTransactions
        "synergy_getPendingTransactions" => {
            let limit = params.get(0).and_then(|v| v.as_u64()).unwrap_or(100) as usize;
            let sort_by = params
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("timestamp");
            let _ = prune_invalid_transactions_from_pool();

            let pool = tx_pool.lock().unwrap();
            let mut txs: Vec<&Transaction> = pool.iter().collect();

            match sort_by {
                "gasPrice" => txs.sort_by(|a, b| b.gas_price.cmp(&a.gas_price)),
                "nonce" => txs.sort_by(|a, b| a.nonce.cmp(&b.nonce)),
                _ => txs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)),
            }

            let result: Vec<Value> = txs
                .iter()
                .take(limit)
                .map(|tx| tx_to_explorer_json(tx, "pending", None, None))
                .collect();
            json!(result)
        }

        // synergy_getTransactionByBlockNumberAndIndex
        "synergy_getTransactionByBlockNumberAndIndex" => {
            if let (Some(block_num), Some(index)) = (
                params.get(0).and_then(|v| v.as_u64()),
                params.get(1).and_then(|v| v.as_u64()),
            ) {
                let chain = chain.lock().unwrap();
                if let Some(block) = chain.chain.iter().find(|b| b.block_index == block_num) {
                    if let Some(tx) = block.transactions.get(index as usize) {
                        tx_to_explorer_json(
                            tx,
                            "confirmed",
                            Some(block.block_index),
                            Some(index as usize),
                        )
                    } else {
                        json!(null)
                    }
                } else {
                    json!(null)
                }
            } else {
                json!({"error": "Missing required parameters: blockNumber, index"})
            }
        }

        // synergy_getTransactionByBlockHashAndIndex
        "synergy_getTransactionByBlockHashAndIndex" => {
            if let (Some(block_hash), Some(index)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_u64()),
            ) {
                let chain = chain.lock().unwrap();
                if let Some(block) = chain
                    .chain
                    .iter()
                    .find(|b| b.hash.eq_ignore_ascii_case(block_hash))
                {
                    if let Some(tx) = block.transactions.get(index as usize) {
                        tx_to_explorer_json(
                            tx,
                            "confirmed",
                            Some(block.block_index),
                            Some(index as usize),
                        )
                    } else {
                        json!(null)
                    }
                } else {
                    json!(null)
                }
            } else {
                json!({"error": "Missing required parameters: blockHash, index"})
            }
        }

        // synergy_maxFeePerGas
        // No priority-fee/tip market exists yet (see `synergy_maxPriorityFeePerGas`
        // below), so there is no protocol-defined "cap above base fee" to
        // report. This returns the authoritative next-block base fee itself
        // -- the amount that will actually be charged -- rather than
        // fabricating an arbitrary safety multiplier the protocol never
        // agreed to. `note` documents this explicitly for callers so a
        // client-side safety margin (if any) is understood to be a client
        // choice, not a protocol price.
        "synergy_maxFeePerGas" => {
            let state = current_fee_market_state_from_chain(chain);
            json!({
                "maxFeePerGas": state.base_fee_per_gas_nwei,
                "baseFeePerGas": state.base_fee_per_gas_nwei,
                "priorityFeeEnabled": false,
                "feeAsset": "SNRG",
                "source": "protocol",
                "note": "No priority-fee/tip market exists yet; maxFeePerGas equals the authoritative next-block base fee. Any additional safety margin is a client-side choice, not a protocol value.",
                "feeMarketVersion": state.params.fee_market_version,
            })
        }

        // synergy_maxPriorityFeePerGas
        // There is currently no priority-fee/tip market on Synergy: every
        // transaction pays exactly `base_fee_per_gas` per unit of gas, and
        // `priority_fee_per_gas` is always 0 (see `docs/fee-market.md`).
        // This must never fabricate a recommended tip.
        "synergy_maxPriorityFeePerGas" => {
            json!({
                "maxPriorityFeePerGas": 0,
                "priorityFeeEnabled": false,
                "feeAsset": "SNRG",
                "note": "No priority-fee/tip market exists on Synergy yet; this is always 0, not a client recommendation.",
            })
        }

        // synergy_getFeeHistory
        "synergy_getFeeHistory" => {
            let block_count = params.get(0).and_then(|v| v.as_u64()).unwrap_or(10) as usize;
            let _newest_block = params.get(1).and_then(|v| v.as_str()).unwrap_or("latest");
            let reward_percentiles = params.get(2).and_then(|v| v.as_array());

            let chain = chain.lock().unwrap();
            let recent_blocks: Vec<_> = chain.chain.iter().rev().take(block_count).collect();

            let mut base_fees: Vec<u64> = Vec::new();
            let mut gas_used_ratios: Vec<f64> = Vec::new();
            let mut rewards: Vec<Vec<u64>> = Vec::new();
            let block_gas_limit = crate::gas::constants::BLOCK_GAS_LIMIT;

            for block in recent_blocks.iter().rev() {
                let block_gas: u64 = block.transactions.iter().map(|tx| tx.get_fee()).sum();
                let ratio = block_gas as f64 / block_gas_limit as f64;

                base_fees.push(crate::gas::constants::DEFAULT_GAS_PRICE);
                gas_used_ratios.push(ratio);

                if let Some(percentiles) = reward_percentiles {
                    let mut gas_prices: Vec<u64> =
                        block.transactions.iter().map(|tx| tx.gas_price).collect();
                    gas_prices.sort();
                    let block_rewards: Vec<u64> = percentiles
                        .iter()
                        .map(|p| {
                            let pct = p.as_f64().unwrap_or(50.0) / 100.0;
                            if gas_prices.is_empty() {
                                0
                            } else {
                                let idx = ((gas_prices.len() as f64 * pct) as usize)
                                    .min(gas_prices.len() - 1);
                                gas_prices[idx]
                            }
                        })
                        .collect();
                    rewards.push(block_rewards);
                }
            }

            json!({
                "baseFeePerGas": base_fees,
                "gasUsedRatio": gas_used_ratios,
                "reward": rewards,
                "oldestBlock": recent_blocks.last().map(|b| b.block_index).unwrap_or(0)
            })
        }

        // =====================================================================
        // Phase 2: Enhanced Validator & Staking (New RPC Methods)
        // =====================================================================

        // synergy_getChainId
        "synergy_getChainId" => {
            json!(format!("0x{:x}", current_chain_id()))
        }

        // synergy_getValidatorByCluster
        "synergy_getValidatorByCluster" => {
            if let Some(cluster_id) = params.get(0).and_then(|v| v.as_u64()) {
                let all_validators = validator_manager.get_all_validators();
                let cluster_validators: Vec<_> = all_validators
                    .into_iter()
                    .filter(|v| v.cluster_id == Some(cluster_id))
                    .collect();
                json!(cluster_validators)
            } else {
                json!({"error": "Missing cluster ID parameter"})
            }
        }

        // synergy_getValidatorRewards
        "synergy_getValidatorRewards" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                let _from_epoch = params.get(1).and_then(|v| v.as_u64()).unwrap_or(0);
                let _to_epoch = params.get(2).and_then(|v| v.as_u64());

                // Look up the validator to get block production stats
                match validator_manager.get_validator(address) {
                    Some(validator) => {
                        // Calculate rewards from blocks produced
                        let chain = chain.lock().unwrap();
                        let mut rewards: Vec<Value> = Vec::new();
                        let blocks_by_validator: Vec<_> = chain
                            .chain
                            .iter()
                            .filter(|b| b.validator_id.eq_ignore_ascii_case(address))
                            .collect();

                        for block in &blocks_by_validator {
                            let block_reward = 10_000_000_000u64; // 10 SNRG per block in nWei
                            let tx_fees: u64 = block
                                .transactions
                                .iter()
                                .map(|tx| tx.get_total_network_fee_u64().unwrap_or(u64::MAX))
                                .fold(0u64, |acc, fee| acc.saturating_add(fee));
                            rewards.push(json!({
                                "blockNumber": block.block_index,
                                "amount": block_reward + tx_fees,
                                "type": "block",
                                "timestamp": block.timestamp
                            }));
                        }

                        json!({
                            "address": address,
                            "totalBlocksProduced": validator.total_blocks_produced,
                            "rewards": rewards,
                            "totalRewards": rewards.iter()
                                .filter_map(|r| r.get("amount").and_then(|a| a.as_u64()))
                                .sum::<u64>()
                        })
                    }
                    None => json!({"error": "Validator not found"}),
                }
            } else {
                json!({"error": "Missing address parameter"})
            }
        }

        // synergy_getValidatorRewardStatus
        "synergy_getValidatorRewardStatus" => {
            if let Some(validator_id) = params.get(0).and_then(|v| v.as_str()) {
                let current_epoch = validator_manager
                    .registry
                    .lock()
                    .map(|registry| registry.current_epoch)
                    .unwrap_or(0);
                match crate::rewards::REWARD_LEDGER.lock() {
                    Ok(ledger) => {
                        json!(ledger.get_validator_reward_status(validator_id, current_epoch))
                    }
                    Err(_) => json!({"error": "Failed to access reward ledger"}),
                }
            } else {
                json!({"error": "Missing validator ID parameter"})
            }
        }

        // synergy_getValidatorPendingRewards
        "synergy_getValidatorPendingRewards" => {
            if let Some(validator_id) = params.get(0).and_then(|v| v.as_str()) {
                match crate::rewards::REWARD_LEDGER.lock() {
                    Ok(ledger) => json!(ledger.get_validator_pending_rewards(validator_id)),
                    Err(_) => json!({"error": "Failed to access reward ledger"}),
                }
            } else {
                json!({"error": "Missing validator ID parameter"})
            }
        }

        // synergy_getEpochFeeDistribution
        "synergy_getEpochFeeDistribution" => {
            if let Some(epoch_id) = params.get(0).and_then(|v| v.as_u64()) {
                match crate::rewards::REWARD_LEDGER.lock() {
                    Ok(ledger) => json!({
                        "epoch": epoch_id,
                        "feeAccumulator": ledger.fee_accumulators.get(&epoch_id),
                        "feeDistribution": ledger.fee_distributions.get(&epoch_id),
                        "feeCollectorDistribution": ledger.fee_collector_distributions.get(&epoch_id)
                    }),
                    Err(_) => json!({"error": "Failed to access reward ledger"}),
                }
            } else {
                json!({"error": "Missing epoch ID parameter"})
            }
        }

        // synergy_getClusterRewardEscrow
        "synergy_getClusterRewardEscrow" => {
            if let (Some(cluster_address), Some(epoch_id)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_u64()),
            ) {
                match crate::rewards::REWARD_LEDGER.lock() {
                    Ok(ledger) => json!({
                        "epoch": epoch_id,
                        "clusterAddress": cluster_address,
                        "escrow": ledger
                            .cluster_reward_escrows
                            .get(&(epoch_id, cluster_address.to_string())),
                        "settlement": ledger
                            .cluster_settlements
                            .get(&(epoch_id, cluster_address.to_string())),
                    }),
                    Err(_) => json!({"error": "Failed to access reward ledger"}),
                }
            } else {
                json!({"error": "Missing cluster address or epoch ID parameter"})
            }
        }

        // synergy_getTreasuryRecovery
        "synergy_getTreasuryRecovery" => match crate::rewards::REWARD_LEDGER.lock() {
            Ok(ledger) => {
                if let Some(epoch_id) = params.get(0).and_then(|v| v.as_u64()) {
                    json!({
                        "epoch": epoch_id,
                        "treasuryRecovery": ledger.treasury_recovery_ledger.get(&epoch_id)
                    })
                } else {
                    json!({
                        "treasuryRecoveryByEpoch": ledger.treasury_recovery_ledger
                    })
                }
            }
            Err(_) => json!({"error": "Failed to access reward ledger"}),
        },

        // synergy_getEpochRewardAudit
        "synergy_getEpochRewardAudit" => {
            let epoch = params.get(0).and_then(|value| value.as_u64());
            match crate::rewards::REWARD_LEDGER.lock() {
                Ok(ledger) => {
                    let audit_events = ledger.get_epoch_audit_events(epoch);
                    json!({
                        "epoch": epoch,
                        "eventCount": audit_events.len(),
                        "events": audit_events,
                    })
                }
                Err(_) => json!({"error": "Failed to access reward ledger"}),
            }
        }

        // synergy_checkRewardInvariants
        "synergy_checkRewardInvariants" => {
            let epoch = params.get(0).and_then(|value| value.as_u64());
            match crate::rewards::REWARD_LEDGER.lock() {
                Ok(ledger) => json!(ledger.check_invariants(epoch)),
                Err(_) => json!({"error": "Failed to access reward ledger"}),
            }
        },

        // synergy_getValidatorPerformance
        "synergy_getValidatorPerformance" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                match validator_manager.get_validator(address) {
                    Some(validator) => {
                        let chain = chain.lock().unwrap();
                        let total_blocks = chain.chain.len() as u64;
                        let blocks_produced: u64 = chain
                            .chain
                            .iter()
                            .filter(|b| b.validator_id.eq_ignore_ascii_case(address))
                            .count() as u64;

                        let total_validators =
                            validator_manager.get_validator_count().max(1) as f64;
                        let expected_blocks = total_blocks as f64 / total_validators;
                        let proposal_rate = if expected_blocks > 0.0 {
                            (blocks_produced as f64 / expected_blocks).min(1.0)
                        } else {
                            0.0
                        };

                        json!({
                            "address": address,
                            "attestationSuccessRate": validator.uptime_percentage,
                            "blockProposalSuccessRate": proposal_rate,
                            "averageInclusionDelay": validator.average_block_time,
                            "missedAttestations": validator.missed_blocks,
                            "orphanedBlocks": 0,
                            "effectiveBalance": validator.stake_amount,
                            "totalBlocksProduced": blocks_produced,
                            "synergyScore": validator.synergy_score,
                            "reputationScore": validator.reputation_score,
                            "collaborationScore": validator.collaboration_score,
                            "uptime": validator.uptime_percentage
                        })
                    }
                    None => json!({"error": "Validator not found"}),
                }
            } else {
                json!({"error": "Missing address parameter"})
            }
        }

        // synergy_getValidatorQueue
        "synergy_getValidatorQueue" => {
            if let Ok(registry) = validator_manager.registry.lock() {
                let activation_queue: Vec<Value> = registry
                    .pending_registrations
                    .values()
                    .map(|r| {
                        json!({
                            "address": r.address,
                            "name": r.name,
                            "stakeAmount": r.stake_amount,
                            "submittedAt": r.submitted_at
                        })
                    })
                    .collect();

                let exit_queue: Vec<Value> = registry
                    .jailed_validators
                    .iter()
                    .map(|addr| json!({"address": addr}))
                    .collect();

                json!({
                    "activationQueue": activation_queue,
                    "activationQueueLength": activation_queue.len(),
                    "exitQueue": exit_queue,
                    "exitQueueLength": exit_queue.len(),
                    "estimatedActivationTime": if activation_queue.is_empty() { 0 } else { current_timestamp() + 3600 },
                    "estimatedExitTime": if exit_queue.is_empty() { 0 } else { current_timestamp() + 7200 }
                })
            } else {
                json!({"error": "Failed to access validator registry"})
            }
        }

        // synergy_requestValidatorExit
        "synergy_requestValidatorExit" => {
            if let (Some(address), Some(_signature)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
            ) {
                match validator_manager.get_validator(address) {
                    Some(_validator) => {
                        if let Ok(registry) = validator_manager.registry.lock() {
                            let current_epoch = registry.current_epoch;
                            let exit_epoch = current_epoch + 2; // 2 epoch delay
                            let epoch_length = registry.epoch_length;
                            let withdrawal_time = current_timestamp() + (2 * epoch_length);

                            json!({
                                "success": true,
                                "message": "Validator exit requested",
                                "validatorAddress": address,
                                "currentEpoch": current_epoch,
                                "exitEpoch": exit_epoch,
                                "withdrawalAvailableAt": withdrawal_time
                            })
                        } else {
                            json!({"success": false, "error": "Failed to access registry"})
                        }
                    }
                    None => json!({"success": false, "error": "Validator not found"}),
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: address, signature"})
            }
        }

        // synergy_getValidatorSlashingHistory
        "synergy_getValidatorSlashingHistory" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                match validator_manager.get_validator(address) {
                    Some(validator) => {
                        // Build slashing history from validator state
                        let mut history: Vec<Value> = Vec::new();
                        if validator.slashing_penalty > 0.0 {
                            history.push(json!({
                                "reason": "Slashing penalty recorded",
                                "penalty": validator.slashing_penalty,
                                "doubleSignCount": validator.double_signs,
                                "missedBlocks": validator.missed_blocks,
                                "balanceAfter": validator.stake_amount
                            }));
                        }
                        json!({
                            "address": address,
                            "slashingEvents": history,
                            "totalPenalties": validator.slashing_penalty,
                            "doubleSignCount": validator.double_signs
                        })
                    }
                    None => json!({"error": "Validator not found"}),
                }
            } else {
                json!({"error": "Missing address parameter"})
            }
        }

        // synergy_getClusterStatus
        "synergy_getClusterStatus" => {
            if let Some(cluster_address) = params.get(0).and_then(|v| v.as_str()) {
                let ledger = crate::cluster::CLUSTER_LEDGER.lock();
                let registry = validator_manager.registry.lock();
                match (ledger, registry) {
                    (Ok(ledger), Ok(registry)) => canonical_cluster_status(
                        &registry,
                        cluster_address,
                        ledger.get_cluster_status(cluster_address).as_ref(),
                    ),
                    _ => json!({"error": "Failed to access cluster or validator ledger"}),
                }
            } else {
                json!({"error": "Missing cluster address parameter"})
            }
        }

        // synergy_getValidatorClusterHistory
        "synergy_getValidatorClusterHistory" => {
            if let Some(validator_id) = params.get(0).and_then(|v| v.as_str()) {
                let cluster_ledger = crate::cluster::CLUSTER_LEDGER.lock();
                let registry = validator_manager.registry.lock();
                let reward_ledger = crate::rewards::REWARD_LEDGER.lock();
                match (cluster_ledger, registry, reward_ledger) {
                    (Ok(cluster_ledger), Ok(registry), Ok(reward_ledger)) => {
                        let mut prior_assignments = Vec::new();
                        let mut epochs_by_cluster: BTreeMap<String, Vec<u64>> = BTreeMap::new();
                        for snapshots in cluster_ledger.assignment_snapshots.values() {
                            for snapshot in snapshots {
                                if snapshot.validator_ids.iter().any(|id| id == validator_id) {
                                    prior_assignments.push(snapshot.clone());
                                    epochs_by_cluster
                                        .entry(snapshot.cluster_address.clone())
                                        .or_default()
                                        .push(snapshot.epoch_id);
                                }
                            }
                        }
                        prior_assignments.sort_by_key(|snapshot| snapshot.epoch_id);
                        let participation_segments = cluster_ledger
                            .participation_segments
                            .iter()
                            .filter(|segment| segment.validator_id == validator_id)
                            .cloned()
                            .collect::<Vec<_>>();
                        let current_cluster_address = registry
                            .get_validator_cluster(validator_id)
                            .map(|cluster| cluster.address.clone());
                        let mut pending_rewards_by_original_cluster: BTreeMap<String, u128> =
                            BTreeMap::new();
                        for reward in reward_ledger.get_validator_pending_rewards(validator_id) {
                            *pending_rewards_by_original_cluster
                                .entry(reward.original_cluster_address)
                                .or_default() += reward.pending_reward_nwei;
                        }
                        let reliability = reward_ledger
                            .reliability_states
                            .get(validator_id)
                            .cloned()
                            .unwrap_or_else(|| {
                                crate::rewards::ValidatorReliabilityState::new(validator_id)
                            });
                        json!(crate::cluster::ValidatorClusterHistoryResponse {
                            validator_id: validator_id.to_string(),
                            current_cluster_address,
                            prior_cluster_assignments: prior_assignments,
                            epochs_by_cluster,
                            pending_rewards_by_original_cluster,
                            participation_segments,
                            reliability_streak: reliability.current_streak_epochs,
                            current_bonus_tier: reliability.current_bonus_tier_bps,
                            next_bonus_tier: crate::rewards::bonus_tier_bps(
                                reliability.current_streak_epochs.saturating_add(1),
                                &crate::rewards::RewardConfig::default(),
                            ),
                        })
                    }
                    _ => json!({"error": "Failed to access cluster or reward ledger"}),
                }
            } else {
                json!({"error": "Missing validator ID parameter"})
            }
        }

        // synergy_getEpochClusterAssignments
        "synergy_getEpochClusterAssignments" => {
            if let Some(epoch_id) = params.get(0).and_then(|v| v.as_u64()) {
                let (current_height, current_randomness_source) = match chain.lock() {
                    Ok(chain) => {
                        let current_height =
                            chain.last().map(|block| block.block_index).unwrap_or(0);
                        let supplied_epoch = epoch_for_block_height(
                            current_height,
                            TESTNET_EPOCH_LENGTH_BLOCKS,
                        );
                        let effective_epoch = match effective_cluster_epoch_for_height(
                            supplied_epoch,
                            current_height,
                        ) {
                            Ok(epoch) => epoch,
                            Err(error) => {
                                return json!({"error": error, "fail_closed": true})
                            }
                        };
                        let randomness_source = if epoch_id == effective_epoch {
                            match ProofOfSynergy::cluster_epoch_randomness_evidence(
                                &chain,
                                effective_epoch,
                                TESTNET_EPOCH_LENGTH_BLOCKS,
                                validator_manager,
                            ) {
                                Ok(evidence) => Some(hex::encode(evidence.randomness)),
                                Err(error) => {
                                    return json!({"error": error, "fail_closed": true})
                                }
                            }
                        } else {
                            None
                        };
                        (current_height, randomness_source)
                    }
                    Err(_) => return json!({"error": "Failed to access blockchain"}),
                };
                let ledger = crate::cluster::CLUSTER_LEDGER.lock();
                let registry = validator_manager.registry.lock();
                match (ledger, registry) {
                    (Ok(ledger), Ok(registry)) => {
                        match epoch_cluster_assignments_for_rpc(
                            &registry,
                            &ledger,
                            epoch_id,
                            current_height,
                            current_randomness_source.as_deref(),
                        ) {
                            Ok(assignments) => json!(assignments),
                            Err(error) => json!({"error": error, "fail_closed": true}),
                        }
                    }
                    _ => json!({"error": "Failed to access cluster or validator ledger"}),
                }
            } else {
                json!({"error": "Missing epoch ID parameter"})
            }
        }

        // synergy_getClusterInfo
        "synergy_getClusterInfo" => {
            if let Some(cluster_id) = params.get(0).and_then(|v| v.as_u64()) {
                if let Ok(registry) = validator_manager.registry.lock() {
                    if let Some(cluster) = registry.clusters.get(&cluster_id) {
                        let validator_details: Vec<Value> = cluster
                            .validators
                            .iter()
                            .map(|addr| {
                                if let Some(v) = registry.validators.get(addr) {
                                    json!({
                                        "address": v.address,
                                        "name": v.name,
                                        "stakeAmount": v.stake_amount,
                                        "synergyScore": v.synergy_score,
                                        "status": format!("{:?}", v.status)
                                    })
                                } else {
                                    json!({"address": addr})
                                }
                            })
                            .collect();

                        json!({
                            "clusterId": cluster.id,
                            "address": cluster.address,
                            "validators": validator_details,
                            "validatorCount": cluster.validators.len(),
                            "totalStake": cluster.total_stake,
                            "averageSynergyScore": cluster.average_synergy_score,
                            "createdAt": cluster.created_at,
                            "lastRotation": cluster.last_rotation,
                            "group": cluster.group
                        })
                    } else {
                        json!(null)
                    }
                } else {
                    json!({"error": "Failed to access validator registry"})
                }
            } else {
                json!({"error": "Missing cluster ID parameter"})
            }
        }

        // synergy_getClusterRewards
        "synergy_getClusterRewards" => {
            if let Some(cluster_id) = params.get(0).and_then(|v| v.as_u64()) {
                let epoch = params.get(1).and_then(|v| v.as_u64()).unwrap_or(0);
                if let Ok(registry) = validator_manager.registry.lock() {
                    if let Some(cluster) = registry.clusters.get(&cluster_id) {
                        let epoch_rewards = registry.calculate_epoch_rewards(epoch);
                        let cluster_rewards: Vec<Value> = cluster
                            .validators
                            .iter()
                            .map(|addr| {
                                let reward = epoch_rewards.get(addr).copied().unwrap_or(0);
                                json!({
                                    "validatorAddress": addr,
                                    "rewardAmount": reward
                                })
                            })
                            .collect();

                        let total: u64 = cluster_rewards
                            .iter()
                            .filter_map(|r| r.get("rewardAmount").and_then(|a| a.as_u64()))
                            .sum();

                        json!({
                            "clusterId": cluster_id,
                            "epoch": epoch,
                            "totalRewards": total,
                            "distributions": cluster_rewards
                        })
                    } else {
                        json!(null)
                    }
                } else {
                    json!({"error": "Failed to access validator registry"})
                }
            } else {
                json!({"error": "Missing cluster ID parameter"})
            }
        }

        // synergy_proposeClusterChange
        "synergy_proposeClusterChange" => {
            if let (Some(cluster_id), Some(_proposal), Some(proposer)) = (
                params.get(0).and_then(|v| v.as_u64()),
                params.get(1),
                params.get(2).and_then(|v| v.as_str()),
            ) {
                // Verify proposer is a validator
                match validator_manager.get_validator(proposer) {
                    Some(_) => {
                        let proposal_id = format!("prop_{}_{}", cluster_id, current_timestamp());
                        json!({
                            "success": true,
                            "proposalId": proposal_id,
                            "clusterId": cluster_id,
                            "proposer": proposer,
                            "votingEndsAt": current_timestamp() + 86400 // 24 hours
                        })
                    }
                    None => {
                        json!({"success": false, "error": "Proposer must be a registered validator"})
                    }
                }
            } else {
                json!({"success": false, "error": "Missing required parameters: clusterId, proposal, proposer"})
            }
        }

        // synergy_getStakingRewards
        "synergy_getStakingRewards" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                let specific_validator = params.get(1).and_then(|v| v.as_str());
                let token_manager = TOKEN_MANAGER.clone();
                let staking_info = token_manager.get_staking_info(address);

                let rewards: Vec<Value> = staking_info
                    .iter()
                    .filter(|info| {
                        specific_validator
                            .map_or(true, |v| info.validator_address.eq_ignore_ascii_case(v))
                    })
                    .map(|info| {
                        json!({
                            "validator": info.validator_address,
                            "stakedAmount": info.amount,
                            "rewardsEarned": info.rewards_earned,
                            "stakingStart": info.stake_start,
                            "isActive": info.is_active
                        })
                    })
                    .collect();

                let total_rewards: u64 = rewards
                    .iter()
                    .filter_map(|r| r.get("rewardsEarned").and_then(|a| a.as_u64()))
                    .sum();

                json!({
                    "address": address,
                    "rewards": rewards,
                    "totalRewardsEarned": total_rewards
                })
            } else {
                json!({"error": "Missing address parameter"})
            }
        }

        // synergy_getStakingAPY
        "synergy_getStakingAPY" => {
            let specific_validator = params.get(0).and_then(|v| v.as_str());
            let token_manager = TOKEN_MANAGER.clone();
            let total_staked = token_manager.get_staked_balance("*", "SNRG");
            let total_supply = token_manager
                .get_all_tokens()
                .iter()
                .find(|t| t.symbol == "SNRG")
                .and_then(|t| t.total_supply.parse::<u128>().ok())
                .unwrap_or(0);

            let staking_rate = if total_supply > 0 {
                total_staked as f64 / total_supply as f64
            } else {
                0.0
            };

            // Base APY: 5% annual, adjusted by staking participation
            // Lower participation = higher APY to incentivize staking
            let base_apy = 0.05;
            let current_apy = if staking_rate > 0.0 && staking_rate < 1.0 {
                base_apy / staking_rate.max(0.01)
            } else {
                base_apy
            };
            let capped_apy = current_apy.min(0.20); // Cap at 20%

            let mut result = json!({
                "currentAPY": capped_apy,
                "averageAPY": capped_apy, // Simplified: same as current in testnet
                "networkStakingRate": staking_rate,
                "totalStaked": total_staked,
                "totalSupply": total_supply.to_string(),
                "baseAPY": base_apy
            });

            if let Some(validator_addr) = specific_validator {
                if let Some(validator) = validator_manager.get_validator(validator_addr) {
                    // Higher synergy score = slightly better APY
                    let validator_apy = capped_apy * (1.0 + validator.synergy_score * 0.1);
                    result
                        .as_object_mut()
                        .unwrap()
                        .insert("validatorAPY".to_string(), json!(validator_apy.min(0.25)));
                    result.as_object_mut().unwrap().insert(
                        "validatorSynergyScore".to_string(),
                        json!(validator.synergy_score),
                    );
                }
            }

            result
        }

        // synergy_getDelegatedStakes
        "synergy_getDelegatedStakes" => {
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                let token_manager = TOKEN_MANAGER.clone();
                let staking_info = token_manager.get_staking_info(address);

                let delegations: Vec<Value> = staking_info
                    .iter()
                    .filter(|info| info.is_active)
                    .map(|info| {
                        json!({
                            "validator": info.validator_address,
                            "amount": info.amount,
                            "rewardsEarned": info.rewards_earned,
                            "delegatedAt": info.stake_start
                        })
                    })
                    .collect();

                json!({
                    "address": address,
                    "delegations": delegations,
                    "totalDelegated": delegations.iter()
                        .filter_map(|d| d.get("amount").and_then(|a| a.as_u64()))
                        .sum::<u64>()
                })
            } else {
                json!({"error": "Missing address parameter"})
            }
        }

        // synergy_getDelegators
        "synergy_getDelegators" => {
            if let Some(validator_addr) = params.get(0).and_then(|v| v.as_str()) {
                let _limit = params.get(1).and_then(|v| v.as_u64()).unwrap_or(100) as usize;
                let token_manager = TOKEN_MANAGER.clone();

                let addresses: Vec<String> = {
                    let balances = token_manager.balances.lock().unwrap();
                    balances.keys().cloned().collect()
                };
                let mut delegators: Vec<Value> = Vec::new();

                for address in &addresses {
                    let staking_info = token_manager.get_staking_info(address);
                    for info in &staking_info {
                        if info.validator_address.eq_ignore_ascii_case(validator_addr)
                            && info.is_active
                        {
                            delegators.push(json!({
                                "address": address,
                                "amount": info.amount,
                                "rewardsEarned": info.rewards_earned,
                                "delegatedAt": info.stake_start
                            }));
                        }
                    }
                }

                delegators.sort_by(|a, b| {
                    let a_amt = a.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                    let b_amt = b.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                    b_amt.cmp(&a_amt)
                });
                delegators.truncate(_limit);

                json!({
                    "validator": validator_addr,
                    "delegators": delegators,
                    "totalDelegators": delegators.len()
                })
            } else {
                json!({"error": "Missing validator address parameter"})
            }
        }

        // synergy_claimRewards
        "synergy_claimRewards" => {
            if let Some(staker) = params.get(0).and_then(|v| v.as_str()) {
                let specific_validator = params.get(1).and_then(|v| v.as_str());
                let token_manager = TOKEN_MANAGER.clone();
                let staking_info = token_manager.get_staking_info(staker);

                let mut total_claimed: u64 = 0;
                for info in &staking_info {
                    if specific_validator
                        .map_or(true, |v| info.validator_address.eq_ignore_ascii_case(v))
                    {
                        total_claimed += info.rewards_earned;
                    }
                }

                if total_claimed > 0 {
                    // Credit rewards to staker's balance
                    match token_manager.mint_tokens(staker, "SNRG", total_claimed) {
                        Ok(_) => {
                            json!({
                                "success": true,
                                "claimedAmount": total_claimed,
                                "stakerAddress": staker,
                                "message": "Rewards claimed successfully"
                            })
                        }
                        Err(e) => json!({"success": false, "error": e}),
                    }
                } else {
                    json!({
                        "success": false,
                        "error": "No rewards available to claim",
                        "stakerAddress": staker
                    })
                }
            } else {
                json!({"success": false, "error": "Missing staker address parameter"})
            }
        }

        // synergy_getRewardsProjection
        "synergy_getRewardsProjection" => {
            if let (Some(address), Some(amount), Some(duration_days)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_u64()),
                params.get(2).and_then(|v| v.as_u64()),
            ) {
                let specific_validator = params.get(3).and_then(|v| v.as_str());

                // Calculate APY for projection
                let token_manager = TOKEN_MANAGER.clone();
                let total_staked = token_manager.get_staked_balance("*", "SNRG");
                let total_supply = token_manager
                    .get_all_tokens()
                    .iter()
                    .find(|t| t.symbol == "SNRG")
                    .and_then(|t| t.total_supply.parse::<u128>().ok())
                    .unwrap_or(1);

                let staking_rate = (total_staked as f64 / total_supply as f64).max(0.01);
                let base_apy = 0.05;
                let apy = (base_apy / staking_rate).min(0.20);

                let daily_rate = apy / 365.0;
                let projected_reward = (amount as f64 * daily_rate * duration_days as f64) as u64;

                json!({
                    "address": address,
                    "stakeAmount": amount,
                    "durationDays": duration_days,
                    "estimatedAPY": apy,
                    "projectedReward": projected_reward,
                    "projectedTotal": amount + projected_reward,
                    "validator": specific_validator
                })
            } else {
                json!({"error": "Missing required parameters: address, amount, duration"})
            }
        }

        // synergy_getUnstakingPeriod
        "synergy_getUnstakingPeriod" => {
            json!({
                "unstakingPeriodDays": 7,
                "unstakingPeriodSeconds": 604800,
                "currentQueueLength": 0,
                "estimatedWithdrawalTime": current_timestamp() + 604800
            })
        }

        // Legacy support
        "synergy_status" => {
            json!("ok")
        }

        _ => {
            json!("Unknown method")
        }
    }
}

/// Returns the immutable, finalized execution snapshot used by public SynQ
/// reads.  The typed coordinator derives it from the Genesis-bound snapshot,
/// then advances it only after finalized block execution and durable QC
/// persistence; RPC itself has no path to fabricate or mutate it.
fn finalized_synq_query_state() -> Result<crate::execution::ExecutionState, String> {
    crate::execution::finalized_execution_state_snapshot()
}

fn synq_static_call_json(call_obj: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(to) = call_obj.get("to").and_then(Value::as_str) else {
        return json!({"error": "Missing 'to' field in call object"});
    };
    if !to.starts_with("sync1") && !to.starts_with("sync0") {
        return json!({"result": "0x", "note": "Target address is not a SynQ contract"});
    }
    if !synq_static_call_has_zero_value(call_obj.get("value")) {
        return json!({
            "error": "SynQ static calls must use zero call value",
            "code": "SYNQ_STATIC_CALL_VALUE"
        });
    }
    let data = call_obj.get("data").and_then(Value::as_str).unwrap_or("0x");
    let encoded = data.strip_prefix("0x").unwrap_or(data);
    let calldata = match hex::decode(encoded) {
        Ok(bytes) => bytes,
        Err(_) => {
            return json!({"error": "SynQ static call data must be 0x-prefixed hex", "code": "SYNQ_STATIC_CALL_DATA"})
        }
    };
    let caller = call_obj
        .get("from")
        .and_then(Value::as_str)
        .unwrap_or("synq-static-readonly");
    let (height, timestamp) = match chain.lock() {
        Ok(chain) => chain
            .last()
            .map(|block| (block.block_index, block.timestamp))
            .unwrap_or((0, 0)),
        Err(_) => {
            return json!({"error": "Chain state is unavailable", "code": "SYNQ_STATIC_CALL_CHAIN"})
        }
    };
    let state = match finalized_synq_query_state() {
        Ok(state) => state,
        Err(error) => return json!({"error": error, "code": "SYNQ_STATIC_CALL_STATE_UNAVAILABLE"}),
    };
    match execute_synq_static_call(
        to,
        caller,
        &calldata,
        &state.synq_aivm_state,
        &state.synq_artifacts,
        &state.synq_contracts,
        SynQExecutionContext {
            runtime_block_height: height,
            runtime_block_timestamp_unix: timestamp,
            sts_host: None,
            applied_fee_market: None,
        },
    ) {
        Ok(receipt) if receipt.status == "succeeded" => json!({
            "result": format!("0x{}", receipt.return_data_hex),
            "synq_aivm": receipt,
            "state_source": "finalized_execution_snapshot",
            "read_only": true,
        }),
        Ok(receipt) => json!({
            "error": receipt.error_message.clone().unwrap_or_else(|| "SynQ static call failed".to_string()),
            "code": receipt.error_code,
            "synq_aivm": receipt,
            "state_source": "finalized_execution_snapshot",
            "read_only": true,
        }),
        Err(error) => json!({"error": error, "code": "SYNQ_STATIC_CALL_REJECTED"}),
    }
}

fn synq_static_call_has_zero_value(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::Number(value)) => value.as_u64() == Some(0),
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if let Some(hex_value) = trimmed.strip_prefix("0x") {
                u128::from_str_radix(hex_value, 16) == Ok(0)
            } else {
                trimmed.parse::<u128>() == Ok(0)
            }
        }
        _ => false,
    }
}

fn parse_http_headers(headers: &str) -> HashMap<String, String> {
    headers
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect()
}

fn current_rpc_role_profile() -> Option<&'static RoleProfile> {
    let role_id = std::env::var("SYNERGY_NODE_ROLE_ID").unwrap_or_default();
    let compiled_profile = std::env::var("SYNERGY_COMPILED_PROFILE").unwrap_or_default();
    resolve_configured_role(&role_id, &compiled_profile)
        .ok()
        .flatten()
}

fn parse_forwarded_ip(value: Option<&str>) -> Option<IpAddr> {
    value.and_then(|raw| {
        raw.split(',')
            .map(|segment| segment.trim())
            .find_map(|segment| segment.parse::<IpAddr>().ok())
    })
}

fn trusted_rpc_proxy_peer(peer_ip: IpAddr) -> bool {
    if peer_ip.is_loopback() {
        return true;
    }

    std::env::var("SYNERGY_RPC_TRUSTED_PROXIES")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .any(|entry| trusted_proxy_entry_matches(peer_ip, entry))
        })
        .unwrap_or(false)
}

fn trusted_proxy_entry_matches(peer_ip: IpAddr, entry: &str) -> bool {
    if entry.eq_ignore_ascii_case("loopback") {
        return peer_ip.is_loopback();
    }

    if let Some((network, prefix)) = entry.split_once('/') {
        let Ok(network_ip) = network.trim().parse::<IpAddr>() else {
            return false;
        };
        let Ok(prefix) = prefix.trim().parse::<u8>() else {
            return false;
        };
        return ip_in_prefix(peer_ip, network_ip, prefix);
    }

    entry
        .parse::<IpAddr>()
        .map(|trusted_ip| trusted_ip == peer_ip)
        .unwrap_or(false)
}

fn ip_in_prefix(peer_ip: IpAddr, network_ip: IpAddr, prefix: u8) -> bool {
    match (peer_ip, network_ip) {
        (IpAddr::V4(peer), IpAddr::V4(network)) if prefix <= 32 => {
            let peer = u32::from(peer);
            let network = u32::from(network);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (peer & mask) == (network & mask)
        }
        (IpAddr::V6(peer), IpAddr::V6(network)) if prefix <= 128 => {
            let peer = u128::from(peer);
            let network = u128::from(network);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (peer & mask) == (network & mask)
        }
        _ => false,
    }
}

fn rpc_method_exposure(method: &str) -> Option<RpcMethodExposure> {
    match method {
        "synergy_subscribe"
        | "synergy_unsubscribe"
        | "synergy_getAccountNonce"
        | "synergy_getAccountAuthNonce"
        | "synergy_chainId"
        | "synergy_networkId"
        | "synergy_genesisHash"
        | "synergy_protocolVersion"
        | "synergy_syncing"
        | "synergy_getHealth"
        | "synergy_getReadiness"
        | "synergy_getPeers"
        | "synergy_getFinalizedHead"
        | "synergy_getCanonicalLock"
        | "synergy_getCommittedQC"
        | "synergy_getConsensusSafetyHalt"
        | "synergy_getDivergenceStatus"
        | "synergy_getQuarantineStatus"
        | "synergy_getReconciliationPlan"
        | "synergy_getSelfHealStatus"
        | "synergy_listSnapshots"
        | "synergy_getSnapshotCatalog"
        | "synergy_verifySnapshot"
        | "synergy_diagnoseConsensusStall"
        | "synergy_diagnoseVoteLocks"
        | "synergy_getShadowStatus"
        | "synergy_getRejoinEligibility"
        | "synergy_getValidatorSet"
        | "synergy_getValidatorSetSnapshot"
        | "synergy_getProtocolConfig"
        | "synergy_getAegisStatus"
        | "synergy_getAegisCapabilities"
        | "synergy_getAegisKeyStatus"
        | "synergy_verifyAegisSignature"
        | "synergy_verifyAegisTransaction"
        | "synergy_verifyAegisQC"
        | "synergy_verifyAegisSnapshotManifest"
        | "synergy_verifyAegisSnapshotCatalog"
        | "synergy_blockNumber"
        | "synergy_getBlockNumber"
        | "synergy_getBlockByNumber"
        | "synergy_getBlockByHash"
        | "synergy_getLatestBlock"
        | "synergy_getTransactionPool"
        | "synergy_getRelayerSet"
        | "synergy_getRelayerHealth"
        | "synergy_getSxcpStatus"
        | "synergy_getEventAttestation"
        | "synergy_getAttestations"
        | "synergy_nodeInfo"
        | "synergy_getDeterminismDigest"
        | "synergy_getConsensusForkStatus"
        | "synergy_getValidators"
        | "synergy_getValidator"
        | "synergy_getTokenBalance"
        | "synergy_getTokens"
        | "synergy_stsGetNativeAsset"
        | "synergy_stsGetTokens"
        | "synergy_stsGetToken"
        | "synergy_stsGetBalance"
        | "synergy_stsGetBalances"
        | "synergy_stsGetNftCollection"
        | "synergy_stsGetNft"
        | "synergy_stsGetNftsByOwner"
        | "synergy_stsGetNftsByCollection"
        | "synergy_stsGetMultiAssetCollection"
        | "synergy_stsGetMultiAssetItem"
        | "synergy_stsGetMultiAssetBalance"
        | "synergy_stsGetMultiAssetBalances"
        | "synergy_stsGetCredentialSchema"
        | "synergy_stsGetCredential"
        | "synergy_stsGetCredentialsBySubject"
        | "synergy_stsVerifyCredential"
        | "synergy_stsGetCredentialStatus"
        | "synergy_stsGetEvents"
        | "sts_getNativeAsset"
        | "sts_getTokens"
        | "sts_getToken"
        | "sts_getBalance"
        | "sts_getBalances"
        | "sts_getNftCollection"
        | "sts_getNft"
        | "sts_getNftsByOwner"
        | "sts_getNftsByCollection"
        | "sts_getMultiAssetCollection"
        | "sts_getMultiAssetItem"
        | "sts_getMultiAssetBalance"
        | "sts_getMultiAssetBalances"
        | "sts_getCredentialSchema"
        | "sts_getCredential"
        | "sts_getCredentialsBySubject"
        | "sts_verifyCredential"
        | "sts_getCredentialStatus"
        | "sts_get_nft_collection"
        | "sts_get_nft"
        | "sts_get_nfts_by_owner"
        | "sts_get_nfts_by_collection"
        | "sts_get_multi_asset_collection"
        | "sts_get_multi_asset_item"
        | "sts_get_multi_asset_balance"
        | "sts_get_multi_asset_balances"
        | "sts_get_credential_schema"
        | "sts_get_credential"
        | "sts_get_credentials_by_subject"
        | "sts_verify_credential"
        | "sts_get_credential_status"
        | "sts_getEvents"
        | "synergy_getTopValidators"
        | "synergy_getBlockRange"
        | "synergy_getTransactionByHash"
        | "synergy_getTransactionsInBlock"
        | "synergy_getDagStatus"
        | "synergy_getEtdagStatus"
        | "synergy_getDagFrontier"
        | "synergy_getDagVertices"
        | "synergy_getDagVertex"
        | "synergy_getDagNode"
        | "synergy_getDagTransactionStatus"
        | "synergy_getDagTopology"
        | "synergy_getDagGraph"
        | "synergy_getDagDependencies"
        | "synergy_getDagTxOrderRoot"
        | "synergy_getValidatorStats"
        | "synergy_getNetworkStats"
        | "synergy_getTokenStats"
        | "synergy_getAllBalances"
        | "synergy_getTransferHistory"
        | "synergy_getNodeStatus"
        | "synergy_getSyncStatus"
        | "synergy_getBlockValidationStatus"
        | "synergy_getValidatorActivity"
        | "synergy_getSynergyScoreBreakdown"
        | "synergy_getPeerInfo"
        | "synergy_getTransactionReceipt"
        | "synergy_getTransaction"
        | "synergy_getTransactionStatus"
        | "synergy_getPendingTransaction"
        | "synergy_getReceipt"
        | "synergy_getTransactionCount"
        | "synergy_getBalance"
        | "synergy_getAccount"
        | "synergy_getNonce"
        | "synergy_estimateFee"
        | "synergy_getFeeSchedule"
        | "synergy_getFeeMarket"
        | "synergy_getFeeCollector"
        | "synergy_getTransactionFees"
        | "synergy_getFeeCollectorBalance"
        | "synergy_getFeeCollectorDeposits"
        | "synergy_getBurnLedger"
        | "synergy_gasPrice"
        | "synergy_getLogs"
        | "synergy_getCode"
        | "synergy_getStorageAt"
        | "synergy_getBlockTransactionCount"
        | "synergy_getBlockReceipts"
        | "synergy_getPendingTransactions"
        | "synergy_getTransactionByBlockNumberAndIndex"
        | "synergy_getTransactionByBlockHashAndIndex"
        | "synergy_maxFeePerGas"
        | "synergy_maxPriorityFeePerGas"
        | "synergy_getFeeHistory"
        | "synergy_getChainId"
        | "synergy_getEtdagAdmissionPackage"
        | "synergy_getValidatorByCluster"
        | "synergy_getValidatorRewards"
        | "synergy_getValidatorRewardStatus"
        | "synergy_getValidatorPendingRewards"
        | "synergy_getEpochFeeDistribution"
        | "synergy_getClusterRewardEscrow"
        | "synergy_getTreasuryRecovery"
        | "synergy_getEpochRewardAudit"
        | "synergy_checkRewardInvariants"
        | "synergy_getValidatorPerformance"
        | "synergy_getValidatorQueue"
        | "synergy_getValidatorSlashingHistory"
        | "synergy_getClusterStatus"
        | "synergy_getValidatorClusterHistory"
        | "synergy_getEpochClusterAssignments"
        | "synergy_getClusterInfo"
        | "synergy_getClusterRewards"
        | "synergy_getStakedBalance"
        | "synergy_getStakingInfo"
        | "synergy_getStakingRewards"
        | "synergy_getStakingAPY"
        | "synergy_getDelegatedStakes"
        | "synergy_getDelegators"
        | "synergy_getRewardsProjection"
        | "synergy_getUnstakingPeriod"
        | "synergy_getActiveApprovals"
        | "synergy_getApprovalHistory"
        | "synergy_resolveSynID"
        | "synergy_reverseResolveSynID"
        | "synergy_getAddressBook"
        | "synergy_status" => Some(RpcMethodExposure::PublicRead),
        "synergy_simulateTransaction"
        | "synergy_submitEncryptedTransaction"
        | "synergy_submitEtdagTransaction"
        | "synergy_sendTransaction"
        | "synergy_submitAegisTransaction"
        | "synergy_submitAegisTransactionBatch"
        | "synergy_submitAegisDagTransaction"
        | "synergy_submitAegisDagTransactionBatch"
        | "synergy_call"
        | "synergy_estimateGas"
        | "synergy_createApproval"
        | "synergy_revokeAllApprovals"
        | "synergy_registerSynID" => Some(RpcMethodExposure::PublicClient),
        "synergy_createWallet"
        | "synergy_getWallet"
        | "synergy_createWalletFromKeypair"
        | "synergy_getAllWallets"
        | "synergy_signTransaction"
        | "synergy_signMessage"
        | "synergy_verifyMessage"
        | "synergy_getEncryptionKey"
        | "synergy_rotateKeys"
        | "synergy_getActiveDelegations"
        | "synergy_revokeDelegation"
        | "synergy_initiateRecovery"
        | "synergy_confirmRecovery"
        | "synergy_getGuardians"
        | "synergy_verifyCurrentAuthKey"
        | "synergy_getPendingGuardianNotifications"
        | "synergy_getPendingTransfers"
        | "synergy_cancelPendingTransfer"
        | "synergy_freezeAccount"
        | "synergy_getSecurityAlerts" => Some(RpcMethodExposure::AuthorityPlane),
        "synergy_sendTokens"
        | "synergy_stakeTokens"
        | "synergy_stakeTokensDirect"
        | "synergy_unstakeTokens"
        | "synergy_activateValidator"
        | "synergy_registerValidator"
        | "synergy_approveValidator"
        | "synergy_slashValidator"
        | "synergy_requestValidatorExit"
        | "synergy_registerRelayer"
        | "synergy_unregisterRelayer"
        | "synergy_relayerHeartbeat"
        | "synergy_submitAttestation"
        | "synergy_slashRelayer"
        | "synergy_createToken"
        | "synergy_mintTokens"
        | "synergy_burnTokens"
        | "synergy_transferTokens"
        | "synergy_claimRewards"
        | "synergy_proposeClusterChange" => Some(RpcMethodExposure::NonPublicWrite),
        "synergy_setSxcpHeartbeatTimeout"
        | "synergy_resetSxcpState"
        | "synergy_mine"
        | "synergy_setAccountBalance"
        | "synergy_resetChainHead"
        | "synergy_startSync"
        | "synergy_startSelfHeal"
        | "synergy_recoverTransientVoteLocks"
        | "synergy_syncFromCanonicalPeer"
        | "synergy_selfHealFromArchive"
        | "synergy_createSnapshot"
        | "synergy_selfHealFromSnapshot"
        | "synergy_startShadowObserve"
        | "synergy_requestRejoin" => Some(RpcMethodExposure::Operator),
        _ => None,
    }
}

fn build_exposure_error(
    method: &str,
    exposure: RpcMethodExposure,
    request_context: &RpcRequestContext,
    detail: &str,
) -> RpcError {
    RpcError::with_data(
        -32003,
        format!("RPC method '{method}' is not available on this exposure profile"),
        json!({
            "method": method,
            "requiredProfile": exposure.label(),
            "transport": request_context.transport_label(),
            "clientIp": request_context.effective_client_ip().map(|ip| ip.to_string()),
            "roleId": request_context.role_profile.map(|profile| profile.role_id),
            "compiledProfile": request_context.role_profile.map(|profile| profile.compiled_profile),
            "detail": detail,
        }),
    )
}

fn enforce_rpc_exposure_policy(
    method: &str,
    request_context: &RpcRequestContext,
) -> Result<(), RpcError> {
    let Some(exposure) = rpc_method_exposure(method) else {
        return Ok(());
    };

    if !request_context.is_public_request() {
        return Ok(());
    }

    let is_service_access_role = request_context
        .role_profile
        .map(|profile| profile.authority_plane == AuthorityPlane::ServiceAccess)
        .unwrap_or(false);

    match exposure {
        RpcMethodExposure::PublicRead => Ok(()),
        RpcMethodExposure::PublicClient if is_service_access_role => Ok(()),
        RpcMethodExposure::PublicClient => Err(build_exposure_error(
            method,
            exposure,
            request_context,
            "public client methods are only exposed on service-access node roles",
        )),
        RpcMethodExposure::AuthorityPlane => Err(build_exposure_error(
            method,
            exposure,
            request_context,
            "authority-plane methods must not be exposed on unauthenticated public endpoints",
        )),
        RpcMethodExposure::NonPublicWrite => Err(build_exposure_error(
            method,
            exposure,
            request_context,
            "this state-mutating method is restricted to non-public authenticated routing",
        )),
        RpcMethodExposure::Operator => Err(build_exposure_error(
            method,
            exposure,
            request_context,
            "operator methods require non-public administrative routing and audit controls",
        )),
    }
}

fn request_is_json(headers: &HashMap<String, String>) -> bool {
    headers
        .get("content-type")
        .map(|value| value.to_ascii_lowercase().starts_with("application/json"))
        .unwrap_or(false)
}

fn json_rpc_error_response(id: Option<Value>, error: &RpcError) -> Value {
    let mut payload = serde_json::Map::new();
    payload.insert("code".to_string(), json!(error.code));
    payload.insert("message".to_string(), json!(error.message.clone()));
    if let Some(data) = &error.data {
        payload.insert("data".to_string(), data.clone());
    }

    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": Value::Object(payload),
        "chain_context": rpc_chain_context_json()
    })
}

fn send_json_rpc_error(
    stream: &mut std::net::TcpStream,
    id: Option<Value>,
    error: &RpcError,
    cors_enabled: bool,
    cors_origins: &[String],
) {
    let response = json_rpc_error_response(id, error);
    let response = format_response(&response.to_string(), cors_enabled, cors_origins);
    write_http_response_and_close(stream, &response);
}

fn write_http_response_and_close(stream: &mut std::net::TcpStream, response: &str) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Both);
}

fn translate_legacy_rpc_result(value: Value) -> Result<Value, RpcError> {
    if let Some(message) = value.as_str() {
        if message == "Unknown method" {
            return Err(RpcError::new(-32601, "Method not found"));
        }
        if message.starts_with("Invalid") || message.starts_with("Missing") {
            return Err(RpcError::new(-32602, message));
        }
    }

    if let Some(map) = value.as_object() {
        if matches!(map.get("success"), Some(Value::Bool(false))) {
            let message = map
                .get("error")
                .and_then(|entry| entry.as_str())
                .unwrap_or("RPC request failed");
            return Err(RpcError::with_data(-32000, message, value.clone()));
        }

        if let Some(error) = map.get("error") {
            let message = error
                .as_str()
                .map(|entry| entry.to_string())
                .unwrap_or_else(|| error.to_string());
            return Err(RpcError::with_data(-32000, message, value.clone()));
        }
    }

    Ok(value)
}

fn current_chain_id() -> u64 {
    crate::config::load_node_config(None)
        .ok()
        .map(|cfg| cfg.blockchain.chain_id)
        .unwrap_or(1266)
}

fn current_network_id() -> String {
    crate::config::load_node_config(None)
        .ok()
        .map(|cfg| cfg.network.network_id)
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| "synergy-testnet-v3".to_string())
}

fn current_chain_name() -> String {
    crate::config::load_node_config(None)
        .ok()
        .map(|cfg| cfg.network.name)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "Synergy Testnet".to_string())
}

fn current_genesis_hash() -> String {
    // Fail closed. The previous fallback returned the retired Testnet-v2 genesis
    // hash whenever the canonical genesis could not be loaded, which made a v3
    // node advertise a v2 chain identity. Reporting nothing is always safer than
    // reporting the wrong chain.
    canonical_genesis()
        .map(|genesis| genesis.hash().to_string())
        .unwrap_or_default()
}

fn rpc_chain_context_json() -> Value {
    canonical_genesis()
        .map(|genesis| {
            json!({
                "chain_id": genesis.chain_id(),
                "chain_incarnation": genesis.chain_incarnation(),
                "genesis_hash": genesis.hash(),
            })
        })
        .unwrap_or_else(|_| {
            json!({
                "chain_id": 1266,
                "chain_incarnation": Value::Null,
                "genesis_hash": "",
            })
        })
}

fn current_protocol_version() -> String {
    canonical_genesis()
        .map(|genesis| genesis.protocol_version().to_string())
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
}

fn chain_identity_json() -> Value {
    let chain_id = current_chain_id();
    json!({
        "name": current_chain_name(),
        "chain_id": chain_id,
        "chain_id_hex": format!("0x{chain_id:x}"),
        "network_id": current_network_id(),
        "chain_incarnation": crate::synergy_types::TESTNET_V3_CHAIN_INCARNATION,
        "genesis_hash": current_genesis_hash(),
    })
}

/// Loads the finalized Testnet-v3 authority used by the typed PoSy coordinator.
/// `None` means that no typed store exists yet and legacy reads retain their
/// existing behavior. Once the file exists, even an empty store is authoritative
/// and legacy post-Genesis blocks must not leak through explorer RPC.
fn typed_finality_records_for_rpc() -> Result<Option<Vec<TypedFinalityRecord>>, String> {
    let path = configured_typed_finality_path();
    if !path.is_file() {
        return Ok(None);
    }

    let genesis = canonical_genesis()
        .map_err(|error| format!("typed finality RPC cannot load canonical Genesis: {error}"))?;
    let genesis_anchor = Hash::from_hex(genesis.hash()).map_err(|error| {
        format!("typed finality RPC cannot parse the canonical Genesis anchor: {error}")
    })?;
    let store = TypedFinalityStore::for_genesis_anchor(genesis_anchor)
        .map_err(|error| format!("typed finality RPC store initialization failed: {error}"))?;
    store
        .recover()
        .map(Some)
        .map_err(|error| format!("typed finality RPC store validation failed: {error}"))
}

/// Loads and independently re-verifies every finalized coordinated package
/// before exposing it to public reads. The store's append boundary already
/// checks continuity, but RPC repeats signature verification so an operator
/// cannot turn a copied or tampered journal into a public finality claim.
fn coordinated_finality_records_for_rpc() -> Result<Option<Vec<CoordinatedFinalityRecord>>, String>
{
    let path = configured_coordinated_finality_path();
    if !path.is_file() {
        return Ok(None);
    }

    let node_config = crate::config::load_node_config(None).map_err(|error| {
        format!("coordinated finality RPC cannot load the selected node configuration: {error}")
    })?;
    let coordinated_config = match node_config.consensus.resolve_mode(
        node_config.blockchain.chain_id,
        &node_config.network.network_id,
    ) {
        Ok(ResolvedConsensusMode::CoordinatedRoundRobinV1(config)) => config,
        Ok(ResolvedConsensusMode::PosySimplifiedV3) => {
            return Err(
                "coordinated finality journal exists while the selected consensus mode is not coordinated_round_robin_v1"
                    .to_string(),
            )
        }
        Err(error) => {
            return Err(format!(
                "coordinated finality RPC cannot resolve the selected consensus mode: {error}"
            ))
        }
    };

    let genesis = canonical_genesis().map_err(|error| {
        format!("coordinated finality RPC cannot load canonical Genesis: {error}")
    })?;
    let genesis_anchor = Hash::from_hex(genesis.hash()).map_err(|error| {
        format!("coordinated finality RPC cannot parse the canonical Genesis anchor: {error}")
    })?;
    let genesis_state_root = genesis
        .value()
        .get("execution")
        .and_then(|execution| execution.get("genesis_execution_state_root"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "coordinated finality RPC canonical Genesis omits execution.genesis_execution_state_root"
                .to_string()
        })
        .and_then(|root| {
            Hash::from_hex(root).map_err(|error| {
                format!(
                    "coordinated finality RPC cannot parse the canonical Genesis state root: {error}"
                )
            })
        })?;
    let store = CoordinatedFinalityStore::for_migration_anchor(
        genesis_anchor,
        genesis_state_root,
        crate::synergy_types::Height(1),
    )
    .map_err(|error| format!("coordinated finality RPC store initialization failed: {error}"))?;
    let records = store
        .recover(&coordinated_config)
        .map_err(|error| format!("coordinated finality RPC store validation failed: {error}"))?;

    let bootstrap = load_testnet_v3_genesis_bootstrap(&genesis).map_err(|error| {
        format!("coordinated finality RPC cannot load canonical validator keys: {error}")
    })?;
    let verifier = CoordinatedConsensusVerifier::new(
        coordinated_config,
        &bootstrap.validator_set,
        bootstrap.verifier,
    )
    .map_err(|error| format!("coordinated finality RPC verifier initialization failed: {error}"))?;
    for record in &records {
        verifier
            .verify_committed_block_package(&record.package)
            .map_err(|error| {
                format!(
                    "coordinated finality RPC rejects persisted package at height {}: {error}",
                    record.height.0
                )
            })?;
    }
    Ok(Some(records))
}

/// Public finality has exactly one durable source. A typed PoSy journal and a
/// coordinated journal can never coexist in a single chain incarnation: that
/// would make the explorer select consensus evidence rather than verify it.
enum RpcFinalityRecords {
    Typed(Vec<TypedFinalityRecord>),
    Coordinated(Vec<CoordinatedFinalityRecord>),
}

#[derive(Clone, Copy)]
enum RpcFinalityRecordRef<'a> {
    Typed(&'a TypedFinalityRecord),
    Coordinated(&'a CoordinatedFinalityRecord),
}

impl RpcFinalityRecords {
    fn iter(&self) -> Box<dyn Iterator<Item = RpcFinalityRecordRef<'_>> + '_> {
        match self {
            Self::Typed(records) => Box::new(records.iter().map(RpcFinalityRecordRef::Typed)),
            Self::Coordinated(records) => {
                Box::new(records.iter().map(RpcFinalityRecordRef::Coordinated))
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Typed(records) => records.len(),
            Self::Coordinated(records) => records.len(),
        }
    }
}

impl<'a> RpcFinalityRecordRef<'a> {
    fn height(self) -> u64 {
        match self {
            Self::Typed(record) => record.height.0,
            Self::Coordinated(record) => record.height.0,
        }
    }

    fn block_id(self) -> &'a str {
        match self {
            Self::Typed(record) => record.block_id.0.as_str(),
            Self::Coordinated(record) => record.block_id.0.as_str(),
        }
    }

    fn proposer_validator_id(self) -> &'a str {
        match self {
            Self::Typed(record) => record.block.header.proposer_validator_id.0.as_str(),
            Self::Coordinated(record) => {
                record.package.block.header.proposer_validator_id.0.as_str()
            }
        }
    }

    fn transaction_count(self) -> usize {
        match self {
            Self::Typed(record) => record.block.transactions.len(),
            Self::Coordinated(record) => record.package.block.transactions.len(),
        }
    }

    fn timestamp_ms(self) -> u64 {
        match self {
            Self::Typed(record) => record.block.header.timestamp_ms_consensus_bounded,
            Self::Coordinated(record) => record.package.block.header.timestamp_ms_consensus_bounded,
        }
    }
}

fn finality_records_for_rpc() -> Result<Option<RpcFinalityRecords>, String> {
    let typed_exists = configured_typed_finality_path().is_file();
    let coordinated_exists = configured_coordinated_finality_path().is_file();
    if typed_exists && coordinated_exists {
        return Err(
            "typed PoSy and coordinated finality journals both exist; refusing mixed consensus authority"
                .to_string(),
        );
    }
    if coordinated_exists {
        return coordinated_finality_records_for_rpc()
            .map(|records| records.map(RpcFinalityRecords::Coordinated));
    }
    if typed_exists {
        return typed_finality_records_for_rpc()
            .map(|records| records.map(RpcFinalityRecords::Typed));
    }
    Ok(None)
}

fn finality_rpc_error(error: impl Into<String>) -> Value {
    json!({
        "error": error.into(),
        "fail_closed": true,
        "source": "finality_authority",
        "typed_posy_path": configured_typed_finality_path().to_string_lossy(),
        "coordinated_round_robin_path": configured_coordinated_finality_path().to_string_lossy(),
        "chain": chain_identity_json(),
    })
}

fn typed_finality_record_to_explorer_json(record: &TypedFinalityRecord) -> Result<Value, String> {
    let transactions = serde_json::to_value(&record.block.transactions)
        .map_err(|error| format!("serialize typed PoSy finalized transactions: {error}"))?;
    let header = &record.block.header;
    Ok(json!({
        "block_index": record.height.0,
        "height": record.height.0,
        "timestamp": header.timestamp_ms_consensus_bounded / 1_000,
        "timestamp_ms": header.timestamp_ms_consensus_bounded,
        "hash": record.block_id.0.as_str(),
        "block_id": record.block_id.0.as_str(),
        "previous_hash": header.parent_block_hash.to_hex(),
        "parent_hash": header.parent_block_hash.to_hex(),
        "validator_id": header.proposer_validator_id.0.as_str(),
        "validator": header.proposer_validator_id.0.as_str(),
        "proposer_uma_id": header.proposer_uma_id.0.as_str(),
        "proposer_key_id": header.proposer_key_id.0.as_str(),
        "tx_count": record.block.transactions.len() as u64,
        // These are the exact typed transactions persisted with the finalized
        // block. They are not converted into the incompatible legacy
        // transaction schema.
        "transactions": transactions,
        "transaction_format": "typed_posy_v2",
        "state_root_before": header.state_root_before.to_hex(),
        "state_root_after": header.state_root_after.to_hex(),
        "receipt_root": header.receipt_root.to_hex(),
        "height_context_root": header.height_context_root.to_hex(),
        "active_validator_set_hash": header.active_validator_set_hash.to_hex(),
        "cluster_map_hash": header.cluster_map_hash.to_hex(),
        "round": header.round.0,
        "epoch": header.epoch.0,
        "cluster_id": header.cluster_id.0,
        "protocol_version": header.protocol_version.as_str(),
        "quorum_certificate_root": record.quorum_certificate_root.to_hex(),
        "qc_signed_weight": record.quorum_certificate.signed_weight,
        "qc_threshold_weight_required": record.quorum_certificate.threshold_weight_required,
        "qc_signer_count": record.quorum_certificate.aegis_pq_key_ids.len(),
        "finalized": true,
        "source": "typed_posy_finality_store",
    }))
}

fn typed_finality_record_to_finalized_head_json(record: &TypedFinalityRecord) -> Value {
    let header = &record.block.header;
    json!({
        "found": true,
        "height": record.height.0,
        "block_hash": record.block_id.0.as_str(),
        "block_id": record.block_id.0.as_str(),
        "parent_hash": header.parent_block_hash.to_hex(),
        "state_root": header.state_root_after.to_hex(),
        "quorum_certificate_root": record.quorum_certificate_root.to_hex(),
        "timestamp": header.timestamp_ms_consensus_bounded / 1_000,
        "timestamp_ms": header.timestamp_ms_consensus_bounded,
        "round": header.round.0,
        "epoch": header.epoch.0,
        "source": "typed_posy_finality_store",
        "chain": chain_identity_json(),
    })
}

fn coordinated_finality_record_to_explorer_json(
    record: &CoordinatedFinalityRecord,
) -> Result<Value, String> {
    let package = &record.package;
    let block = &package.block;
    let header = &block.header;
    let transactions = serde_json::to_value(&block.transactions)
        .map_err(|error| format!("serialize coordinated finalized transactions: {error}"))?;
    Ok(json!({
        "block_index": record.height.0,
        "height": record.height.0,
        "timestamp": header.timestamp_ms_consensus_bounded / 1_000,
        "timestamp_ms": header.timestamp_ms_consensus_bounded,
        "hash": record.block_id.0.as_str(),
        "block_id": record.block_id.0.as_str(),
        "previous_hash": header.parent_block_hash.to_hex(),
        "parent_hash": header.parent_block_hash.to_hex(),
        "validator_id": header.proposer_validator_id.0.as_str(),
        "validator": header.proposer_validator_id.0.as_str(),
        "proposer_uma_id": header.proposer_uma_id.0.as_str(),
        "proposer_key_id": header.proposer_key_id.0.as_str(),
        "tx_count": block.transactions.len() as u64,
        "transactions": transactions,
        "transaction_format": "coordinated_round_robin_v1",
        "state_root_before": header.state_root_before.to_hex(),
        "state_root_after": header.state_root_after.to_hex(),
        "receipt_root": header.receipt_root.to_hex(),
        "height_context_root": header.height_context_root.to_hex(),
        "active_validator_set_hash": header.active_validator_set_hash.to_hex(),
        "cluster_map_hash": header.cluster_map_hash.to_hex(),
        "round": header.round.0,
        "epoch": header.epoch.0,
        "cluster_id": header.cluster_id.0,
        "protocol_version": header.protocol_version.as_str(),
        "coordinator_id": package.coordinator_commit.coordinator_id,
        "assigned_producer_id": package.assignment.assigned_producer_id,
        "producer_turn": package.assignment.producer_round,
        "producer_assignment_hash": package.assignment.signing_hash()?.to_hex(),
        "coordinator_commit_hash": record.coordinator_commit_hash.to_hex(),
        "coordinator_commit_signature_algorithm": package.coordinator_commit.coordinator_signature.algorithm,
        "finality_proof_type": "coordinator_commit",
        "finalized": true,
        "source": "coordinated_round_robin_finality_store",
    }))
}

fn coordinated_finality_record_to_finalized_head_json(record: &CoordinatedFinalityRecord) -> Value {
    let package = &record.package;
    let header = &package.block.header;
    json!({
        "found": true,
        "height": record.height.0,
        "block_hash": record.block_id.0.as_str(),
        "block_id": record.block_id.0.as_str(),
        "parent_hash": header.parent_block_hash.to_hex(),
        "state_root": header.state_root_after.to_hex(),
        "coordinator_id": package.coordinator_commit.coordinator_id,
        "assigned_producer_id": package.assignment.assigned_producer_id,
        "producer_turn": package.assignment.producer_round,
        "producer_assignment_hash": package.proposal.assignment_hash.to_hex(),
        "coordinator_commit_hash": record.coordinator_commit_hash.to_hex(),
        "finality_proof_type": "coordinator_commit",
        "timestamp": header.timestamp_ms_consensus_bounded / 1_000,
        "timestamp_ms": header.timestamp_ms_consensus_bounded,
        "round": header.round.0,
        "epoch": header.epoch.0,
        "source": "coordinated_round_robin_finality_store",
        "chain": chain_identity_json(),
    })
}

fn finality_record_to_explorer_json(record: RpcFinalityRecordRef<'_>) -> Result<Value, String> {
    match record {
        RpcFinalityRecordRef::Typed(record) => typed_finality_record_to_explorer_json(record),
        RpcFinalityRecordRef::Coordinated(record) => {
            coordinated_finality_record_to_explorer_json(record)
        }
    }
}

fn finality_record_to_finalized_head_json(record: RpcFinalityRecordRef<'_>) -> Value {
    match record {
        RpcFinalityRecordRef::Typed(record) => typed_finality_record_to_finalized_head_json(record),
        RpcFinalityRecordRef::Coordinated(record) => {
            coordinated_finality_record_to_finalized_head_json(record)
        }
    }
}

fn authoritative_block_height(
    finality_records: Option<&RpcFinalityRecords>,
    legacy_height: Option<u64>,
) -> Option<u64> {
    match finality_records {
        Some(records) => Some(
            records
                .iter()
                .last()
                .map(|record| record.height())
                .unwrap_or(0),
        ),
        None => legacy_height,
    }
}

fn legacy_block_by_number(
    chain: &Arc<Mutex<BlockChain>>,
    block_number: u64,
) -> Option<crate::block::Block> {
    chain.lock().ok().and_then(|chain| {
        chain
            .chain
            .iter()
            .find(|block| block.block_index == block_number)
            .cloned()
    })
}

fn block_by_number_json(chain: &Arc<Mutex<BlockChain>>, block_number: u64) -> Value {
    match finality_records_for_rpc() {
        Err(error) => finality_rpc_error(error),
        Ok(Some(records)) => {
            if block_number == 0 {
                return legacy_block_by_number(chain, 0)
                    .as_ref()
                    .map(block_to_explorer_json)
                    .unwrap_or(Value::Null);
            }
            match records
                .iter()
                .find(|record| record.height() == block_number)
            {
                Some(record) => finality_record_to_explorer_json(record)
                    .unwrap_or_else(|error| finality_rpc_error(error)),
                None => Value::Null,
            }
        }
        Ok(None) => legacy_block_by_number(chain, block_number)
            .as_ref()
            .map(block_to_explorer_json)
            .unwrap_or(Value::Null),
    }
}

fn block_by_hash_json(chain: &Arc<Mutex<BlockChain>>, block_hash: &str) -> Value {
    let normalized = block_hash.trim().trim_start_matches("0x");
    match finality_records_for_rpc() {
        Err(error) => finality_rpc_error(error),
        Ok(Some(records)) => {
            if let Some(record) = records
                .iter()
                .find(|record| record.block_id().eq_ignore_ascii_case(normalized))
            {
                return finality_record_to_explorer_json(record)
                    .unwrap_or_else(|error| finality_rpc_error(error));
            }
            legacy_block_by_number(chain, 0)
                .filter(|block| block.hash.trim().eq_ignore_ascii_case(normalized))
                .as_ref()
                .map(block_to_explorer_json)
                .unwrap_or(Value::Null)
        }
        Ok(None) => chain
            .lock()
            .ok()
            .and_then(|chain| {
                chain
                    .chain
                    .iter()
                    .find(|block| block.hash.trim().eq_ignore_ascii_case(normalized))
                    .cloned()
            })
            .as_ref()
            .map(block_to_explorer_json)
            .unwrap_or(Value::Null),
    }
}

fn latest_block_json(chain: &Arc<Mutex<BlockChain>>) -> Value {
    match finality_records_for_rpc() {
        Err(error) => finality_rpc_error(error),
        Ok(Some(records)) => match records.iter().last() {
            Some(record) => finality_record_to_explorer_json(record)
                .unwrap_or_else(|error| finality_rpc_error(error)),
            None => legacy_block_by_number(chain, 0)
                .as_ref()
                .map(block_to_explorer_json)
                .unwrap_or(Value::Null),
        },
        Ok(None) => read_through_chain_tip_block(chain)
            .as_ref()
            .map(block_to_explorer_json)
            .unwrap_or(Value::Null),
    }
}

fn block_range_json(chain: &Arc<Mutex<BlockChain>>, start: u64, end: u64) -> Value {
    match finality_records_for_rpc() {
        Err(error) => finality_rpc_error(error),
        Ok(Some(records)) => {
            let mut blocks = Vec::new();
            if start == 0 && end >= start {
                if let Some(genesis) = legacy_block_by_number(chain, 0) {
                    blocks.push(block_to_explorer_json(&genesis));
                }
            }
            for record in records
                .iter()
                .filter(|record| record.height() >= start && record.height() <= end)
            {
                match finality_record_to_explorer_json(record) {
                    Ok(block) => blocks.push(block),
                    Err(error) => return finality_rpc_error(error),
                }
            }
            json!(blocks)
        }
        Ok(None) => chain
            .lock()
            .map(|chain| {
                json!(chain
                    .chain
                    .iter()
                    .filter(|block| block.block_index >= start && block.block_index <= end)
                    .map(block_to_explorer_json)
                    .collect::<Vec<_>>())
            })
            .unwrap_or_else(|_| {
                finality_rpc_error("legacy block range unavailable: chain lock poisoned")
            }),
    }
}

fn protocol_config_json() -> Value {
    let configured_count = configured_validator_addresses().len();
    let active_count = VALIDATOR_MANAGER.get_active_validators().len();
    protocol_config_json_for_validator_counts(configured_count, active_count)
}

fn protocol_config_json_for_validator_counts(
    configured_count: usize,
    active_count: usize,
) -> Value {
    let validator_count = if active_count > 0 {
        active_count
    } else {
        configured_count
    };
    let required_quorum = required_validator_quorum(validator_count);
    let cluster_count = target_validator_cluster_count(validator_count);
    json!({
        "chain": chain_identity_json(),
        "protocol_version": current_protocol_version(),
        "package_version": env!("CARGO_PKG_VERSION"),
        "validator_count": validator_count,
        "validator_quorum": {
            "required": required_quorum,
            "total": validator_count,
        },
        "target_block_cadence_seconds": 2,
        "cluster_count": cluster_count,
        "cluster_id": if cluster_count == 1 { Some(0u64) } else { None },
    })
}

fn sync_status_json(chain: &Arc<Mutex<BlockChain>>) -> Value {
    let tip = chain_tip_snapshot_for_status(chain);
    sync_status_json_with_tip(&tip)
}

fn sync_status_json_with_tip(tip: &ChainTipSnapshot) -> Value {
    if let Ok(manager) = SYNC_MANAGER.try_lock() {
        let state = manager.get_state();
        let highest_block = manager
            .get_network_height()
            .max(best_observed_sync_source_height());
        let syncing = !matches!(state, SyncState::Synced | SyncState::Idle)
            || tip
                .height
                .map(|current_block| current_block < highest_block)
                .unwrap_or(true);
        json!({
            "syncing": syncing,
            "current_block": tip.height,
            "highest_block": highest_block,
            "starting_block": manager.get_sync_start_height(),
            "sync_percentage": manager.get_progress_percentage(),
            "state": format!("{:?}", state),
            "chain_state_available": tip.available,
            "chain_state_error": tip.error,
            "fail_closed": !tip.available,
            "chain": chain_identity_json(),
        })
    } else {
        record_qrpc_fallback("sync_status_manager_lock_unavailable");
        json!({
            "syncing": true,
            "current_block": tip.height,
            "highest_block": best_observed_sync_source_height(),
            "sync_manager_available": false,
            "chain_state_available": tip.available,
            "chain_state_error": tip.error,
            "fallback": true,
            "fail_closed": false,
            "chain": chain_identity_json(),
        })
    }
}

fn sync_state_is_active(state: SyncState) -> bool {
    matches!(
        state,
        SyncState::Discovering
            | SyncState::Downloading
            | SyncState::Validating
            | SyncState::Applying
    )
}

fn start_live_sync_json() -> Value {
    let Some(network) = crate::p2p::get_p2p_network() else {
        return json!({
            "success": false,
            "fail_closed": true,
            "status": "blocked",
            "error": "P2P network is not available; start the node runtime before requesting live sync.",
            "chain": chain_identity_json(),
        });
    };

    let peer_count = network.get_peer_count() as u64;
    let observed_height = best_observed_sync_source_height();
    let current_block = SHARED_CHAIN
        .lock()
        .ok()
        .and_then(|chain| chain.last().map(|block| block.block_index))
        .unwrap_or(0);

    {
        let mut manager = match SYNC_MANAGER.try_lock() {
            Ok(manager) => manager,
            Err(TryLockError::WouldBlock) => {
                return json!({
                    "success": true,
                    "status": "already_running",
                    "message": "Live sync is already running.",
                    "current_block": current_block,
                    "highest_block": observed_height,
                    "peer_count": peer_count,
                    "chain": chain_identity_json(),
                });
            }
            Err(TryLockError::Poisoned(_)) => {
                return json!({
                    "success": false,
                    "fail_closed": true,
                    "status": "failed",
                    "error": "Sync manager lock is poisoned.",
                    "chain": chain_identity_json(),
                });
            }
        };

        if sync_state_is_active(manager.get_state()) {
            return json!({
                "success": true,
                "status": "already_running",
                "message": "Live sync is already running.",
                "current_block": current_block,
                "highest_block": manager.get_network_height().max(observed_height),
                "peer_count": peer_count,
                "chain": chain_identity_json(),
            });
        }

        manager.attach_network(Arc::clone(&network));
        let discovered_height = manager.discover_network_height().unwrap_or(observed_height);
        if current_block >= discovered_height {
            return json!({
                "success": true,
                "status": "already_synced",
                "message": "Local chain is already at the best observed peer height.",
                "current_block": current_block,
                "highest_block": discovered_height,
                "peer_count": peer_count,
                "chain": chain_identity_json(),
            });
        }
    }

    match thread::Builder::new()
        .name("synergy-live-sync".to_string())
        .spawn(move || {
            let mut manager = match SYNC_MANAGER.lock() {
                Ok(manager) => manager,
                Err(error) => {
                    warn!(
                        "rpc",
                        "Live sync could not acquire sync manager",
                        "error" => error.to_string()
                    );
                    return;
                }
            };
            manager.attach_network(Arc::clone(&network));
            match manager.start_sync() {
                Ok(()) => info!(
                    "rpc",
                    "Live sync completed",
                    "local_height" => manager.local_height,
                    "network_height" => manager.get_network_height()
                ),
                Err(error) => warn!(
                    "rpc",
                    "Live sync failed",
                    "error" => error.to_string(),
                    "local_height" => manager.local_height,
                    "network_height" => manager.get_network_height()
                ),
            }
        }) {
        Ok(_) => json!({
            "success": true,
            "status": "started",
            "message": "Live sync was requested for the running node.",
            "current_block": current_block,
            "highest_block": observed_height,
            "peer_count": peer_count,
            "chain": chain_identity_json(),
        }),
        Err(error) => json!({
            "success": false,
            "fail_closed": true,
            "status": "failed",
            "error": format!("Failed to spawn live sync worker: {error}"),
            "current_block": current_block,
            "highest_block": observed_height,
            "peer_count": peer_count,
            "chain": chain_identity_json(),
        }),
    }
}

fn peer_info_json() -> Value {
    if let Some(p2p) = crate::p2p::get_p2p_network() {
        let peers = p2p.get_peer_info();
        let status_ready_validator_addresses = p2p.get_status_ready_validator_addresses();
        return peer_info_response_json(
            peers,
            status_ready_validator_addresses,
            p2p.get_peer_count(),
        );
    }

    peer_info_response_json(Vec::new(), Vec::new(), 0)
}

fn peer_info_response_json(
    peers: Vec<Value>,
    status_ready_validator_addresses: Vec<String>,
    connected_validator_count: usize,
) -> Value {
    json!({
        "peer_count": peers.len(),
        "connected_validator_count": connected_validator_count,
        "status_ready_validator_count": status_ready_validator_addresses.len(),
        "status_ready_validator_addresses": status_ready_validator_addresses,
        "peers": peers,
        "chain": chain_identity_json(),
    })
}

fn best_observed_sync_source_height() -> u64 {
    crate::p2p::get_p2p_network()
        .map(|network| {
            network
                .collect_peer_snapshots()
                .into_iter()
                .filter(|peer| {
                    peer.status_received_at.is_some()
                        && !peer.quarantined
                        && (!peer.consensus_duties_disabled
                            || peer
                                .validator_address
                                .as_deref()
                                .map(str::trim)
                                .filter(|value| !value.is_empty())
                                .is_none())
                })
                .map(|peer| peer.block_height)
                .max()
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

fn chain_tip_snapshot_nonblocking(chain: &Arc<Mutex<BlockChain>>) -> ChainTipSnapshot {
    if let Some(block) = read_through_chain_tip_block(chain) {
        chain_tip_snapshot_from_block(&block)
    } else {
        ChainTipSnapshot {
            available: false,
            height: None,
            hash: None,
            timestamp: None,
            error: Some(QRPC_CHAIN_UNAVAILABLE_ERROR.to_string()),
        }
    }
}

fn chain_tip_snapshot_for_status(chain: &Arc<Mutex<BlockChain>>) -> ChainTipSnapshot {
    let mut snapshot = chain_tip_snapshot_nonblocking(chain);
    for _ in 0..QRPC_STATUS_CHAIN_SNAPSHOT_RETRY_ATTEMPTS {
        if snapshot.available || snapshot.error.as_deref() != Some(QRPC_CHAIN_UNAVAILABLE_ERROR) {
            return snapshot;
        }
        thread::sleep(Duration::from_millis(
            QRPC_STATUS_CHAIN_SNAPSHOT_RETRY_DELAY_MILLIS,
        ));
        snapshot = chain_tip_snapshot_nonblocking(chain);
    }
    snapshot
}

fn block_number_json(chain: &Arc<Mutex<BlockChain>>) -> Value {
    match finality_records_for_rpc() {
        Err(error) => return finality_rpc_error(error),
        Ok(Some(records)) => {
            return json!(authoritative_block_height(Some(&records), None).unwrap_or(0));
        }
        Ok(None) => {}
    }

    let tip = chain_tip_snapshot_nonblocking(chain);
    if tip.available {
        json!(authoritative_block_height(None, tip.height).unwrap_or(0))
    } else {
        json!({
            "error": tip.error,
            "fail_closed": true,
            "chain_state_available": false,
            "chain": chain_identity_json(),
        })
    }
}

fn node_health_json(chain: &Arc<Mutex<BlockChain>>) -> Value {
    let tip = chain_tip_snapshot_for_status(chain);
    let timestamp_delta_seconds = tip
        .timestamp
        .map(|timestamp| current_timestamp().saturating_sub(timestamp));
    let quarantine_files = quarantine_marker_paths();
    let status = if !quarantine_files.is_empty() {
        "quarantined"
    } else if tip.available {
        "healthy"
    } else {
        "degraded"
    };
    json!({
        "status": status,
        "latest_height": tip.height,
        "latest_hash": tip.hash,
        "latest_timestamp": tip.timestamp,
        "timestamp_delta_seconds": timestamp_delta_seconds,
        "quarantine_files": quarantine_files,
        "chain_state_available": tip.available,
        "chain_state_error": tip.error,
        "fail_closed": !tip.available,
        "sync": sync_status_json_with_tip(&tip),
        "chain": chain_identity_json(),
    })
}

fn node_readiness_json(chain: &Arc<Mutex<BlockChain>>) -> Value {
    let health = node_health_json(chain);
    let ready = health
        .get("status")
        .and_then(Value::as_str)
        .map(|status| status == "healthy")
        .unwrap_or(false);
    json!({
        "ready": ready,
        "health": health,
        "chain": chain_identity_json(),
    })
}

fn quarantine_marker_paths() -> Vec<String> {
    [
        "data/validator_quarantine.json",
        "data/validator_quarantine_peer_evidence.json",
    ]
    .into_iter()
    .filter_map(|path| {
        let resolved = crate::utils::resolve_data_path(path);
        resolved
            .exists()
            .then(|| resolved.to_string_lossy().to_string())
    })
    .collect()
}

fn latest_canonical_lock_json() -> Value {
    let path = crate::utils::resolve_data_path("data/canonical_locks.json");
    let Ok(content) = fs::read_to_string(&path) else {
        return json!({
            "found": false,
            "path": path.to_string_lossy(),
            "chain": chain_identity_json(),
        });
    };
    let Ok(value) = serde_json::from_str::<Value>(&content) else {
        return json!({
            "found": false,
            "error": "canonical lock file is not valid JSON",
            "path": path.to_string_lossy(),
            "chain": chain_identity_json(),
        });
    };
    let Some(map) = value.as_object() else {
        return json!({
            "found": false,
            "error": "canonical lock file is not a height map",
            "path": path.to_string_lossy(),
            "chain": chain_identity_json(),
        });
    };
    let Some(height) = map.keys().filter_map(|key| key.parse::<u64>().ok()).max() else {
        return json!({
            "found": false,
            "path": path.to_string_lossy(),
            "chain": chain_identity_json(),
        });
    };
    let mut lock = map
        .get(&height.to_string())
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let Value::Object(ref mut obj) = lock {
        obj.insert("found".to_string(), json!(true));
        obj.insert("chain".to_string(), chain_identity_json());
    }
    lock
}

fn latest_finalized_head_json(chain: &Arc<Mutex<BlockChain>>) -> Value {
    match finality_records_for_rpc() {
        Err(error) => return finality_rpc_error(error),
        Ok(Some(records)) => {
            if let Some(record) = records.iter().last() {
                return finality_record_to_finalized_head_json(record);
            }
            return json!({
                "found": false,
                "height": 0,
                "block_hash": current_genesis_hash(),
                "source": "finality_store_genesis_boundary",
                "chain": chain_identity_json(),
            });
        }
        Ok(None) => {}
    }

    let lock = latest_canonical_lock_json();
    if lock.get("found").and_then(Value::as_bool) == Some(true) {
        return lock;
    }
    if let Some(block) = read_through_chain_tip_block(chain) {
        json!({
            "found": true,
            "height": block.block_index,
            "block_hash": block.hash,
            "parent_hash": block.previous_hash,
            "timestamp": block.timestamp,
            "source": "chain_tip_without_canonical_lock_file",
            "chain": chain_identity_json(),
        })
    } else {
        json!({
            "found": false,
            "error": QRPC_CHAIN_UNAVAILABLE_ERROR,
            "fail_closed": true,
            "chain_state_available": false,
            "chain": chain_identity_json(),
        })
    }
}

const REVERSE_LINE_CHUNK_BYTES: usize = 64 * 1024;

fn read_last_nonempty_line(path: &Path) -> std::io::Result<Option<String>> {
    let mut file = fs::File::open(path)?;
    let mut position = file.seek(SeekFrom::End(0))?;
    let mut suffix = Vec::new();

    while position > 0 {
        let chunk_len = usize::try_from(position.min(REVERSE_LINE_CHUNK_BYTES as u64))
            .unwrap_or(REVERSE_LINE_CHUNK_BYTES);
        position -= chunk_len as u64;
        file.seek(SeekFrom::Start(position))?;

        let mut chunk = vec![0_u8; chunk_len];
        file.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&suffix);

        let mut line_end = chunk.len();
        for newline in chunk
            .iter()
            .enumerate()
            .rev()
            .filter_map(|(index, byte)| (*byte == b'\n').then_some(index))
        {
            let line = &chunk[newline + 1..line_end];
            if line.iter().any(|byte| !byte.is_ascii_whitespace()) {
                return String::from_utf8(line.to_vec())
                    .map(Some)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
            }
            line_end = newline;
        }

        suffix = chunk[..line_end].to_vec();
    }

    if suffix.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return String::from_utf8(suffix)
            .map(Some)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
    }
    Ok(None)
}

fn latest_committed_qc_json() -> Value {
    let path = crate::utils::resolve_data_path("data/committed_qcs.jsonl");
    let Ok(last_line) = read_last_nonempty_line(&path) else {
        return json!({
            "found": false,
            "path": path.to_string_lossy(),
            "chain": chain_identity_json(),
        });
    };
    let Some(line) = last_line else {
        return json!({
            "found": false,
            "path": path.to_string_lossy(),
            "chain": chain_identity_json(),
        });
    };
    match serde_json::from_str::<Value>(&line) {
        Ok(mut value) => {
            if let Value::Object(ref mut obj) = value {
                obj.insert("found".to_string(), json!(true));
                obj.insert("chain".to_string(), chain_identity_json());
            }
            value
        }
        Err(error) => json!({
            "found": false,
            "error": format!("latest committed QC line is not JSON: {error}"),
            "path": path.to_string_lossy(),
            "chain": chain_identity_json(),
        }),
    }
}

fn aegis_status_json() -> Value {
    match crate::crypto::aegis_pqvm::AegisPqvmSigner::initialize_required() {
        Ok(_) => json!({
            "present": true,
            "initialized": true,
            "available": true,
            "fail_closed": true,
            "private_key_material_exposed": false,
            "chain": chain_identity_json(),
        }),
        Err(error) => json!({
            "present": false,
            "initialized": false,
            "available": false,
            "fail_closed": true,
            "error": error.to_string(),
            "chain": chain_identity_json(),
        }),
    }
}

fn aegis_capabilities_json() -> Value {
    json!({
        "domains": [
            "SYNERGY_TX_V1",
            "SYNERGY_DAG_NODE_V1",
            "SYNERGY_BLOCK_V1",
            "SYNERGY_VOTE_V1",
            "SYNERGY_QC_V1",
            "SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1",
            "SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1"
        ],
        "roles": [
            "Transaction",
            "ConsensusVote",
            "ConsensusProposer",
            "PeerIdentity",
            "ArchivePeer",
            "ArchiveSnapshotSigner"
        ],
        "signing_via_public_rpc": false,
        "private_key_material_exposed": false,
        "fail_closed": true,
        "chain": chain_identity_json(),
    })
}

fn aegis_fail_closed_json(method: &str, reason: &str) -> Value {
    json!({
        "error": reason,
        "method": method,
        "fail_closed": true,
        "aegis_pqvm_required": true,
        "chain": chain_identity_json(),
    })
}

fn verify_aegis_transaction_envelope(envelope_value: &Value) -> Value {
    let envelope = match serde_json::from_value::<crate::aegis_tx_tool::AegisTxSubmissionEnvelope>(
        envelope_value.clone(),
    ) {
        Ok(envelope) => envelope,
        Err(error) => {
            return json!({
                "error": format!("Invalid Aegis transaction envelope: {error}"),
                "fail_closed": true,
            });
        }
    };
    match crate::aegis_tx_tool::legacy_transaction_from_aegis_envelope(&envelope) {
        Ok(transaction) => json!({
            "valid": true,
            "aegis_pqvm_verification": "verified",
            "wallet_cli_used": false,
            "tx_hash": transaction.hash(),
            "chain": chain_identity_json(),
        }),
        Err(error) => json!({
            "error": error,
            "valid": false,
            "fail_closed": true,
            "wallet_cli_used": false,
            "chain": chain_identity_json(),
        }),
    }
}

fn dag_dependencies_json(params: &Value) -> Value {
    if let Some(hash) = params.get(0).and_then(Value::as_str) {
        let vertex = crate::dag::vertex_json(hash);
        let parents = vertex
            .get("parent_hashes")
            .cloned()
            .unwrap_or_else(|| json!([]));
        return json!({
            "dag_node_id": hash,
            "dependencies": parents,
            "found": vertex.is_object(),
            "chain": chain_identity_json(),
        });
    }
    let limit = dag_rpc_limit(params, 100, 1_000);
    let topology = crate::dag::topology_json(limit);
    json!({
        "root": topology.get("root").cloned().unwrap_or_else(|| json!(crate::dag::GENESIS_DAG_ROOT)),
        "dependencies": topology.get("edges").cloned().unwrap_or_else(|| json!([])),
        "chain": chain_identity_json(),
    })
}

fn dag_tx_order_root_json(params: &Value) -> Value {
    let limit = dag_rpc_limit(params, 1_000, 10_000);
    let topology = crate::dag::topology_json(limit);
    let tx_order_root = canonical_value_digest(&topology)
        .unwrap_or_else(|| crate::dag::GENESIS_DAG_ROOT.to_string());
    json!({
        "tx_order_root": tx_order_root,
        "root": topology.get("root").cloned().unwrap_or_else(|| json!(crate::dag::GENESIS_DAG_ROOT)),
        "vertex_count": topology.get("vertices").and_then(Value::as_array).map(|items| items.len()).unwrap_or(0),
        "edge_count": topology.get("edges").and_then(Value::as_array).map(|items| items.len()).unwrap_or(0),
        "deterministic": true,
        "chain": chain_identity_json(),
    })
}

fn transaction_lookup_json(
    params: &Value,
    tx_pool: &Arc<Mutex<Vec<Transaction>>>,
    chain: &Arc<Mutex<BlockChain>>,
) -> Value {
    let Some(tx_hash) = params.get(0).and_then(Value::as_str) else {
        return json!({"error": "Missing transaction hash parameter"});
    };
    let normalized = tx_hash.strip_prefix("0x").unwrap_or(tx_hash).to_lowercase();
    let raw_hash_search = normalized
        .strip_prefix("syntxn-")
        .or_else(|| normalized.strip_prefix("synxxn-"))
        .unwrap_or(&normalized);
    let matches_tx = |tx: &Transaction| -> bool {
        let tx_hash_formatted = tx.hash().to_lowercase();
        let tx_hash_raw = tx.raw_hash().to_lowercase();
        tx_hash_formatted == normalized
            || tx_hash_raw == normalized
            || tx_hash_raw == raw_hash_search
            || tx_hash_formatted
                .strip_prefix("syntxn-")
                .map(|hash| hash == raw_hash_search)
                .unwrap_or(false)
            || tx_hash_formatted
                .strip_prefix("synxxn-")
                .map(|hash| hash == raw_hash_search)
                .unwrap_or(false)
    };
    {
        let chain = chain.lock().unwrap();
        for block in &chain.chain {
            for (idx, tx) in block.transactions.iter().enumerate() {
                if matches_tx(tx) {
                    return tx_to_explorer_json(
                        tx,
                        "confirmed",
                        Some(block.block_index),
                        Some(idx),
                    );
                }
            }
        }
    }
    let pool = tx_pool.lock().unwrap();
    for tx in pool.iter() {
        if matches_tx(tx) {
            return tx_to_explorer_json(tx, "pending", None, None);
        }
    }
    json!(null)
}

fn transaction_status_json(
    params: &Value,
    tx_pool: &Arc<Mutex<Vec<Transaction>>>,
    chain: &Arc<Mutex<BlockChain>>,
) -> Value {
    let Some(tx_hash) = params.get(0).and_then(Value::as_str) else {
        return json!({"error": "Missing transaction hash parameter"});
    };
    let dag_status = crate::dag::transaction_status_json(tx_hash);
    if dag_status.get("found").and_then(Value::as_bool) == Some(true) {
        return dag_status;
    }
    let transaction = transaction_lookup_json(params, tx_pool, chain);
    if transaction.is_null() {
        json!({
            "found": false,
            "tx_hash": tx_hash,
            "status": "not_found",
            "dag": dag_status,
            "chain": chain_identity_json(),
        })
    } else {
        json!({
            "found": true,
            "tx_hash": tx_hash,
            "status": transaction.get("status").cloned().unwrap_or_else(|| json!("unknown")),
            "transaction": transaction,
            "dag": dag_status,
            "chain": chain_identity_json(),
        })
    }
}

fn transaction_receipt_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let index_path = configured_synq_receipt_index_path();
    transaction_receipt_json_with_index_path(params, chain, Some(&index_path))
}

fn block_receipts_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let index_path = configured_synq_receipt_index_path();
    block_receipts_json_with_index_path(params, chain, Some(&index_path))
}

fn transaction_receipt_json_with_index_path(
    params: &Value,
    chain: &Arc<Mutex<BlockChain>>,
    index_path: Option<&Path>,
) -> Value {
    let Some(tx_hash) = params.get(0).and_then(Value::as_str) else {
        return json!({"error": "Missing transaction hash parameter"});
    };
    let chain = chain.lock().unwrap();

    let Some((block_index, tx_index)) = find_confirmed_transaction_position(&chain, tx_hash) else {
        let index = load_synq_receipt_index(index_path);
        if let Some(indexed) = index.receipt_by_query(tx_hash) {
            return indexed.receipt.clone();
        }
        return json!(null);
    };

    let synq_receipts = materialize_synq_receipt_index(&chain, Some(block_index), index_path);
    let Some(block) = chain
        .chain
        .iter()
        .find(|block| block.block_index == block_index)
    else {
        return json!(null);
    };

    let mut cumulative_gas: u64 = 0;
    for (idx, tx) in block.transactions.iter().enumerate() {
        let synq = synq_receipts
            .receipt_for_position(block.block_index, idx)
            .map(|receipt| &receipt.receipt);
        let gas_used = receipt_gas_used(tx, synq);
        cumulative_gas = cumulative_gas.saturating_add(gas_used);
        if idx == tx_index {
            if let Some(indexed) = synq_receipts.receipt_by_query(tx_hash) {
                return indexed.receipt.clone();
            }
            return confirmed_transaction_receipt_json(
                block,
                idx,
                tx,
                cumulative_gas,
                gas_used,
                synq,
            );
        }
    }
    json!(null)
}

fn block_receipts_json_with_index_path(
    params: &Value,
    chain: &Arc<Mutex<BlockChain>>,
    index_path: Option<&Path>,
) -> Value {
    let chain = chain.lock().unwrap();
    let block = if let Some(block_num) = params.get(0).and_then(|v| v.as_u64()) {
        chain.chain.iter().find(|b| b.block_index == block_num)
    } else if let Some(block_hash) = params.get(0).and_then(|v| v.as_str()) {
        chain
            .chain
            .iter()
            .find(|b| b.hash.eq_ignore_ascii_case(block_hash))
    } else {
        return json!({"error": "Missing block number or block hash parameter"});
    };

    if let Some(block) = block {
        let synq_receipts =
            materialize_synq_receipt_index(&chain, Some(block.block_index), index_path);
        let mut cumulative_gas: u64 = 0;
        let receipts: Vec<Value> = block
            .transactions
            .iter()
            .enumerate()
            .map(|(idx, tx)| {
                let synq = synq_receipts
                    .receipt_for_position(block.block_index, idx)
                    .map(|receipt| &receipt.receipt);
                let gas_used = receipt_gas_used(tx, synq);
                cumulative_gas = cumulative_gas.saturating_add(gas_used);
                confirmed_transaction_receipt_json(block, idx, tx, cumulative_gas, gas_used, synq)
            })
            .collect();
        json!(receipts)
    } else {
        json!(null)
    }
}

fn find_confirmed_transaction_position(chain: &BlockChain, tx_hash: &str) -> Option<(u64, usize)> {
    let normalized = tx_hash.strip_prefix("0x").unwrap_or(tx_hash).to_lowercase();
    let raw_hash_search = normalized
        .strip_prefix("syntxn-")
        .or_else(|| normalized.strip_prefix("synxxn-"))
        .unwrap_or(&normalized);
    for block in &chain.chain {
        for (idx, tx) in block.transactions.iter().enumerate() {
            if transaction_matches_hash_query(tx, &normalized, raw_hash_search) {
                return Some((block.block_index, idx));
            }
        }
    }
    None
}

fn transaction_matches_hash_query(
    tx: &Transaction,
    normalized: &str,
    raw_hash_search: &str,
) -> bool {
    let tx_hash_formatted = tx.hash().to_lowercase();
    let tx_hash_raw = tx.raw_hash().to_lowercase();
    tx_hash_formatted == normalized
        || tx_hash_raw == normalized
        || tx_hash_raw == raw_hash_search
        || tx_hash_formatted
            .strip_prefix("syntxn-")
            .map(|hash| hash == raw_hash_search)
            .unwrap_or(false)
        || tx_hash_formatted
            .strip_prefix("synxxn-")
            .map(|hash| hash == raw_hash_search)
            .unwrap_or(false)
}

fn legacy_receipt_gas_used(tx: &Transaction) -> u64 {
    if tx.data.is_some() {
        tx.gas_limit.min(tx.estimate_gas())
    } else {
        crate::gas::constants::GAS_LIMIT_TRANSFER
    }
}

fn receipt_gas_used(tx: &Transaction, synq_receipt: Option<&Value>) -> u64 {
    synq_receipt
        .and_then(|receipt| receipt.get("synq_aivm"))
        .and_then(|aivm| aivm.get("gas_used"))
        .and_then(Value::as_u64)
        .unwrap_or_else(|| legacy_receipt_gas_used(tx))
}

fn u128_rpc_value(value: u128) -> Value {
    u64::try_from(value)
        .map(Value::from)
        .unwrap_or_else(|_| Value::String(value.to_string()))
}

fn sts_native_asset_json() -> Value {
    let native = crate::sts::native_snrg_definition();
    json!({
        "asset_kind": "native",
        "native": native.native,
        "gas_asset": native.gas_asset,
        "symbol": native.symbol,
        "name": native.name,
        "decimals": native.decimals,
        "token_id": null,
        "token_address": native.token_address,
        "compatibility_placeholder_address": crate::sts::NATIVE_SNRG_PLACEHOLDER_ADDRESS,
        "chain_id": crate::sts::STS_TESTNET_CHAIN_ID,
        "network": crate::sts::STS_TESTNET_NETWORK,
    })
}

fn is_native_snrg_ref(token_ref: &str) -> bool {
    let token_ref = token_ref.trim();
    token_ref.eq_ignore_ascii_case(crate::sts::NATIVE_SNRG_SYMBOL)
        || token_ref == crate::sts::NATIVE_SNRG_PLACEHOLDER_ADDRESS
}

fn sts_rpc_token_param(params: &Value, array_index: usize) -> Option<String> {
    rpc_string_param(params, "token", array_index)
        .or_else(|| rpc_string_param(params, "token_id", array_index))
        .or_else(|| rpc_string_param(params, "tokenId", array_index))
        .or_else(|| rpc_string_param(params, "token_address", array_index))
        .or_else(|| rpc_string_param(params, "tokenAddress", array_index))
}

fn sts_rpc_owner_param(params: &Value, array_index: usize) -> Option<String> {
    rpc_string_param(params, "owner", array_index)
        .or_else(|| rpc_string_param(params, "address", array_index))
        .or_else(|| rpc_string_param(params, "wallet", array_index))
        .or_else(|| rpc_string_param(params, "account", array_index))
}

fn sts_rpc_collection_param(params: &Value, array_index: usize) -> Option<String> {
    rpc_string_param(params, "collection", array_index)
        .or_else(|| rpc_string_param(params, "collection_id", array_index))
        .or_else(|| rpc_string_param(params, "collectionId", array_index))
        .or_else(|| rpc_string_param(params, "collection_address", array_index))
        .or_else(|| rpc_string_param(params, "collectionAddress", array_index))
}

fn sts_rpc_nft_param(params: &Value, array_index: usize) -> Option<String> {
    rpc_string_param(params, "nft", array_index)
        .or_else(|| rpc_string_param(params, "nft_id", array_index))
        .or_else(|| rpc_string_param(params, "nftId", array_index))
        .or_else(|| rpc_string_param(params, "nft_address", array_index))
        .or_else(|| rpc_string_param(params, "nftAddress", array_index))
}

fn sts_rpc_credential_param(params: &Value, array_index: usize) -> Option<String> {
    rpc_string_param(params, "credential", array_index)
        .or_else(|| rpc_string_param(params, "credential_id", array_index))
        .or_else(|| rpc_string_param(params, "credentialId", array_index))
}

fn sts_rpc_schema_param(params: &Value, array_index: usize) -> Option<String> {
    rpc_string_param(params, "schema", array_index)
        .or_else(|| rpc_string_param(params, "schema_id", array_index))
        .or_else(|| rpc_string_param(params, "schemaId", array_index))
}

fn sts_rpc_issuer_param(params: &Value, array_index: usize) -> Option<String> {
    rpc_string_param(params, "issuer", array_index)
        .or_else(|| rpc_string_param(params, "issuer_address", array_index))
        .or_else(|| rpc_string_param(params, "issuerAddress", array_index))
}

fn sts_tokens_json(chain: &Arc<Mutex<BlockChain>>) -> Value {
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => {
            let sts_items = report
                .state
                .fungible_definitions()
                .into_iter()
                .map(sts_fungible_definition_json)
                .collect::<Vec<_>>();
            let mut items = Vec::with_capacity(sts_items.len() + 1);
            items.push(sts_native_asset_json());
            items.extend(sts_items.clone());
            json!({
                "success": true,
                "source": report.source,
                "native": sts_native_asset_json(),
                "sts": sts_items,
                "items": items,
                "count": items.len(),
                "replay": sts_replay_metadata_json(&report),
            })
        }
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_token_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(token_ref) = sts_rpc_token_param(params, 0) else {
        return json!({"success": false, "error": "Missing token, token_id, or token_address parameter"});
    };
    if is_native_snrg_ref(&token_ref) {
        return json!({
            "success": true,
            "source": "native_runtime_identity",
            "item": sts_native_asset_json(),
        });
    }

    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => match report.state.fungible_definition(&token_ref) {
            Some(definition) => json!({
                "success": true,
                "source": report.source,
                "item": sts_fungible_definition_json(definition),
                "replay": sts_replay_metadata_json(&report),
            }),
            None => json!({
                "success": false,
                "error": "STS token not found",
                "token_ref": token_ref,
                "replay": sts_replay_metadata_json(&report),
            }),
        },
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_balance_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(owner) = sts_rpc_owner_param(params, 0) else {
        return json!({"success": false, "error": "Missing owner/address parameter"});
    };
    let Some(token_ref) = sts_rpc_token_param(params, 1) else {
        return json!({"success": false, "error": "Missing token, token_id, or token_address parameter"});
    };
    if is_native_snrg_ref(&token_ref) {
        let balance = TOKEN_MANAGER
            .clone()
            .get_balance(&owner, crate::sts::NATIVE_SNRG_SYMBOL);
        return json!({
            "success": true,
            "source": "native_snrg_ledger",
            "asset_kind": "native",
            "owner": owner,
            "symbol": crate::sts::NATIVE_SNRG_SYMBOL,
            "token_id": null,
            "token_address": null,
            "balance": balance,
            "balance_nwei": balance,
        });
    }

    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => {
            let Some(definition) = report.state.fungible_definition(&token_ref) else {
                return json!({
                    "success": false,
                    "error": "STS token not found",
                    "owner": owner,
                    "token_ref": token_ref,
                    "replay": sts_replay_metadata_json(&report),
                });
            };
            let balance = report.state.fungible_balance(&owner, &definition.token_id);
            let frozen = report
                .state
                .fungible_balance_entry(&owner, &definition.token_id)
                .map(|entry| entry.frozen)
                .unwrap_or(false);
            json!({
                "success": true,
                "source": report.source,
                "asset_kind": "sts",
                "owner": owner,
                "token_id": definition.token_id,
                "token_address": definition.token_address,
                "symbol": definition.symbol,
                "decimals": definition.decimals,
                "balance": u128_rpc_value(balance),
                "frozen": frozen,
                "replay": sts_replay_metadata_json(&report),
            })
        }
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_balances_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(owner) = sts_rpc_owner_param(params, 0) else {
        return json!({"success": false, "error": "Missing owner/address parameter"});
    };
    let native_balance = TOKEN_MANAGER
        .clone()
        .get_balance(&owner, crate::sts::NATIVE_SNRG_SYMBOL);

    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => {
            let mut items = vec![json!({
                "asset_kind": "native",
                "owner": owner,
                "symbol": crate::sts::NATIVE_SNRG_SYMBOL,
                "token_id": null,
                "token_address": null,
                "balance": native_balance,
                "balance_nwei": native_balance,
            })];
            items.extend(
                report
                    .state
                    .fungible_balances_for_owner(&owner)
                    .into_iter()
                    .filter_map(|balance| {
                        report
                            .state
                            .fungible_definition(&balance.token_id)
                            .map(|definition| sts_fungible_balance_json(balance, definition))
                    }),
            );
            json!({
                "success": true,
                "source": format!("native_snrg_ledger_and_{}", report.source),
                "owner": owner,
                "items": items,
                "count": items.len(),
                "replay": sts_replay_metadata_json(&report),
            })
        }
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_nft_collection_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(collection_ref) = sts_rpc_collection_param(params, 0) else {
        return json!({"success": false, "error": "Missing collection parameter"});
    };
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => match report.state.nft_collection(&collection_ref) {
            Some(collection) => json!({
                "success": true,
                "source": report.source,
                "item": sts_nft_collection_item_json(collection),
                "replay": sts_replay_metadata_json(&report),
            }),
            None => json!({
                "success": false,
                "error": "STS NFT collection not found",
                "collection_ref": collection_ref,
                "replay": sts_replay_metadata_json(&report),
            }),
        },
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_nft_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(nft_ref) = sts_rpc_nft_param(params, 0) else {
        return json!({"success": false, "error": "Missing nft parameter"});
    };
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => match report.state.nft(&nft_ref) {
            Some(nft) => json!({
                "success": true,
                "source": report.source,
                "item": sts_nft_item_json(nft),
                "replay": sts_replay_metadata_json(&report),
            }),
            None => json!({
                "success": false,
                "error": "STS NFT not found",
                "nft_ref": nft_ref,
                "replay": sts_replay_metadata_json(&report),
            }),
        },
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_nfts_by_owner_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(owner) = sts_rpc_owner_param(params, 0) else {
        return json!({"success": false, "error": "Missing owner/address parameter"});
    };
    let limit = rpc_u64_param(params, "limit", 1).unwrap_or(100).min(1_000) as usize;
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => {
            let mut items = report
                .state
                .nfts_for_owner(&owner)
                .into_iter()
                .map(sts_nft_item_json)
                .collect::<Vec<_>>();
            if items.len() > limit {
                items.truncate(limit);
            }
            json!({
                "success": true,
                "source": report.source,
                "owner": owner,
                "items": items,
                "count": items.len(),
                "replay": sts_replay_metadata_json(&report),
            })
        }
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_nfts_by_collection_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(collection_ref) = sts_rpc_collection_param(params, 0) else {
        return json!({"success": false, "error": "Missing collection parameter"});
    };
    let limit = rpc_u64_param(params, "limit", 1).unwrap_or(100).min(1_000) as usize;
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => {
            let mut items = report
                .state
                .nfts_for_collection(&collection_ref)
                .into_iter()
                .map(sts_nft_item_json)
                .collect::<Vec<_>>();
            if items.len() > limit {
                items.truncate(limit);
            }
            json!({
                "success": true,
                "source": report.source,
                "collection_ref": collection_ref,
                "items": items,
                "count": items.len(),
                "replay": sts_replay_metadata_json(&report),
            })
        }
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_multi_asset_collection_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(collection_ref) = sts_rpc_collection_param(params, 0) else {
        return json!({"success": false, "error": "Missing collection parameter"});
    };
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => match report.state.multi_asset_collection(&collection_ref) {
            Some(collection) => json!({
                "success": true,
                "source": report.source,
                "item": sts_multi_asset_collection_item_json(collection),
                "replay": sts_replay_metadata_json(&report),
            }),
            None => json!({
                "success": false,
                "error": "STS multi-asset collection not found",
                "collection_ref": collection_ref,
                "replay": sts_replay_metadata_json(&report),
            }),
        },
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_multi_asset_item_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(collection_ref) = sts_rpc_collection_param(params, 0) else {
        return json!({"success": false, "error": "Missing collection parameter"});
    };
    let Some(item_id) =
        rpc_u64_param(params, "item_id", 1).or_else(|| rpc_u64_param(params, "itemId", 1))
    else {
        return json!({"success": false, "error": "Missing item_id parameter"});
    };
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => match report.state.multi_asset_item(&collection_ref, item_id) {
            Some(item) => json!({
                "success": true,
                "source": report.source,
                "item": sts_multi_asset_item_item_json(item),
                "replay": sts_replay_metadata_json(&report),
            }),
            None => json!({
                "success": false,
                "error": "STS multi-asset item not found",
                "collection_ref": collection_ref,
                "item_id": item_id,
                "replay": sts_replay_metadata_json(&report),
            }),
        },
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_multi_asset_balance_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(owner) = sts_rpc_owner_param(params, 0) else {
        return json!({"success": false, "error": "Missing owner/address parameter"});
    };
    let Some(collection_ref) = sts_rpc_collection_param(params, 1) else {
        return json!({"success": false, "error": "Missing collection parameter"});
    };
    let Some(item_id) =
        rpc_u64_param(params, "item_id", 2).or_else(|| rpc_u64_param(params, "itemId", 2))
    else {
        return json!({"success": false, "error": "Missing item_id parameter"});
    };
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => {
            let Some(collection) = report.state.multi_asset_collection(&collection_ref) else {
                return json!({
                    "success": false,
                    "error": "STS multi-asset collection not found",
                    "collection_ref": collection_ref,
                    "replay": sts_replay_metadata_json(&report),
                });
            };
            let balance =
                report
                    .state
                    .multi_asset_balance(&owner, &collection.collection_id, item_id);
            json!({
                "success": true,
                "source": report.source,
                "owner": owner,
                "collection_id": collection.collection_id,
                "collection_address": collection.collection_address,
                "item_id": item_id,
                "amount": u128_rpc_value(balance),
                "replay": sts_replay_metadata_json(&report),
            })
        }
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_multi_asset_balances_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(owner) = sts_rpc_owner_param(params, 0) else {
        return json!({"success": false, "error": "Missing owner/address parameter"});
    };
    let collection_ref = sts_rpc_collection_param(params, 1);
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => {
            let items = report
                .state
                .multi_asset_balances_for_owner(&owner, collection_ref.as_deref())
                .into_iter()
                .map(sts_multi_asset_balance_entry_json)
                .collect::<Vec<_>>();
            json!({
                "success": true,
                "source": report.source,
                "owner": owner,
                "collection_ref": collection_ref,
                "items": items,
                "count": items.len(),
                "replay": sts_replay_metadata_json(&report),
            })
        }
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_credential_schema_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(issuer) = sts_rpc_issuer_param(params, 0) else {
        return json!({"success": false, "error": "Missing issuer parameter"});
    };
    let Some(schema_id) = sts_rpc_schema_param(params, 1) else {
        return json!({"success": false, "error": "Missing schema_id parameter"});
    };
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => match report.state.credential_schema(&issuer, &schema_id) {
            Some(schema) => json!({
                "success": true,
                "source": report.source,
                "item": sts_credential_schema_item_json(schema),
                "replay": sts_replay_metadata_json(&report),
            }),
            None => json!({
                "success": false,
                "error": "STS credential schema not found",
                "issuer": issuer,
                "schema_id": schema_id,
                "replay": sts_replay_metadata_json(&report),
            }),
        },
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_credential_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(credential_id) = sts_rpc_credential_param(params, 0) else {
        return json!({"success": false, "error": "Missing credential parameter"});
    };
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => match report.state.credential(&credential_id) {
            Some(credential) => json!({
                "success": true,
                "source": report.source,
                "item": sts_credential_item_json(credential),
                "replay": sts_replay_metadata_json(&report),
            }),
            None => json!({
                "success": false,
                "error": "STS credential not found",
                "credential_id": credential_id,
                "replay": sts_replay_metadata_json(&report),
            }),
        },
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_credentials_by_subject_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(subject) = rpc_string_param(params, "subject", 0)
        .or_else(|| rpc_string_param(params, "subject_commitment", 0))
        .or_else(|| rpc_string_param(params, "subjectCommitment", 0))
    else {
        return json!({"success": false, "error": "Missing subject or subject_commitment parameter"});
    };
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => {
            let items = report
                .state
                .credentials_for_subject(&subject)
                .into_iter()
                .map(sts_credential_item_json)
                .collect::<Vec<_>>();
            json!({
                "success": true,
                "source": report.source,
                "subject": subject,
                "items": items,
                "count": items.len(),
                "replay": sts_replay_metadata_json(&report),
            })
        }
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_verify_credential_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(subject) = rpc_string_param(params, "subject", 0)
        .or_else(|| rpc_string_param(params, "subject_commitment", 0))
        .or_else(|| rpc_string_param(params, "subjectCommitment", 0))
    else {
        return json!({"success": false, "error": "Missing subject or subject_commitment parameter"});
    };
    let Some(schema_id) = sts_rpc_schema_param(params, 1) else {
        return json!({"success": false, "error": "Missing schema_id parameter"});
    };
    let Some(issuer) = sts_rpc_issuer_param(params, 2) else {
        return json!({"success": false, "error": "Missing issuer parameter"});
    };
    let timestamp = rpc_u64_param(params, "timestamp", 3).unwrap_or_else(current_unix_seconds);
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => {
            let matching = report
                .state
                .credentials_for_subject(&subject)
                .into_iter()
                .find(|credential| {
                    credential.schema_id == schema_id && credential.issuer == issuer
                });
            match matching {
                Some(credential) => match report
                    .state
                    .verify_credential_active_at(&credential.credential_id, timestamp)
                {
                    Ok(()) => json!({
                        "success": true,
                        "source": report.source,
                        "verified": true,
                        "credential_id": credential.credential_id,
                        "status": credential.status,
                        "timestamp": timestamp,
                        "replay": sts_replay_metadata_json(&report),
                    }),
                    Err(error) => json!({
                        "success": true,
                        "source": report.source,
                        "verified": false,
                        "credential_id": credential.credential_id,
                        "status": credential.status,
                        "error": error.to_string(),
                        "timestamp": timestamp,
                        "replay": sts_replay_metadata_json(&report),
                    }),
                },
                None => json!({
                    "success": true,
                    "source": report.source,
                    "verified": false,
                    "error": "credential not found",
                    "subject": subject,
                    "schema_id": schema_id,
                    "issuer": issuer,
                    "timestamp": timestamp,
                    "replay": sts_replay_metadata_json(&report),
                }),
            }
        }
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_credential_status_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(credential_id) = sts_rpc_credential_param(params, 0) else {
        return json!({"success": false, "error": "Missing credential parameter"});
    };
    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => match report.state.credential(&credential_id) {
            Some(credential) => json!({
                "success": true,
                "source": report.source,
                "credential_id": credential.credential_id,
                "status": credential.status,
                "expires_at": credential.expires_at,
                "revoked_at": credential.revoked_at,
                "replay": sts_replay_metadata_json(&report),
            }),
            None => json!({
                "success": false,
                "error": "STS credential not found",
                "credential_id": credential_id,
                "replay": sts_replay_metadata_json(&report),
            }),
        },
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_events_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let token_ref = sts_rpc_token_param(params, 0);
    let owner = sts_rpc_owner_param(params, 1);
    let limit = rpc_u64_param(params, "limit", 2).unwrap_or(100).min(1_000) as usize;

    let chain = chain.lock().unwrap();
    match sts_state_from_snapshot_or_chain(&chain) {
        Ok(report) => {
            let events = report
                .state
                .events_for(token_ref.as_deref(), owner.as_deref(), limit)
                .into_iter()
                .map(sts_event_json)
                .collect::<Vec<_>>();
            json!({
                "success": true,
                "source": report.source,
                "token_ref": token_ref,
                "owner": owner,
                "items": events,
                "count": events.len(),
                "replay": sts_replay_metadata_json(&report),
            })
        }
        Err(error) => sts_unavailable_json(error.message),
    }
}

fn sts_state_from_snapshot_or_chain(chain: &BlockChain) -> Result<StsReplayReport, RpcError> {
    match crate::sts::load_sts_state_snapshot() {
        Ok(Some(snapshot)) => {
            let latest_height = chain
                .last()
                .map(|block| block.block_index)
                .unwrap_or(snapshot.latest_block_height);
            let applied_transactions = snapshot.processed_transactions.len();
            let skipped_payloads = snapshot
                .processed_transactions
                .values()
                .filter(|tx| tx.status != "applied")
                .count();
            let errors = snapshot
                .processed_transactions
                .iter()
                .filter_map(|(tx_hash, tx)| {
                    tx.error.as_ref().map(|error| {
                        format!(
                            "block {} tx {} skipped: {}",
                            tx.block_height, tx_hash, error
                        )
                    })
                })
                .collect();
            Ok(StsReplayReport {
                source: "finalized_sts_snapshot",
                state: snapshot.state,
                chain_start_height: snapshot.latest_block_height,
                latest_height,
                snapshot_block_hash: Some(snapshot.latest_block_hash),
                snapshot_updated_at: Some(snapshot.updated_at),
                scanned_blocks: 0,
                scanned_transactions: 0,
                applied_transactions,
                skipped_payloads,
                errors,
            })
        }
        Ok(None) => sts_replay_from_chain(chain),
        Err(error) => Err(RpcError::new(
            -32021,
            format!("STS state unavailable: finalized STS snapshot is invalid: {error}"),
        )),
    }
}

fn sts_replay_from_chain(chain: &BlockChain) -> Result<StsReplayReport, RpcError> {
    let Some(first_block) = chain.chain.first() else {
        return Err(RpcError::new(
            -32021,
            "STS state unavailable: committed chain is empty and cannot be replayed from genesis",
        ));
    };
    if first_block.block_index != 0 {
        return Err(RpcError::new(
            -32021,
            format!(
                "STS state unavailable: hot chain starts at height {}, so replay from genesis is incomplete",
                first_block.block_index
            ),
        ));
    }

    let mut state = crate::sts::StsState::new();
    let mut scanned_transactions = 0usize;
    let mut applied_transactions = 0usize;
    let mut skipped_payloads = 0usize;
    let mut errors = Vec::new();

    for block in &chain.chain {
        for transaction in &block.transactions {
            scanned_transactions = scanned_transactions.saturating_add(1);
            let Some(data) = transaction.data.as_deref() else {
                continue;
            };
            match extract_sts_payload_from_transaction_data(data) {
                Ok(Some(payload)) => {
                    match state.apply_signed_payload(&transaction.sender, &payload) {
                        Ok(_) => {
                            applied_transactions = applied_transactions.saturating_add(1);
                        }
                        Err(error) => {
                            skipped_payloads = skipped_payloads.saturating_add(1);
                            errors.push(format!(
                                "block {} tx {} skipped: {}",
                                block.block_index,
                                transaction.hash(),
                                error
                            ));
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    skipped_payloads = skipped_payloads.saturating_add(1);
                    errors.push(format!(
                        "block {} tx {} malformed STS payload: {}",
                        block.block_index,
                        transaction.hash(),
                        error
                    ));
                }
            }
        }
    }

    Ok(StsReplayReport {
        source: "committed_chain_replay",
        state,
        chain_start_height: first_block.block_index,
        latest_height: chain.last().map(|block| block.block_index).unwrap_or(0),
        snapshot_block_hash: None,
        snapshot_updated_at: None,
        scanned_blocks: chain.chain.len(),
        scanned_transactions,
        applied_transactions,
        skipped_payloads,
        errors,
    })
}

fn extract_sts_payload_from_transaction_data(
    data: &str,
) -> Result<Option<crate::sts::StsSignedPayload>, String> {
    crate::sts::extract_sts_payload_from_transaction_data(data)
}

fn sts_replay_metadata_json(report: &StsReplayReport) -> Value {
    json!({
        "source": report.source,
        "complete": report.errors.is_empty(),
        "chain_start_height": report.chain_start_height,
        "latest_height": report.latest_height,
        "snapshot_block_hash": report.snapshot_block_hash,
        "snapshot_updated_at": report.snapshot_updated_at,
        "scanned_blocks": report.scanned_blocks,
        "scanned_transactions": report.scanned_transactions,
        "applied_transactions": report.applied_transactions,
        "skipped_payloads": report.skipped_payloads,
        "errors": report.errors,
    })
}

fn sts_unavailable_json(message: String) -> Value {
    json!({
        "success": false,
        "source": "finalized_sts_snapshot_or_committed_chain_replay",
        "state_available": false,
        "error": message,
    })
}

fn sts_fungible_definition_json(definition: &crate::sts::FungibleDefinition) -> Value {
    json!({
        "asset_kind": "sts",
        "native": false,
        "gas_asset": false,
        "token_id": definition.token_id,
        "token_address": definition.token_address,
        "class": definition.class,
        "class_prefix": definition.class.prefix(),
        "creator": definition.creator,
        "name": definition.name,
        "symbol": definition.symbol,
        "decimals": definition.decimals,
        "total_supply": u128_rpc_value(definition.total_supply),
        "max_supply": definition.max_supply.map(u128_rpc_value),
        "authorities": definition.authorities,
        "metadata_uri": definition.metadata_uri,
        "metadata_hash": definition.metadata_hash,
        "metadata_mutable": definition.metadata_mutable,
        "image_uri": definition.image_uri,
        "image_hash": definition.image_hash,
        "image_locked": definition.image_locked,
        "created_at": definition.created_at,
        "updated_at": definition.updated_at,
        "flags": definition.flags,
        "policies": definition.policies,
        "paused": definition.paused,
        "verified": definition.verified,
    })
}

fn sts_fungible_balance_json(
    balance: &crate::sts::FungibleBalance,
    definition: &crate::sts::FungibleDefinition,
) -> Value {
    json!({
        "asset_kind": "sts",
        "owner": balance.owner,
        "token_id": definition.token_id,
        "token_address": definition.token_address,
        "symbol": definition.symbol,
        "decimals": definition.decimals,
        "balance": u128_rpc_value(balance.balance),
        "frozen": balance.frozen,
        "created_at": balance.created_at,
        "updated_at": balance.updated_at,
    })
}

fn sts_nft_collection_item_json(collection: &crate::sts::NftCollection) -> Value {
    json!({
        "asset_kind": "nft_collection",
        "collection_id": collection.collection_id,
        "collection_address": collection.collection_address,
        "class": collection.class,
        "class_prefix": collection.class.prefix(),
        "creator": collection.creator,
        "name": collection.name,
        "symbol": collection.symbol,
        "metadata_uri": collection.metadata_uri,
        "metadata_hash": collection.metadata_hash,
        "metadata_mutable": collection.metadata_mutable,
        "image_uri": collection.image_uri,
        "image_hash": collection.image_hash,
        "image_locked": collection.image_locked,
        "authorities": collection.authorities,
        "royalty_basis_points": collection.royalty_basis_points,
        "royalty_recipient": collection.royalty_recipient,
        "verified": collection.verified,
        "transferable": collection.transferable,
        "requires_issuer_approval": collection.requires_issuer_approval,
        "next_serial_number": collection.next_serial_number,
        "created_at": collection.created_at,
        "updated_at": collection.updated_at,
    })
}

fn sts_nft_item_json(nft: &crate::sts::NftInstance) -> Value {
    json!({
        "asset_kind": "nft",
        "nft_id": nft.nft_id,
        "nft_address": nft.nft_address,
        "collection_id": nft.collection_id,
        "class": nft.class,
        "class_prefix": nft.class.prefix(),
        "serial_number": nft.serial_number,
        "owner": nft.owner,
        "metadata_uri": nft.metadata_uri,
        "metadata_hash": nft.metadata_hash,
        "metadata_mutable": nft.metadata_mutable,
        "burned": nft.burned,
        "frozen": nft.frozen,
        "transferable": nft.transferable,
        "requires_issuer_approval": nft.requires_issuer_approval,
        "expires_at": nft.expires_at,
        "revoked": nft.revoked,
        "revoked_at": nft.revoked_at,
        "used": nft.used,
        "used_at": nft.used_at,
        "issuer_authority": nft.issuer_authority,
        "transfer_authority": nft.transfer_authority,
        "created_at": nft.created_at,
        "updated_at": nft.updated_at,
    })
}

fn sts_multi_asset_collection_item_json(collection: &crate::sts::MultiAssetCollection) -> Value {
    json!({
        "asset_kind": "multi_asset_collection",
        "collection_id": collection.collection_id,
        "collection_address": collection.collection_address,
        "creator": collection.creator,
        "name": collection.name,
        "symbol": collection.symbol,
        "metadata_uri": collection.metadata_uri,
        "metadata_hash": collection.metadata_hash,
        "image_uri": collection.image_uri,
        "image_hash": collection.image_hash,
        "image_locked": collection.image_locked,
        "authorities": collection.authorities,
        "created_at": collection.created_at,
        "updated_at": collection.updated_at,
    })
}

fn sts_multi_asset_item_item_json(item: &crate::sts::MultiAssetItem) -> Value {
    json!({
        "asset_kind": "multi_asset_item",
        "collection_id": item.collection_id,
        "item_id": item.item_id,
        "item_type": item.item_type,
        "name": item.name,
        "symbol": item.symbol,
        "decimals": item.decimals,
        "metadata_uri": item.metadata_uri,
        "metadata_hash": item.metadata_hash,
        "max_supply": item.max_supply.map(u128_rpc_value),
        "total_supply": u128_rpc_value(item.total_supply),
        "mint_authority": item.mint_authority,
        "burn_authority": item.burn_authority,
        "transfer_policy": item.transfer_policy,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    })
}

fn sts_multi_asset_balance_entry_json(balance: &crate::sts::MultiAssetBalance) -> Value {
    json!({
        "asset_kind": "multi_asset_balance",
        "owner": balance.owner,
        "collection_id": balance.collection_id,
        "item_id": balance.item_id,
        "amount": u128_rpc_value(balance.amount),
        "created_at": balance.created_at,
        "updated_at": balance.updated_at,
    })
}

fn sts_credential_schema_item_json(schema: &crate::sts::CredentialSchema) -> Value {
    json!({
        "asset_kind": "credential_schema",
        "schema_id": schema.schema_id,
        "issuer": schema.issuer,
        "name": schema.name,
        "description_hash": schema.description_hash,
        "schema_hash": schema.schema_hash,
        "active": schema.active,
        "created_at": schema.created_at,
        "updated_at": schema.updated_at,
    })
}

fn sts_credential_item_json(credential: &crate::sts::CredentialRecord) -> Value {
    json!({
        "asset_kind": "credential",
        "credential_id": credential.credential_id,
        "issuer": credential.issuer,
        "subject": credential.subject,
        "subject_commitment": credential.subject_commitment,
        "schema_id": credential.schema_id,
        "credential_hash": credential.credential_hash,
        "status": credential.status,
        "issued_at": credential.issued_at,
        "expires_at": credential.expires_at,
        "revoked_at": credential.revoked_at,
        "revocation_reason_hash": credential.revocation_reason_hash,
        "transferable": credential.transferable,
        "updated_at": credential.updated_at,
    })
}

fn sts_event_json(event: &crate::sts::StsEvent) -> Value {
    json!({
        "event_type": event.event_type,
        "token_id": event.token_id,
        "sender": event.sender,
        "owner": event.owner,
        "recipient": event.recipient,
        "amount": event.amount,
        "timestamp": event.timestamp,
        "attributes": event.attributes,
    })
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn fee_breakdown_json(breakdown: &crate::gas::NetworkFeeBreakdown) -> Value {
    json!({
        "txType": breakdown.tx_type_name,
        "assetId": breakdown.asset_id,
        "amountRaw": u128_rpc_value(breakdown.amount_raw),
        "amountSnrgEquivalentNwei": u128_rpc_value(breakdown.amount_snrgequivalent_nwei),
        "valuationSource": breakdown.valuation_source,
        "valuationStatus": breakdown.valuation_status_name,
        "amountFeeBps": breakdown.amount_fee_bps,
        "gasUsed": breakdown.gas_used,
        "baseFeePerGasNwei": breakdown.base_fee_per_gas_nwei,
        "gasFeeNwei": u128_rpc_value(breakdown.gas_fee_nwei),
        "amountProtocolFeeNwei": u128_rpc_value(breakdown.amount_protocol_fee_nwei),
        "storageFeeNwei": u128_rpc_value(breakdown.storage_fee_nwei),
        "priorityFeeNwei": u128_rpc_value(breakdown.priority_fee_nwei),
        "totalNetworkFeeNwei": u128_rpc_value(breakdown.total_network_fee_nwei),
        "feeCollector": breakdown.fee_collector_address,
    })
}

fn confirmed_transaction_receipt_json(
    block: &crate::block::Block,
    tx_index: usize,
    tx: &Transaction,
    cumulative_gas: u64,
    gas_used: u64,
    synq_receipt: Option<&Value>,
) -> Value {
    let is_contract_creation = tx.receiver.is_empty() || tx.receiver == "0x0";
    let contract_address = if is_contract_creation {
        let hash_input = format!("{}{}", tx.sender, tx.nonce);
        let addr_hash = hex::encode(blake3::hash(hash_input.as_bytes()).as_bytes());
        Some(format!("sync1{}", &addr_hash[..38]))
    } else {
        None
    };
    let status = if synq_receipt_failed(synq_receipt) {
        "0x0"
    } else {
        "0x1"
    };
    let fee_breakdown = tx
        .network_fee_breakdown_with_gas(gas_used, tx.gas_price)
        .ok();
    let fee_charged = fee_breakdown
        .as_ref()
        .map(|breakdown| u128_rpc_value(breakdown.total_network_fee_nwei))
        .unwrap_or_else(|| Value::from(gas_used.saturating_mul(tx.gas_price)));
    let mut receipt = json!({
        "transactionHash": tx.hash(),
        "transactionIndex": tx_index,
        "blockHash": block.hash.clone(),
        "blockNumber": block.block_index,
        "from": tx.sender.clone(),
        "to": if is_contract_creation { Value::Null } else { json!(tx.receiver.clone()) },
        "cumulativeGasUsed": cumulative_gas,
        "gasUsed": gas_used,
        "effectiveGasPrice": tx.gas_price,
        "feeCharged": fee_charged,
        "feeCollector": crate::token::fee_collector_address().ok(),
        "feeBreakdown": fee_breakdown.as_ref().map(fee_breakdown_json).unwrap_or(Value::Null),
        "status": status,
        "logs": [],
        "logsBloom": "0x".to_string() + &"0".repeat(512),
        "contractAddress": contract_address,
        "chain": chain_identity_json(),
    });
    if let Some(synq_receipt) = synq_receipt {
        if let Some(object) = receipt.as_object_mut() {
            object.insert(
                "synq_verification".to_string(),
                synq_receipt
                    .get("synq_verification")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            object.insert(
                "synq_aivm".to_string(),
                synq_receipt
                    .get("synq_aivm")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            object.insert(
                "synq_replay".to_string(),
                synq_receipt
                    .get("synq_replay")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            if let Some(hash) = synq_receipt
                .get("synq_aivm")
                .and_then(|aivm| aivm.get("receipt_hash"))
                .cloned()
            {
                object.insert("synq_receipt_hash".to_string(), hash);
            }
            if let Some(status) = synq_receipt
                .get("synq_aivm")
                .and_then(|aivm| aivm.get("status"))
                .cloned()
            {
                object.insert("synq_execution_status".to_string(), status);
            }
            for field in ["synq_error_code", "synq_error_message", "synq_replay_error"] {
                if let Some(value) = synq_receipt.get(field).cloned() {
                    object.insert(field.to_string(), value);
                }
            }
        }
    }
    receipt
}

fn synq_receipt_failed(synq_receipt: Option<&Value>) -> bool {
    let Some(receipt) = synq_receipt else {
        return false;
    };
    if receipt.get("synq_error_code").is_some() || receipt.get("synq_replay_error").is_some() {
        return true;
    }
    receipt
        .get("synq_aivm")
        .and_then(|aivm| aivm.get("status"))
        .and_then(Value::as_str)
        .map(|status| status != "succeeded")
        .unwrap_or(false)
}

fn load_synq_receipt_index(index_path: Option<&Path>) -> SynQReceiptIndex {
    let Some(index_path) = index_path else {
        return SynQReceiptIndex::new();
    };
    SynQReceiptIndex::load_from_path(index_path).unwrap_or_else(|error| {
        warn!(
            "rpc",
            "Unable to load SynQ receipt index; rebuilding from available chain window",
            "path" => index_path.display().to_string(),
            "error" => error
        );
        SynQReceiptIndex::new()
    })
}

fn save_synq_receipt_index(index: &SynQReceiptIndex, index_path: Option<&Path>) {
    let Some(index_path) = index_path else {
        return;
    };
    if let Err(error) = index.save_to_path_atomic(index_path) {
        warn!(
            "rpc",
            "Unable to persist SynQ receipt index",
            "path" => index_path.display().to_string(),
            "error" => error
        );
    }
}

fn materialize_synq_receipt_index(
    chain: &BlockChain,
    target_block: Option<u64>,
    index_path: Option<&Path>,
) -> SynQReceiptIndex {
    let mut index = load_synq_receipt_index(index_path);
    let mut aivm_state = index.checkpoint.aivm_state.clone();
    let mut artifacts = index.checkpoint.artifact_map();
    let mut deployments = index.checkpoint.deployments.clone();
    let latest_materialized = index.checkpoint.latest_materialized_block;
    let first_materialized_block = index
        .checkpoint
        .first_materialized_block
        .or_else(|| chain.chain.first().map(|block| block.block_index));
    let first_replayed_block = first_materialized_block;
    let mut changed = false;

    for block in &chain.chain {
        if target_block
            .map(|target| block.block_index > target)
            .unwrap_or(false)
        {
            break;
        }
        if latest_materialized
            .map(|height| block.block_index <= height)
            .unwrap_or(false)
        {
            continue;
        }

        let mut cumulative_gas: u64 = 0;
        let mut block_synq_receipts = BTreeMap::<usize, Value>::new();
        for (idx, tx) in block.transactions.iter().enumerate() {
            if let Some(synq_receipt) = replay_synq_receipt_for_legacy_transaction(
                tx,
                block.block_index,
                idx,
                first_replayed_block,
                &mut aivm_state,
                &mut artifacts,
                &mut deployments,
            ) {
                block_synq_receipts.insert(idx, synq_receipt);
            }

            let synq = block_synq_receipts.get(&idx);
            let gas_used = receipt_gas_used(tx, synq);
            cumulative_gas = cumulative_gas.saturating_add(gas_used);
            if let Some(synq) = synq {
                let receipt = confirmed_transaction_receipt_json(
                    block,
                    idx,
                    tx,
                    cumulative_gas,
                    gas_used,
                    Some(synq),
                );
                index.upsert_receipt(SynQIndexedReceipt::new(
                    tx.hash(),
                    tx.raw_hash(),
                    block.hash.clone(),
                    block.block_index,
                    idx,
                    receipt,
                ));
            }
        }

        index.record_checkpoint(
            block.block_index,
            first_materialized_block,
            &aivm_state,
            &artifacts,
            &deployments,
        );
        changed = true;
    }

    if changed {
        save_synq_receipt_index(&index, index_path);
    }
    index
}

fn replay_synq_receipt_for_legacy_transaction(
    legacy_tx: &Transaction,
    block_index: u64,
    tx_index: usize,
    first_replayed_block: Option<u64>,
    aivm_state: &mut aivm_core::state::ContractState,
    artifacts: &mut BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    deployments: &mut BTreeMap<String, SynQDeploymentRecord>,
) -> Option<Value> {
    let data = legacy_tx.data.as_deref()?;
    if !data.starts_with(crate::aegis_tx_tool::AEGIS_TX_CARRIER_PREFIX) {
        return None;
    }
    let envelope = match crate::aegis_tx_tool::decode_aegis_carrier_data(data) {
        Ok(envelope) => envelope,
        Err(error) => {
            return Some(json!({
                "synq_error_code": "SYNQ-RPC-CARRIER",
                "synq_error_message": error,
                "synq_replay": synq_replay_metadata(block_index, tx_index, first_replayed_block),
            }));
        }
    };
    let typed_tx = envelope.transaction;
    let verification = match crate::synq_admission::verify_transaction_payload_for_chain_admission(
        &typed_tx,
        legacy_tx.timestamp,
    ) {
        Ok(Some(summary)) => summary,
        Ok(None) => return None,
        Err(error) => {
            return Some(json!({
                "synq_error_code": error.code(),
                "synq_error_message": error.to_string(),
                "synq_replay": synq_replay_metadata(block_index, tx_index, first_replayed_block),
            }));
        }
    };
    let tx_id = match replay_tx_id(&typed_tx) {
        Ok(tx_id) => tx_id,
        Err(error) => {
            return Some(json!({
                "synq_verification": serde_json::to_value(&verification).unwrap_or(Value::Null),
                "synq_error_code": "SYNQ-RPC-CANON",
                "synq_error_message": error,
                "synq_replay": synq_replay_metadata(block_index, tx_index, first_replayed_block),
            }));
        }
    };
    match execute_synq_transaction_at(
        &tx_id,
        &typed_tx,
        &verification,
        aivm_state,
        artifacts,
        deployments,
        SynQExecutionContext {
            runtime_block_height: block_index,
            runtime_block_timestamp_unix: legacy_tx.timestamp,
            sts_host: None,
            applied_fee_market: None,
        },
    ) {
        Ok(Some(aivm)) => Some(json!({
            "synq_verification": serde_json::to_value(&verification).unwrap_or(Value::Null),
            "synq_aivm": serde_json::to_value(&aivm).unwrap_or(Value::Null),
            "synq_replay": synq_replay_metadata(block_index, tx_index, first_replayed_block),
        })),
        Ok(None) => None,
        Err(error) => Some(json!({
            "synq_verification": serde_json::to_value(&verification).unwrap_or(Value::Null),
            "synq_error_code": "SYNQ-RPC-REPLAY",
            "synq_error_message": error,
            "synq_replay": synq_replay_metadata(block_index, tx_index, first_replayed_block),
        })),
    }
}

fn replay_tx_id(tx: &crate::synergy_types::Transaction) -> Result<TxId, String> {
    Ok(TxId::from_hash(Hash::from_domain_bytes(
        "SYNERGY_EXECUTION_TX_ID_V1",
        &tx.canonical_bytes()?,
    )))
}

fn synq_replay_metadata(
    block_index: u64,
    tx_index: usize,
    first_replayed_block: Option<u64>,
) -> Value {
    json!({
        "source": "committed_aegis_carrier_hot_chain_replay",
        "deterministic": true,
        "block_number": block_index,
        "transaction_index": tx_index,
        "first_replayed_block": first_replayed_block,
        "compacted_chain_window": first_replayed_block.map(|height| height > 0).unwrap_or(false),
    })
}

fn transaction_fees_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let receipt = transaction_receipt_json(params, chain);
    if receipt.is_null() {
        return json!(null);
    }
    json!({
        "transactionHash": receipt.get("transactionHash").cloned(),
        "feeCharged": receipt.get("feeCharged").cloned().unwrap_or_else(|| json!(0)),
        "feeCollector": receipt.get("feeCollector").cloned().unwrap_or_else(|| json!(crate::token::fee_collector_address().ok())),
        "feeBreakdown": receipt.get("feeBreakdown").cloned().unwrap_or(Value::Null),
        "gasUsed": receipt.get("gasUsed").cloned().unwrap_or_else(|| json!(0)),
        "effectiveGasPrice": receipt.get("effectiveGasPrice").cloned().unwrap_or_else(|| json!(0)),
        "chain": chain_identity_json(),
    })
}

fn estimate_fee_json(params: &Value, chain: &Arc<Mutex<BlockChain>>) -> Value {
    let Some(tx_obj) = params.get(0) else {
        return json!({"error": "Missing transaction object parameter"});
    };
    match normalize_rpc_transaction(tx_obj, false) {
        Ok(normalized) => {
            let gas = estimate_gas_for_transaction(&normalized.transaction);
            let gas_price = current_gas_price_from_chain(chain);
            let safe_breakdown = normalized
                .transaction
                .network_fee_breakdown_with_gas(gas, gas_price)
                .ok();
            let max_breakdown = normalized
                .transaction
                .network_fee_breakdown_with_gas(gas, normalized.transaction.gas_price)
                .ok();
            let safe_fee = safe_breakdown
                .as_ref()
                .map(|breakdown| breakdown.total_network_fee_nwei)
                .unwrap_or_else(|| (gas as u128).saturating_mul(gas_price as u128));
            let max_fee = max_breakdown
                .as_ref()
                .map(|breakdown| breakdown.total_network_fee_nwei)
                .unwrap_or_else(|| {
                    (gas as u128).saturating_mul(normalized.transaction.gas_price as u128)
                });
            let gas_fee = safe_breakdown
                .as_ref()
                .map(|breakdown| breakdown.gas_fee_nwei)
                .unwrap_or_else(|| (gas as u128).saturating_mul(gas_price as u128));
            let amount_fee = safe_breakdown
                .as_ref()
                .map(|breakdown| breakdown.amount_protocol_fee_nwei)
                .unwrap_or(0);
            json!({
                "fee_nwei": u128_rpc_value(safe_fee),
                "safeFee": u128_rpc_value(safe_fee),
                "maxFee": u128_rpc_value(max_fee),
                "gas": gas,
                "gasPrice": gas_price,
                "feeCollector": crate::token::fee_collector_address().ok(),
                "feeBreakdown": safe_breakdown.as_ref().map(fee_breakdown_json).unwrap_or(Value::Null),
                "maxFeeBreakdown": max_breakdown.as_ref().map(fee_breakdown_json).unwrap_or(Value::Null),
                "components": {
                    "gas": u128_rpc_value(gas_fee),
                    "amountProtocol": u128_rpc_value(amount_fee),
                    "storage": u128_rpc_value(safe_breakdown.as_ref().map(|breakdown| breakdown.storage_fee_nwei).unwrap_or(0)),
                    "priority": u128_rpc_value(safe_breakdown.as_ref().map(|breakdown| breakdown.priority_fee_nwei).unwrap_or(0)),
                },
                "integer_base_units": true,
                "warnings": normalized.warnings,
                "chain": chain_identity_json(),
            })
        }
        Err(error) => json!({"error": error.message, "code": error.code, "data": error.data}),
    }
}

fn fee_schedule_json(chain: &Arc<Mutex<BlockChain>>) -> Value {
    let state = current_fee_market_state_from_chain(chain);
    let fee_schedule = match crate::gas::fee_schedule_for_runtime() {
        Ok(schedule) => schedule,
        Err(error) => {
            return json!({
                "error": error,
                "code": "GOVERNED_FEE_SCHEDULE_UNAVAILABLE",
                "chain": chain_identity_json(),
            });
        }
    };
    let amount_fee_schedule = fee_schedule
        .entries
        .iter()
        .map(|entry| {
            json!({
                "txType": entry.tx_type.as_str(),
                "amountFeeBps": entry.amount_fee_bps,
                "minAmountFeeNwei": u128_rpc_value(entry.min_amount_fee_nwei),
                "maxAmountFeeNwei": u128_rpc_value(entry.max_amount_fee_nwei),
                "valuationRequired": entry.valuation_required,
                "storageFeeEnabled": entry.storage_fee_enabled,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "feeCollector": crate::token::fee_collector_address().ok(),
        "feeAsset": "SNRG",
        "gasPrice": state.base_fee_per_gas_nwei,
        "baseFeePerGas": state.base_fee_per_gas_nwei,
        "effectivePqGasPrice": state.effective_pq_gas_price_nwei,
        "pqGasMultiplier": state.params.pq_gas_multiplier,
        "priorityFeeEnabled": false,
        "minGasPrice": crate::gas::constants::MIN_GAS_PRICE,
        "maxGasPrice": crate::gas::constants::MAX_GAS_PRICE,
        "defaultGasPrice": crate::gas::constants::DEFAULT_GAS_PRICE,
        "baseFeeFloor": state.params.base_fee_floor_nwei,
        "targetBlockGas": state.params.target_block_gas,
        "blockGasLimit": crate::gas::constants::BLOCK_GAS_LIMIT,
        "maxBlockGas": state.params.max_block_gas,
        "maxBlockPqGas": state.params.max_block_pq_gas,
        "baseFeeChangeDenominator": state.params.base_fee_change_denominator,
        "activationHeight": state.params.activation_height,
        "feeMarketVersion": state.params.fee_market_version,
        "amountFeeSchedule": amount_fee_schedule,
        "integer_base_units": true,
        "chain": chain_identity_json(),
    })
}

/// `synergy_getFeeMarket`: the preferred, structured fee-market API for
/// Forge/Atlas/wallets/SDKs. See `docs/fee-market.md` for the full field
/// semantics and `canonical_fee_market_state`'s doc comment for the
/// architecture note about this endpoint's (legacy-chain) data source.
fn fee_market_json(chain: &Arc<Mutex<BlockChain>>) -> Value {
    let state = current_fee_market_state_from_chain(chain);
    let utilization_bps = crate::gas::fee_market::utilization_bps(
        state.last_block_gas_used,
        state.params.max_block_gas,
    );
    json!({
        "version": state.params.fee_market_version,
        "enabled": state.params.fee_market_enabled,
        "feeAsset": "SNRG",
        "current": {
            "blockNumber": state.last_block_height,
            "baseFeePerGas": state.current_base_fee_per_gas_nwei,
            "gasUsed": state.last_block_gas_used,
            "gasLimit": state.params.max_block_gas,
            "utilizationBps": utilization_bps,
        },
        "next": {
            "blockNumber": state.last_block_height.saturating_add(1),
            "baseFeePerGas": state.base_fee_per_gas_nwei,
            "effectivePqGasPrice": state.effective_pq_gas_price_nwei,
        },
        "pq": {
            "multiplier": state.params.pq_gas_multiplier,
            "maxBlockPqGas": state.params.max_block_pq_gas,
            "targetBlockPqGas": state.params.target_block_pq_gas,
        },
        "priorityFee": {
            "enabled": false,
            "recommended": Value::Null,
        },
        "parameters": {
            "baseFeeFloor": state.params.base_fee_floor_nwei,
            "initialBaseFee": state.params.initial_base_fee_nwei,
            "targetGas": state.params.target_block_gas,
            "maxBlockGas": state.params.max_block_gas,
            "baseFeeChangeDenominator": state.params.base_fee_change_denominator,
            "activationHeight": state.params.activation_height,
        },
        "feeCollector": crate::token::fee_collector_address().ok(),
        "source": "protocol",
        "integer_base_units": true,
        "chain": chain_identity_json(),
    })
}

fn fee_collector_json() -> Value {
    match crate::token::fee_collector_address() {
        Ok(collector) => json!({
            "address": collector,
            "uma": collector,
            "source": "testnet_v3_genesis_system_account",
            "chain": chain_identity_json(),
        }),
        Err(error) => json!({"error": error, "chain": chain_identity_json()}),
    }
}

fn parse_u64ish(value: Option<&Value>) -> Result<Option<u64>, RpcError> {
    let Some(value) = value else {
        return Ok(None);
    };

    match value {
        Value::Null => Ok(None),
        Value::Number(number) => number
            .as_u64()
            .map(Some)
            .ok_or_else(|| RpcError::new(-32602, "Numeric field must be an unsigned integer")),
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            let parsed = if let Some(hex_value) = trimmed.strip_prefix("0x") {
                u64::from_str_radix(hex_value, 16)
            } else {
                trimmed.parse::<u64>()
            };
            parsed.map(Some).map_err(|_| {
                RpcError::new(-32602, format!("Unable to parse integer value '{}'", text))
            })
        }
        _ => Err(RpcError::new(
            -32602,
            "Numeric field must be a number or string",
        )),
    }
}

fn parse_signature_bytes(
    value: Option<&Value>,
    require_signature: bool,
) -> Result<Vec<u8>, RpcError> {
    let Some(value) = value else {
        return if require_signature {
            Err(RpcError::new(-32602, "Missing signature"))
        } else {
            Ok(Vec::new())
        };
    };

    match value {
        Value::String(text) => {
            let normalized = text.trim().strip_prefix("0x").unwrap_or(text.trim());
            if normalized.is_empty() {
                return if require_signature {
                    Err(RpcError::new(-32602, "Missing signature"))
                } else {
                    Ok(Vec::new())
                };
            }
            hex::decode(normalized)
                .map_err(|_| RpcError::new(-32602, "Signature must be valid hex"))
        }
        Value::Array(values) => {
            let mut bytes = Vec::with_capacity(values.len());
            for value in values {
                let byte = value
                    .as_u64()
                    .filter(|entry| *entry <= 255)
                    .ok_or_else(|| RpcError::new(-32602, "Signature array must contain bytes"))?;
                bytes.push(byte as u8);
            }
            Ok(bytes)
        }
        _ => Err(RpcError::new(
            -32602,
            "Signature must be a hex string or byte array",
        )),
    }
}

fn parse_required_hex_or_bytes(
    value: Option<&Value>,
    missing_message: &'static str,
    invalid_message: &'static str,
) -> Result<Vec<u8>, RpcError> {
    let Some(value) = value else {
        return Err(RpcError::new(-32602, missing_message));
    };
    match value {
        Value::String(text) => {
            let normalized = text.trim().strip_prefix("0x").unwrap_or(text.trim());
            if normalized.is_empty() {
                return Err(RpcError::new(-32602, missing_message));
            }
            hex::decode(normalized).map_err(|_| RpcError::new(-32602, invalid_message))
        }
        Value::Array(values) => {
            let mut bytes = Vec::with_capacity(values.len());
            for value in values {
                let byte = value
                    .as_u64()
                    .filter(|entry| *entry <= 255)
                    .ok_or_else(|| RpcError::new(-32602, invalid_message))?;
                bytes.push(byte as u8);
            }
            if bytes.is_empty() {
                Err(RpcError::new(-32602, missing_message))
            } else {
                Ok(bytes)
            }
        }
        _ => Err(RpcError::new(-32602, invalid_message)),
    }
}

fn normalize_signature_algorithm(
    value: Option<&str>,
    require_signature: bool,
) -> Result<String, RpcError> {
    // Testnet-v3 user/account transactions are ML-DSA-87. FN-DSA labels are
    // REJECTED rather than silently normalised: FN-DSA material belongs to the
    // address-derivation domain, and quietly relabelling it as ML-DSA-87 would
    // collapse the domain separation this endpoint is supposed to enforce.
    const MISSING: &str = "Missing signatureAlgorithm; use mldsa87 explicitly";
    let Some(value) = value else {
        return if require_signature {
            Err(RpcError::new(-32602, MISSING))
        } else {
            Ok("mldsa87".to_string())
        };
    };
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" if require_signature => Err(RpcError::new(-32602, MISSING)),
        "" | "mldsa87" | "ml-dsa-87" | "ml_dsa_87" => Ok("mldsa87".to_string()),
        "fndsa" | "fn-dsa" | "fn-dsa-512" | "fn-dsa-1024" | "falcon" | "falcon-1024" => {
            Err(RpcError::new(
                -32602,
                format!(
                    "Signature algorithm '{}' is the address-derivation domain and cannot sign a user transaction; use mldsa87",
                    value
                ),
            ))
        }
        "mldsa65" | "ml-dsa-65" | "ml_dsa_65" => Err(RpcError::new(
            -32602,
            format!(
                "Signature algorithm '{}' is the validator consensus domain and cannot sign a user transaction; use mldsa87",
                value
            ),
        )),
        "pqc" | "aegis" => Err(RpcError::new(
            -32602,
            format!(
                "Ambiguous signature algorithm '{}'; use mldsa87 explicitly",
                value
            ),
        )),
        _ => Err(RpcError::new(
            -32602,
            format!("Unsupported signature algorithm '{}'; use mldsa87", value),
        )),
    }
}

fn normalize_rpc_transaction(
    value: &Value,
    require_signature: bool,
) -> Result<NormalizedEnvelopeResult, RpcError> {
    if let Ok(transaction) = serde_json::from_value::<Transaction>(value.clone()) {
        let chain_id = Some(transaction.chain_id);
        return Ok(NormalizedEnvelopeResult {
            chain_id,
            warnings: Vec::new(),
            transaction,
        });
    }

    let envelope = serde_json::from_value::<RpcTransactionEnvelope>(value.clone())
        .map_err(|_| RpcError::new(-32602, "Invalid transaction format"))?;

    if matches!(
        envelope.envelope_type.as_deref(),
        Some("0x04") | Some("4") | Some("delegation")
    ) || envelope.delegation.is_some()
        || envelope.delegations.is_some()
        || envelope.authorization_list.is_some()
        || matches!(
            envelope.tx_type.as_deref(),
            Some("0x04") | Some("4") | Some("delegation")
        )
    {
        return Err(RpcError::with_data(
            -32014,
            "Delegation-bearing transaction envelopes are not permitted on Synergy",
            json!({"reason": "type-0x04 / delegation payload rejected"}),
        ));
    }

    let sender = envelope
        .from
        .clone()
        .or(envelope.sender.clone())
        .ok_or_else(|| RpcError::new(-32602, "Missing transaction sender"))?;
    let receiver = envelope
        .to
        .clone()
        .or(envelope.receiver.clone())
        .ok_or_else(|| RpcError::new(-32602, "Missing transaction recipient"))?;
    let amount = parse_u64ish(envelope.value.as_ref().or(envelope.amount.as_ref()))?.unwrap_or(0);
    let nonce = envelope
        .nonce
        .ok_or_else(|| RpcError::new(-32602, "Missing transaction nonce"))?;
    let gas_price = parse_u64ish(
        envelope
            .max_fee
            .as_ref()
            .or(envelope.gas_price.as_ref())
            .or(envelope.gas_price_alias.as_ref()),
    )?
    .unwrap_or_else(|| current_gas_price_from_chain(&CHAIN));
    let gas_limit = parse_u64ish(
        envelope
            .gas_limit_alias
            .as_ref()
            .or(envelope.gas_limit.as_ref()),
    )?
    .unwrap_or(crate::gas::constants::GAS_LIMIT_TRANSFER);
    let signature = parse_signature_bytes(envelope.signature.as_ref(), require_signature)?;
    let signer_public_key_value = envelope
        .signer_public_key_alias
        .as_ref()
        .or(envelope.signer_public_key.as_ref())
        .or(envelope.public_key_alias.as_ref());
    let signer_public_key = if require_signature {
        parse_required_hex_or_bytes(
            signer_public_key_value,
            "Missing signerPublicKey",
            "signerPublicKey must be a valid hex string or byte array",
        )?
    } else {
        signer_public_key_value
            .map(|value| {
                parse_required_hex_or_bytes(
                    Some(value),
                    "Missing signerPublicKey",
                    "signerPublicKey must be a valid hex string or byte array",
                )
            })
            .transpose()?
            .unwrap_or_default()
    };
    let signature_algorithm = normalize_signature_algorithm(
        envelope
            .signature_algorithm_alias
            .as_deref()
            .or(envelope.signature_algorithm.as_deref()),
        require_signature,
    )?;
    let chain_id = parse_u64ish(envelope.chain_id.as_ref())?.unwrap_or(0);
    let network_id = envelope
        .network_id_alias
        .clone()
        .or(envelope.network_id.clone())
        .unwrap_or_default();

    let normalized = NormalizedRpcTransaction {
        chain_id,
        network_id,
        sender,
        receiver,
        amount,
        nonce,
        signature,
        signer_public_key,
        timestamp: envelope.timestamp.unwrap_or_else(current_timestamp),
        gas_price,
        gas_limit,
        data: envelope.data.clone(),
        signature_algorithm,
    };

    let mut warnings = Vec::new();
    if envelope.max_priority_fee_per_gas.is_some() {
        warnings.push(
            "maxPriorityFeePerGas is accepted for compatibility but not used by the current fee model"
                .to_string(),
        );
    }

    if normalized.amount == 0
        && normalized
            .data
            .as_deref()
            .map(|value| !value.is_empty() && value != "0x")
            .unwrap_or(false)
    {
        warnings.push(
            "Zero-value contract calls remain subject to the current AIVM execution limitations"
                .to_string(),
        );
    }

    let transaction = Transaction {
        chain_id: normalized.chain_id,
        network_id: normalized.network_id,
        sender: normalized.sender,
        receiver: normalized.receiver,
        amount: normalized.amount,
        nonce: normalized.nonce,
        signature: normalized.signature,
        signer_public_key: normalized.signer_public_key,
        timestamp: normalized.timestamp,
        gas_price: normalized.gas_price,
        gas_limit: normalized.gas_limit,
        data: normalized.data,
        signature_algorithm: normalized.signature_algorithm,
    };

    Ok(NormalizedEnvelopeResult {
        transaction,
        warnings,
        chain_id: Some(normalized.chain_id),
    })
}

fn estimate_gas_for_transaction(transaction: &Transaction) -> u64 {
    use crate::gas::GasEstimator;

    if transaction.receiver.is_empty() || transaction.receiver == "0x0" {
        let bytecode_size = transaction
            .data
            .as_deref()
            .map(|data| {
                let data = data.strip_prefix("0x").unwrap_or(data);
                data.len() / 2
            })
            .unwrap_or(0);
        GasEstimator::estimate_contract_deploy(bytecode_size).as_u64()
    } else if transaction
        .data
        .as_deref()
        .map(|data| !data.is_empty() && data != "0x")
        .unwrap_or(false)
    {
        let calldata_size = transaction
            .data
            .as_deref()
            .map(|data| {
                let data = data.strip_prefix("0x").unwrap_or(data);
                data.len() / 2
            })
            .unwrap_or(0);
        GasEstimator::estimate_contract_call(calldata_size).as_u64()
    } else {
        GasEstimator::estimate_transfer().as_u64()
    }
}

/// Canonical Live Gas Pricing (see `docs/fee-market.md`) result for the
/// RPC-facing legacy chain.
///
/// ARCHITECTURE NOTE (read before touching this function): this file's
/// `chain: Arc<Mutex<BlockChain>>` (`block.rs`) is a *separate* object from
/// the canonical `synergy_types::Block` / `execution::ExecutionState` /
/// `consensus::coordinated_runtime::CoordinatedRuntime` stack that the
/// Canonical Live Gas Pricing engine (`gas::fee_market`, block-header fee
/// fields, real transaction charging, block validation) is fully wired
/// into -- see `execution.rs` and `consensus/coordinated_runtime.rs`.
/// `consensus/consensus_algorithm.rs`'s `ProofOfSynergy` block producer is
/// what actually appends to *this* `BlockChain` (via `add_block`/
/// `add_block_extending_tip`), and it does not call
/// `execution::execute_transaction`; it applies transactions through its
/// own, separate path (`crate::wallet::WALLET_MANAGER`). This is a
/// pre-existing fork between two block/consensus representations in this
/// codebase, not something introduced by this change -- see the Canonical
/// Live Gas Pricing deliverables report for the full finding and the
/// remaining-blocker this creates for end-to-end enforcement.
///
/// Until those two stacks are unified, this function computes the
/// deterministic base fee RPC callers are quoted by *replaying* the real,
/// integer-only, protocol-formula recurrence
/// (`gas::fee_market::next_base_fee_per_gas`) over this chain's actual
/// observed block-by-block gas usage, starting from
/// `FeeMarketParams::initial_base_fee_nwei` at genesis. This is
/// deliberately NOT a historical percentile or average (forbidden by
/// design -- see `docs/fee-market.md`): it is the exact same single-step
/// deterministic formula the canonical engine enforces, applied once per
/// real historical block in causal order, so any two nodes replaying the
/// same block sequence deterministically derive the same result. No
/// floating point is used anywhere in this computation.
///
/// Per-block gas usage is measured via `Transaction::estimate_gas()` (the
/// same deterministic activity-gas table shared with the canonical
/// execution path in `crate::gas`), because this legacy chain does not
/// persist a post-execution actual-gas-used receipt the way
/// `execution.rs`'s `TransactionReceipt` does.
///
/// Performance note: this replays the full chain on every call (cost is
/// O(blocks x transactions-per-block)). That is acceptable at current
/// testnet block volume but should be replaced with incremental caching
/// (persist the running base fee alongside the chain tip, update it by one
/// step per new block) before this endpoint needs to serve a chain with a
/// large block count.
#[derive(Debug, Clone, Copy)]
struct CanonicalFeeMarketState {
    params: crate::gas::fee_market::FeeMarketParams,
    /// The base fee that was (deterministically, by replay) actually
    /// applied to the most recently mined block. `None` when the chain has
    /// no blocks yet (nothing has been "applied").
    current_base_fee_per_gas_nwei: Option<u64>,
    /// The deterministic base fee that will apply to the *next* block,
    /// derived from the last mined block's declared base fee and gas
    /// usage. This is what `synergy_gasPrice` and friends quote as "the"
    /// price, since it is the price a transaction submitted right now will
    /// actually be charged once included.
    base_fee_per_gas_nwei: u64,
    effective_pq_gas_price_nwei: u64,
    last_block_height: u64,
    last_block_gas_used: u64,
}

fn canonical_fee_market_state(chain: &BlockChain) -> CanonicalFeeMarketState {
    let params = *crate::gas::fee_market_params_for_runtime().expect(
        "fee RPC must not run before verified fresh-P3 Genesis installs governed fee-market parameters",
    );
    // Once the legacy producer has crossed the fee-market activation
    // boundary, the latest signed block header is authoritative.  Retaining
    // the replay below only for historical version-0 chains preserves the
    // existing read-only migration behavior without allowing it to override
    // a consensus-bound price.
    if let Some(tip) = chain
        .chain
        .last()
        .filter(|block| block.fee_market_version == params.fee_market_version)
    {
        let next_base_fee = crate::gas::fee_market::next_base_fee_per_gas(
            tip.base_fee_per_gas_nwei,
            tip.gas_used,
            &params,
        )
        .unwrap_or(tip.base_fee_per_gas_nwei);
        let effective_pq_gas_price_nwei =
            crate::gas::fee_market::effective_pq_gas_price(next_base_fee, params.pq_gas_multiplier)
                .unwrap_or(next_base_fee);
        return CanonicalFeeMarketState {
            params,
            current_base_fee_per_gas_nwei: Some(tip.base_fee_per_gas_nwei),
            base_fee_per_gas_nwei: next_base_fee,
            effective_pq_gas_price_nwei,
            last_block_height: tip.block_index,
            last_block_gas_used: tip.gas_used,
        };
    }
    let mut base_fee = params.initial_base_fee_nwei;
    let mut current_base_fee = None;
    let mut last_block_gas_used = 0u64;
    for block in &chain.chain {
        // The fee this block was actually charged under is whatever the
        // replay had computed *before* folding this block's own usage in.
        current_base_fee = Some(base_fee);
        let gas_used: u64 = block
            .transactions
            .iter()
            .map(|tx| tx.estimate_gas())
            .fold(0u64, |total, gas| total.saturating_add(gas));
        base_fee = crate::gas::fee_market::next_base_fee_per_gas(base_fee, gas_used, &params)
            .unwrap_or(base_fee);
        last_block_gas_used = gas_used;
    }
    let effective_pq_gas_price_nwei =
        crate::gas::fee_market::effective_pq_gas_price(base_fee, params.pq_gas_multiplier)
            .unwrap_or(base_fee);
    CanonicalFeeMarketState {
        params,
        current_base_fee_per_gas_nwei: current_base_fee,
        base_fee_per_gas_nwei: base_fee,
        effective_pq_gas_price_nwei,
        last_block_height: chain
            .chain
            .last()
            .map(|block| block.block_index)
            .unwrap_or(0),
        last_block_gas_used,
    }
}

fn current_gas_price_from_chain(chain: &Arc<Mutex<BlockChain>>) -> u64 {
    let chain = chain.lock().unwrap();
    canonical_fee_market_state(&chain).base_fee_per_gas_nwei
}

fn current_fee_market_state_from_chain(chain: &Arc<Mutex<BlockChain>>) -> CanonicalFeeMarketState {
    let chain = chain.lock().unwrap();
    canonical_fee_market_state(&chain)
}

fn next_account_nonce_value(
    address: &str,
    tx_pool: &Arc<Mutex<Vec<Transaction>>>,
    chain: &Arc<Mutex<BlockChain>>,
) -> u64 {
    get_account_nonce(&json!([address]), tx_pool, chain)
        .ok()
        .and_then(|value| value.as_u64())
        .unwrap_or(0)
}

fn get_account_nonce(
    params: &Value,
    tx_pool: &Arc<Mutex<Vec<Transaction>>>,
    chain: &Arc<Mutex<BlockChain>>,
) -> Result<Value, RpcError> {
    let address = params
        .get(0)
        .and_then(|value| value.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing address parameter"))?;

    let mut next_nonce = 0u64;

    if let Ok(wallet_manager) = WALLET_MANAGER.lock() {
        if let Some(wallet) = wallet_manager.get_wallet(address) {
            next_nonce = next_nonce.max(wallet.nonce);
        }
    }

    {
        let chain = chain.lock().unwrap();
        for block in &chain.chain {
            for tx in &block.transactions {
                if tx.sender.eq_ignore_ascii_case(address) {
                    next_nonce = next_nonce.max(tx.nonce.saturating_add(1));
                }
            }
        }
    }

    for nonce in crate::dag::committed_sender_nonces(address) {
        next_nonce = next_nonce.max(nonce.saturating_add(1));
    }

    {
        let pool = tx_pool.lock().unwrap();
        for tx in pool.iter() {
            if tx.sender.eq_ignore_ascii_case(address) {
                next_nonce = next_nonce.max(tx.nonce.saturating_add(1));
            }
        }
    }

    Ok(json!(next_nonce))
}

fn simulate_transaction(
    params: &Value,
    _tx_pool: &Arc<Mutex<Vec<Transaction>>>,
    chain: &Arc<Mutex<BlockChain>>,
) -> Result<Value, RpcError> {
    let transaction_value = params
        .get(0)
        .ok_or_else(|| RpcError::new(-32602, "Missing transaction parameter"))?;
    let normalized = normalize_rpc_transaction(transaction_value, false)?;

    let configured_chain_id = current_chain_id();
    if let Some(chain_id) = normalized.chain_id {
        if chain_id != configured_chain_id {
            return Err(RpcError::with_data(
                -32015,
                "Simulation chainId does not match the local chain",
                json!({
                    "expected": format!("0x{:x}", configured_chain_id),
                    "actual": format!("0x{:x}", chain_id)
                }),
            ));
        }
    }

    let gas = estimate_gas_for_transaction(&normalized.transaction);
    let network_gas_price = current_gas_price_from_chain(chain);
    let safe_breakdown = normalized
        .transaction
        .network_fee_breakdown_with_gas(gas, network_gas_price)
        .ok();
    let max_breakdown = normalized
        .transaction
        .network_fee_breakdown_with_gas(gas, normalized.transaction.gas_price)
        .ok();
    let safe_fee = safe_breakdown
        .as_ref()
        .map(|breakdown| breakdown.total_network_fee_nwei)
        .unwrap_or_else(|| (gas as u128).saturating_mul(network_gas_price as u128));
    let max_fee = max_breakdown
        .as_ref()
        .map(|breakdown| breakdown.total_network_fee_nwei)
        .unwrap_or_else(|| (gas as u128).saturating_mul(normalized.transaction.gas_price as u128));
    let sender_balance = TOKEN_MANAGER
        .clone()
        .get_balance(&normalized.transaction.sender, "SNRG");
    let total_cost = (normalized.transaction.amount as u128).saturating_add(max_fee);

    let mut warnings = normalized.warnings.clone();
    let mut divergence = false;
    if normalized
        .transaction
        .data
        .as_deref()
        .map(|value| !value.is_empty() && value != "0x")
        .unwrap_or(false)
    {
        divergence = true;
        warnings.push(
            "Legacy public simulation does not execute AIVM contract side effects; use a finalized SynQ view call or submit an authenticated encrypted transaction"
                .to_string(),
        );
    }

    if (sender_balance as u128) < total_cost {
        warnings.push(format!(
            "Sender balance {} is below the projected total cost {}",
            sender_balance, total_cost
        ));
    }

    let asset_flows = if normalized.transaction.amount > 0 {
        vec![json!({
            "asset": "SNRG",
            "from": normalized.transaction.sender,
            "to": normalized.transaction.receiver,
            "amount": normalized.transaction.amount
        })]
    } else {
        Vec::new()
    };

    let tx_digest =
        canonical_value_digest(transaction_value).unwrap_or_else(|| normalized.transaction.hash());
    let preview = json!({
        "accepted": (sender_balance as u128) >= total_cost,
        "chainId": format!("0x{:x}", configured_chain_id),
        "txDigest": tx_digest,
        "gas": gas,
        "safeFee": u128_rpc_value(safe_fee),
        "maxFee": u128_rpc_value(max_fee),
        "totalCostNwei": u128_rpc_value(total_cost),
        "feeBreakdown": safe_breakdown.as_ref().map(fee_breakdown_json).unwrap_or(Value::Null),
        "maxFeeBreakdown": max_breakdown.as_ref().map(fee_breakdown_json).unwrap_or(Value::Null),
        "assetFlows": asset_flows,
        "approvals": [],
        "delegations": [],
        "warnings": warnings,
        "divergence": divergence
    });
    let simulation_hash = canonical_value_digest(&preview)
        .unwrap_or_else(|| hex::encode(blake3::hash(preview.to_string().as_bytes()).as_bytes()));

    {
        let mut cache = SIMULATION_CACHE.lock().unwrap();
        cache.retain(|_, entry| current_timestamp().saturating_sub(entry.created_at) <= 900);
        cache.insert(
            preview
                .get("txDigest")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            CachedSimulation {
                simulation_hash: simulation_hash.clone(),
                created_at: current_timestamp(),
            },
        );
    }

    Ok(json!({
        "simulationHash": simulation_hash,
        "transactionHashPreview": normalized.transaction.hash(),
        "result": preview
    }))
}

fn register_subscription(
    params: &Value,
    chain: &Arc<Mutex<BlockChain>>,
    tx_pool: &Arc<Mutex<Vec<Transaction>>>,
    subscriptions: &mut HashMap<String, SubscriptionCursor>,
) -> Result<Value, RpcError> {
    let subscription_type = params
        .get(0)
        .and_then(|value| value.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing subscription type"))?;
    let current_height = {
        let chain = chain.lock().unwrap();
        chain.last().map(|block| block.block_index).unwrap_or(0)
    };
    let filter = params.get(1).cloned().unwrap_or(Value::Null);

    let cursor = match subscription_type {
        "newHeads" => SubscriptionCursor::NewHeads {
            last_block: current_height,
        },
        "logs" => SubscriptionCursor::Logs {
            last_block: current_height,
            address: filter
                .get("address")
                .and_then(|value| value.as_str())
                .map(|value| value.to_ascii_lowercase()),
            topics: filter
                .get("topics")
                .and_then(|value| value.as_array())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(|entry| entry.to_ascii_lowercase()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        },
        "pendingTransactions" => {
            let seen_hashes = tx_pool
                .lock()
                .unwrap()
                .iter()
                .map(|transaction| transaction.hash())
                .collect();
            SubscriptionCursor::PendingTransactions { seen_hashes }
        }
        "validatorEvents" => SubscriptionCursor::ValidatorEvents {
            last_block: current_height,
        },
        _ => {
            return Err(RpcError::new(
                -32602,
                format!("Unsupported subscription type '{}'", subscription_type),
            ));
        }
    };

    let subscription_id = format!(
        "0x{:016x}",
        SUBSCRIPTION_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    subscriptions.insert(subscription_id.clone(), cursor);
    Ok(json!(subscription_id))
}

fn unregister_subscription(
    params: &Value,
    subscriptions: &mut HashMap<String, SubscriptionCursor>,
) -> Result<Value, RpcError> {
    let subscription_id = params
        .get(0)
        .and_then(|value| value.as_str())
        .ok_or_else(|| RpcError::new(-32602, "Missing subscriptionId parameter"))?;
    Ok(json!(subscriptions.remove(subscription_id).is_some()))
}

fn emit_subscription_notifications(
    websocket: &mut tungstenite::WebSocket<std::net::TcpStream>,
    subscriptions: &mut HashMap<String, SubscriptionCursor>,
    tx_pool: &Arc<Mutex<Vec<Transaction>>>,
    chain: &Arc<Mutex<BlockChain>>,
) {
    if subscriptions.is_empty() {
        return;
    }

    let subscription_ids: Vec<String> = subscriptions.keys().cloned().collect();
    for subscription_id in subscription_ids {
        let Some(cursor) = subscriptions.get_mut(&subscription_id) else {
            continue;
        };

        match cursor {
            SubscriptionCursor::NewHeads { last_block } => {
                let blocks = {
                    let chain = chain.lock().unwrap();
                    chain
                        .chain
                        .iter()
                        .filter(|block| block.block_index > *last_block)
                        .cloned()
                        .collect::<Vec<_>>()
                };

                for block in blocks {
                    *last_block = block.block_index;
                    let notification = json!({
                        "jsonrpc": "2.0",
                        "method": "synergy_subscription",
                        "chain_context": rpc_chain_context_json(),
                        "params": {
                            "subscription": subscription_id,
                            "result": {
                                "block_index": block.block_index,
                                "hash": block.hash,
                                "parent_hash": block.previous_hash,
                                "timestamp": block.timestamp,
                                "validator": block.validator_id,
                                "tx_count": block.transactions.len()
                            }
                        }
                    });
                    if websocket
                        .send(WsMessage::Text(notification.to_string()))
                        .is_err()
                    {
                        return;
                    }
                }
            }
            SubscriptionCursor::Logs {
                last_block,
                address,
                topics,
            } => {
                let blocks = {
                    let chain = chain.lock().unwrap();
                    chain
                        .chain
                        .iter()
                        .filter(|block| block.block_index > *last_block)
                        .cloned()
                        .collect::<Vec<_>>()
                };

                for block in blocks {
                    *last_block = block.block_index;
                    for log in collect_logs_for_block(&block, address.as_deref(), topics) {
                        let notification = json!({
                            "jsonrpc": "2.0",
                            "method": "synergy_subscription",
                            "chain_context": rpc_chain_context_json(),
                            "params": {
                                "subscription": subscription_id,
                                "result": log
                            }
                        });
                        if websocket
                            .send(WsMessage::Text(notification.to_string()))
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
            SubscriptionCursor::PendingTransactions { seen_hashes } => {
                let pending_transactions =
                    tx_pool.lock().unwrap().iter().cloned().collect::<Vec<_>>();

                for transaction in pending_transactions {
                    let hash = transaction.hash();
                    if seen_hashes.insert(hash.clone()) {
                        let notification = json!({
                            "jsonrpc": "2.0",
                            "method": "synergy_subscription",
                            "chain_context": rpc_chain_context_json(),
                            "params": {
                                "subscription": subscription_id,
                                "result": hash
                            }
                        });
                        if websocket
                            .send(WsMessage::Text(notification.to_string()))
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
            SubscriptionCursor::ValidatorEvents { last_block } => {
                let blocks = {
                    let chain = chain.lock().unwrap();
                    chain
                        .chain
                        .iter()
                        .filter(|block| block.block_index > *last_block)
                        .cloned()
                        .collect::<Vec<_>>()
                };

                for block in blocks {
                    *last_block = block.block_index;
                    let notification = json!({
                        "jsonrpc": "2.0",
                        "method": "synergy_subscription",
                        "chain_context": rpc_chain_context_json(),
                        "params": {
                            "subscription": subscription_id,
                            "result": {
                                "event": "blockAccepted",
                                "block_index": block.block_index,
                                "validator": block.validator_id,
                                "hash": block.hash
                            }
                        }
                    });
                    if websocket
                        .send(WsMessage::Text(notification.to_string()))
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    }
}

fn collect_logs_for_block(
    block: &crate::block::Block,
    address_filter: Option<&str>,
    topics_filter: &[String],
) -> Vec<Value> {
    if !topics_filter.is_empty() {
        return Vec::new();
    }

    let mut logs = Vec::new();
    for (tx_index, transaction) in block.transactions.iter().enumerate() {
        if let Some(address_filter) = address_filter {
            if !transaction.sender.eq_ignore_ascii_case(address_filter)
                && !transaction.receiver.eq_ignore_ascii_case(address_filter)
            {
                continue;
            }
        }

        if transaction.data.is_none() && address_filter.is_none() {
            continue;
        }

        logs.push(json!({
            "logIndex": logs.len(),
            "transactionIndex": tx_index,
            "transactionHash": transaction.hash(),
            "blockHash": block.hash.clone(),
            "blockNumber": block.block_index,
            "address": transaction.receiver.clone(),
            "data": transaction.data.clone().unwrap_or_else(|| "0x".to_string()),
            "topics": [],
            "removed": false
        }));
    }

    logs
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn canonicalize_json_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();

            let mut ordered = serde_json::Map::new();
            for key in keys {
                if let Some(child) = map.get(&key) {
                    ordered.insert(key, canonicalize_json_value(child));
                }
            }
            Value::Object(ordered)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_json_value).collect()),
        _ => value.clone(),
    }
}

fn canonical_value_digest(value: &Value) -> Option<String> {
    let canonical = canonicalize_json_value(value);
    let bytes = serde_json::to_vec(&canonical).ok()?;
    Some(hex::encode(blake3::hash(&bytes).as_bytes()))
}

fn stable_json_file_digest<P: AsRef<Path>>(path: P) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let parsed: Value = serde_json::from_str(&content).ok()?;
    canonical_value_digest(&parsed)
}

fn compute_receipt_hash(chain: &BlockChain) -> String {
    let mut hasher = blake3::Hasher::new();
    for block in &chain.chain {
        hasher.update(block.hash.as_bytes());
        for tx in &block.transactions {
            hasher.update(tx.hash().as_bytes());
        }
    }
    hex::encode(hasher.finalize().as_bytes())
}

fn select_cors_origin(cors_origins: &[String]) -> String {
    if cors_origins.iter().any(|origin| origin == "*") {
        return "*".to_string();
    }

    cors_origins
        .iter()
        .find(|origin| !origin.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| "*".to_string())
}

fn format_response(body: &str, cors_enabled: bool, cors_origins: &[String]) -> String {
    format_http_response(
        "200 OK",
        "application/json",
        body,
        cors_enabled,
        cors_origins,
    )
}

fn format_text_response(body: &str, cors_enabled: bool, cors_origins: &[String]) -> String {
    format_http_response(
        "200 OK",
        "text/plain; charset=utf-8",
        body,
        cors_enabled,
        cors_origins,
    )
}

fn format_not_found_response(cors_enabled: bool, cors_origins: &[String]) -> String {
    format_http_response(
        "404 Not Found",
        "text/plain; charset=utf-8",
        "not found\n",
        cors_enabled,
        cors_origins,
    )
}

fn format_http_response(
    status: &str,
    content_type: &str,
    body: &str,
    cors_enabled: bool,
    cors_origins: &[String],
) -> String {
    if cors_enabled {
        let origin = select_cors_origin(cors_origins);
        return format!(
            "HTTP/1.1 {}\r\nContent-Type: {}\r\nAccess-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status,
            content_type,
            origin,
            body.len(),
            body
        );
    }

    format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        body.len(),
        body
    )
}

fn format_cors_preflight_response(cors_enabled: bool, cors_origins: &[String]) -> String {
    if !cors_enabled {
        return "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_string();
    }

    let origin = select_cors_origin(cors_origins);
    format!(
        "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        origin
    )
}

fn calculate_average_block_time(chain: &BlockChain) -> f64 {
    let recent_blocks: Vec<_> = chain.chain.iter().rev().take(20).collect();
    if recent_blocks.len() < 2 {
        return 0.0;
    }

    let mut total_diff = 0u64;
    let mut count = 0u64;

    for window in recent_blocks.windows(2) {
        let newer = window[0];
        let older = window[1];
        if newer.timestamp > older.timestamp {
            total_diff += newer.timestamp - older.timestamp;
            count += 1;
        }
    }

    if count == 0 {
        return 0.0;
    }

    total_diff as f64 / count as f64
}

fn dag_rpc_limit(params: &Value, default: usize, max: usize) -> usize {
    let raw = params
        .get(0)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.get("limit").and_then(|limit| limit.as_u64()))
        })
        .unwrap_or(default as u64);
    raw.max(1).min(max as u64) as usize
}

fn dag_rpc_status_filter(params: &Value) -> Option<crate::dag::DagVertexStatus> {
    params
        .get(0)
        .and_then(|value| {
            value
                .as_str()
                .or_else(|| value.get("status").and_then(|status| status.as_str()))
        })
        .and_then(|status| crate::dag::parse_status_filter(Some(status)))
}

fn tx_to_explorer_json(
    tx: &Transaction,
    status: &str,
    block_number: Option<u64>,
    tx_index: Option<usize>,
) -> Value {
    // Convert amount from nWei to SNRG for display (per SNTS-04: 1 SNRG = 1,000,000,000 nWei)
    use crate::gas::constants::NWEI_PER_SNRG;
    let amount_snrg = tx.amount as f64 / NWEI_PER_SNRG as f64;
    let fee_breakdown = tx.get_network_fee_breakdown().ok();
    let fee = fee_breakdown
        .as_ref()
        .map(|breakdown| u128_rpc_value(breakdown.total_network_fee_nwei))
        .unwrap_or_else(|| Value::from(tx.get_fee()));

    json!({
        "hash": tx.hash(),
        "sender": tx.sender.clone(),
        "receiver": tx.receiver.clone(),
        "from": tx.sender.clone(), // explorer-friendly alias
        "to": tx.receiver.clone(), // explorer-friendly alias
        "amount": tx.amount, // amount in nWei (for compatibility)
        "amount_snrg": amount_snrg, // amount in SNRG (for explorer display)
        "nonce": tx.nonce,
        "chain_id": tx.chain_id,
        "network_id": tx.network_id.clone(),
        "gas_price": tx.gas_price,
        "gas_limit": tx.gas_limit,
        "fee": fee,
        "fee_breakdown": fee_breakdown.as_ref().map(fee_breakdown_json).unwrap_or(Value::Null),
        "timestamp": tx.timestamp,
        "data": tx.data.clone(),
        "signature_algorithm": tx.signature_algorithm.clone(),
        "signature": hex::encode(&tx.signature),
        "status": status,
        "block_number": block_number,
        "transaction_index": tx_index
    })
}

fn block_to_explorer_json(block: &crate::block::Block) -> Value {
    let txs: Vec<Value> = block
        .transactions
        .iter()
        .enumerate()
        .map(|(idx, tx)| tx_to_explorer_json(tx, "confirmed", Some(block.block_index), Some(idx)))
        .collect();

    json!({
        "block_index": block.block_index,
        "timestamp": block.timestamp,
        "hash": block.hash.clone(),
        "previous_hash": block.previous_hash.clone(),
        "parent_hash": block.previous_hash.clone(), // explorer-friendly alias
        "validator_id": block.validator_id.clone(),
        "validator": block.validator_id.clone(), // explorer-friendly alias
        "nonce": block.nonce,
        "tx_count": block.transactions.len() as u64,
        "transactions": txs
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aegis_tx_tool::{sign_with_new_aegis_transaction_key, AegisTxBuildOptions};
    use crate::block::{Block, BlockChain};
    use crate::consensus::consensus_algorithm::ProofOfSynergy;
    use crate::consensus::coordinated_finality_store::CoordinatedFinalityRecord;
    use crate::consensus::coordinated_round_robin::{
        CoordinatedProposal, CoordinatorCommit, ProducerAssignment, COORDINATED_ROUND_ROBIN_V1,
    };
    use crate::crypto::pqc::{PQCAlgorithm, PQCManager};
    use crate::sts::{
        encode_sts_payload, CreateFungibleParams, FungibleControlFlags, StsSignedPayload, StsTx,
        TokenClass,
    };
    use crate::synergy_types::{
        AegisPqKeyId, AegisPqSignature, Block as TypedBlock, BlockHeader as TypedBlockHeader,
        ChainId as TypedChainId, ClusterId, Epoch as TypedEpoch, Height,
        NetworkId as TypedNetworkId, QuorumCertificate as TypedQuorumCertificate, Round,
        Transaction as TypedTransaction, UmaId, ValidatorId, VotePhase,
    };
    use crate::synq_execution::{
        derive_synq_contract_address_from_deploy, synergy_contract_address_from_pqsynq_address,
    };
    use pqsynq::{
        canonicalize_signing_payload, derive_synq_address, hash_contract_call_body,
        hash_contract_deploy_body, AlgorithmId, ChainId as PqSynQChainId, ContractCallEnvelope,
        ContractDeployEnvelope, DigitalSignature, DomainTag, NetworkId as PqSynQNetworkId, Sign,
        SignaturePurpose, SynQAddress, SynQPublicKey, SynQSignature, SynQSigningPayload,
    };
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;

    const STS_TEST_CREATOR: &str = "synw1creator000000000000000000000000000";
    const STS_TEST_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // --- Canonical Live Gas Pricing: RPC-layer fee-market tests ---
    // See `canonical_fee_market_state`'s doc comment for the architecture
    // note this file operates under (legacy `BlockChain`, not the
    // canonical `coordinated_runtime` chain).

    fn fee_market_test_transaction(gas_limit: u64) -> Transaction {
        Transaction::new(
            "synw1feemarkettestsender00000000000000".to_string(),
            "synw1feemarkettestreceiver000000000000".to_string(),
            1,
            0,
            Vec::new(),
            crate::gas::constants::DEFAULT_GAS_PRICE,
            gas_limit,
            None,
            "mldsa65".to_string(),
        )
    }

    #[test]
    fn canonical_fee_market_state_on_empty_chain_reports_initial_base_fee_and_no_current() {
        let chain = BlockChain::new();
        let state = canonical_fee_market_state(&chain);
        let params = crate::gas::fee_market::FeeMarketParams::testnet_v3_defaults();
        assert_eq!(state.base_fee_per_gas_nwei, params.initial_base_fee_nwei);
        assert_eq!(state.current_base_fee_per_gas_nwei, None);
        assert_eq!(state.last_block_height, 0);
        assert_eq!(state.last_block_gas_used, 0);
    }

    #[test]
    fn canonical_fee_market_state_replay_matches_manual_recurrence() {
        let mut chain = BlockChain::new();
        // Block 1: a single small transaction (utilization well below
        // target) -- deterministic activity-gas cost via
        // `Transaction::estimate_gas()`, no floating point involved.
        let tx = fee_market_test_transaction(21_000);
        let gas_used_block_1 = tx.estimate_gas();
        chain.add_block(Block::new(
            1,
            vec![tx],
            "genesis".to_string(),
            "v1".to_string(),
            0,
        ));

        let params = crate::gas::fee_market::FeeMarketParams::testnet_v3_defaults();
        let expected_after_block_1 = crate::gas::fee_market::next_base_fee_per_gas(
            params.initial_base_fee_nwei,
            gas_used_block_1,
            &params,
        )
        .unwrap();

        let state = canonical_fee_market_state(&chain);
        assert_eq!(
            state.current_base_fee_per_gas_nwei,
            Some(params.initial_base_fee_nwei),
            "the only mined block was charged the genesis/initial base fee"
        );
        assert_eq!(
            state.base_fee_per_gas_nwei, expected_after_block_1,
            "the next-block price must equal one deterministic recurrence step from the real observed usage"
        );
        assert_eq!(state.last_block_height, 1);
        assert_eq!(state.last_block_gas_used, gas_used_block_1);

        // A second, otherwise-identical block must move the price by
        // exactly one more deterministic step from `expected_after_block_1`,
        // proving this is a true per-block recurrence and not a
        // multi-block average or percentile.
        let tx2 = fee_market_test_transaction(21_000);
        let gas_used_block_2 = tx2.estimate_gas();
        let previous_hash = chain.chain.last().unwrap().hash.clone();
        chain.add_block(Block::new(2, vec![tx2], previous_hash, "v1".to_string(), 0));
        let expected_after_block_2 = crate::gas::fee_market::next_base_fee_per_gas(
            expected_after_block_1,
            gas_used_block_2,
            &params,
        )
        .unwrap();
        let state2 = canonical_fee_market_state(&chain);
        assert_eq!(
            state2.current_base_fee_per_gas_nwei,
            Some(expected_after_block_1)
        );
        assert_eq!(state2.base_fee_per_gas_nwei, expected_after_block_2);
    }

    #[test]
    fn canonical_fee_market_state_never_uses_percentile_or_average_across_blocks() {
        // Ten identical low-utilization blocks: an average/percentile-based
        // implementation (the forbidden anti-pattern) would report a value
        // derived from all ten blocks blended together. The true per-block
        // recurrence instead strictly decreases (toward the floor) every
        // single block, since each block is individually below target.
        let mut chain = BlockChain::new();
        let mut previous_hash = "genesis".to_string();
        for i in 1..=10u64 {
            let tx = fee_market_test_transaction(21_000);
            chain.add_block(Block::new(
                i,
                vec![tx],
                previous_hash.clone(),
                "v1".to_string(),
                0,
            ));
            previous_hash = chain.chain.last().unwrap().hash.clone();
        }
        let params = crate::gas::fee_market::FeeMarketParams::testnet_v3_defaults();
        let mut expected = params.initial_base_fee_nwei;
        let mut prev = u64::MAX;
        for block in &chain.chain {
            let gas_used: u64 = block.transactions.iter().map(|tx| tx.estimate_gas()).sum();
            expected =
                crate::gas::fee_market::next_base_fee_per_gas(expected, gas_used, &params).unwrap();
            assert!(
                expected <= prev,
                "base fee must monotonically move toward the floor under sustained low utilization"
            );
            prev = expected;
        }
        let state = canonical_fee_market_state(&chain);
        assert_eq!(state.base_fee_per_gas_nwei, expected);
    }

    #[test]
    fn fee_market_json_reports_priority_fee_disabled_and_snrg_asset() {
        let chain = Arc::new(Mutex::new(BlockChain::new()));
        let response = fee_market_json(&chain);
        assert_eq!(response["feeAsset"], json!("SNRG"));
        assert_eq!(response["priorityFee"]["enabled"], json!(false));
        assert_eq!(response["source"], json!("protocol"));
        assert_eq!(response["current"]["baseFeePerGas"], Value::Null);
    }

    #[test]
    fn max_priority_fee_per_gas_is_always_zero_not_fabricated() {
        // `synergy_maxPriorityFeePerGas` must report exactly 0 with
        // `priorityFeeEnabled: false`, never a fabricated recommended tip.
        let response = json!({
            "maxPriorityFeePerGas": 0,
            "priorityFeeEnabled": false,
            "feeAsset": "SNRG",
            "note": "No priority-fee/tip market exists on Synergy yet; this is always 0, not a client recommendation.",
        });
        assert_eq!(response["maxPriorityFeePerGas"], json!(0));
        assert_eq!(response["priorityFeeEnabled"], json!(false));
    }

    /// Shared with `validator`, `consensus_algorithm` and `dual_quorum`: these
    /// tests override the process-global `SYNERGY_EPOCH_VALIDATOR_SETS_FILE`,
    /// so the lock has to be the same one everywhere.
    fn rpc_validator_env_lock() -> &'static Mutex<()> {
        crate::validator::epoch_validator_sets_env_lock()
    }

    fn typed_rpc_hash(label: &str) -> Hash {
        Hash::from_domain_bytes("SYNERGY_TYPED_FINALITY_RPC_TEST_V1", label.as_bytes())
    }

    fn typed_rpc_finality_record(height: u64) -> TypedFinalityRecord {
        let transaction = TypedTransaction {
            version: 2,
            chain_id: TypedChainId::synergy_testnet_v3(),
            network_id: TypedNetworkId::synergy_testnet_v3(),
            epoch: TypedEpoch(0),
            sender_uma_or_account: "syna1typed-sender".to_string(),
            receiver_uma_or_account: "syna1typed-receiver".to_string(),
            account_nonce_or_sequence: 7,
            amount_nwei: 42,
            gas_limit: 21_000,
            max_fee_nwei: 9,
            ttl_height: Height(height + 10),
            explicit_dependencies: Vec::new(),
            read_set_hint: Vec::new(),
            write_set_hint: Vec::new(),
            payload: vec![1, 2, 3],
            signer_uma_id: UmaId("uma-sender".to_string()),
            aegis_pq_key_id: AegisPqKeyId("transaction-key".to_string()),
            aegis_pq_signature: AegisPqSignature {
                algorithm: "mldsa87".to_string(),
                signature_bytes: vec![4, 5, 6],
            },
        };
        let block = TypedBlock {
            header: TypedBlockHeader {
                version: 2,
                chain_id: TypedChainId::synergy_testnet_v3(),
                network_id: TypedNetworkId::synergy_testnet_v3(),
                protocol_version: "posy/2.2".to_string(),
                height: Height(height),
                round: Round(0),
                epoch: TypedEpoch(0),
                cluster_id: ClusterId(0),
                height_context_root: typed_rpc_hash("context"),
                parent_block_hash: typed_rpc_hash("parent"),
                parent_state_root: typed_rpc_hash("state-before"),
                last_finalized_qc_hash: typed_rpc_hash("prior-qc"),
                proposer_validator_id: ValidatorId("validator-1".to_string()),
                proposer_uma_id: UmaId("uma-validator-1".to_string()),
                proposer_key_id: AegisPqKeyId("validator-key-1".to_string()),
                active_validator_set_hash: typed_rpc_hash("active-set"),
                eligible_validator_set_hash: typed_rpc_hash("eligible-set"),
                validator_consensus_key_root: typed_rpc_hash("validator-keys"),
                frozen_bonded_weight_root: typed_rpc_hash("weights"),
                cluster_schedule_version: "dynamic-v3-floor7".to_string(),
                cluster_map_hash: typed_rpc_hash("cluster-map"),
                assigned_cluster_membership_root: typed_rpc_hash("members"),
                assigned_cluster_validator_count: 6,
                assigned_cluster_total_voting_weight: 600,
                proposer_schedule_hash: typed_rpc_hash("schedule"),
                protocol_config_hash:
                    crate::consensus_parameters::ConsensusParameterRoot::from_canonical_manifest_bytes(
                        b"typed-rpc-test-parameters",
                    ),
                cryptographic_profile_root: typed_rpc_hash("crypto"),
                dag_frontier_root: typed_rpc_hash("dag"),
                tx_order_root: typed_rpc_hash("tx-order"),
                tx_count: 1,
                protected_batch: None,
                evidence_root: typed_rpc_hash("evidence"),
                state_root_before: typed_rpc_hash("state-before"),
                state_root_after: typed_rpc_hash("state-after"),
                receipt_root: typed_rpc_hash("receipts"),
                app_version: 1,
                execution_version: 1,
                dag_version: 1,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: 2_000,
                base_fee_per_gas_nwei: crate::gas::constants::DEFAULT_GAS_PRICE,
                gas_used: 21_000,
                gas_limit: crate::gas::constants::BLOCK_GAS_LIMIT,
                pq_gas_used: 0,
                pq_gas_limit: 4_000_000,
                pq_gas_multiplier: 4,
                fee_market_version: crate::gas::fee_market::FEE_MARKET_VERSION,
            },
            transactions: vec![transaction],
            proposer_signature: AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![1],
            },
        };
        let quorum_certificate = TypedQuorumCertificate {
            qc_version: 1,
            chain_id: block.header.chain_id,
            network_id: block.header.network_id.clone(),
            protocol_version: block.header.protocol_version.clone(),
            height: block.header.height,
            round: block.header.round,
            epoch: block.header.epoch,
            cluster_id: block.header.cluster_id,
            height_context_root: block.header.height_context_root,
            phase: VotePhase::Finality,
            block_id: block.candidate_id().unwrap(),
            highest_prepared_vc_root: None,
            active_validator_set_hash: block.header.active_validator_set_hash,
            cluster_map_hash: block.header.cluster_map_hash,
            threshold_weight_required: 500,
            signed_weight: 500,
            signer_bitmap: vec![0b0001_1111],
            aegis_pq_signatures: (1..=5)
                .map(|index| AegisPqSignature {
                    algorithm: "mldsa65".to_string(),
                    signature_bytes: vec![index],
                })
                .collect(),
            aegis_pq_key_ids: (1..=5)
                .map(|index| AegisPqKeyId(format!("validator-key-{index}")))
                .collect(),
        };
        TypedFinalityRecord {
            record_version: 3,
            height: block.header.height,
            block_id: block.block_id().unwrap(),
            quorum_certificate_root: quorum_certificate.root().unwrap(),
            block,
            quorum_certificate,
        }
    }

    fn coordinated_rpc_finality_record(height: u64) -> CoordinatedFinalityRecord {
        let mut block = typed_rpc_finality_record(height).block;
        block.header.protocol_version = COORDINATED_ROUND_ROBIN_V1.to_string();
        block.header.last_finalized_qc_hash = Hash::zero();
        block.header.proposer_validator_id = ValidatorId("validator-2".to_string());
        block.header.proposer_uma_id = UmaId("uma-validator-2".to_string());
        block.header.proposer_key_id = AegisPqKeyId("validator-key-2".to_string());

        let assignment = ProducerAssignment {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
            epoch: 0,
            height,
            producer_round: 0,
            parent_block_hash: block.header.parent_block_hash,
            prior_finality_reference: block.header.evidence_root,
            assigned_producer_id: "validator-2".to_string(),
            coordinator_id: "validator-1".to_string(),
            assignment_sequence: 1,
            intended_block_timestamp_ms: block.header.timestamp_ms_consensus_bounded,
            coordinator_signature: AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![2],
            },
        };
        let assignment_hash = assignment.signing_hash().unwrap();
        let block_hash = Hash::from_hex(&block.block_id().unwrap().0).unwrap();
        let proposal = CoordinatedProposal {
            epoch: 0,
            height,
            producer_round: 0,
            parent_block_hash: block.header.parent_block_hash,
            prior_finality_reference: block.header.evidence_root,
            block_hash,
            transaction_root: block.header.tx_order_root,
            transaction_admission_root: Hash::zero(),
            transaction_admissions: Vec::new(),
            receipt_root: block.header.receipt_root,
            state_root: block.header.state_root_after,
            producer_id: "validator-2".to_string(),
            assignment_hash,
            producer_signature: block.proposer_signature.clone(),
        };
        let coordinator_commit = CoordinatorCommit {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            consensus_version: COORDINATED_ROUND_ROBIN_V1.to_string(),
            epoch: 0,
            height,
            producer_round: 0,
            parent_block_hash: block.header.parent_block_hash,
            prior_finality_reference: block.header.evidence_root,
            block_hash,
            transaction_root: block.header.tx_order_root,
            transaction_admission_root: Hash::zero(),
            receipt_root: block.header.receipt_root,
            state_root: block.header.state_root_after,
            producer_id: "validator-2".to_string(),
            coordinator_id: "validator-1".to_string(),
            assignment_hash,
            coordinator_signature: AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![1],
            },
        };
        CoordinatedFinalityRecord {
            record_version: 1,
            height: Height(height),
            block_id: block.block_id().unwrap(),
            coordinator_commit_hash: coordinator_commit.signing_hash().unwrap(),
            package: crate::p2p::messages::CoordinatedCommittedBlockPackage {
                block,
                assignment,
                proposal,
                coordinator_commit,
            },
        }
    }

    #[test]
    fn typed_finality_explorer_block_preserves_real_identity_and_transactions() {
        let record = typed_rpc_finality_record(1);
        let response = typed_finality_record_to_explorer_json(&record).unwrap();

        assert_eq!(response["block_index"], json!(1));
        assert_eq!(response["hash"], json!(record.block_id.0.as_str()));
        assert_eq!(
            response["previous_hash"],
            json!(record.block.header.parent_block_hash.to_hex())
        );
        assert_eq!(response["tx_count"], json!(1));
        assert_eq!(response["transaction_format"], json!("typed_posy_v2"));
        assert_eq!(
            response["transactions"][0]["sender_uma_or_account"],
            json!("syna1typed-sender")
        );
        assert_eq!(response["transactions"][0]["amount_nwei"], json!(42));
        assert!(response["transactions"][0].get("sender").is_none());
        assert!(response.get("nonce").is_none());
        assert_eq!(response["qc_signer_count"], json!(5));
        assert_eq!(response["source"], json!("typed_posy_finality_store"));
    }

    #[test]
    fn typed_finality_height_is_authoritative_only_after_store_presence() {
        let record = typed_rpc_finality_record(7);
        let records = RpcFinalityRecords::Typed(vec![record]);
        assert_eq!(
            authoritative_block_height(Some(&records), Some(99)),
            Some(7)
        );
        assert_eq!(
            authoritative_block_height(Some(&RpcFinalityRecords::Typed(Vec::new())), Some(99)),
            Some(0)
        );
        assert_eq!(authoritative_block_height(None, Some(99)), Some(99));
    }

    #[test]
    fn coordinated_finality_explorer_block_preserves_commit_proof_without_qc_fields() {
        let record = coordinated_rpc_finality_record(4);
        let response = coordinated_finality_record_to_explorer_json(&record).unwrap();

        assert_eq!(response["height"], json!(4));
        assert_eq!(response["validator_id"], json!("validator-2"));
        assert_eq!(response["coordinator_id"], json!("validator-1"));
        assert_eq!(response["assigned_producer_id"], json!("validator-2"));
        assert_eq!(
            response["coordinator_commit_hash"],
            json!(record.coordinator_commit_hash.to_hex())
        );
        assert_eq!(response["finality_proof_type"], json!("coordinator_commit"));
        assert_eq!(
            response["source"],
            json!("coordinated_round_robin_finality_store")
        );
        assert!(response.get("quorum_certificate_root").is_none());
        assert!(response.get("qc_signed_weight").is_none());
    }

    #[test]
    fn coordinated_finality_height_is_authoritative_only_after_store_presence() {
        let records = RpcFinalityRecords::Coordinated(vec![coordinated_rpc_finality_record(4)]);
        assert_eq!(
            authoritative_block_height(Some(&records), Some(99)),
            Some(4)
        );
        assert_eq!(
            authoritative_block_height(
                Some(&RpcFinalityRecords::Coordinated(Vec::new())),
                Some(99)
            ),
            Some(0)
        );
    }

    #[test]
    fn typed_finalized_head_uses_persisted_block_and_qc_identity() {
        let record = typed_rpc_finality_record(3);
        let response = typed_finality_record_to_finalized_head_json(&record);

        assert_eq!(response["height"], json!(3));
        assert_eq!(response["block_hash"], json!(record.block_id.0.as_str()));
        assert_eq!(
            response["quorum_certificate_root"],
            json!(record.quorum_certificate_root.to_hex())
        );
        assert_eq!(response["source"], json!("typed_posy_finality_store"));
    }

    #[test]
    fn etdag_raw_envelopes_are_never_acknowledged_without_a_distributed_scheduler() {
        let response = etdag_distributed_admission_unavailable_json();
        assert_eq!(response["success"], json!(false));
        assert_eq!(
            response["code"],
            json!("ERR_ETDAG_DISTRIBUTED_ADMISSION_UNAVAILABLE")
        );
        assert_eq!(response["admission_status"], json!("NOT_ACCEPTED"));
        assert_eq!(response["automatic_plaintext_fallback"], json!(false));
    }

    struct RpcEnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl RpcEnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for RpcEnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.as_ref() {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn sts_test_create_params() -> CreateFungibleParams {
        CreateFungibleParams {
            class: TokenClass::B1BasicFungible,
            creator: STS_TEST_CREATOR.to_string(),
            creator_nonce: 1,
            name: "Testnet Gold".to_string(),
            symbol: "TGLD".to_string(),
            decimals: 9,
            initial_supply: 1_000_000,
            max_supply: Some(1_000_000),
            mint_authority: None,
            metadata_authority: None,
            metadata_uri: Some("ipfs://tgld".to_string()),
            metadata_hash: Some(STS_TEST_HASH.to_string()),
            metadata_mutable: false,
            image_uri: None,
            image_hash: None,
            flags: FungibleControlFlags::default(),
            policies: Vec::new(),
            created_at: 1_700_000_000,
        }
    }

    fn sts_test_transaction(data: String) -> Transaction {
        Transaction {
            chain_id: crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID.to_string(),
            sender: STS_TEST_CREATOR.to_string(),
            receiver: "sts".to_string(),
            amount: 0,
            nonce: 1,
            signature: vec![1, 2, 3],
            signer_public_key: vec![4, 5, 6],
            timestamp: 1_700_000_001,
            gas_price: 40,
            gas_limit: 125_000,
            data: Some(data),
            signature_algorithm: "mldsa87".to_string(),
        }
    }

    fn sts_test_chain(data: String) -> BlockChain {
        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "0".to_string(),
            "genesis".to_string(),
            0,
            1_700_000_000,
        );
        let block = Block::new_with_timestamp(
            1,
            vec![sts_test_transaction(data)],
            genesis.hash.clone(),
            "validator-1".to_string(),
            0,
            1_700_000_001,
        );
        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        chain.add_block(block);
        chain
    }

    fn sts_test_payload_hex() -> String {
        let payload = StsSignedPayload::new(StsTx::CreateFungible(sts_test_create_params()));
        hex::encode(encode_sts_payload(&payload).expect("sts payload encodes"))
    }

    #[test]
    fn sts_payload_extractor_reads_cli_artifact_payload_hex() {
        let artifact = json!({"payload_hex": sts_test_payload_hex()}).to_string();
        let payload = extract_sts_payload_from_transaction_data(&artifact)
            .expect("artifact parses")
            .expect("payload exists");

        assert_eq!(payload.chain_id, crate::sts::STS_TESTNET_CHAIN_ID);
    }

    #[test]
    fn sts_replay_from_chain_materializes_fungible_registry() {
        let chain = sts_test_chain(sts_test_payload_hex());
        let report = sts_replay_from_chain(&chain).expect("genesis chain replays");
        let definition = report
            .state
            .fungible_definitions()
            .into_iter()
            .next()
            .expect("created token exists");

        assert!(definition.token_address.starts_with("synb1"));
        assert_eq!(
            report
                .state
                .fungible_balance(STS_TEST_CREATOR, &definition.token_id),
            1_000_000
        );
    }

    #[test]
    fn sts_replay_from_chain_fails_closed_for_compact_chain() {
        let compact_block = Block::new_with_timestamp(
            42,
            Vec::new(),
            "previous".to_string(),
            "validator-1".to_string(),
            0,
            1_700_000_000,
        );
        let mut chain = BlockChain::new();
        chain.add_block(compact_block);

        let error = sts_replay_from_chain(&chain).expect_err("compact chain is incomplete");
        assert_eq!(error.code, -32021);
    }

    #[derive(Clone)]
    struct RpcCounterSynQFixture {
        public_key: SynQPublicKey,
        private_key: Vec<u8>,
        address: SynQAddress,
        bytecode: Vec<u8>,
        abi_json: String,
        manifest_json: String,
        bytecode_hash: [u8; 32],
        manifest_hash: [u8; 32],
        abi_hash: [u8; 32],
    }

    impl RpcCounterSynQFixture {
        fn new() -> Option<Self> {
            let signer = Sign::mldsa87();
            let (public_key_bytes, private_key) = signer.keygen().expect("ML-DSA-87 keygen");
            let public_key = SynQPublicKey::new(public_key_bytes);
            let address = derive_synq_address(
                &public_key,
                AlgorithmId::MlDsa87,
                &PqSynQNetworkId(
                    crate::synq_admission::SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string(),
                ),
            )
            .expect("derive SynQ address");
            let root =
                PathBuf::from("/Volumes/xcode/Synergy-Network-Projects/synq-language/contracts");
            if !root.join("Counter.compiled.synq").exists()
                || !root.join("Counter.abi.json").exists()
                || !root.join("Counter.manifest.json").exists()
            {
                return None;
            }
            let bytecode = fs::read(root.join("Counter.compiled.synq")).expect("Counter bytecode");
            let abi_json = fs::read_to_string(root.join("Counter.abi.json")).expect("Counter ABI");
            let manifest_json =
                fs::read_to_string(root.join("Counter.manifest.json")).expect("Counter manifest");
            let bytecode_hash = sha256_array(&bytecode);
            let manifest_hash = sha256_array(manifest_json.as_bytes());
            let abi_hash = sha256_array(abi_json.as_bytes());
            Some(Self {
                public_key,
                private_key,
                address,
                bytecode,
                abi_json,
                manifest_json,
                bytecode_hash,
                manifest_hash,
                abi_hash,
            })
        }

        fn deploy_envelope(&self) -> ContractDeployEnvelope {
            let constructor_args_hash = sha256_array(&[]);
            let payload_hash = hash_contract_deploy_body(
                &self.bytecode_hash,
                &self.manifest_hash,
                &self.abi_hash,
                self.address.as_bytes(),
                &constructor_args_hash,
            );
            let signing_payload = self.signing_payload(
                DomainTag::SynqContractDeployV1,
                SignaturePurpose::ContractDeploy,
                payload_hash,
                501,
            );
            let signature = self.sign_payload(&signing_payload);
            ContractDeployEnvelope {
                signing_payload,
                public_key: self.public_key.clone(),
                signature: SynQSignature::new(signature),
                bytecode_hash: self.bytecode_hash,
                manifest_hash: self.manifest_hash,
                abi_hash: self.abi_hash,
                constructor_args_hash,
            }
        }

        fn contract_address(&self) -> SynQAddress {
            derive_synq_contract_address_from_deploy(&self.deploy_envelope())
                .expect("derive SynQ contract address")
        }

        fn deploy_payload(&self) -> Vec<u8> {
            let deploy = self.deploy_envelope();
            let pqsynq_bytes = serde_json::to_vec(&deploy).expect("deploy JSON");
            crate::synq_admission::build_deploy_admission_carrier_from_pqsynq_bytes_with_artifacts(
                crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID,
                crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID,
                &pqsynq_bytes,
                self.bytecode.clone(),
                self.abi_json.clone(),
                self.manifest_json.clone(),
                crate::synq_admission::test_support::TEST_NOW,
            )
            .expect("deploy carrier with artifacts")
        }

        fn call_payload(
            &self,
            contract_address: SynQAddress,
            method_selector: [u8; 4],
            nonce: u64,
        ) -> Vec<u8> {
            let encoded_args_hash = sha256_array(&[]);
            let payload_hash = hash_contract_call_body(
                contract_address.as_bytes(),
                &method_selector,
                &encoded_args_hash,
                self.address.as_bytes(),
            );
            let signing_payload = self.signing_payload(
                DomainTag::SynqContractCallV1,
                SignaturePurpose::ContractCall,
                payload_hash,
                nonce,
            );
            let signature = self.sign_payload(&signing_payload);
            let call = ContractCallEnvelope {
                signing_payload,
                public_key: self.public_key.clone(),
                signature: SynQSignature::new(signature),
                contract_address,
                method_selector,
                encoded_args_hash,
            };
            crate::synq_admission::build_call_admission_carrier_from_pqsynq_bytes(
                crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID,
                crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID,
                &serde_json::to_vec(&call).expect("call JSON"),
                crate::synq_admission::test_support::TEST_NOW,
            )
            .expect("call carrier")
        }

        fn signing_payload(
            &self,
            domain_tag: DomainTag,
            signature_purpose: SignaturePurpose,
            payload_hash: [u8; 32],
            nonce: u64,
        ) -> SynQSigningPayload {
            SynQSigningPayload {
                domain_tag,
                chain_id: PqSynQChainId(crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID),
                network_id: PqSynQNetworkId(
                    crate::synq_admission::SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string(),
                ),
                protocol_version: 1,
                algorithm_id: AlgorithmId::MlDsa87,
                signature_purpose,
                nonce,
                not_before_unix: 0,
                expiration_unix: 4_102_444_800,
                signer_address: self.address,
                payload_hash,
            }
        }

        fn sign_payload(&self, payload: &SynQSigningPayload) -> Vec<u8> {
            let canonical = canonicalize_signing_payload(payload).expect("canonical payload");
            Sign::mldsa87()
                .detached_sign(&canonical, &self.private_key)
                .expect("ML-DSA-65 sign")
        }
    }

    fn sha256_array(bytes: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(bytes);
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    fn aegis_synq_legacy_transaction(payload: Vec<u8>, nonce: u64) -> Transaction {
        sign_with_new_aegis_transaction_key(AegisTxBuildOptions {
            nonce,
            amount_nwei: 1,
            gas_limit: 150_000,
            max_fee_nwei: 1_000,
            write_set_hint: vec![format!("synq-counter-{nonce}")],
            payload,
            ..AegisTxBuildOptions::default()
        })
        .expect("Aegis transaction should sign")
        .rpc_transaction
    }

    fn decode_u256_hex(value: &str) -> u64 {
        let bytes = hex::decode(value).expect("return data hex");
        assert_eq!(bytes.len(), 32);
        u64::from_be_bytes(bytes[24..32].try_into().expect("u64 tail"))
    }

    fn temp_synq_receipt_index_path(test_name: &str) -> PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = crate::utils::test_temp_root(format!(
            "synergy-synq-receipts-{test_name}-{}-{suffix}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        path
    }

    fn admission_valid_but_runtime_invalid_transaction() -> Transaction {
        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::MLDSA87)
            .expect("test keypair should generate");
        let sender = crate::address::generate_wallet_address(&hex::encode(&public_key.key_data));
        let receiver = crate::address::generate_wallet_address(&hex::encode([7u8; 32]));
        let mut transaction = Transaction::new(
            sender,
            receiver,
            1,
            0,
            Vec::new(),
            100,
            21_000,
            None,
            "mldsa87".to_string(),
        );
        transaction
            .sign_with_public_key(&public_key, &private_key, &mut manager)
            .expect("test transaction should sign");
        transaction
    }

    #[test]
    fn normalize_spec_transaction_envelope_maps_to_internal_transaction() {
        let envelope = json!({
            "from": "syna1sender",
            "to": "syna1receiver",
            "value": 42,
            "nonce": 7,
            "gasLimit": 21000,
            "maxFee": 1000,
            "signature": "0x01020304",
            "signerPublicKey": "0x05060708",
            "signatureAlgorithm": "ML-DSA-87",
            "chainId": "0x1234",
            "networkId": "synergy-testnet-v3"
        });

        let normalized =
            normalize_rpc_transaction(&envelope, true).expect("envelope should normalize");
        assert_eq!(normalized.transaction.sender, "syna1sender");
        assert_eq!(normalized.transaction.receiver, "syna1receiver");
        assert_eq!(normalized.transaction.amount, 42);
        assert_eq!(normalized.transaction.nonce, 7);
        assert_eq!(normalized.transaction.gas_limit, 21000);
        assert_eq!(normalized.transaction.gas_price, 1000);
        assert_eq!(normalized.transaction.signature, vec![1, 2, 3, 4]);
        assert_eq!(normalized.transaction.signer_public_key, vec![5, 6, 7, 8]);
        assert_eq!(normalized.transaction.signature_algorithm, "mldsa87");
        assert_eq!(normalized.transaction.network_id, "synergy-testnet-v3");
        assert_eq!(normalized.chain_id, Some(0x1234));
    }

    #[test]
    fn normalize_signed_transaction_requires_explicit_signature_algorithm() {
        let envelope = json!({
            "from": "syna1sender",
            "to": "syna1receiver",
            "value": 42,
            "nonce": 7,
            "gasLimit": 21000,
            "maxFee": 1000,
            "signature": "0x01020304",
            "signerPublicKey": "0x05060708",
            "chainId": "0x1234",
            "networkId": "synergy-testnet-v3"
        });

        let error =
            normalize_rpc_transaction(&envelope, true).expect_err("algorithm must be explicit");

        assert_eq!(error.code, -32602);
        assert!(error.message.contains("Missing signatureAlgorithm"));
    }

    #[test]
    fn normalize_transaction_rejects_ambiguous_signature_algorithm() {
        let envelope = json!({
            "from": "syna1sender",
            "to": "syna1receiver",
            "value": 42,
            "nonce": 7,
            "gasLimit": 21000,
            "maxFee": 1000,
            "signature": "0x01020304",
            "signerPublicKey": "0x05060708",
            "signatureAlgorithm": "pqc",
            "chainId": "0x1234",
            "networkId": "synergy-testnet-v3"
        });

        let error = normalize_rpc_transaction(&envelope, true).expect_err("algorithm is ambiguous");

        assert_eq!(error.code, -32602);
        assert!(error.message.contains("Ambiguous signature algorithm"));
    }

    #[test]
    fn normalize_transaction_rejects_unsupported_signature_algorithm() {
        let envelope = json!({
            "from": "syna1sender",
            "to": "syna1receiver",
            "value": 42,
            "nonce": 7,
            "gasLimit": 21000,
            "maxFee": 1000,
            "signature": "0x01020304",
            "signerPublicKey": "0x05060708",
            "signatureAlgorithm": "unsupported-signature",
            "chainId": "0x1234",
            "networkId": "synergy-testnet-v3"
        });

        let error =
            normalize_rpc_transaction(&envelope, true).expect_err("algorithm is unsupported");

        assert_eq!(error.code, -32602);
        assert!(error.message.contains("use mldsa87"));
    }

    #[test]
    fn normalize_transaction_rejects_delegation_payloads() {
        let envelope = json!({
            "from": "syna1sender",
            "to": "syna1receiver",
            "value": 1,
            "nonce": 1,
            "signature": "0x01",
            "type": "0x04"
        });

        let error =
            normalize_rpc_transaction(&envelope, true).expect_err("delegations must be rejected");
        assert_eq!(error.code, -32014);
    }

    #[test]
    fn translate_legacy_result_promotes_embedded_errors() {
        let legacy = json!({
            "success": false,
            "error": "boom"
        });

        let error =
            translate_legacy_rpc_result(legacy).expect_err("legacy error should map to RpcError");
        assert_eq!(error.code, -32000);
        assert_eq!(error.message, "boom");
    }

    #[test]
    fn peer_info_response_reports_snapshot_readiness_counts_and_reasons() {
        let response = peer_info_response_json(
            vec![
                json!({
                    "validator_address": "synv1ready",
                    "status_fresh": true,
                    "readiness_exclusion_reason": null
                }),
                json!({
                    "validator_address": "synv1stale",
                    "status_fresh": false,
                    "readiness_exclusion_reason": "stale-status"
                }),
            ],
            vec!["synv1ready".to_string()],
            2,
        );

        assert_eq!(response["peer_count"].as_u64(), Some(2));
        assert_eq!(response["connected_validator_count"].as_u64(), Some(2));
        assert_eq!(response["status_ready_validator_count"].as_u64(), Some(1));
        assert_eq!(
            response["status_ready_validator_addresses"]
                .as_array()
                .and_then(|items| items.first())
                .and_then(Value::as_str),
            Some("synv1ready")
        );
        assert_eq!(
            response["peers"]
                .as_array()
                .and_then(|items| items.get(1))
                .and_then(|peer| peer.get("readiness_exclusion_reason"))
                .and_then(Value::as_str),
            Some("stale-status")
        );
    }

    #[test]
    fn request_is_json_recognizes_application_json() {
        let headers = parse_http_headers(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json; charset=utf-8\r\n\r\n",
        );
        assert!(request_is_json(&headers));
    }

    #[test]
    fn http_header_end_detects_split_body_boundary() {
        let request =
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 14\r\n\r\n{\"jsonrpc\":\"2";
        let header_end = find_http_header_end(request).expect("header delimiter should be found");
        assert_eq!(&request[header_end..header_end + 4], b"\r\n\r\n");
        assert_eq!(&request[header_end + 4..], b"{\"jsonrpc\":\"2");
    }

    #[test]
    fn http_responses_close_connections_explicitly() {
        let response = format_http_response("200 OK", "application/json", "{}", false, &[]);
        assert!(response.contains("\r\nConnection: close\r\n"));

        let preflight = format_cors_preflight_response(true, &["https://example.com".to_string()]);
        assert!(preflight.contains("\r\nConnection: close\r\n"));
    }

    #[test]
    fn trusted_proxy_forwarded_ip_prefers_proxy_header() {
        let mut headers = HashMap::new();
        headers.insert(
            "x-forwarded-for".to_string(),
            "198.51.100.22, 127.0.0.1".to_string(),
        );

        let context = RpcRequestContext {
            transport: RpcTransport::Http,
            peer_addr: Some("127.0.0.1:5646".parse().unwrap()),
            headers,
            role_profile: None,
        };

        assert_eq!(
            context
                .effective_client_ip()
                .expect("forwarded ip should be present")
                .to_string(),
            "198.51.100.22"
        );
        assert!(context.is_public_request());
    }

    #[test]
    fn untrusted_proxy_header_cannot_spoof_loopback() {
        let mut headers = HashMap::new();
        headers.insert("x-forwarded-for".to_string(), "127.0.0.1".to_string());

        let context = RpcRequestContext {
            transport: RpcTransport::Http,
            peer_addr: Some("198.51.100.10:5646".parse().unwrap()),
            headers,
            role_profile: crate::role_profiles::profile_from_compiled_profile("rpc_gateway_node"),
        };

        assert_eq!(
            context
                .effective_client_ip()
                .expect("socket peer ip should be used")
                .to_string(),
            "198.51.100.10"
        );
        assert!(context.is_public_request());
        let error = enforce_rpc_exposure_policy("synergy_resetSxcpState", &context)
            .expect_err("spoofed forwarded loopback must not unlock operator methods");
        assert_eq!(error.code, -32003);
    }

    #[test]
    fn trusted_proxy_entries_support_exact_and_cidr_matches() {
        assert!(trusted_proxy_entry_matches(
            "203.0.113.8".parse().unwrap(),
            "203.0.113.8"
        ));
        assert!(trusted_proxy_entry_matches(
            "203.0.113.8".parse().unwrap(),
            "203.0.113.0/24"
        ));
        assert!(!trusted_proxy_entry_matches(
            "198.51.100.8".parse().unwrap(),
            "203.0.113.0/24"
        ));
    }

    #[test]
    fn trusted_proxy_forwarded_ip_accepts_cloudflare_header() {
        let mut headers = HashMap::new();
        headers.insert("cf-connecting-ip".to_string(), "198.51.100.44".to_string());
        headers.insert(
            "x-forwarded-for".to_string(),
            "127.0.0.1, 127.0.0.1".to_string(),
        );

        let context = RpcRequestContext {
            transport: RpcTransport::WebSocket,
            peer_addr: Some("127.0.0.1:5666".parse().unwrap()),
            headers,
            role_profile: crate::role_profiles::profile_from_compiled_profile("rpc_gateway_node"),
        };

        assert_eq!(
            context
                .effective_client_ip()
                .expect("cloudflare header should be present")
                .to_string(),
            "198.51.100.44"
        );
        assert!(context.is_public_request());
        let error = enforce_rpc_exposure_policy("synergy_createWallet", &context)
            .expect_err("authority-plane method should be denied");
        assert_eq!(error.code, -32003);
    }

    #[test]
    fn public_proxy_denies_authority_plane_methods() {
        let mut headers = HashMap::new();
        headers.insert("x-forwarded-for".to_string(), "198.51.100.22".to_string());
        let context = RpcRequestContext {
            transport: RpcTransport::Http,
            peer_addr: Some("127.0.0.1:5646".parse().unwrap()),
            headers,
            role_profile: crate::role_profiles::profile_from_compiled_profile("rpc_gateway_node"),
        };

        let error = enforce_rpc_exposure_policy("synergy_createWallet", &context)
            .expect_err("authority-plane method should be denied");
        assert_eq!(error.code, -32003);
        assert!(error.message.contains("exposure profile"));
    }

    #[test]
    fn public_gateway_allows_encrypted_client_pipeline() {
        let mut headers = HashMap::new();
        headers.insert("x-forwarded-for".to_string(), "198.51.100.22".to_string());
        let context = RpcRequestContext {
            transport: RpcTransport::Http,
            peer_addr: Some("127.0.0.1:5646".parse().unwrap()),
            headers,
            role_profile: crate::role_profiles::profile_from_compiled_profile("rpc_gateway_node"),
        };

        enforce_rpc_exposure_policy("synergy_submitEncryptedTransaction", &context)
            .expect("encrypted public client method should be allowed");
        enforce_rpc_exposure_policy("synergy_getEtdagStatus", &context)
            .expect("content-free ETDAG status should be public");
        enforce_rpc_exposure_policy("synergy_getEtdagAdmissionPackage", &context)
            .expect("certified public ETDAG admission package should be public");
        enforce_rpc_exposure_policy("synergy_getConsensusSafetyHalt", &context)
            .expect("content-free consensus SafetyHalt status should be public");
    }

    #[test]
    fn consensus_safety_halt_status_is_operator_visible_and_fail_closed() {
        let path = crate::utils::test_temp_root(format!(
            "synergy-rpc-safety-halt-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let authority =
            crate::consensus::signing_authority::DurableConsensusSigningAuthority::at_path(path);
        let allowed = consensus_safety_halt_status_for(&authority);
        assert_eq!(allowed["status"], "SIGNING_ALLOWED");
        assert_eq!(allowed["signing_allowed"], true);

        authority
            .enter_safety_halt(
                &crate::consensus::signing_authority::SafetyHaltIncident {
                    incident_version: 1,
                    kind: crate::consensus::signing_authority::SafetyHaltKind::ConflictingFinalityCertificates,
                    chain_id: crate::synergy_types::ChainId::synergy_testnet_v3(),
                    network_id: crate::synergy_types::NetworkId::synergy_testnet_v3(),
                    protocol_version: crate::synergy_types::POSY_PROTOCOL_VERSION.to_string(),
                    epoch: crate::synergy_types::Epoch(0),
                    height: crate::synergy_types::Height(8),
                    context_root: Hash::from_domain_bytes("rpc-halt-context", b"height-eight"),
                    first_evidence_root: Hash::from_domain_bytes("rpc-halt-qc", b"candidate-a"),
                    second_evidence_root: Hash::from_domain_bytes("rpc-halt-qc", b"candidate-b"),
                },
            )
            .unwrap();
        let halted = consensus_safety_halt_status_for(&authority);
        assert_eq!(halted["status"], "SAFETY_HALT");
        assert_eq!(halted["signing_allowed"], false);
        assert_eq!(halted["incident_count"], 1);
        assert_eq!(halted["clearable_by_runtime"], false);
        assert_eq!(
            halted["incidents"][0]["kind"],
            "CONFLICTING_FINALITY_CERTIFICATES"
        );
    }

    #[test]
    fn public_gateway_allows_launch_read_rpc_surface() {
        let mut headers = HashMap::new();
        headers.insert("x-forwarded-for".to_string(), "198.51.100.22".to_string());
        let context = RpcRequestContext {
            transport: RpcTransport::Http,
            peer_addr: Some("127.0.0.1:5646".parse().unwrap()),
            headers,
            role_profile: crate::role_profiles::profile_from_compiled_profile("rpc_gateway_node"),
        };

        for method in [
            "synergy_chainId",
            "synergy_networkId",
            "synergy_genesisHash",
            "synergy_getHealth",
            "synergy_getReadiness",
            "synergy_getFinalizedHead",
            "synergy_getCanonicalLock",
            "synergy_getCommittedQC",
            "synergy_getAegisStatus",
            "synergy_getAegisCapabilities",
            "synergy_verifyAegisTransaction",
            "synergy_getDagGraph",
            "synergy_getDagDependencies",
            "synergy_getDagTxOrderRoot",
            "synergy_getValidatorStats",
            "synergy_getNetworkStats",
            "synergy_estimateFee",
            "synergy_gasPrice",
            "synergy_getFeeSchedule",
            "synergy_getFeeMarket",
            "synergy_maxFeePerGas",
            "synergy_maxPriorityFeePerGas",
            "synergy_getFeeCollector",
            "synergy_getFeeCollectorBalance",
            "synergy_getBurnLedger",
            "synergy_getEpochRewardAudit",
            "synergy_checkRewardInvariants",
        ] {
            enforce_rpc_exposure_policy(method, &context)
                .unwrap_or_else(|error| panic!("{method} should be public: {error:?}"));
        }
    }

    #[test]
    fn legacy_plaintext_submit_routes_are_classified_but_fail_closed_in_execution() {
        let mut headers = HashMap::new();
        headers.insert("x-forwarded-for".to_string(), "198.51.100.22".to_string());
        let context = RpcRequestContext {
            transport: RpcTransport::Http,
            peer_addr: Some("127.0.0.1:5646".parse().unwrap()),
            headers,
            role_profile: crate::role_profiles::profile_from_compiled_profile("rpc_gateway_node"),
        };

        for method in [
            "synergy_sendTransaction",
            "synergy_submitAegisTransaction",
            "synergy_submitAegisTransactionBatch",
            "synergy_submitAegisDagTransaction",
            "synergy_submitAegisDagTransactionBatch",
        ] {
            enforce_rpc_exposure_policy(method, &context)
                .unwrap_or_else(|error| panic!("{method} should be client-safe: {error:?}"));
        }

        let tx_pool = Arc::new(Mutex::new(Vec::<Transaction>::new()));
        let chain = Arc::new(Mutex::new(BlockChain::new()));
        let validator_manager = Arc::new(ValidatorManager::new());
        for method in [
            "synergy_sendTransaction",
            "synergy_submitAegisTransaction",
            "synergy_submitAegisTransactionBatch",
            "synergy_submitAegisDagTransaction",
            "synergy_submitAegisDagTransactionBatch",
        ] {
            let result = handle_json_rpc(method, json!([{}]), &tx_pool, &chain, &validator_manager);
            assert_eq!(
                result["code"],
                json!(crate::etdag::ERR_PLAINTEXT_USER_TX_DISABLED),
                "{method} did not fail closed"
            );
            assert_eq!(result["automatic_plaintext_fallback"], json!(false));
        }
        let pending = handle_json_rpc(
            "synergy_getDagGraph",
            json!([]),
            &tx_pool,
            &chain,
            &validator_manager,
        );
        assert_eq!(
            pending["code"],
            json!("ERR_PRE_REVEAL_PENDING_CONTENT_DISABLED")
        );
        let status = handle_json_rpc(
            "synergy_getEtdagStatus",
            json!([]),
            &tx_pool,
            &chain,
            &validator_manager,
        );
        assert_eq!(status["plaintext_user_tx_allowed"], json!(false));
        assert_eq!(
            status["public_pending_content_before_reveal_gate"],
            json!(false)
        );
    }

    #[test]
    fn launch_identity_rpc_reports_canonical_testnet_identity() {
        let tx_pool = Arc::new(Mutex::new(Vec::<Transaction>::new()));
        let chain = Arc::new(Mutex::new(BlockChain::new()));
        let validator_manager = Arc::new(ValidatorManager::new());

        let identity = handle_json_rpc(
            "synergy_chainId",
            json!([]),
            &tx_pool,
            &chain,
            &validator_manager,
        );

        assert_eq!(identity["chain_id"], 1266);
        assert_eq!(identity["chain_id_hex"], "0x4f2"); // 1266
        assert_eq!(identity["network_id"], "synergy-testnet-v3");
        // Chain identity is asserted against the genesis actually loaded, never
        // against a hardcoded literal: a stale literal is how the retired
        // Testnet-v2 genesis hash survived in this suite.
        let expected_genesis_hash = canonical_genesis()
            .expect("canonical genesis must load")
            .hash()
            .to_string();
        assert_eq!(identity["genesis_hash"], expected_genesis_hash);
        assert_ne!(
            identity["genesis_hash"],
            "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789",
            "Testnet-v2 genesis hash must never be reported by a Testnet-v3 node"
        );
    }

    #[test]
    fn burn_ledger_rpc_reports_canonical_burn_address() {
        let tx_pool = Arc::new(Mutex::new(Vec::<Transaction>::new()));
        let chain = Arc::new(Mutex::new(BlockChain::new()));
        let validator_manager = Arc::new(ValidatorManager::new());

        let ledger = handle_json_rpc(
            "synergy_getBurnLedger",
            json!(["SNRG"]),
            &tx_pool,
            &chain,
            &validator_manager,
        );

        assert_eq!(ledger["assetId"], "SNRG");
        assert_eq!(ledger["burnAddress"], crate::address::NETWORK_BURN_ADDRESS);
        assert!(ledger["records"].is_array());
    }

    #[test]
    fn reward_invariant_rpc_returns_epoch_scoped_report() {
        let _ledger_guard = crate::rewards::reward_ledger_test_guard();
        crate::rewards::reset_reward_ledger_for_test();
        let tx_pool = Arc::new(Mutex::new(Vec::<Transaction>::new()));
        let chain = Arc::new(Mutex::new(BlockChain::new()));
        let validator_manager = Arc::new(ValidatorManager::new());

        let report = handle_json_rpc(
            "synergy_checkRewardInvariants",
            json!([787]),
            &tx_pool,
            &chain,
            &validator_manager,
        );

        assert_eq!(report["epoch"], 787);
        assert!(report["checked_invariants"].is_array());
        assert!(report["violations"].is_array());
        assert!(report["passed"].is_boolean());
    }

    #[test]
    fn reward_audit_rpc_returns_epoch_scoped_events() {
        let _ledger_guard = crate::rewards::reward_ledger_test_guard();
        crate::rewards::reset_reward_ledger_for_test();
        let tx_pool = Arc::new(Mutex::new(Vec::<Transaction>::new()));
        let chain = Arc::new(Mutex::new(BlockChain::new()));
        let validator_manager = Arc::new(ValidatorManager::new());

        let audit = handle_json_rpc(
            "synergy_getEpochRewardAudit",
            json!([787]),
            &tx_pool,
            &chain,
            &validator_manager,
        );

        assert_eq!(audit["epoch"], json!(787));
        assert!(audit["eventCount"].is_number());
        assert!(audit["events"].is_array());
    }

    #[test]
    fn read_last_nonempty_line_handles_large_lines_and_missing_final_newline() {
        let path = crate::utils::test_temp_root(format!(
            "synergy-rpc-last-line-{}-{}.jsonl",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let large_line = format!("{{\"payload\":\"{}\"}}", "x".repeat(96 * 1024));
        fs::write(&path, format!("{{\"height\":1}}\n{large_line}\n  \n")).unwrap();
        assert_eq!(read_last_nonempty_line(&path).unwrap(), Some(large_line));
        fs::write(&path, b"first\nlast").unwrap();
        assert_eq!(
            read_last_nonempty_line(&path).unwrap().as_deref(),
            Some("last")
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn synq_transaction_receipt_replays_counter_state_from_committed_aegis_carriers() {
        let Some(fixture) = RpcCounterSynQFixture::new() else {
            eprintln!("skipping SynQ Counter RPC fixture test; contract artifacts are missing");
            return;
        };
        let deploy = aegis_synq_legacy_transaction(fixture.deploy_payload(), 0);
        let contract_address = fixture.contract_address();
        let contract_address_text = synergy_contract_address_from_pqsynq_address(&contract_address);
        let increment = aegis_synq_legacy_transaction(
            fixture.call_payload(contract_address, [0x58, 0x42, 0xf1, 0xbe], 502),
            1,
        );
        let get = aegis_synq_legacy_transaction(
            fixture.call_payload(contract_address, [0x75, 0xb7, 0x04, 0x57], 503),
            2,
        );
        let get_hash = get.hash();
        let mut chain = BlockChain::new();
        chain.add_block(Block::new_with_timestamp(
            1,
            vec![deploy, increment, get],
            "genesis".to_string(),
            "validator".to_string(),
            0,
            crate::synq_admission::test_support::TEST_NOW,
        ));
        let chain = Arc::new(Mutex::new(chain));
        let index_path = temp_synq_receipt_index_path("counter-replay");

        let receipt =
            transaction_receipt_json_with_index_path(&json!([get_hash]), &chain, Some(&index_path));

        assert_eq!(receipt["status"], "0x1");
        assert_eq!(
            receipt["synq_verification"]["domain"],
            "SYNQ_CONTRACT_CALL_V1"
        );
        assert_eq!(receipt["synq_verification"]["algorithm"], "ML-DSA-87");
        assert_eq!(receipt["synq_aivm"]["status"], "succeeded");
        assert_eq!(receipt["synq_aivm"]["operation"], "call");
        assert_eq!(
            receipt["synq_aivm"]["contract_address"],
            contract_address_text
        );
        assert_eq!(
            decode_u256_hex(receipt["synq_aivm"]["return_data_hex"].as_str().unwrap()),
            1
        );
        assert!(receipt["synq_receipt_hash"]
            .as_str()
            .map(|hash| !hash.is_empty())
            .unwrap_or(false));
        assert_eq!(
            receipt["synq_replay"]["source"],
            "committed_aegis_carrier_hot_chain_replay"
        );
        let _ = fs::remove_file(index_path);
    }

    #[test]
    fn synq_receipt_index_carries_aivm_state_across_compacted_chain_window() {
        let Some(fixture) = RpcCounterSynQFixture::new() else {
            eprintln!("skipping SynQ Counter RPC fixture test; contract artifacts are missing");
            return;
        };
        let deploy = aegis_synq_legacy_transaction(fixture.deploy_payload(), 0);
        let deploy_hash = deploy.hash();
        let contract_address = fixture.contract_address();
        let contract_address_text = synergy_contract_address_from_pqsynq_address(&contract_address);
        let increment = aegis_synq_legacy_transaction(
            fixture.call_payload(contract_address, [0x58, 0x42, 0xf1, 0xbe], 502),
            1,
        );
        let get = aegis_synq_legacy_transaction(
            fixture.call_payload(contract_address, [0x75, 0xb7, 0x04, 0x57], 503),
            2,
        );
        let get_hash = get.hash();
        let index_path = temp_synq_receipt_index_path("compacted-continuation");

        let mut deploy_chain = BlockChain::new();
        deploy_chain.add_block(Block::new_with_timestamp(
            1,
            vec![deploy],
            "genesis".to_string(),
            "validator".to_string(),
            0,
            crate::synq_admission::test_support::TEST_NOW,
        ));
        let deploy_chain = Arc::new(Mutex::new(deploy_chain));
        let deploy_receipt = transaction_receipt_json_with_index_path(
            &json!([deploy_hash]),
            &deploy_chain,
            Some(&index_path),
        );
        assert_eq!(deploy_receipt["synq_aivm"]["status"], "succeeded");

        let mut compacted_chain = BlockChain::new();
        compacted_chain.chain.clear();
        compacted_chain.add_block(Block::new_with_timestamp(
            2,
            vec![increment, get],
            "block-1-compacted".to_string(),
            "validator".to_string(),
            0,
            crate::synq_admission::test_support::TEST_NOW + 1,
        ));
        let compacted_chain = Arc::new(Mutex::new(compacted_chain));
        let get_receipt = transaction_receipt_json_with_index_path(
            &json!([get_hash.clone()]),
            &compacted_chain,
            Some(&index_path),
        );

        assert_eq!(get_receipt["status"], "0x1");
        assert_eq!(get_receipt["synq_aivm"]["status"], "succeeded");
        assert_eq!(
            get_receipt["synq_aivm"]["contract_address"],
            contract_address_text
        );
        assert_eq!(
            decode_u256_hex(
                get_receipt["synq_aivm"]["return_data_hex"]
                    .as_str()
                    .unwrap()
            ),
            1
        );

        let empty_chain = Arc::new(Mutex::new(BlockChain::new()));
        let indexed_receipt = transaction_receipt_json_with_index_path(
            &json!([get_hash]),
            &empty_chain,
            Some(&index_path),
        );
        assert_eq!(
            indexed_receipt["synq_receipt_hash"],
            get_receipt["synq_receipt_hash"]
        );
        assert_eq!(
            decode_u256_hex(
                indexed_receipt["synq_aivm"]["return_data_hex"]
                    .as_str()
                    .unwrap()
            ),
            1
        );

        let index =
            SynQReceiptIndex::load_from_path(&index_path).expect("persisted SynQ receipt index");
        assert_eq!(index.checkpoint.latest_materialized_block, Some(2));
        assert_eq!(
            index.checkpoint.aivm_state_root,
            get_receipt["synq_aivm"]["post_state_root"]
                .as_str()
                .unwrap()
        );
        assert!(index.receipt_by_query(&get_hash).is_some());
        let _ = fs::remove_file(index_path);
    }

    #[test]
    fn synq_block_receipts_include_aivm_status_and_fail_closed_errors() {
        let carrier = crate::synq_admission::test_support::deploy_carrier(
            crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID,
        );
        let payload = crate::synq_admission::encode_synq_admission_carrier(&carrier)
            .expect("encode hash-only deploy carrier");
        let deploy = aegis_synq_legacy_transaction(payload, 7);
        let mut chain = BlockChain::new();
        chain.add_block(Block::new_with_timestamp(
            11,
            vec![deploy],
            "genesis".to_string(),
            "validator".to_string(),
            0,
            crate::synq_admission::test_support::TEST_NOW,
        ));
        let chain = Arc::new(Mutex::new(chain));
        let index_path = temp_synq_receipt_index_path("block-receipts");
        let receipts = block_receipts_json_with_index_path(&json!([11]), &chain, Some(&index_path));
        let first = receipts
            .as_array()
            .and_then(|items| items.first())
            .expect("block receipt should exist");

        assert_eq!(first["status"], "0x0");
        assert_eq!(
            first["synq_verification"]["domain"],
            "SYNQ_CONTRACT_DEPLOY_V1"
        );
        assert_eq!(first["synq_aivm"]["status"], "failed");
        assert_eq!(first["synq_aivm"]["error_code"], "SYNQ-AIVM-ARTIFACT");
        let _ = fs::remove_file(index_path);
    }

    #[test]
    fn next_account_nonce_accounts_for_committed_and_pending_transactions() {
        let sender = "syna1nonce-source".to_string();
        let receiver = "syna1nonce-target".to_string();
        let committed = Transaction::new(
            sender.clone(),
            receiver.clone(),
            1,
            7,
            Vec::new(),
            1000,
            21_000,
            None,
            "mldsa87".to_string(),
        );
        let pending = Transaction::new(
            sender.clone(),
            receiver,
            1,
            8,
            Vec::new(),
            1000,
            21_000,
            None,
            "mldsa87".to_string(),
        );
        let mut chain = BlockChain::new();
        chain.add_block(Block::new_with_timestamp(
            1,
            vec![committed],
            "genesis".to_string(),
            "validator".to_string(),
            0,
            1,
        ));
        let chain = Arc::new(Mutex::new(chain));
        let tx_pool = Arc::new(Mutex::new(vec![pending]));

        assert_eq!(next_account_nonce_value(&sender, &tx_pool, &chain), 9);
    }

    #[test]
    fn missing_aegis_transaction_envelope_fails_closed() {
        let tx_pool = Arc::new(Mutex::new(Vec::<Transaction>::new()));
        let chain = Arc::new(Mutex::new(BlockChain::new()));
        let validator_manager = Arc::new(ValidatorManager::new());

        let result = handle_json_rpc(
            "synergy_verifyAegisTransaction",
            json!([]),
            &tx_pool,
            &chain,
            &validator_manager,
        );

        assert_eq!(result["fail_closed"], true);
        assert!(result["error"].as_str().unwrap().contains("Missing Aegis"));
    }

    #[test]
    fn public_gateway_allows_synid_resolution_and_registration() {
        let mut headers = HashMap::new();
        headers.insert("x-forwarded-for".to_string(), "198.51.100.22".to_string());
        let context = RpcRequestContext {
            transport: RpcTransport::Http,
            peer_addr: Some("127.0.0.1:5646".parse().unwrap()),
            headers,
            role_profile: crate::role_profiles::profile_from_compiled_profile("rpc_gateway_node"),
        };

        enforce_rpc_exposure_policy("synergy_resolveSynID", &context)
            .expect("SynID lookup must be public-read for wallet sends");
        enforce_rpc_exposure_policy("synergy_reverseResolveSynID", &context)
            .expect("reverse SynID lookup must be public-read");
        enforce_rpc_exposure_policy("synergy_registerSynID", &context)
            .expect("wallets must be able to publish their own SynID mapping");
    }

    #[test]
    fn loopback_allows_non_public_write_methods() {
        let context = RpcRequestContext {
            transport: RpcTransport::Http,
            peer_addr: Some("127.0.0.1:5646".parse().unwrap()),
            headers: HashMap::new(),
            role_profile: crate::role_profiles::profile_from_compiled_profile("validator_node"),
        };

        enforce_rpc_exposure_policy("synergy_sendTokens", &context)
            .expect("loopback traffic should retain access to local write methods");
        enforce_rpc_exposure_policy("synergy_resetSxcpState", &context)
            .expect("loopback traffic should retain access to operator methods");
    }

    #[test]
    fn qrpc_status_uses_last_known_good_snapshot_when_consensus_chain_lock_is_busy() {
        if let Ok(mut cached_tip) = LAST_KNOWN_GOOD_CHAIN_TIP.lock() {
            *cached_tip = None;
        }

        let mut chain = BlockChain::new();
        chain.genesis().unwrap();
        let chain = Arc::new(Mutex::new(chain));

        let primed_tip = chain_tip_snapshot_nonblocking(&chain);
        assert_eq!(primed_tip.available, true);
        assert_eq!(primed_tip.height, Some(0));

        let worker_chain = Arc::clone(&chain);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            let _held_consensus_lock = worker_chain.lock().unwrap();
            ready_tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(
                QRPC_STATUS_CHAIN_SNAPSHOT_RETRY_DELAY_MILLIS * 2,
            ));
        });
        ready_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let block_number = block_number_json(&chain);
        assert_eq!(block_number, json!(0));

        let health = node_health_json(&chain);
        assert_eq!(health["status"].as_str(), Some("healthy"));
        assert_eq!(health["fail_closed"], false);
        assert_eq!(health["chain_state_available"], true);
        assert_eq!(health["chain_state_error"], Value::Null);
        assert_eq!(health["latest_height"], json!(0));
        assert_eq!(health["sync"]["fail_closed"], false);
        assert_eq!(health["sync"]["chain_state_available"], true);

        let sync = sync_status_json(&chain);
        assert_eq!(sync["fail_closed"], false);
        assert_eq!(sync["chain_state_available"], true);
        assert_eq!(sync["current_block"], json!(0));

        let node_info = handle_json_rpc(
            "synergy_nodeInfo",
            json!([]),
            &TX_POOL,
            &chain,
            &VALIDATOR_MANAGER,
        );
        assert_eq!(node_info["failClosed"], false);
        assert_eq!(node_info["chainStateAvailable"], true);
        assert_eq!(node_info["chainStateError"], Value::Null);
        assert_eq!(node_info["currentBlock"], json!(0));

        let latest_block = handle_json_rpc(
            "synergy_getLatestBlock",
            json!([]),
            &TX_POOL,
            &chain,
            &VALIDATOR_MANAGER,
        );
        assert_eq!(latest_block["block_index"], json!(0));

        handle.join().unwrap();
    }

    #[test]
    fn qrpc_fallback_does_not_load_persisted_chain_when_cache_is_primed() {
        let mut chain = BlockChain::new();
        chain.genesis().unwrap();
        let cached_tip = chain.last().cloned().unwrap();

        let selected = cached_or_load_chain_tip(Some(cached_tip.clone()), || {
            panic!("primed qRPC fallback must not parse the full persisted chain")
        })
        .unwrap();
        assert_eq!(selected.block_index, cached_tip.block_index);
        assert_eq!(selected.hash, cached_tip.hash);
    }

    #[test]
    fn qrpc_fallback_loads_persisted_tip_only_when_cache_is_empty() {
        let mut chain = BlockChain::new();
        chain.genesis().unwrap();
        let persisted_tip = chain.last().cloned().unwrap();

        let selected = cached_or_load_chain_tip(None, || Some(persisted_tip.clone())).unwrap();
        assert_eq!(selected.block_index, persisted_tip.block_index);
        assert_eq!(selected.hash, persisted_tip.hash);
    }

    #[test]
    fn prune_confirmed_transactions_from_pool_removes_only_matching_hashes() {
        let tx_a = Transaction::new(
            "syna1sendera".to_string(),
            "syna1receivera".to_string(),
            1,
            0,
            vec![1, 2, 3],
            1000,
            21000,
            None,
            "mldsa87".to_string(),
        );
        let tx_b = Transaction::new(
            "syna1senderb".to_string(),
            "syna1receiverb".to_string(),
            2,
            1,
            vec![4, 5, 6],
            1000,
            21000,
            None,
            "mldsa87".to_string(),
        );

        {
            let mut pool = TX_POOL.lock().unwrap();
            pool.clear();
            pool.push(tx_a.clone());
            pool.push(tx_b.clone());
        }

        let pruned = prune_transaction_hashes_from_pool(&transaction_hashes(&[tx_a]));
        assert_eq!(pruned, 1);

        let remaining_hashes = TX_POOL
            .lock()
            .unwrap()
            .iter()
            .map(|transaction| transaction.hash())
            .collect::<Vec<_>>();
        assert_eq!(remaining_hashes, vec![tx_b.hash()]);

        TX_POOL.lock().unwrap().clear();
    }

    #[test]
    fn prune_invalid_transactions_from_pool_removes_runtime_invalid_entries() {
        let transaction = admission_valid_but_runtime_invalid_transaction();
        assert!(
            transaction.validate_for_admission().is_valid,
            "transaction must pass ingress admission first"
        );
        let error = ProofOfSynergy::validate_transaction_for_mempool(&transaction)
            .expect_err("unfunded transaction must fail runtime validation");
        assert!(
            error.starts_with("insufficient SNRG balance for transaction"),
            "embedded sender key must pass signature verification before the balance check: {error}"
        );

        {
            let mut pool = TX_POOL.lock().unwrap();
            pool.clear();
            pool.push(transaction);
        }

        let pruned = prune_invalid_transactions_from_pool();
        assert_eq!(pruned, 1);
        assert!(TX_POOL.lock().unwrap().is_empty());
    }

    fn rpc_test_validator(address: &str, cluster_id: u64, status: ValidatorStatus) -> Validator {
        let mut validator = synthesize_validator(
            address.to_string(),
            String::new(),
            address.to_string(),
            50_000_000_000_000,
            0,
        );
        validator.cluster_id = Some(cluster_id);
        validator.cluster_address = Some(format!("cluster-{cluster_id}"));
        validator.status = status;
        validator
    }

    #[test]
    fn protocol_config_reports_zero_topology_for_empty_network() {
        let config = protocol_config_json_for_validator_counts(0, 0);

        assert_eq!(config["validator_count"], json!(0));
        assert_eq!(config["validator_quorum"]["required"], json!(0));
        assert_eq!(config["validator_quorum"]["total"], json!(0));
        assert_eq!(config["cluster_count"], json!(0));
        assert_eq!(config["cluster_id"], Value::Null);
    }

    #[test]
    fn protocol_config_prefers_active_topology_and_uses_configured_fallback() {
        let configured = protocol_config_json_for_validator_counts(6, 0);
        assert_eq!(configured["validator_count"], json!(6));
        assert_eq!(configured["validator_quorum"]["required"], json!(5));
        assert_eq!(configured["cluster_count"], json!(1));
        assert_eq!(configured["cluster_id"], json!(0));

        let active = protocol_config_json_for_validator_counts(6, 10);
        assert_eq!(active["validator_count"], json!(10));
        assert_eq!(active["validator_quorum"]["required"], json!(7));
        assert_eq!(active["cluster_count"], json!(2));
        assert_eq!(active["cluster_id"], Value::Null);
    }

    #[test]
    fn network_cluster_summary_reports_current_six_validator_quorum() {
        let validators = (1..=6)
            .map(|index| {
                rpc_test_validator(&format!("validator-{index}"), 0, ValidatorStatus::Active)
            })
            .collect::<Vec<_>>();

        let summary = network_cluster_summary(&validators);
        let clusters = summary["clusters"].as_array().expect("clusters array");
        let cluster = &clusters[0];

        assert_eq!(summary["total_validators"].as_u64(), Some(6));
        assert_eq!(summary["active_validators"].as_u64(), Some(6));
        assert_eq!(summary["cluster_count"].as_u64(), Some(1));
        assert_eq!(
            summary["consensus_mode"].as_str(),
            Some("single_cluster_testnet")
        );
        assert_eq!(cluster["validator_count"].as_u64(), Some(6));
        assert_eq!(cluster["active_validator_count"].as_u64(), Some(6));
        assert_eq!(cluster["fault_tolerance_f"].as_u64(), Some(1));
        assert_eq!(cluster["quorum_threshold"].as_u64(), Some(5));
        assert_eq!(cluster["can_finalize"].as_bool(), Some(true));
        assert_eq!(cluster["validators_until_liveness_risk"].as_u64(), Some(1));
        assert_eq!(cluster["health"].as_str(), Some("healthy"));
    }

    #[test]
    fn network_cluster_summary_reports_independent_multicluster_liveness() {
        let mut validators = (1..=6)
            .map(|index| {
                let status = if index <= 4 {
                    ValidatorStatus::Active
                } else {
                    ValidatorStatus::Inactive
                };
                rpc_test_validator(&format!("cluster-a-validator-{index}"), 0, status)
            })
            .collect::<Vec<_>>();
        validators.extend((1..=7).map(|index| {
            let status = if index <= 4 {
                ValidatorStatus::Active
            } else {
                ValidatorStatus::Inactive
            };
            rpc_test_validator(&format!("cluster-b-validator-{index}"), 1, status)
        }));

        let summary = network_cluster_summary(&validators);
        let clusters = summary["clusters"].as_array().expect("clusters array");
        let first = &clusters[0];
        let second = &clusters[1];

        assert_eq!(summary["total_validators"].as_u64(), Some(13));
        assert_eq!(summary["active_validators"].as_u64(), Some(8));
        assert_eq!(summary["cluster_count"].as_u64(), Some(2));
        assert_eq!(
            summary["consensus_mode"].as_str(),
            Some("multi_cluster_posy")
        );
        assert_eq!(summary["all_clusters_can_finalize"].as_bool(), Some(false));

        // Governed strict count quorum: (n*2)/3 + 1 over the FROZEN eligible set.
        // 6 eligible -> 5 required. A cluster with only 4 live validators must
        // NOT finalize; lowering the threshold to the live count would be a
        // quorum-lowering safety bug.
        assert_eq!(first["validator_count"].as_u64(), Some(6));
        assert_eq!(first["active_validator_count"].as_u64(), Some(4));
        assert_eq!(first["quorum_threshold"].as_u64(), Some(5));
        assert_eq!(first["can_finalize"].as_bool(), Some(false));
        assert_eq!(first["validators_until_liveness_risk"].as_u64(), Some(0));
        assert_eq!(first["health"].as_str(), Some("halted_safely"));

        assert_eq!(second["validator_count"].as_u64(), Some(7));
        assert_eq!(second["active_validator_count"].as_u64(), Some(4));
        assert_eq!(second["quorum_threshold"].as_u64(), Some(5));
        assert_eq!(second["fault_tolerance_f"].as_u64(), Some(2));
        assert_eq!(second["can_finalize"].as_bool(), Some(false));
        assert_eq!(second["health"].as_str(), Some("halted_safely"));
    }

    #[test]
    fn rpc_startup_uses_service_safe_replay_for_rpc_capable_service_roles() {
        for role in [
            crate::role_profiles::NodeRole::ArchiveValidator,
            crate::role_profiles::NodeRole::Relayer,
            crate::role_profiles::NodeRole::RpcGateway,
            crate::role_profiles::NodeRole::IndexerExplorer,
            crate::role_profiles::NodeRole::ObserverLight,
        ] {
            assert!(
                rpc_startup_uses_service_safe_replay(Some(role.profile())),
                "role {:?} should use service-safe activation replay",
                role
            );
        }
    }

    #[test]
    fn rpc_startup_preserves_consensus_replay_for_validator_and_committee() {
        for role in [
            crate::role_profiles::NodeRole::Validator,
            crate::role_profiles::NodeRole::Committee,
        ] {
            assert!(
                !rpc_startup_uses_service_safe_replay(Some(role.profile())),
                "role {:?} should retain consensus activation replay",
                role
            );
        }
        assert!(!rpc_startup_uses_service_safe_replay(None));
    }

    #[test]
    fn startup_replay_restores_stale_registry_before_membership_and_reconciliation() {
        let public_key = "startup-replay-public-key";
        let validator_address = crate::address::generate_validator_address(public_key, 1);
        let bonded_stake = TESTNET_MIN_VALIDATOR_STAKE_NWEI;
        let funding_source = canonical_genesis()
            .expect("canonical genesis should load")
            .balances()
            .iter()
            .find(|balance| balance.balance_nwei >= bonded_stake)
            .expect("canonical genesis should provide a funding balance")
            .address
            .clone();
        let token_manager = crate::token::TokenManager::new();
        token_manager
            .transfer_tokens(&funding_source, &validator_address, "SNRG", bonded_stake, 0)
            .expect("test validator should receive genesis-funded stake");
        token_manager
            .stake_tokens(&validator_address, &validator_address, "SNRG", bonded_stake)
            .expect("test validator should bond stake");

        let activation_tx = Transaction::new(
            validator_address.clone(),
            validator_address.clone(),
            0,
            0,
            vec![31, 32, 33],
            1,
            21_000,
            Some(format!(
                "validator_activation:{{\"validator\":\"{}\",\"public_key\":\"{}\",\"name\":\"Startup Replay Validator\",\"stake_amount_nwei\":{}}}",
                validator_address, public_key, bonded_stake
            )),
            "mldsa87".to_string(),
        );
        let activation_height = 1;
        let recorded_height = activation_height + crate::validator::VALIDATOR_SHADOW_PHASE_BLOCKS;
        let effective_height = recorded_height + 1;
        let mut chain = BlockChain::new();
        chain
            .genesis()
            .expect("test chain should initialize canonical genesis");
        let genesis_hash = chain
            .last()
            .expect("initialized chain should contain canonical genesis")
            .hash
            .clone();
        chain.add_block(Block::new_with_timestamp(
            activation_height,
            vec![activation_tx],
            genesis_hash,
            "genesis-validator".to_string(),
            0,
            1,
        ));
        let recorded_parent = chain.last().unwrap().hash.clone();
        chain.add_block(Block::new_with_timestamp(
            recorded_height,
            Vec::new(),
            recorded_parent,
            "genesis-validator".to_string(),
            0,
            2,
        ));
        let effective_parent = chain.last().unwrap().hash.clone();
        chain.add_block(Block::new_with_timestamp(
            effective_height,
            Vec::new(),
            effective_parent,
            "genesis-validator".to_string(),
            0,
            3,
        ));

        let validator_manager = Arc::new(ValidatorManager::new());
        let mut stale = Validator::new(
            validator_address.clone(),
            "stale-public-key".to_string(),
            "Stale Validator".to_string(),
            bonded_stake,
        );
        stale.status = ValidatorStatus::Inactive;
        validator_manager
            .registry
            .lock()
            .expect("validator registry should lock")
            .validators
            .insert(validator_address.clone(), stale);

        let (replayed, rejected) = replay_validator_activations_from_canonical_chain(
            &chain,
            &token_manager,
            &validator_manager,
        );
        assert_eq!((replayed, rejected), (1, 0));

        let membership = consensus_membership_validators_for_height(
            validator_manager.get_all_validators(),
            effective_height,
        )
        .expect("replayed activation should be usable by height-scoped membership");
        assert!(membership
            .iter()
            .any(|validator| validator.address == validator_address));

        reconcile_validator_registry_clusters_for_height(&validator_manager, effective_height)
            .expect("startup reconciliation should accept the replayed active validator");
        let restored = validator_manager
            .get_validator(&validator_address)
            .expect("replayed validator should remain in the registry");
        assert_eq!(restored.status, ValidatorStatus::Active);
        assert_eq!(restored.public_key, public_key);
        assert!(restored.cluster_id.is_some());
    }

    #[test]
    fn epoch_cluster_rpc_uses_finalized_height_when_registry_epoch_is_stale() {
        let _env_lock = rpc_validator_env_lock()
            .lock()
            .expect("RPC validator environment mutex should lock");
        let validator_manager = Arc::new(ValidatorManager::new());
        let epoch_seed = "11".repeat(64);
        {
            let mut registry = validator_manager
                .registry
                .lock()
                .expect("validator registry should lock");
            for index in 0..10 {
                let validator =
                    rpc_test_validator(&format!("validator-{index}"), 0, ValidatorStatus::Active);
                registry
                    .validators
                    .insert(validator.address.clone(), validator);
            }
            registry.leader_randomness_epoch = Some(12);
            registry.leader_randomness_seed = Some(epoch_seed.clone());
            registry.reorganize_clusters_for_epoch_with_seed(12, &epoch_seed, 12_001);
            registry.current_epoch = 650;
        }

        let chain = Arc::new(Mutex::new(BlockChain::new()));
        chain.lock().unwrap().add_block(Block::new_with_timestamp(
            12_001,
            Vec::new(),
            "epoch-cluster-parent".to_string(),
            "validator-0".to_string(),
            0,
            1,
        ));
        let response = handle_json_rpc(
            "synergy_getEpochClusterAssignments",
            json!([12]),
            &TX_POOL,
            &chain,
            &validator_manager,
        );
        let assignments = response
            .as_array()
            .expect("epoch cluster RPC should return an array");
        let mut members = assignments
            .iter()
            .map(|assignment| {
                (
                    assignment["cluster_address"]
                        .as_str()
                        .expect("cluster address")
                        .to_string(),
                    assignment["validator_ids"]
                        .as_array()
                        .expect("validator IDs")
                        .iter()
                        .map(|validator| validator.as_str().unwrap().to_string())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for cluster_members in members.values_mut() {
            cluster_members.sort();
        }

        assert_eq!(members.len(), 2);
        assert_eq!(
            members.values().map(Vec::len).collect::<Vec<_>>(),
            vec![5, 5]
        );
        assert_eq!(
            assignments
                .iter()
                .map(|assignment| assignment["assignment_hash"].as_str().unwrap())
                .collect::<HashSet<_>>()
                .len(),
            1,
            "all RPC assignments must carry one canonical map digest"
        );
    }

    #[test]
    fn epoch_cluster_rpc_uses_effective_manifest_epoch_at_current_height() {
        let _env_lock = rpc_validator_env_lock()
            .lock()
            .expect("RPC validator environment mutex should lock");
        let temp_dir = crate::utils::test_temp_root(format!(
            "synergy-rpc-cluster-epoch-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after UNIX epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).expect("RPC epoch snapshot directory should be created");
        let snapshot_path = temp_dir.join("epoch-validator-sets.json");
        let old_addresses = (0..=8)
            .map(|index| format!("validator-{index}"))
            .collect::<Vec<_>>();
        let all_addresses = (0..=9)
            .map(|index| format!("validator-{index}"))
            .collect::<Vec<_>>();
        fs::write(
            &snapshot_path,
            json!({
                "epoch_validator_sets": [
                    {
                        "epoch_id": 12,
                        "validator_set_version": 1,
                        "effective_from_height": 0,
                        "effective_to_height": 1000,
                        "active_validators": old_addresses,
                        "validator_set_hash": "nine-validator-set"
                    },
                    {
                        "epoch_id": 13,
                        "validator_set_version": 2,
                        "effective_from_height": 1001,
                        "active_validators": all_addresses,
                        "previous_set_hash": "nine-validator-set",
                        "validator_set_hash": "ten-validator-set"
                    }
                ]
            })
            .to_string(),
        )
        .expect("RPC epoch snapshot should be written");
        let _snapshot_env = RpcEnvVarGuard::set(
            crate::validator::EPOCH_VALIDATOR_SETS_ENV,
            &snapshot_path.to_string_lossy(),
        );

        let validator_manager = Arc::new(ValidatorManager::new());
        let expected_assignment_hash;
        {
            let mut registry = validator_manager
                .registry
                .lock()
                .expect("validator registry should lock");
            for index in 0..10 {
                let validator =
                    rpc_test_validator(&format!("validator-{index}"), 0, ValidatorStatus::Active);
                registry
                    .validators
                    .insert(validator.address.clone(), validator);
            }
            registry.reorganize_clusters_for_epoch(12);
            let epoch_13_seed = "11".repeat(64);
            registry.leader_randomness_epoch = Some(13);
            registry.leader_randomness_seed = Some(epoch_13_seed.clone());
            registry.reorganize_clusters_for_epoch_with_seed(13, &epoch_13_seed, 13_001);
            let active_validators = registry
                .get_active_validators()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>();
            let expected_plan =
                crate::validator::canonical_validator_cluster_plan_for_epoch_with_seed(
                    &active_validators,
                    13,
                    &epoch_13_seed,
                );
            expected_assignment_hash =
                canonical_validator_cluster_plan_digest(&expected_plan.clusters, 13);
        }

        let chain = Arc::new(Mutex::new(BlockChain::new()));
        chain.lock().unwrap().add_block(Block::new_with_timestamp(
            1001,
            Vec::new(),
            "parent".to_string(),
            "validator-0".to_string(),
            0,
            1,
        ));
        let expected_historical_epoch12 = crate::cluster::CLUSTER_LEDGER
            .lock()
            .expect("cluster ledger should lock")
            .get_epoch_cluster_assignments(12);
        let response = handle_json_rpc(
            "synergy_getEpochClusterAssignments",
            json!([13]),
            &TX_POOL,
            &chain,
            &validator_manager,
        );
        let assignments = response
            .as_array()
            .expect("current epoch RPC should return canonical assignments");

        assert_eq!(assignments.len(), 2);
        assert!(assignments
            .iter()
            .all(|assignment| assignment["epoch_id"] == json!(13)));
        assert!(assignments
            .iter()
            .all(|assignment| assignment["assignment_hash"] == json!(expected_assignment_hash)));
        assert!(assignments
            .iter()
            .all(|assignment| assignment["created_block_height"] == json!(1001)));
        assert_eq!(
            assignments
                .iter()
                .map(|assignment| assignment["validator_ids"].as_array().unwrap().len())
                .collect::<Vec<_>>(),
            vec![5, 5]
        );
        assert_eq!(
            assignments
                .iter()
                .flat_map(|assignment| assignment["validator_ids"].as_array().unwrap())
                .collect::<HashSet<_>>()
                .len(),
            10
        );

        let historical_epoch12 = handle_json_rpc(
            "synergy_getEpochClusterAssignments",
            json!([12]),
            &TX_POOL,
            &chain,
            &validator_manager,
        );
        assert_eq!(
            historical_epoch12,
            json!(expected_historical_epoch12),
            "non-effective epochs must remain ledger-backed history"
        );

        fs::remove_dir_all(temp_dir).ok();
    }

    #[test]
    fn historical_epoch_cluster_rpc_preserves_ledger_snapshots() {
        // Resolves the epoch validator set path, so it must exclude the tests
        // that override SYNERGY_EPOCH_VALIDATOR_SETS_FILE.
        let _env_lock = rpc_validator_env_lock()
            .lock()
            .expect("rpc validator env lock should succeed");
        let validator_manager = Arc::new(ValidatorManager::new());
        let cluster_address;
        {
            let mut registry = validator_manager
                .registry
                .lock()
                .expect("validator registry should lock");
            for index in 0..10 {
                let validator =
                    rpc_test_validator(&format!("validator-{index}"), 0, ValidatorStatus::Active);
                registry
                    .validators
                    .insert(validator.address.clone(), validator);
            }
            registry.reorganize_clusters_for_epoch(12);
            cluster_address = registry
                .get_validator_cluster("validator-0")
                .expect("validator-0 canonical cluster should exist")
                .address
                .clone();
        }

        let historical = crate::cluster::EpochClusterAssignmentSnapshot {
            epoch_id: 11,
            cluster_address: "historical-cluster".to_string(),
            validator_ids: vec!["validator-0".to_string()],
            quorum_threshold: 1,
            fault_tolerance_f: 0,
            assignment_hash: "historical-hash".to_string(),
            rotation_mode: crate::cluster::RotationMode::RoutineRotation,
            created_block_height: 110,
        };
        let historical_segment = crate::cluster::EpochParticipationSegment {
            epoch_id: 11,
            segment_id: "segment-11".to_string(),
            cluster_address: "historical-cluster".to_string(),
            validator_id: "validator-0".to_string(),
            start_block_height: 100,
            end_block_height: 110,
            participation_score_bps: 9_000,
            cluster_performance_score_bps: 8_500,
            segment_reward_nwei: 123,
            segment_reason: "historical-test".to_string(),
        };
        let previous_ledger = {
            let mut ledger = crate::cluster::CLUSTER_LEDGER
                .lock()
                .expect("cluster ledger should lock");
            let previous = ledger.clone();
            ledger.assignment_snapshots.clear();
            ledger
                .assignment_snapshots
                .insert(11, vec![historical.clone()]);
            ledger.participation_segments = vec![historical_segment.clone()];
            let mut ledger_cluster = crate::cluster::Cluster::new(
                "network",
                "genesis",
                0,
                11,
                110,
                &crate::cluster::ClusterConfig::default(),
            );
            ledger_cluster.cluster_address = cluster_address.clone();
            ledger_cluster.status = crate::cluster::ClusterStatus::Degraded;
            ledger_cluster.current_validator_ids = vec!["ledger-old-membership".to_string()];
            ledger_cluster.current_quorum_threshold = 1;
            ledger_cluster.current_fault_tolerance_f = 0;
            ledger_cluster.total_rewards_earned_nwei = 1_234;
            ledger_cluster.last_rotation_epoch = Some(9);
            ledger.clusters.clear();
            ledger
                .clusters
                .insert(cluster_address.clone(), ledger_cluster);
            previous
        };

        let chain = Arc::new(Mutex::new(BlockChain::new()));
        let status = handle_json_rpc(
            "synergy_getClusterStatus",
            json!([cluster_address.clone()]),
            &TX_POOL,
            &chain,
            &validator_manager,
        );
        let history = handle_json_rpc(
            "synergy_getValidatorClusterHistory",
            json!(["validator-0"]),
            &TX_POOL,
            &chain,
            &validator_manager,
        );
        let historical_assignments = handle_json_rpc(
            "synergy_getEpochClusterAssignments",
            json!([11]),
            &TX_POOL,
            &chain,
            &validator_manager,
        );

        {
            let mut ledger = crate::cluster::CLUSTER_LEDGER
                .lock()
                .expect("cluster ledger should lock for restore");
            *ledger = previous_ledger;
        }

        assert_eq!(status["cluster_address"], json!(cluster_address));
        assert_eq!(status["current_epoch"], json!(12));
        assert_eq!(status["current_validator_ids"].as_array().unwrap().len(), 5);
        // governed strict count quorum: (5*2)/3 + 1 = 4
        assert_eq!(status["current_quorum_threshold"], json!(4));
        assert_eq!(status["status"], json!("Degraded"));
        assert_eq!(status["total_rewards_earned_nwei"], json!(1_234));
        assert_eq!(status["last_rotation_epoch"], json!(9));

        assert_eq!(history["current_cluster_address"], json!(cluster_address));
        assert_eq!(
            history["prior_cluster_assignments"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            history["epochs_by_cluster"]["historical-cluster"],
            json!([11])
        );
        assert_eq!(
            history["participation_segments"].as_array().unwrap().len(),
            1
        );
        assert_eq!(historical_assignments, json!([historical]));
    }

    #[test]
    fn network_validator_snapshot_uses_configured_validators_for_read_only_nodes() {
        let genesis_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../config/genesis.testnet-v3.test-fixture.json")
            .canonicalize()
            .expect("repo genesis path should resolve");
        std::env::set_var("SYNERGY_GENESIS_FILE", genesis_path);
        let genesis = canonical_genesis().expect("canonical genesis must load");
        let first_validator = genesis
            .validators()
            .first()
            .expect("canonical genesis should define validators");

        let mut chain = BlockChain::new();
        chain.genesis().expect("genesis block should load");
        chain.add_block(Block::new_with_timestamp(
            1,
            Vec::new(),
            chain.last().unwrap().hash.clone(),
            first_validator.validator_id.clone(),
            1,
            genesis.timestamp().saturating_add(2),
        ));

        let validator_manager = ValidatorManager::new();
        let validators = network_validator_snapshot(&chain, &validator_manager);
        let matched = validators
            .iter()
            .find(|validator| validator.address == first_validator.operator_address)
            .expect("canonical validator should be present in synthesized snapshot");

        assert_eq!(matched.name, first_validator.moniker);
        assert_eq!(matched.stake_amount, first_validator.stake_nwei);
        assert_eq!(matched.status, ValidatorStatus::Active);
        assert_eq!(matched.total_blocks_produced, 1);
        assert_eq!(matched.last_active, genesis.timestamp().saturating_add(2));
        assert!(
            validators
                .iter()
                .all(|validator| validator.address != first_validator.validator_id),
            "genesis validator IDs must not create duplicate alias rows"
        );
    }

    #[test]
    fn validator_set_snapshot_handles_non_genesis_seed_without_registry_relock() {
        let _env_lock = rpc_validator_env_lock()
            .lock()
            .expect("RPC validator environment mutex should lock");
        let validator_manager = Arc::new(ValidatorManager::new());
        let epoch_seed = "22".repeat(64);
        {
            let mut registry = validator_manager.registry.lock().unwrap();
            for index in 0..10 {
                let mut validator = Validator::new(
                    format!("snapshot-lock-validator-{index}"),
                    format!("snapshot-lock-key-{index}"),
                    format!("Snapshot Lock Validator {index}"),
                    TESTNET_MIN_VALIDATOR_STAKE_NWEI,
                );
                validator.status = ValidatorStatus::Active;
                registry
                    .validators
                    .insert(validator.address.clone(), validator);
            }
            registry.leader_randomness_epoch = Some(12);
            registry.leader_randomness_seed = Some(epoch_seed.clone());
            registry.reorganize_clusters_for_epoch_with_seed(12, &epoch_seed, 12_001);
        }

        let chain = Arc::new(Mutex::new(BlockChain::new()));
        chain.lock().unwrap().add_block(Block::new_with_timestamp(
            12_001,
            Vec::new(),
            "snapshot-lock-parent".to_string(),
            "snapshot-lock-validator-0".to_string(),
            0,
            1,
        ));
        let snapshot = handle_json_rpc(
            "synergy_getValidatorSetSnapshot",
            json!([]),
            &TX_POOL,
            &chain,
            &validator_manager,
        );
        assert_eq!(snapshot["is_latest"], json!(true));
        assert_eq!(snapshot["epoch_id"], json!(12));
        assert_eq!(snapshot["cluster_count"], json!(2));
        assert_eq!(snapshot["cluster_assignment_epoch"], json!(12));
        assert_eq!(snapshot["cluster_randomness_source"], json!(epoch_seed));
    }

    #[test]
    fn validator_set_snapshot_reports_live_membership_and_hashes() {
        let validator_manager = Arc::new(ValidatorManager::new());
        {
            let mut registry = validator_manager.registry.lock().unwrap();
            for index in 0..10 {
                let mut validator = Validator::new(
                    format!("snapshot-validator-{index}"),
                    format!("snapshot-key-{index}"),
                    format!("Snapshot Validator {index}"),
                    TESTNET_MIN_VALIDATOR_STAKE_NWEI,
                );
                validator.status = ValidatorStatus::Active;
                registry
                    .validators
                    .insert(validator.address.clone(), validator);
            }
            for (address, status) in [
                ("snapshot-pending", ValidatorStatus::Pending),
                ("snapshot-shadow", ValidatorStatus::Shadow),
                ("snapshot-jailed", ValidatorStatus::Jailed),
                ("snapshot-slashed", ValidatorStatus::Slashed),
            ] {
                let mut validator = Validator::new(
                    address.to_string(),
                    format!("{address}-key"),
                    address.to_string(),
                    TESTNET_MIN_VALIDATOR_STAKE_NWEI,
                );
                validator.status = status;
                registry.validators.insert(address.to_string(), validator);
            }
            registry.current_epoch = 12;
            registry.validator_set_version = 7;
            registry.reorganize_clusters_for_epoch_with_seed(12, "snapshot-qc-seed", 12_001);
        }

        let chain = Arc::new(Mutex::new(BlockChain::new()));
        chain.lock().unwrap().add_block(Block::new_with_timestamp(
            1,
            Vec::new(),
            "snapshot-parent".to_string(),
            "snapshot-validator-0".to_string(),
            0,
            1,
        ));
        {
            let canonical_chain = chain.lock().unwrap();
            reconcile_validator_registry_from_finalized_chain(&canonical_chain, &validator_manager)
                .expect(
                    "epoch-zero service reconciliation should use the canonical genesis boundary",
                );
        }
        let snapshot = handle_json_rpc(
            "synergy_getValidatorSetSnapshot",
            json!([]),
            &TX_POOL,
            &chain,
            &validator_manager,
        );

        assert_eq!(
            rpc_method_exposure("synergy_getValidatorSetSnapshot"),
            Some(RpcMethodExposure::PublicRead)
        );
        assert_eq!(snapshot["chain_id"], json!(1266));
        assert_eq!(snapshot["snapshot_format_version"], json!(1));
        assert_eq!(snapshot["membership_bundle_format_version"], json!(2));
        assert_eq!(snapshot["epoch_id"], json!(0));
        assert_eq!(snapshot["validator_set_version"], json!(7));
        assert_eq!(snapshot["active_validators"].as_array().unwrap().len(), 10);
        assert_eq!(snapshot["pending_validators"], json!(["snapshot-pending"]));
        assert_eq!(snapshot["syncing_validators"], json!(["snapshot-shadow"]));
        assert_eq!(snapshot["jailed_validators"], json!(["snapshot-jailed"]));
        assert_eq!(snapshot["removed_validators"], json!(["snapshot-slashed"]));
        assert_eq!(snapshot["quorum_threshold"], json!(7));
        assert_eq!(snapshot["network_quorum_threshold"], json!(7));
        assert_eq!(
            snapshot["quorum_scope"],
            json!("network_aggregate_not_cluster_finality")
        );
        assert_eq!(
            snapshot["cluster_quorum_scope"],
            json!("independent_per_cluster")
        );
        assert_eq!(snapshot["effective_from_height"], json!(0));
        assert_eq!(snapshot["effective_height_verified"], json!(false));
        assert_eq!(snapshot["cluster_count"], json!(2));
        assert_eq!(snapshot["cluster_assignments_complete"], json!(true));
        assert_eq!(snapshot["cluster_assignment_epoch"], json!(0));
        assert_eq!(snapshot["cluster_assignment_effective_height"], json!(1));
        assert!(snapshot["cluster_randomness_source"]
            .as_str()
            .is_some_and(|seed| !seed.is_empty()));
        assert_eq!(snapshot["cluster_assignment_boundary_height"], json!(0));
        let cluster_assignments = snapshot["cluster_assignments"].as_array().unwrap();
        assert_eq!(cluster_assignments.len(), 2);
        assert!(cluster_assignments.iter().all(|cluster| {
            // governed strict count quorum: (5*2)/3 + 1 = 4
            cluster["validator_ids"].as_array().unwrap().len() == 5
                && cluster["quorum_threshold"] == json!(4)
                && cluster["validators"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|validator| {
                        validator["public_key"].as_str().is_some()
                            && validator["stake_amount"].as_u64().is_some()
                            && validator["cluster_id"].as_u64().is_some()
                    })
        }));
        assert!(snapshot["cluster_map_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty()));
        assert!(snapshot["membership_bundle_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty()));
        assert_eq!(
            snapshot["validator_set_hash"],
            snapshot["local_validator_set_hash"]
        );
        assert_eq!(
            snapshot["validator_set_hash"],
            snapshot["network_validator_set_hash"]
        );
        assert_eq!(snapshot["is_latest"], json!(true));

        let restarted_manager = Arc::new(ValidatorManager::new());
        {
            let source = validator_manager.registry.lock().unwrap().clone();
            let mut restarted = restarted_manager.registry.lock().unwrap();
            *restarted = source;
            restarted.current_epoch = 650;
            restarted.validator_set_version = 999;
            restarted.clusters.clear();
            for (index, validator) in restarted.validators.values_mut().enumerate() {
                validator.finalized_synergy_score_bps = 1_000 + index as u64;
            }
        }
        let later_chain = Arc::new(Mutex::new(BlockChain::new()));
        later_chain
            .lock()
            .unwrap()
            .add_block(Block::new_with_timestamp(
                999,
                Vec::new(),
                "restart-parent".to_string(),
                "snapshot-validator-0".to_string(),
                0,
                2,
            ));
        let restarted_snapshot = handle_json_rpc(
            "synergy_getValidatorSetSnapshot",
            json!([]),
            &TX_POOL,
            &later_chain,
            &restarted_manager,
        );
        assert_eq!(restarted_snapshot["is_latest"], json!(true));
        assert_eq!(restarted_snapshot["cluster_count"], json!(2));
        assert_eq!(restarted_snapshot["validator_set_version"], json!(999));
        assert_eq!(
            restarted_snapshot["cluster_assignment_effective_height"],
            json!(1)
        );
        assert_eq!(
            restarted_snapshot["cluster_map_hash"], snapshot["cluster_map_hash"],
            "restart height must not change the canonical two-cluster map"
        );
        assert_eq!(
            restarted_snapshot["membership_bundle_hash"], snapshot["membership_bundle_hash"],
            "restart height, local registry version, and node-local score observations must not change canonical membership"
        );
        assert!(restarted_snapshot["cluster_quorum_thresholds"]
            .as_array()
            .unwrap()
            .iter()
            // governed strict count quorum: (5*2)/3 + 1 = 4
            .all(|cluster| cluster["validator_count"] == json!(5)
                && cluster["quorum_threshold"] == json!(4)));

        {
            let mut registry = validator_manager.registry.lock().unwrap();
            let validator = registry
                .validators
                .values_mut()
                .find(|validator| validator.status == ValidatorStatus::Active)
                .unwrap();
            validator.cluster_address = Some("syngrp1corrupted-membership".to_string());
        }
        let corrupted_snapshot = handle_json_rpc(
            "synergy_getValidatorSetSnapshot",
            json!([]),
            &TX_POOL,
            &chain,
            &validator_manager,
        );
        assert_eq!(
            corrupted_snapshot["is_latest"],
            json!(true),
            "service restart reconciliation should repair stale persisted assignment metadata"
        );
        assert_eq!(
            corrupted_snapshot["cluster_assignments_complete"],
            json!(true)
        );
        assert!(corrupted_snapshot["cluster_assignments"]
            .as_array()
            .unwrap()
            .iter()
            .all(|cluster| cluster["cluster_address"] != json!("syngrp1corrupted-membership")));
        assert_eq!(
            corrupted_snapshot["cluster_map_hash"], snapshot["cluster_map_hash"],
            "repairing a stale registry must preserve the canonical cluster-map hash"
        );
        assert_eq!(
            corrupted_snapshot["membership_bundle_hash"], snapshot["membership_bundle_hash"],
            "repairing a stale registry must preserve the canonical membership-bundle hash"
        );
        assert_eq!(
            corrupted_snapshot["cluster_assignment_effective_height"],
            json!(1),
            "restart reconciliation must retain the one-based epoch start height"
        );
    }

    #[test]
    fn validator_set_snapshot_uses_effective_height_and_cluster_quorum_semantics() {
        let validator_manager = Arc::new(ValidatorManager::new());
        {
            let mut registry = validator_manager.registry.lock().unwrap();
            for index in 0..9 {
                let mut validator = Validator::new(
                    format!("snapshot-nine-validator-{index}"),
                    format!("snapshot-nine-key-{index}"),
                    format!("Snapshot Nine Validator {index}"),
                    TESTNET_MIN_VALIDATOR_STAKE_NWEI,
                );
                validator.status = ValidatorStatus::Active;
                registry
                    .validators
                    .insert(validator.address.clone(), validator);
            }
            registry.reorganize_clusters_for_epoch(0);

            let mut joining = Validator::new(
                "snapshot-effective-validator-10".to_string(),
                "snapshot-effective-key-10".to_string(),
                "Snapshot Effective Validator 10".to_string(),
                TESTNET_MIN_VALIDATOR_STAKE_NWEI,
            );
            joining.status = ValidatorStatus::Shadow;
            joining.shadow_started_at_height = Some(1);
            joining.activation_recorded_height = Some(0);
            joining.activation_effective_height = Some(1);
            registry.validators.insert(joining.address.clone(), joining);
        }

        let chain = Arc::new(Mutex::new(BlockChain::new()));
        chain.lock().unwrap().add_block(Block::new_with_timestamp(
            1,
            Vec::new(),
            "parent".to_string(),
            "snapshot-nine-validator-0".to_string(),
            0,
            1,
        ));
        {
            let canonical_chain = chain.lock().unwrap();
            reconcile_validator_registry_from_finalized_chain(&canonical_chain, &validator_manager)
                .expect(
                    "epoch-zero service reconciliation should derive the canonical height epoch",
                );
        }
        let snapshot = handle_json_rpc(
            "synergy_getValidatorSetSnapshot",
            json!([]),
            &TX_POOL,
            &chain,
            &validator_manager,
        );

        assert_eq!(snapshot["current_finalized_height"], json!(1));
        assert_eq!(snapshot["effective_from_height"], json!(1));
        assert_eq!(snapshot["validator_set_effective_height"], json!(1));
        assert_eq!(
            snapshot["effective_height_source"],
            json!("activation_replay")
        );
        assert_eq!(snapshot["effective_height_verified"], json!(true));
        assert_eq!(snapshot["active_validators"].as_array().unwrap().len(), 10);
        assert_eq!(snapshot["syncing_validators"], json!([]));
        assert_eq!(snapshot["cluster_count"], json!(2));
        assert_eq!(
            snapshot["cluster_quorum_scope"],
            json!("independent_per_cluster")
        );
        assert!(snapshot["cluster_quorum_thresholds"]
            .as_array()
            .unwrap()
            .iter()
            // governed strict count quorum: (5*2)/3 + 1 = 4
            .all(|cluster| cluster["validator_count"] == json!(5)
                && cluster["quorum_threshold"] == json!(4)));
    }

    #[test]
    fn validator_set_snapshot_fails_closed_for_stale_service_epoch_without_boundary_evidence() {
        let validator_manager = Arc::new(ValidatorManager::new());
        {
            let mut registry = validator_manager.registry.lock().unwrap();
            registry.current_epoch = 650;
            registry.clusters.clear();
            for index in 0..10 {
                let mut validator = Validator::new(
                    format!("stale-epoch-validator-{index}"),
                    format!("stale-epoch-key-{index}"),
                    format!("Stale Epoch Validator {index}"),
                    TESTNET_MIN_VALIDATOR_STAKE_NWEI,
                );
                validator.status = ValidatorStatus::Active;
                registry
                    .validators
                    .insert(validator.address.clone(), validator);
            }
        }

        let chain = Arc::new(Mutex::new(BlockChain::new()));
        chain.lock().unwrap().add_block(Block::new_with_timestamp(
            1_139_151,
            Vec::new(),
            "stale-epoch-parent".to_string(),
            "stale-epoch-validator-0".to_string(),
            0,
            1,
        ));
        let snapshot = handle_json_rpc(
            "synergy_getValidatorSetSnapshot",
            json!([]),
            &TX_POOL,
            &chain,
            &validator_manager,
        );

        assert_eq!(snapshot["current_finalized_height"], json!(1_139_151));
        assert_eq!(snapshot["epoch_id"], json!(1_139));
        assert_eq!(snapshot["fail_closed"], json!(true));
        assert_eq!(snapshot["is_latest"], json!(false));
        assert!(snapshot["error"].as_str().is_some_and(|error| {
            error.contains("epoch 1139 boundary block 1139000 is unavailable")
        }));
    }

    #[test]
    fn validator_set_snapshot_fails_closed_without_qc_seed_for_three_clusters() {
        let validator_manager = Arc::new(ValidatorManager::new());
        {
            let mut registry = validator_manager.registry.lock().unwrap();
            registry.current_epoch = 650;
            registry.clusters.clear();
            for index in 0..21 {
                let mut validator = Validator::new(
                    format!("missing-qc-validator-{index}"),
                    format!("missing-qc-key-{index}"),
                    format!("Missing QC Validator {index}"),
                    TESTNET_MIN_VALIDATOR_STAKE_NWEI,
                );
                validator.status = ValidatorStatus::Active;
                registry
                    .validators
                    .insert(validator.address.clone(), validator);
            }
        }

        let chain = Arc::new(Mutex::new(BlockChain::new()));
        chain.lock().unwrap().add_block(Block::new_with_timestamp(
            1_139_151,
            Vec::new(),
            "missing-qc-parent".to_string(),
            "missing-qc-validator-0".to_string(),
            0,
            1,
        ));
        let snapshot = handle_json_rpc(
            "synergy_getValidatorSetSnapshot",
            json!([]),
            &TX_POOL,
            &chain,
            &validator_manager,
        );

        assert_eq!(snapshot["fail_closed"], json!(true));
        assert_eq!(snapshot["is_latest"], json!(false));
        assert_eq!(snapshot["epoch_id"], json!(1_139));
        assert!(snapshot["error"].as_str().is_some_and(|error| {
            error.contains("epoch 1139 boundary block 1139000 is unavailable")
        }));
        assert!(snapshot["cluster_assignments"].is_null());
    }

    #[test]
    fn network_validator_snapshot_ages_out_historical_unconfigured_validators() {
        let genesis_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../config/genesis.testnet-v3.test-fixture.json")
            .canonicalize()
            .expect("repo genesis path should resolve");
        std::env::set_var("SYNERGY_GENESIS_FILE", genesis_path);
        let genesis = canonical_genesis().expect("canonical genesis must load");
        let initial_validator = genesis
            .validators()
            .first()
            .expect("canonical genesis should define validators")
            .operator_address
            .clone();
        let stale_validator = "synv11stalehistoricalvalidator0000000000000".to_string();

        let mut chain = BlockChain::new();
        chain.genesis().expect("genesis block should load");
        chain.add_block(Block::new_with_timestamp(
            1,
            Vec::new(),
            chain.last().unwrap().hash.clone(),
            stale_validator.clone(),
            1,
            genesis.timestamp().saturating_add(2),
        ));
        for height in 2..=160 {
            chain.add_block(Block::new_with_timestamp(
                height,
                Vec::new(),
                chain.last().unwrap().hash.clone(),
                initial_validator.clone(),
                1,
                genesis.timestamp().saturating_add(height.saturating_mul(2)),
            ));
        }

        let validator_manager = ValidatorManager::new();
        let validators = network_validator_snapshot(&chain, &validator_manager);
        let stale = validators
            .iter()
            .find(|validator| validator.address == stale_validator)
            .expect("historical validator should remain visible for block attribution");
        let configured = validators
            .iter()
            .find(|validator| validator.address == initial_validator)
            .expect("configured validator should remain visible");

        assert_eq!(stale.total_blocks_produced, 1);
        assert_eq!(stale.status, ValidatorStatus::Inactive);
        assert_eq!(configured.status, ValidatorStatus::Active);
    }

    #[test]
    fn network_validator_snapshot_keeps_active_registered_validator_active_after_proposer_gap() {
        let genesis_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../config/genesis.testnet-v3.test-fixture.json")
            .canonicalize()
            .expect("repo genesis path should resolve");
        std::env::set_var("SYNERGY_GENESIS_FILE", genesis_path);
        let genesis = canonical_genesis().expect("canonical genesis must load");
        let steady_validator = genesis
            .validators()
            .first()
            .expect("canonical genesis should define validators")
            .operator_address
            .clone();
        let registered_validator = "synv11registeredvalidator0000000000000000".to_string();

        let mut chain = BlockChain::new();
        chain.genesis().expect("genesis block should load");
        chain.add_block(Block::new_with_timestamp(
            1,
            Vec::new(),
            chain.last().unwrap().hash.clone(),
            registered_validator.clone(),
            1,
            genesis.timestamp().saturating_add(2),
        ));
        for height in 2..=160 {
            chain.add_block(Block::new_with_timestamp(
                height,
                Vec::new(),
                chain.last().unwrap().hash.clone(),
                steady_validator.clone(),
                1,
                genesis.timestamp().saturating_add(height.saturating_mul(2)),
            ));
        }

        let validator_manager = ValidatorManager::new();
        validator_manager
            .register_validator(crate::validator::ValidatorRegistration {
                address: registered_validator.clone(),
                public_key: "registered-public-key".to_string(),
                name: "Registered Validator".to_string(),
                stake_amount: TESTNET_MIN_VALIDATOR_STAKE_NWEI,
                submitted_at: genesis.timestamp(),
                registration_tx_hash: "syntxn-registered".to_string(),
            })
            .expect("validator registration should be accepted");
        validator_manager
            .approve_validator(&registered_validator)
            .expect("validator should activate");

        let validators = network_validator_snapshot(&chain, &validator_manager);
        let registered = validators
            .iter()
            .find(|validator| validator.address == registered_validator)
            .expect("registered validator should remain visible");

        assert_eq!(registered.total_blocks_produced, 1);
        assert_eq!(registered.status, ValidatorStatus::Active);
    }
}
