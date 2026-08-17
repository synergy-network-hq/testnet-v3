//! RPC read path for the `single_authority_v1` finalized journal.
//!
//! This is a READ path only. It never writes, never selects a consensus
//! driver, and never substitutes another journal. When the canonical Genesis
//! binds Chain 1266 incarnation 5 to `single_authority_v1`, this is the ONLY
//! finality source RPC may consult: the typed-PoSy and coordinated journals,
//! the validator registry, and the execution-state snapshot are all off-limits
//! as block sources, and any failure here fails closed rather than falling back
//! to a stale incarnation.

use crate::block::Block;
use crate::consensus::single_authority_finality_store::{
    SingleAuthorityChainBinding, SingleAuthorityFinalityRecord, SingleAuthorityFinalityStore,
    SingleAuthorityFinalizedHead, SINGLE_AUTHORITY_CONSENSUS_PROTOCOL,
    SINGLE_AUTHORITY_FINALITY_SCHEMA_VERSION,
};
use crate::genesis::GenesisDocument;
use crate::synergy_types::{SYNERGY_TESTNET_V3_CHAIN_ID, TESTNET_V3_CHAIN_INCARNATION};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// A bounded in-process projection of the finality/body tail.  The authority
/// driver fills it only from history it has already reconciled at startup and
/// from records it has durably finalized.  It is an acceleration only: an
/// unavailable or incomplete cache is never treated as a finality source.
const SINGLE_AUTHORITY_RPC_CACHE_CAPACITY: usize = 8_192;

#[derive(Debug, Clone)]
struct CachedSingleAuthorityRpcEntry {
    record: SingleAuthorityFinalityRecord,
    body: Block,
}

#[derive(Debug, Default)]
struct SingleAuthorityRpcCache {
    entries: BTreeMap<u64, CachedSingleAuthorityRpcEntry>,
}

fn single_authority_rpc_cache() -> &'static Mutex<SingleAuthorityRpcCache> {
    static CACHE: OnceLock<Mutex<SingleAuthorityRpcCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(SingleAuthorityRpcCache::default()))
}

/// One finalized height: the verified finality record plus, when the committed
/// body log carries it, the canonical block body for its transaction list.
#[derive(Debug, Clone)]
pub struct SingleAuthorityRpcEntry {
    pub record: SingleAuthorityFinalityRecord,
    pub body: Option<Block>,
    /// The synv1 authority address, taken from the canonical Genesis.
    pub authority_address: String,
}

impl SingleAuthorityRpcEntry {
    pub fn height(&self) -> u64 {
        self.record.height
    }

    pub fn block_id(&self) -> String {
        self.record.block_hash.to_hex()
    }

    pub fn parent_hash(&self) -> String {
        self.record.parent_hash.to_hex()
    }

    pub fn timestamp_ms(&self) -> u64 {
        self.record.finalized_timestamp_ms
    }

    pub fn transaction_count(&self) -> usize {
        self.body
            .as_ref()
            .map(|b| b.transactions.len())
            .unwrap_or(0)
    }
}

fn cached_entry_is_consistent(entry: &CachedSingleAuthorityRpcEntry) -> bool {
    entry.record.height == entry.body.block_index
        && entry
            .record
            .block_hash
            .to_hex()
            .eq_ignore_ascii_case(&entry.body.hash)
        && entry.record.chain_id == SYNERGY_TESTNET_V3_CHAIN_ID
        && entry.record.chain_incarnation == TESTNET_V3_CHAIN_INCARNATION
        && entry.record.consensus_protocol == SINGLE_AUTHORITY_CONSENSUS_PROTOCOL
}

/// Replaces the bounded RPC tail from history the authority driver recovered
/// and reconciled during startup.  This does not read or write durable state.
pub fn replace_single_authority_rpc_cache(
    entries: Vec<(SingleAuthorityFinalityRecord, Block)>,
) -> Result<(), String> {
    let mut cache = SingleAuthorityRpcCache::default();
    for (record, body) in entries
        .into_iter()
        .rev()
        .take(SINGLE_AUTHORITY_RPC_CACHE_CAPACITY)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let entry = CachedSingleAuthorityRpcEntry { record, body };
        if !cached_entry_is_consistent(&entry) {
            return Err(format!(
                "single-authority RPC cache entry at height {} disagrees with finalized history",
                entry.record.height
            ));
        }
        cache.entries.insert(entry.record.height, entry);
    }
    let mut guard = single_authority_rpc_cache()
        .lock()
        .map_err(|_| "single-authority RPC cache lock poisoned".to_string())?;
    *guard = cache;
    Ok(())
}

/// Adds the next finalized block to the bounded in-process RPC tail.  A cache
/// failure must never affect consensus after durable finality has completed,
/// so an inconsistent update simply clears the acceleration cache.
pub fn push_single_authority_rpc_cache_entry(record: SingleAuthorityFinalityRecord, body: Block) {
    let entry = CachedSingleAuthorityRpcEntry { record, body };
    if !cached_entry_is_consistent(&entry) {
        return;
    }
    let Ok(mut cache) = single_authority_rpc_cache().lock() else {
        return;
    };
    cache.entries.insert(entry.record.height, entry);
    while cache.entries.len() > SINGLE_AUTHORITY_RPC_CACHE_CAPACITY {
        let Some(oldest_height) = cache.entries.keys().next().copied() else {
            break;
        };
        cache.entries.remove(&oldest_height);
    }
}

fn cached_entry_to_rpc(
    entry: &CachedSingleAuthorityRpcEntry,
    authority_address: &str,
) -> SingleAuthorityRpcEntry {
    SingleAuthorityRpcEntry {
        record: entry.record.clone(),
        body: Some(entry.body.clone()),
        authority_address: authority_address.to_string(),
    }
}

/// Returns a recent finalized entry only when it is present in the bounded
/// cache. Callers deliberately do not reconstruct the durable journal on a
/// miss: that archive is validated by the authority startup path, and loading
/// it in an RPC handler can recreate an unbounded allocation failure.
pub fn single_authority_cached_entry_for_rpc(
    genesis: &GenesisDocument,
    height: u64,
) -> Result<Option<SingleAuthorityRpcEntry>, String> {
    if !genesis_binds_single_authority(genesis) || height == 0 {
        return Ok(None);
    }
    let authority_address = genesis_authority_address(genesis)?;
    let cache = single_authority_rpc_cache()
        .lock()
        .map_err(|_| "single-authority RPC cache lock poisoned".to_string())?;
    Ok(cache
        .entries
        .get(&height)
        .filter(|entry| cached_entry_is_consistent(entry))
        .map(|entry| cached_entry_to_rpc(entry, &authority_address)))
}

/// Returns a recent contiguous finalized range only when every requested
/// non-genesis height is available in the bounded cache. This is the Atlas
/// catch-up path; a miss is surfaced as unavailable rather than triggering an
/// unbounded durable-history reconstruction in the RPC process.
pub fn single_authority_cached_range_for_rpc(
    genesis: &GenesisDocument,
    start: u64,
    end: u64,
) -> Result<Option<Vec<SingleAuthorityRpcEntry>>, String> {
    if !genesis_binds_single_authority(genesis) || start > end {
        return Ok(None);
    }
    let authority_address = genesis_authority_address(genesis)?;
    let first = start.max(1);
    if first > end {
        return Ok(Some(Vec::new()));
    }
    if end - first + 1 > SINGLE_AUTHORITY_RPC_CACHE_CAPACITY as u64 {
        return Ok(None);
    }
    let cache = single_authority_rpc_cache()
        .lock()
        .map_err(|_| "single-authority RPC cache lock poisoned".to_string())?;
    let mut entries = Vec::with_capacity((end - first + 1) as usize);
    for height in first..=end {
        let Some(entry) = cache.entries.get(&height) else {
            return Ok(None);
        };
        if !cached_entry_is_consistent(entry) {
            return Ok(None);
        }
        entries.push(cached_entry_to_rpc(entry, &authority_address));
    }
    Ok(Some(entries))
}

/// True when the canonical Genesis binds this process to the incarnation-5
/// single-authority chain. Nothing else may select this read path.
pub fn genesis_binds_single_authority(genesis: &GenesisDocument) -> bool {
    genesis.chain_id() == SYNERGY_TESTNET_V3_CHAIN_ID
        && genesis.chain_incarnation() == TESTNET_V3_CHAIN_INCARNATION
        && genesis.consensus_protocol() == SINGLE_AUTHORITY_CONSENSUS_PROTOCOL
}

/// The synv1 authority address this Genesis binds.
pub fn genesis_authority_address(genesis: &GenesisDocument) -> Result<String, String> {
    genesis
        .value()
        .get("consensus")
        .and_then(|consensus| consensus.get("authority_address"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "Genesis consensus binding has no authority address".to_string())
}

fn genesis_authority_id(genesis: &GenesisDocument) -> Result<String, String> {
    genesis
        .value()
        .get("consensus")
        .and_then(|consensus| consensus.get("authority_id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "Genesis consensus binding has no authority id".to_string())
}

fn genesis_authority_fingerprint(
    genesis: &GenesisDocument,
    authority_address: &str,
) -> Result<String, String> {
    use base64::{engine::general_purpose, Engine as _};

    let validator = genesis
        .validators()
        .iter()
        .find(|validator| validator.operator_address == authority_address)
        .ok_or_else(|| format!("Genesis has no validator for authority {authority_address}"))?;
    let key = general_purpose::STANDARD
        .decode(&validator.consensus_public_key)
        .map_err(|error| format!("decode Genesis authority consensus key: {error}"))?;
    Ok(format!(
        "sha256:{}",
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&key))
    ))
}

fn namespace_root(genesis: &GenesisDocument) -> PathBuf {
    crate::utils::resolve_data_path(&format!(
        "data/consensus/chain-{}-incarnation-{}",
        genesis.chain_id(),
        genesis.chain_incarnation()
    ))
}

/// Opens the one finality store that the canonical Genesis authorizes this
/// process to read. Callers must never substitute a different consensus
/// journal when this binding is present.
fn single_authority_store_for_rpc(
    genesis: &GenesisDocument,
) -> Result<Option<SingleAuthorityFinalityStore>, String> {
    if !genesis_binds_single_authority(genesis) {
        return Ok(None);
    }

    let authority_address = genesis_authority_address(genesis)?;
    let authority_id = genesis_authority_id(genesis)?;
    let authority_public_key_fingerprint =
        genesis_authority_fingerprint(genesis, &authority_address)?;
    let root = namespace_root(genesis);
    let log_path = root.join("single-authority-finality.log");
    let head_path = root.join("single-authority-finality.head.json");

    if !log_path.is_file() {
        return Err(format!(
            "single_authority_v1 finality journal {} is unavailable; RPC will not answer from \
             another consensus journal",
            log_path.display()
        ));
    }

    SingleAuthorityFinalityStore::at_paths(
        log_path,
        head_path,
        SingleAuthorityChainBinding {
            first_authority_height: 1,
            chain_id: genesis.chain_id(),
            chain_incarnation: genesis.chain_incarnation(),
            authority_id,
            authority_public_key_fingerprint,
        },
    )
    .map(Some)
}

/// Reads the atomically committed authority head without reconstructing the
/// complete finality and committed-body histories. This is the bounded source
/// for high-frequency height polling. The writer creates this pointer only
/// after the finality frame is fsynced, and startup validates complete history
/// before it admits block production.
pub fn single_authority_finalized_head_for_rpc(
    genesis: &GenesisDocument,
) -> Result<Option<SingleAuthorityFinalizedHead>, String> {
    let Some(store) = single_authority_store_for_rpc(genesis)? else {
        return Ok(None);
    };
    let Some(head) = store.load_head()? else {
        return Ok(None);
    };

    if head.schema_version != SINGLE_AUTHORITY_FINALITY_SCHEMA_VERSION {
        return Err(format!(
            "single_authority_v1 finalized head has unsupported schema {}",
            head.schema_version
        ));
    }
    if head.chain_id != genesis.chain_id() || head.chain_incarnation != genesis.chain_incarnation()
    {
        return Err(
            "single_authority_v1 finalized head chain identity disagrees with Genesis".to_string(),
        );
    }
    if head.height < store.binding().first_authority_height {
        return Err(format!(
            "single_authority_v1 finalized head has invalid authority height {}",
            head.height
        ));
    }
    let log_len = fs::metadata(store.log_path())
        .map_err(|error| format!("stat single_authority_v1 finality journal: {error}"))?
        .len();
    if head.finality_log_end_offset == 0 || head.finality_log_end_offset > log_len {
        return Err(format!(
            "single_authority_v1 finalized head offset {} is outside finality journal length {}",
            head.finality_log_end_offset, log_len
        ));
    }

    Ok(Some(head))
}

/// Returns the startup-reconciled, bounded single-authority RPC tail.
///
/// The complete durable archive is intentionally never reconstructed by an RPC
/// request. Authority startup is the sole full-history validator; a process
/// with an empty bounded cache fails closed rather than allocating proportional
/// to all historical finality records and block bodies.
pub fn single_authority_entries_for_rpc(
    genesis: &GenesisDocument,
) -> Result<Option<Vec<SingleAuthorityRpcEntry>>, String> {
    if !genesis_binds_single_authority(genesis) {
        return Ok(None);
    }

    let authority_address = genesis_authority_address(genesis)?;
    let cache = single_authority_rpc_cache()
        .lock()
        .map_err(|_| "single-authority RPC cache lock poisoned".to_string())?;
    if cache.entries.is_empty() {
        return Err(
            "single-authority bounded RPC tail is unavailable; durable-history recovery is disabled"
                .to_string(),
        );
    }
    let mut entries = Vec::with_capacity(cache.entries.len());
    for entry in cache.entries.values() {
        if !cached_entry_is_consistent(entry) {
            return Err(format!(
                "single-authority bounded RPC tail has an inconsistent entry at height {}",
                entry.record.height
            ));
        }
        entries.push(cached_entry_to_rpc(entry, &authority_address));
    }
    Ok(Some(entries))
}

/// Canonical explorer JSON for one finalized single-authority height.
pub fn entry_to_explorer_json(
    entry: &SingleAuthorityRpcEntry,
) -> Result<serde_json::Value, String> {
    use serde_json::json;

    let transactions = match entry.body.as_ref() {
        Some(block) => serde_json::to_value(&block.transactions)
            .map_err(|error| format!("serialize single-authority transactions: {error}"))?,
        None => serde_json::Value::Array(Vec::new()),
    };
    let record = &entry.record;
    Ok(json!({
        "block_index": record.height,
        "height": record.height,
        "timestamp": record.finalized_timestamp_ms / 1_000,
        "timestamp_ms": record.finalized_timestamp_ms,
        "hash": record.block_hash.to_hex(),
        "block_id": record.block_hash.to_hex(),
        "previous_hash": record.parent_hash.to_hex(),
        "parent_hash": record.parent_hash.to_hex(),
        "validator_id": entry.authority_address.clone(),
        "validator": entry.authority_address.clone(),
        "authority_id": record.authority_id.clone(),
        "authority_address": entry.authority_address.clone(),
        "authority_public_key_fingerprint": record.authority_public_key_fingerprint.clone(),
        "consensus_protocol": record.consensus_protocol.clone(),
        "protocol_version": record.consensus_protocol.clone(),
        "release_id": record.release_id.clone(),
        "chain_id": record.chain_id,
        "chain_incarnation": record.chain_incarnation,
        "state_root": record.state_root.to_hex(),
        "state_root_after": record.state_root.to_hex(),
        "transactions_root": record.transaction_root.to_hex(),
        "receipt_root": record.receipt_root.to_hex(),
        "tx_count": entry.transaction_count() as u64,
        "transactions": transactions,
        "transaction_format": SINGLE_AUTHORITY_CONSENSUS_PROTOCOL,
        "finality_status": "finalized",
        "finalized": true,
        "finality_proof_type": "authority_signature",
        "finality_source": "single_authority_finality_store",
        "source": "single_authority_finality_store",
        "chain": crate::rpc::rpc_server::chain_identity_json(),
    }))
}

/// Canonical finalized-head JSON for one finalized single-authority height.
pub fn entry_to_finalized_head_json(entry: &SingleAuthorityRpcEntry) -> serde_json::Value {
    use serde_json::json;

    let record = &entry.record;
    json!({
        "height": record.height,
        "block_id": record.block_hash.to_hex(),
        "hash": record.block_hash.to_hex(),
        "parent_hash": record.parent_hash.to_hex(),
        "state_root": record.state_root.to_hex(),
        "receipt_root": record.receipt_root.to_hex(),
        "consensus_protocol": record.consensus_protocol.clone(),
        "authority_id": record.authority_id.clone(),
        "authority_address": entry.authority_address.clone(),
        "release_id": record.release_id.clone(),
        "finalized_timestamp_ms": record.finalized_timestamp_ms,
        "finality_status": "finalized",
    })
}
