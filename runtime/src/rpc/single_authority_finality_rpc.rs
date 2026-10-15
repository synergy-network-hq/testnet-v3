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
use crate::execution::TransactionReceipt;
use crate::consensus::single_authority_execution::SingleAuthorityReceiptFrame;
use crate::synergy_types::{SYNERGY_TESTNET_V3_CHAIN_ID, TESTNET_V3_CHAIN_INCARNATION};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
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
    receipts: Option<Vec<TransactionReceipt>>,
}

#[derive(Debug, Default)]
struct SingleAuthorityRpcCache {
    entries: BTreeMap<u64, CachedSingleAuthorityRpcEntry>,
    committed_nonce_index: BTreeMap<String, u64>,
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
    committed_nonce_index: BTreeMap<String, u64>,
    receipt_log_path: &Path,
) -> Result<(), String> {
    let mut cache = SingleAuthorityRpcCache {
        committed_nonce_index,
        ..SingleAuthorityRpcCache::default()
    };
    for (record, body) in entries
        .into_iter()
        .rev()
        .take(SINGLE_AUTHORITY_RPC_CACHE_CAPACITY)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let entry = CachedSingleAuthorityRpcEntry { record, body, receipts: None };
        if !cached_entry_is_consistent(&entry) {
            return Err(format!(
                "Synergy Testnet v3 RPC cache entry at height {} disagrees with finalized history",
                entry.record.height
            ));
        }
        cache.entries.insert(entry.record.height, entry);
    }
    load_recent_receipts(&mut cache, receipt_log_path)?;
    let mut guard = single_authority_rpc_cache()
        .lock()
        .map_err(|_| "Synergy Testnet v3 RPC cache lock poisoned".to_string())?;
    *guard = cache;
    Ok(())
}

/// Adds the next finalized block to the bounded in-process RPC tail.  A cache
/// failure must never affect consensus after durable finality has completed,
/// so an inconsistent update simply clears the acceleration cache.
pub fn push_single_authority_rpc_cache_entry(
    record: SingleAuthorityFinalityRecord,
    body: Block,
    receipts: Vec<TransactionReceipt>,
) {
    let entry = CachedSingleAuthorityRpcEntry { record, body, receipts: Some(receipts) };
    if !cached_entry_is_consistent(&entry) {
        return;
    }
    let Ok(mut cache) = single_authority_rpc_cache().lock() else {
        return;
    };
    for tx in &entry.body.transactions {
        let nonce = cache.committed_nonce_index.entry(tx.sender.to_ascii_lowercase()).or_insert(tx.nonce);
        *nonce = (*nonce).max(tx.nonce);
    }
    cache.entries.insert(entry.record.height, entry);
    while cache.entries.len() > SINGLE_AUTHORITY_RPC_CACHE_CAPACITY {
        let Some(oldest_height) = cache.entries.keys().next().copied() else {
            break;
        };
        cache.entries.remove(&oldest_height);
    }
}

/// Rehydrate only a bounded suffix of the already-reconciled durable receipt
/// journal. The first partial line is discarded after a bounded seek.
fn load_recent_receipts(cache: &mut SingleAuthorityRpcCache, path: &Path) -> Result<(), String> {
    if cache.entries.is_empty() { return Ok(()); }
    let mut file = fs::File::open(path)
        .map_err(|error| format!("open Synergy Testnet v3 receipt tail {}: {error}", path.display()))?;
    let len = file.metadata().map_err(|error| error.to_string())?.len();
    let start = len.saturating_sub(32 * 1024 * 1024);
    file.seek(SeekFrom::Start(start)).map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(file);
    if start > 0 {
        let mut partial = Vec::new();
        reader.read_until(b'\n', &mut partial).map_err(|error| error.to_string())?;
    }
    for line in reader.lines() {
        let line = line.map_err(|error| error.to_string())?;
        if line.trim().is_empty() { continue; }
        let frame: SingleAuthorityReceiptFrame = serde_json::from_str(&line)
            .map_err(|error| format!("parse Synergy Testnet v3 receipt tail: {error}"))?;
        if let Some(entry) = cache.entries.get_mut(&frame.height) {
            if !frame.block_hash.eq_ignore_ascii_case(&entry.body.hash)
                || frame.receipt_root != entry.record.receipt_root
                || frame.state_root_after != entry.record.state_root
                || frame.receipts.len() != entry.body.transactions.len()
            {
                return Err(format!("Synergy Testnet v3 receipt at height {} disagrees with finality", frame.height));
            }
            entry.receipts = Some(frame.receipts);
        }
    }
    Ok(())
}

pub fn single_authority_next_nonce_for_rpc(
    genesis: &GenesisDocument,
    address: &str,
) -> Result<Option<u64>, String> {
    if !genesis_binds_single_authority(genesis) { return Ok(None); }
    let cache = single_authority_rpc_cache().lock()
        .map_err(|_| "Synergy Testnet v3 RPC cache lock poisoned".to_string())?;
    if cache.entries.is_empty() { return Err("Synergy Testnet v3 RPC cache is unavailable".to_string()); }
    Ok(Some(cache.committed_nonce_index.get(&address.to_ascii_lowercase())
        .map(|nonce| nonce.saturating_add(1)).unwrap_or(0)))
}

pub fn single_authority_cached_transaction_for_rpc(
    genesis: &GenesisDocument,
    query: &str,
) -> Result<Option<(SingleAuthorityRpcEntry, usize, Option<TransactionReceipt>)>, String> {
    if !genesis_binds_single_authority(genesis) { return Ok(None); }
    let authority_address = genesis_authority_address(genesis)?;
    let normalized = query.strip_prefix("0x").unwrap_or(query).to_ascii_lowercase();
    let raw = normalized.strip_prefix("syntxn-").or_else(|| normalized.strip_prefix("synxxn-")).unwrap_or(&normalized);
    let cache = single_authority_rpc_cache().lock()
        .map_err(|_| "Synergy Testnet v3 RPC cache lock poisoned".to_string())?;
    for entry in cache.entries.values().rev() {
        if !cached_entry_is_consistent(entry) { continue; }
        for (index, tx) in entry.body.transactions.iter().enumerate() {
            if tx.hash().eq_ignore_ascii_case(&normalized) || tx.raw_hash().eq_ignore_ascii_case(raw) {
                return Ok(Some((cached_entry_to_rpc(entry, &authority_address), index,
                    entry.receipts.as_ref().and_then(|receipts| receipts.get(index)).cloned())));
            }
        }
    }
    Ok(None)
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
        .map_err(|_| "Synergy Testnet v3 RPC cache lock poisoned".to_string())?;
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
        .map_err(|_| "Synergy Testnet v3 RPC cache lock poisoned".to_string())?;
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
        return Err(
            "Synergy Testnet v3 finality journal is unavailable; RPC will not answer from another consensus journal"
                .to_string(),
        );
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
            "Synergy Testnet v3 finalized head has unsupported schema {}",
            head.schema_version
        ));
    }
    if head.chain_id != genesis.chain_id() || head.chain_incarnation != genesis.chain_incarnation()
    {
        return Err(
            "Synergy Testnet v3 finalized head chain identity disagrees with Genesis".to_string(),
        );
    }
    if head.height < store.binding().first_authority_height {
        return Err(format!(
            "Synergy Testnet v3 finalized head has invalid authority height {}",
            head.height
        ));
    }
    let log_len = fs::metadata(store.log_path())
        .map_err(|error| format!("stat Synergy Testnet v3 finality journal: {error}"))?
        .len();
    if head.finality_log_end_offset == 0 || head.finality_log_end_offset > log_len {
        return Err(format!(
            "Synergy Testnet v3 finalized head offset {} is outside finality journal length {}",
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
        .map_err(|_| "Synergy Testnet v3 RPC cache lock poisoned".to_string())?;
    if cache.entries.is_empty() {
        return Err(
            "Synergy Testnet v3 bounded RPC tail is unavailable; durable-history recovery is disabled"
                .to_string(),
        );
    }
    let mut entries = Vec::with_capacity(cache.entries.len());
    for entry in cache.entries.values() {
        if !cached_entry_is_consistent(entry) {
            return Err(format!(
                "Synergy Testnet v3 bounded RPC tail has an inconsistent entry at height {}",
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
            .map_err(|error| format!("serialize Synergy Testnet v3 transactions: {error}"))?,
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
        "consensus_protocol": "Synergy Testnet v3",
        "protocol_version": "Synergy Testnet v3",
        "release_id": "synergy-testnet-v3-chain-1266",
        "chain_id": record.chain_id,
        "chain_incarnation": record.chain_incarnation,
        "state_root": record.state_root.to_hex(),
        "state_root_after": record.state_root.to_hex(),
        "transactions_root": record.transaction_root.to_hex(),
        "receipt_root": record.receipt_root.to_hex(),
        "tx_count": entry.transaction_count() as u64,
        "transactions": transactions,
        "transaction_format": "synergy_native_v3",
        "finality_status": "finalized",
        "finalized": true,
        "finality_proof_type": "authority_signature",
        "finality_source": "canonical_finality_store",
        "source": "canonical_finality_store",
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
        "consensus_protocol": "Synergy Testnet v3",
        "authority_id": record.authority_id.clone(),
        "authority_address": entry.authority_address.clone(),
        "release_id": "synergy-testnet-v3-chain-1266",
        "finalized_timestamp_ms": record.finalized_timestamp_ms,
        "finality_status": "finalized",
    })
}
