//! RPC read path for the `single_authority_v1` finalized journal.
//!
//! This is a READ path only. It never writes, never selects a consensus
//! driver, and never substitutes another journal. When the canonical Genesis
//! binds Chain 1266 incarnation 5 to `single_authority_v1`, this is the ONLY
//! finality source RPC may consult: the typed-PoSy and coordinated journals,
//! the validator registry, and the execution-state snapshot are all off-limits
//! as block sources, and any failure here fails closed rather than falling back
//! to a stale incarnation.

use crate::block::{Block, BlockChain};
use crate::consensus::single_authority_finality_store::{
    SingleAuthorityChainBinding, SingleAuthorityFinalityRecord, SingleAuthorityFinalityStore,
    SINGLE_AUTHORITY_CONSENSUS_PROTOCOL,
};
use crate::genesis::GenesisDocument;
use crate::synergy_types::{SYNERGY_TESTNET_V3_CHAIN_ID, TESTNET_V3_CHAIN_INCARNATION};
use std::collections::BTreeMap;
use std::path::PathBuf;

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
        self.body.as_ref().map(|b| b.transactions.len()).unwrap_or(0)
    }
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

/// Reads the finalized single-authority journal for the bound Genesis.
///
/// Returns `Ok(None)` only when the Genesis does not bind this protocol at all.
/// When it does bind it, every error is returned as `Err` so RPC fails closed:
/// a missing, unreadable, torn or foreign journal must never degrade into a
/// stale incarnation-4 answer.
pub fn single_authority_entries_for_rpc(
    genesis: &GenesisDocument,
) -> Result<Option<Vec<SingleAuthorityRpcEntry>>, String> {
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
    let committed_block_log_path = root.join("single-authority-committed-blocks.ndjson");

    if !log_path.is_file() {
        return Err(format!(
            "single_authority_v1 finality journal {} is unavailable; RPC will not answer from \
             another consensus journal",
            log_path.display()
        ));
    }

    let store = SingleAuthorityFinalityStore::at_paths(
        log_path,
        head_path,
        SingleAuthorityChainBinding {
            first_authority_height: 1,
            chain_id: genesis.chain_id(),
            chain_incarnation: genesis.chain_incarnation(),
            authority_id,
            authority_public_key_fingerprint,
        },
    )?;
    let recovery = store.recover()?;

    let mut bodies: BTreeMap<u64, Block> = BTreeMap::new();
    if committed_block_log_path.is_file() {
        let mut chain = BlockChain::new();
        crate::consensus::chain_durability::recover_chain_from_committed_block_log_at(
            &mut chain,
            &committed_block_log_path,
        )?;
        for block in chain.chain.iter() {
            bodies.insert(block.block_index, block.clone());
        }
    }

    Ok(Some(
        recovery
            .records
            .into_iter()
            .map(|record| SingleAuthorityRpcEntry {
                body: bodies.get(&record.height).cloned(),
                record,
                authority_address: authority_address.clone(),
            })
            .collect(),
    ))
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
