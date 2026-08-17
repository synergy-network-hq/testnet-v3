//! Canonical execution binding for the `single_authority_v1` driver.
//!
//! The driver's block body is the existing PoSy `crate::block::Block`, whose
//! transactions are `crate::transaction::Transaction` carriers. The canonical
//! state transition (`crate::execution::execute_block_contents`) consumes the
//! typed `crate::synergy_types::Transaction`. This module is the ONLY bridge
//! between the two, and it re-runs real admission on every carrier rather than
//! trusting the block body.
//!
//! Nothing here knows about votes, quorum certificates, coordinators,
//! producers, rounds, epochs as a schedule, or clusters. The only block-derived
//! inputs are height and the consensus-bounded timestamp.

use crate::aegis_tx_tool::{
    decode_aegis_carrier_data, legacy_transaction_from_aegis_envelope,
    validate_legacy_aegis_carrier_transaction, verify_aegis_submission_envelope_at,
    AegisTxSubmissionEnvelope,
};
use crate::block::{Block, BlockChain};
use crate::consensus::chain_durability::CommittedBlockLogEntry;
use crate::consensus::consensus_algorithm::ProofOfSynergy;
use crate::execution::{
    compute_state_root_after, ExecutionState, GenesisExecutionSnapshot, TransactionReceipt,
};
use crate::synergy_types::{Hash, Transaction as TypedTransaction};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// The only retained committed-body suffix in a running single-authority
/// process. The complete append-only archive remains durable; startup streams
/// it to validate linkage and rebuild the compact nonce index.
pub const SINGLE_AUTHORITY_RUNTIME_TAIL_CAPACITY: usize = 8_192;

/// The height-0 anchor for a single-authority chain.
///
/// Genesis is a signed document, not a produced block body, so it never appears
/// in the committed block log. This anchor exists solely so the canonical
/// `chain_durability` recovery API can bind the first authority block to the
/// real Genesis hash. It is never signed, never persisted, and never published.
pub fn genesis_anchor_block(genesis_hash: &str) -> crate::block::Block {
    crate::block::Block {
        block_index: 0,
        timestamp: 0,
        transactions: Vec::new(),
        previous_hash: String::new(),
        validator_id: String::new(),
        nonce: 0,
        hash: genesis_hash.to_string(),
        transactions_root: crate::block::compute_merkle_root(&[]),
        proposer_public_key: Vec::new(),
        block_signature: Vec::new(),
        block_signature_algorithm: String::new(),
    }
}

/// Every nonce this sender already has in a committed block body.
pub fn committed_sender_nonces(chain: &BlockChain, sender: &str) -> Vec<u64> {
    let mut nonces = chain
        .chain
        .iter()
        .flat_map(|block| block.transactions.iter())
        .filter(|committed| committed.sender.eq_ignore_ascii_case(sender))
        .map(|committed| committed.nonce)
        .collect::<Vec<_>>();
    nonces.sort_unstable();
    nonces.dedup();
    nonces
}

fn nonce_index_key(sender: &str) -> String {
    sender.to_ascii_lowercase()
}

/// Records the greatest committed nonce per account. The canonical ordering
/// rule depends on the greatest committed nonce, not on retaining every old
/// block body in memory.
pub fn record_committed_block_nonces(
    index: &mut BTreeMap<String, u64>,
    block: &Block,
) {
    for transaction in &block.transactions {
        let entry = index.entry(nonce_index_key(&transaction.sender)).or_insert(transaction.nonce);
        *entry = (*entry).max(transaction.nonce);
    }
}

fn require_canonical_account_sequence_with_nonces(
    carrier: &crate::transaction::Transaction,
    committed_nonces: &[u64],
    pending: &[crate::transaction::Transaction],
) -> Result<(), String> {
    let carrier_hash = carrier.hash();
    let pending_sender_nonces = pending
        .iter()
        .filter(|entry| entry.sender.eq_ignore_ascii_case(&carrier.sender))
        .filter(|entry| entry.hash() != carrier_hash)
        .map(|entry| (entry.hash(), entry.nonce))
        .collect::<Vec<_>>();
    ProofOfSynergy::validate_transaction_nonce_for_ordering(
        carrier.nonce,
        committed_nonces,
        &pending_sender_nonces,
    )
}

/// Canonical single-authority admission for one submitted Aegis envelope.
///
/// This is the only supported way for a transaction to enter single-authority
/// block production. It applies the same account-sequence rule the canonical
/// ordering path applies, sourced from this authority's own committed block
/// bodies and its own pending pool - never from a coordinated or global cache.
pub fn admit_single_authority_transaction(
    envelope: &AegisTxSubmissionEnvelope,
    committed: &BlockChain,
    pending: &[crate::transaction::Transaction],
    consensus_timestamp_unix: u64,
) -> Result<crate::transaction::Transaction, String> {
    verify_aegis_submission_envelope_at(envelope, consensus_timestamp_unix)?;
    let carrier = legacy_transaction_from_aegis_envelope(envelope)?;
    require_canonical_account_sequence(&carrier, committed, pending)?;
    Ok(carrier)
}

/// Enforces the canonical account-sequence rule for one carrier.
pub fn require_canonical_account_sequence(
    carrier: &crate::transaction::Transaction,
    committed: &BlockChain,
    pending: &[crate::transaction::Transaction],
) -> Result<(), String> {
    require_canonical_account_sequence_with_nonces(
        carrier,
        &committed_sender_nonces(committed, &carrier.sender),
        pending,
    )
}

/// Durable per-height receipt frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleAuthorityReceiptFrame {
    pub height: u64,
    pub block_hash: String,
    pub receipt_root: Hash,
    pub state_root_after: Hash,
    pub receipts: Vec<TransactionReceipt>,
}

/// Re-admits every carrier in a block body and returns the canonical typed
/// transactions in block order.
///
/// This performs the exact admission the submission path performs:
/// Aegis envelope verification (chain id, network id, key lifecycle/role,
/// sender address derivation, SynQ payload admission, ML-DSA signature) plus
/// carrier/typed field equality. A block whose body cannot be re-admitted is
/// rejected before any execution occurs.
pub fn typed_transactions_for_block(
    carriers: &[crate::transaction::Transaction],
    committed: &BlockChain,
    consensus_timestamp_unix: u64,
) -> Result<Vec<TypedTransaction>, String> {
    let mut typed = Vec::with_capacity(carriers.len());
    // Nonces already accepted earlier in THIS body must constrain later ones,
    // so a body can never contain the same account sequence twice.
    let mut accepted: Vec<crate::transaction::Transaction> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (index, carrier) in carriers.iter().enumerate() {
        if !seen.insert(carrier.raw_hash()) {
            return Err(format!(
                "single-authority block transaction {index} is a duplicate of an earlier entry"
            ));
        }
        let data = carrier.data.as_deref().ok_or_else(|| {
            format!("single-authority block transaction {index} is not an Aegis carrier")
        })?;
        let envelope = decode_aegis_carrier_data(data)
            .map_err(|error| format!("block transaction {index}: {error}"))?;
        verify_aegis_submission_envelope_at(&envelope, consensus_timestamp_unix)
            .map_err(|error| format!("block transaction {index} failed admission: {error}"))?;
        validate_legacy_aegis_carrier_transaction(carrier)
            .map_err(|error| format!("block transaction {index} carrier mismatch: {error}"))?;
        require_canonical_account_sequence(carrier, committed, &accepted).map_err(|error| {
            format!("block transaction {index} violates the account sequence: {error}")
        })?;
        accepted.push(carrier.clone());
        typed.push(envelope.transaction);
    }
    Ok(typed)
}

/// Re-admits a new body against the compact, startup-rebuilt committed-nonce
/// index. This is equivalent to `typed_transactions_for_block` for canonical
/// ordering while keeping historical block bodies out of the authority heap.
pub fn typed_transactions_for_block_with_nonce_index(
    carriers: &[crate::transaction::Transaction],
    committed_nonce_index: &BTreeMap<String, u64>,
    consensus_timestamp_unix: u64,
) -> Result<Vec<TypedTransaction>, String> {
    let mut typed = Vec::with_capacity(carriers.len());
    let mut accepted: Vec<crate::transaction::Transaction> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (index, carrier) in carriers.iter().enumerate() {
        if !seen.insert(carrier.raw_hash()) {
            return Err(format!(
                "single-authority block transaction {index} is a duplicate of an earlier entry"
            ));
        }
        let data = carrier.data.as_deref().ok_or_else(|| {
            format!("single-authority block transaction {index} is not an Aegis carrier")
        })?;
        let envelope = decode_aegis_carrier_data(data)
            .map_err(|error| format!("block transaction {index}: {error}"))?;
        verify_aegis_submission_envelope_at(&envelope, consensus_timestamp_unix)
            .map_err(|error| format!("block transaction {index} failed admission: {error}"))?;
        validate_legacy_aegis_carrier_transaction(carrier)
            .map_err(|error| format!("block transaction {index} carrier mismatch: {error}"))?;
        let committed = committed_nonce_index
            .get(&nonce_index_key(&carrier.sender))
            .copied()
            .into_iter()
            .collect::<Vec<_>>();
        require_canonical_account_sequence_with_nonces(carrier, &committed, &accepted).map_err(
            |error| {
                format!("block transaction {index} violates the account sequence: {error}")
            },
        )?;
        accepted.push(carrier.clone());
        typed.push(envelope.transaction);
    }
    Ok(typed)
}

/// Binds the canonical PQC authorization context the state transition requires.
///
/// `execute_transaction` refuses to run a transaction whose canonical bytes are
/// not recorded in `verified_authorizations`, so this is the admission-to-
/// execution handoff, not an optimisation.
pub fn authorize_for_execution(
    state: &ExecutionState,
    typed: &[TypedTransaction],
    consensus_timestamp_unix: u64,
) -> Result<ExecutionState, String> {
    let mut authorized = state.clone();
    for tx in typed {
        authorized.mark_authorized_at(tx, consensus_timestamp_unix)?;
    }
    Ok(authorized)
}

/// Durably writes the execution state through the canonical, root-verified
/// snapshot format. The snapshot embeds `compute_state_root_after`, so a
/// corrupted or substituted file fails closed on read.
pub fn persist_execution_state(path: &Path, state: &ExecutionState) -> Result<(), String> {
    let snapshot = GenesisExecutionSnapshot::capture_testnet_v3(state)?;
    let bytes = serde_json::to_vec(&snapshot)
        .map_err(|error| format!("encode single-authority execution state: {error}"))?;
    write_atomically(path, &bytes)
}

/// Reads the durable execution state, or `None` when no state has been
/// persisted yet.
pub fn load_execution_state(path: &Path) -> Result<Option<ExecutionState>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("read execution state {}: {error}", path.display()))?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let snapshot: GenesisExecutionSnapshot = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse execution state {}: {error}", path.display()))?;
    snapshot.restore_testnet_v3().map(Some)
}

/// Appends one durable receipt frame and fsyncs it.
pub fn append_receipt_frame(path: &Path, frame: &SingleAuthorityReceiptFrame) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create receipt log directory: {error}"))?;
    }
    let mut line = serde_json::to_vec(frame)
        .map_err(|error| format!("encode single-authority receipt frame: {error}"))?;
    line.push(b'\n');
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("open receipt log {}: {error}", path.display()))?;
    file.write_all(&line)
        .map_err(|error| format!("append receipt log {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync receipt log {}: {error}", path.display()))
}

/// Recovers every durable receipt frame keyed by height. A duplicate height
/// with a conflicting frame fails closed.
pub fn recover_receipt_frames(
    path: &Path,
) -> Result<BTreeMap<u64, SingleAuthorityReceiptFrame>, String> {
    let mut frames = BTreeMap::new();
    if !path.exists() {
        return Ok(frames);
    }
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("read receipt log {}: {error}", path.display()))?;
    for (index, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let frame: SingleAuthorityReceiptFrame =
            serde_json::from_str(trimmed).map_err(|error| {
                format!(
                    "parse receipt log {} line {}: {error}",
                    path.display(),
                    index + 1
                )
            })?;
        match frames.get(&frame.height) {
            Some(existing) if existing != &frame => {
                return Err(format!(
                    "receipt log {} has conflicting frames at height {}",
                    path.display(),
                    frame.height
                ));
            }
            Some(_) => {}
            None => {
                frames.insert(frame.height, frame);
            }
        }
    }
    Ok(frames)
}

/// Streams receipt history and retains only the current finalized height. The
/// receipt archive can grow indefinitely, but authority startup needs only the
/// durable tip receipt to bind the restored execution snapshot to finality.
pub fn recover_receipt_tip(
    path: &Path,
    finalized_height: u64,
) -> Result<(Option<SingleAuthorityReceiptFrame>, bool), String> {
    if !path.exists() {
        return Ok((None, false));
    }
    let file = fs::File::open(path)
        .map_err(|error| format!("open receipt log {}: {error}", path.display()))?;
    let mut tip = None;
    let mut saw_any = false;
    let mut last_height = None;
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|error| {
            format!(
                "read receipt log {} line {}: {error}",
                path.display(),
                index + 1
            )
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let frame: SingleAuthorityReceiptFrame = serde_json::from_str(trimmed).map_err(|error| {
            format!(
                "parse receipt log {} line {}: {error}",
                path.display(),
                index + 1
            )
        })?;
        saw_any = true;
        if let Some(last_height) = last_height {
            if frame.height <= last_height {
                return Err(format!(
                    "receipt log {} is not strictly ordered at line {}: height {} follows {}",
                    path.display(),
                    index + 1,
                    frame.height,
                    last_height
                ));
            }
        }
        last_height = Some(frame.height);
        if frame.height != finalized_height {
            continue;
        }
        match &tip {
            Some(existing) if existing != &frame => {
                return Err(format!(
                    "receipt log {} has conflicting frames at finalized height {}",
                    path.display(),
                    finalized_height
                ));
            }
            Some(_) => {}
            None => tip = Some(frame),
        }
    }
    Ok((tip, saw_any))
}

/// Streams the complete committed-body archive to preserve its canonical
/// parent linkage and rebuild the compact per-account nonce index, retaining
/// only a bounded body suffix in `chain`. The archive is append-only and
/// ordered by height; accepting an out-of-order record would make a restart
/// depend on materializing an unbounded map, so it fails closed instead.
pub fn recover_single_authority_committed_body_tail(
    chain: &mut BlockChain,
    path: &Path,
    retain: usize,
) -> Result<BTreeMap<String, u64>, String> {
    let genesis = chain.last().cloned().ok_or_else(|| {
        "single-authority body recovery requires the canonical Genesis anchor".to_string()
    })?;
    if genesis.block_index != 0 {
        return Err("single-authority body recovery must begin from Genesis height 0".to_string());
    }
    if !path.exists() {
        return Ok(BTreeMap::new());
    }

    let file = fs::File::open(path)
        .map_err(|error| format!("open committed block log {}: {error}", path.display()))?;
    let mut tip = genesis;
    let mut tail = std::collections::VecDeque::with_capacity(retain);
    let mut nonces = BTreeMap::new();

    for (line_number, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|error| {
            format!(
                "read committed block log {} line {}: {error}",
                path.display(),
                line_number + 1
            )
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry = match serde_json::from_str::<CommittedBlockLogEntry>(trimmed) {
            Ok(entry) => entry,
            // A torn trailing append from an interrupted write cannot be
            // canonical. The finalized-head/body reconciliation below rejects
            // it if finality ever commits beyond the intact prefix.
            Err(_) => continue,
        };
        if entry.height != entry.block.block_index || entry.hash != entry.block.hash {
            return Err(format!(
                "committed block log entry at line {} has inconsistent height/hash",
                line_number + 1
            ));
        }
        if entry.height != tip.block_index.saturating_add(1) {
            return Err(format!(
                "single-authority committed block log is not contiguous at line {}: expected height {}, found {}",
                line_number + 1,
                tip.block_index.saturating_add(1),
                entry.height
            ));
        }
        if entry.previous_hash != tip.hash || entry.block.previous_hash != tip.hash {
            return Err(format!(
                "committed block log entry at height {} does not extend persisted tip {}:{}",
                entry.height, tip.block_index, tip.hash
            ));
        }
        record_committed_block_nonces(&mut nonces, &entry.block);
        if retain > 0 {
            if tail.len() == retain {
                tail.pop_front();
            }
            tail.push_back(entry.block.clone());
        }
        tip = entry.block;
    }

    chain.chain.truncate(1);
    chain.chain.extend(tail);
    Ok(nonces)
}

/// Fails closed unless the recovered execution state reproduces the finalized
/// state root the durable finality record committed.
pub fn require_state_root_agreement(
    state: &ExecutionState,
    expected: Hash,
    context: &str,
) -> Result<(), String> {
    let actual = compute_state_root_after(state)?;
    if actual != expected {
        return Err(format!(
            "{context}: recovered execution state root {} does not match finalized {}",
            actual.to_hex(),
            expected.to_hex()
        ));
    }
    Ok(())
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create execution state directory: {error}"))?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut file = fs::File::create(&temporary)
            .map_err(|error| format!("create {}: {error}", temporary.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync {}: {error}", temporary.display()))?;
    }
    fs::rename(&temporary, path)
        .map_err(|error| format!("publish {}: {error}", path.display()))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "single-authority-execution-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn committed_body_recovery_keeps_a_bounded_suffix_and_nonce_index() {
        let dir = TempDir::new("bounded-tail");
        let path = dir.0.join("committed.ndjson");
        let genesis = genesis_anchor_block("genesis-hash");
        let mut tip = genesis.clone();
        let mut blocks = Vec::new();
        for height in 1..=32 {
            let block = Block::new(
                height,
                Vec::new(),
                tip.hash.clone(),
                "test-authority".to_string(),
                0,
            );
            tip = block.clone();
            blocks.push(block);
        }
        crate::consensus::chain_durability::append_committed_block_bodies_at(&blocks, &path)
            .expect("persist archive");

        let mut recovered = BlockChain::new();
        recovered.add_block(genesis);
        let nonce_index = recover_single_authority_committed_body_tail(&mut recovered, &path, 3)
            .expect("stream recovery");
        assert!(nonce_index.is_empty());
        assert_eq!(
            recovered
                .chain
                .iter()
                .map(|block| block.block_index)
                .collect::<Vec<_>>(),
            vec![0, 30, 31, 32]
        );
        assert_eq!(recovered.last().map(|block| &block.hash), Some(&tip.hash));
    }
}
