use crate::block::{Block, BlockChain};
use crate::synergy_types::CanonicalSerialize;
use crate::transaction::Transaction;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const GENESIS_DAG_ROOT: &str = "synergy-dag-root";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DagVertexStatus {
    Proposed,
    Committed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagVertex {
    pub hash: String,
    pub parent_hashes: Vec<String>,
    pub transaction_hashes: Vec<String>,
    pub transactions: Vec<Transaction>,
    pub proposer: String,
    pub created_at: u64,
    pub height_hint: u64,
    pub block_hash: Option<String>,
    pub block_number: Option<u64>,
    pub status: DagVertexStatus,
    pub availability_cert: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagEdge {
    pub parent_hash: String,
    pub child_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagState {
    pub vertices: BTreeMap<String, DagVertex>,
    pub transaction_index: BTreeMap<String, String>,
    pub tips: BTreeSet<String>,
    pub latest_committed_block: Option<u64>,
}

impl Default for DagState {
    fn default() -> Self {
        let mut tips = BTreeSet::new();
        tips.insert(GENESIS_DAG_ROOT.to_string());
        Self {
            vertices: BTreeMap::new(),
            transaction_index: BTreeMap::new(),
            tips,
            latest_committed_block: None,
        }
    }
}

lazy_static::lazy_static! {
    pub static ref DAG_STATE: Arc<Mutex<DagState>> = Arc::new(Mutex::new(
        DagState::load_from_default_path().unwrap_or_default()
    ));
}

impl DagVertex {
    fn new(
        parent_hashes: Vec<String>,
        transactions: Vec<Transaction>,
        proposer: String,
        height_hint: u64,
        created_at: u64,
        status: DagVertexStatus,
        block_hash: Option<String>,
        block_number: Option<u64>,
    ) -> Self {
        let transaction_hashes = transactions
            .iter()
            .map(Transaction::hash)
            .collect::<Vec<_>>();
        let hash = compute_vertex_hash(&parent_hashes, &transaction_hashes, &proposer, height_hint);
        let availability_cert =
            compute_availability_cert(&hash, &parent_hashes, &transaction_hashes);

        Self {
            hash,
            parent_hashes,
            transaction_hashes,
            transactions,
            proposer,
            created_at,
            height_hint,
            block_hash,
            block_number,
            status,
            availability_cert,
        }
    }
}

impl DagState {
    pub fn load_from_default_path() -> Option<Self> {
        let path = default_dag_path();
        Self::load_from_file(&path)
    }

    pub fn load_from_file(path: &Path) -> Option<Self> {
        let contents = fs::read_to_string(path).ok()?;
        serde_json::from_str::<Self>(&contents).ok()
    }

    pub fn save_to_default_path(&self) -> Result<(), String> {
        self.save_to_file(&default_dag_path())
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        let payload =
            serde_json::to_vec_pretty(self).map_err(|error| format!("serialize dag: {error}"))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!("create dag state directory {}: {error}", parent.display())
            })?;
        }

        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("invalid dag state path: {}", path.display()))?;
        let suffix = current_timestamp();
        let temp_path =
            path.with_file_name(format!("{file_name}.tmp-{}-{suffix}", std::process::id()));

        {
            let mut file = File::create(&temp_path).map_err(|error| {
                format!("create temp dag state {}: {error}", temp_path.display())
            })?;
            file.write_all(&payload).map_err(|error| {
                format!("write temp dag state {}: {error}", temp_path.display())
            })?;
            file.sync_all()
                .map_err(|error| format!("sync temp dag state {}: {error}", temp_path.display()))?;
        }

        fs::rename(&temp_path, path).map_err(|error| {
            let _ = fs::remove_file(&temp_path);
            format!(
                "replace dag state {} with {}: {error}",
                path.display(),
                temp_path.display()
            )
        })?;
        Ok(())
    }

    pub fn rebuild_from_chain(chain: &BlockChain) -> Self {
        let mut state = Self::default();
        for block in &chain.chain {
            state.commit_block(block);
        }
        state
    }

    pub fn create_proposal_vertex(
        &mut self,
        transactions: &[Transaction],
        proposer: &str,
        height_hint: u64,
    ) -> Option<String> {
        if transactions.is_empty() {
            return None;
        }

        let transaction_hashes = transaction_hashes(transactions);
        if let Some(existing_hash) =
            self.find_matching_vertex_hash(height_hint, proposer, &transaction_hashes)
        {
            return Some(existing_hash);
        }

        let parent_hashes = self.current_parent_hashes();
        let vertex = DagVertex::new(
            parent_hashes,
            transactions.to_vec(),
            proposer.to_string(),
            height_hint,
            current_timestamp(),
            DagVertexStatus::Proposed,
            None,
            None,
        );
        let hash = vertex.hash.clone();
        self.insert_vertex(vertex);
        Some(hash)
    }

    pub fn commit_block(&mut self, block: &Block) -> Vec<String> {
        if block.transactions.is_empty() {
            self.latest_committed_block = Some(block.block_index);
            return Vec::new();
        }

        let transaction_hashes = transaction_hashes(&block.transactions);
        let hash = self
            .find_matching_vertex_hash(block.block_index, &block.validator_id, &transaction_hashes)
            .unwrap_or_else(|| {
                let vertex = DagVertex::new(
                    self.current_parent_hashes(),
                    block.transactions.clone(),
                    block.validator_id.clone(),
                    block.block_index,
                    block.timestamp,
                    DagVertexStatus::Committed,
                    Some(block.hash.clone()),
                    Some(block.block_index),
                );
                let hash = vertex.hash.clone();
                self.insert_vertex(vertex);
                hash
            });

        if let Some(vertex) = self.vertices.get_mut(&hash) {
            vertex.status = DagVertexStatus::Committed;
            vertex.block_hash = Some(block.hash.clone());
            vertex.block_number = Some(block.block_index);
            vertex.created_at = block.timestamp;
        }
        self.latest_committed_block = Some(block.block_index);
        vec![hash]
    }

    pub fn status_json(&self) -> Value {
        json!({
            "enabled": true,
            "data_source": "runtime_dag_state",
            "root": GENESIS_DAG_ROOT,
            "vertex_count": self.vertices.len(),
            "transaction_count": self.transaction_index.len(),
            "frontier_count": self.frontier_hashes().len(),
            "latest_committed_block": self.latest_committed_block,
            "frontier": self.frontier_hashes(),
        })
    }

    pub fn frontier_json(&self) -> Value {
        let items = self
            .frontier_hashes()
            .into_iter()
            .filter_map(|hash| self.vertices.get(&hash).cloned())
            .collect::<Vec<_>>();
        json!({
            "root": GENESIS_DAG_ROOT,
            "count": items.len(),
            "items": items,
        })
    }

    pub fn vertices_json(&self, limit: usize, status: Option<DagVertexStatus>) -> Value {
        let items = self.visible_vertices(limit, status);
        json!({
            "count": items.len(),
            "items": items,
        })
    }

    pub fn vertex_json(&self, hash: &str) -> Value {
        self.vertices
            .get(hash)
            .map(|vertex| json!(vertex))
            .unwrap_or_else(|| json!(null))
    }

    pub fn transaction_status_json(&self, tx_id_or_hash: &str) -> Value {
        if let Some(vertex_hash) = self.transaction_index.get(tx_id_or_hash) {
            return self
                .vertices
                .get(vertex_hash)
                .map(|vertex| {
                    json!({
                        "found": true,
                        "tx_id_or_hash": tx_id_or_hash,
                        "tx_hash": tx_id_or_hash,
                        "vertex_hash": vertex.hash,
                        "status": vertex.status,
                        "block_hash": vertex.block_hash,
                        "block_number": vertex.block_number,
                    })
                })
                .unwrap_or_else(|| {
                    json!({
                        "found": false,
                        "tx_id_or_hash": tx_id_or_hash,
                        "reason": "transaction index points to a missing DAG vertex"
                    })
                });
        }

        for vertex in self.vertices.values() {
            for transaction in &vertex.transactions {
                let Some(data) = transaction.data.as_deref() else {
                    continue;
                };
                if !crate::aegis_tx_tool::is_legacy_aegis_carrier_transaction(transaction) {
                    continue;
                }
                let Ok(envelope) = crate::aegis_tx_tool::decode_aegis_carrier_data(data) else {
                    continue;
                };
                let Ok(bytes) = envelope.transaction.canonical_bytes() else {
                    continue;
                };
                let typed_tx_id =
                    crate::crypto::aegis_pqvm::AegisPqvmDomainSeparatedHash::hash_transaction(
                        crate::crypto::aegis_pqvm::SYNERGY_TX_V1,
                        envelope.transaction.chain_id,
                        &envelope.transaction.network_id,
                        &bytes,
                    )
                    .0;
                if typed_tx_id == tx_id_or_hash {
                    return json!({
                        "found": true,
                        "tx_id_or_hash": tx_id_or_hash,
                        "tx_id": typed_tx_id,
                        "tx_hash": transaction.hash(),
                        "vertex_hash": vertex.hash,
                        "status": vertex.status,
                        "block_hash": vertex.block_hash,
                        "block_number": vertex.block_number,
                        "aegis_pqvm_verification": "carrier_present",
                    });
                }
            }
        }

        json!({
            "found": false,
            "tx_id_or_hash": tx_id_or_hash,
            "reason": "transaction is not present in the committed DAG state"
        })
    }

    pub fn committed_sender_nonces(&self, sender: &str) -> Vec<u64> {
        let mut nonces = self
            .vertices
            .values()
            .filter(|vertex| vertex.status == DagVertexStatus::Committed)
            .flat_map(|vertex| vertex.transactions.iter())
            .filter(|transaction| transaction.sender.eq_ignore_ascii_case(sender))
            .map(|transaction| transaction.nonce)
            .collect::<Vec<_>>();
        nonces.sort_unstable();
        nonces.dedup();
        nonces
    }

    pub fn topology_json(&self, limit: usize) -> Value {
        let vertices = self.visible_vertices(limit, None);
        let visible_hashes = vertices
            .iter()
            .map(|vertex| vertex.hash.clone())
            .collect::<BTreeSet<_>>();
        let edges = vertices
            .iter()
            .flat_map(|vertex| {
                vertex.parent_hashes.iter().filter_map(|parent_hash| {
                    if parent_hash == GENESIS_DAG_ROOT || visible_hashes.contains(parent_hash) {
                        Some(DagEdge {
                            parent_hash: parent_hash.clone(),
                            child_hash: vertex.hash.clone(),
                        })
                    } else {
                        None
                    }
                })
            })
            .collect::<Vec<_>>();

        json!({
            "root": GENESIS_DAG_ROOT,
            "vertices": vertices,
            "edges": edges,
        })
    }

    fn insert_vertex(&mut self, vertex: DagVertex) {
        for parent_hash in &vertex.parent_hashes {
            if parent_hash != GENESIS_DAG_ROOT {
                self.tips.remove(parent_hash);
            }
        }
        for tx_hash in &vertex.transaction_hashes {
            self.transaction_index
                .insert(tx_hash.clone(), vertex.hash.clone());
        }
        self.tips.insert(vertex.hash.clone());
        self.vertices.insert(vertex.hash.clone(), vertex);
    }

    fn current_parent_hashes(&self) -> Vec<String> {
        let parents = self
            .tips
            .iter()
            .filter(|hash| hash.as_str() != GENESIS_DAG_ROOT || self.vertices.is_empty())
            .cloned()
            .collect::<Vec<_>>();

        if parents.is_empty() {
            vec![GENESIS_DAG_ROOT.to_string()]
        } else {
            parents
        }
    }

    fn frontier_hashes(&self) -> Vec<String> {
        self.tips
            .iter()
            .filter(|hash| hash.as_str() != GENESIS_DAG_ROOT)
            .cloned()
            .collect()
    }

    fn visible_vertices(&self, limit: usize, status: Option<DagVertexStatus>) -> Vec<DagVertex> {
        let mut vertices = self
            .vertices
            .values()
            .filter(|vertex| {
                status
                    .map(|expected| vertex.status == expected)
                    .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        vertices.sort_by(|left, right| {
            let left_height = left.block_number.unwrap_or(left.height_hint);
            let right_height = right.block_number.unwrap_or(right.height_hint);
            right_height
                .cmp(&left_height)
                .then_with(|| right.created_at.cmp(&left.created_at))
                .then_with(|| right.hash.cmp(&left.hash))
        });
        vertices.truncate(limit);
        vertices
    }

    fn find_matching_vertex_hash(
        &self,
        height_hint: u64,
        proposer: &str,
        transaction_hashes: &[String],
    ) -> Option<String> {
        self.vertices
            .values()
            .find(|vertex| {
                vertex.height_hint == height_hint
                    && vertex.proposer == proposer
                    && vertex.transaction_hashes == transaction_hashes
            })
            .map(|vertex| vertex.hash.clone())
    }
}

pub fn create_proposal_vertex_for_transactions(
    transactions: &[Transaction],
    proposer: &str,
    height_hint: u64,
) -> Option<String> {
    let mut dag = DAG_STATE.lock().ok()?;
    let hash = dag.create_proposal_vertex(transactions, proposer, height_hint);
    if hash.is_some() {
        let _ = dag.save_to_default_path();
    }
    hash
}

pub fn commit_block(block: &Block) -> Vec<String> {
    let Ok(mut dag) = DAG_STATE.lock() else {
        return Vec::new();
    };
    let hashes = dag.commit_block(block);
    let _ = dag.save_to_default_path();
    hashes
}

pub fn commit_blocks(blocks: &[Block]) -> Vec<String> {
    let Ok(mut dag) = DAG_STATE.lock() else {
        return Vec::new();
    };
    let mut hashes = Vec::new();
    for block in blocks {
        hashes.extend(dag.commit_block(block));
    }
    let _ = dag.save_to_default_path();
    hashes
}

pub fn rebuild_global_from_chain(chain: &BlockChain) {
    let rebuilt = DagState::rebuild_from_chain(chain);
    if let Ok(mut dag) = DAG_STATE.lock() {
        *dag = rebuilt;
        let _ = dag.save_to_default_path();
    }
}

pub fn status_json() -> Value {
    DAG_STATE
        .lock()
        .map(|dag| dag.status_json())
        .unwrap_or_else(|_| json!({"enabled": false, "error": "dag state lock unavailable"}))
}

pub fn frontier_json() -> Value {
    DAG_STATE
        .lock()
        .map(|dag| dag.frontier_json())
        .unwrap_or_else(|_| json!({"root": GENESIS_DAG_ROOT, "count": 0, "items": []}))
}

pub fn vertices_json(limit: usize, status: Option<DagVertexStatus>) -> Value {
    DAG_STATE
        .lock()
        .map(|dag| dag.vertices_json(limit, status))
        .unwrap_or_else(|_| json!({"count": 0, "items": []}))
}

pub fn vertex_json(hash: &str) -> Value {
    DAG_STATE
        .lock()
        .map(|dag| dag.vertex_json(hash))
        .unwrap_or_else(|_| json!(null))
}

pub fn transaction_status_json(tx_id_or_hash: &str) -> Value {
    DAG_STATE
        .lock()
        .map(|dag| dag.transaction_status_json(tx_id_or_hash))
        .unwrap_or_else(|_| {
            json!({
                "found": false,
                "tx_id_or_hash": tx_id_or_hash,
                "reason": "dag state lock unavailable"
            })
        })
}

pub fn committed_sender_nonces(sender: &str) -> Vec<u64> {
    DAG_STATE
        .lock()
        .map(|dag| dag.committed_sender_nonces(sender))
        .unwrap_or_default()
}

pub fn topology_json(limit: usize) -> Value {
    DAG_STATE
        .lock()
        .map(|dag| dag.topology_json(limit))
        .unwrap_or_else(|_| json!({"root": GENESIS_DAG_ROOT, "vertices": [], "edges": []}))
}

pub fn parse_status_filter(value: Option<&str>) -> Option<DagVertexStatus> {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "proposed" | "pending" => Some(DagVertexStatus::Proposed),
        "committed" => Some(DagVertexStatus::Committed),
        _ => None,
    }
}

fn default_dag_path() -> std::path::PathBuf {
    crate::utils::resolve_data_path("data/dag_state.json")
}

fn transaction_hashes(transactions: &[Transaction]) -> Vec<String> {
    transactions.iter().map(Transaction::hash).collect()
}

fn compute_vertex_hash(
    parent_hashes: &[String],
    transaction_hashes: &[String],
    proposer: &str,
    height_hint: u64,
) -> String {
    let payload = json!({
        "version": 1,
        "parents": parent_hashes,
        "transactions": transaction_hashes,
        "proposer": proposer,
        "height_hint": height_hint,
    });
    blake3::hash(payload.to_string().as_bytes())
        .to_hex()
        .to_string()
}

fn compute_availability_cert(
    hash: &str,
    parent_hashes: &[String],
    transaction_hashes: &[String],
) -> String {
    let payload = json!({
        "vertex": hash,
        "parents": parent_hashes,
        "transaction_count": transaction_hashes.len(),
    });
    blake3::hash(payload.to_string().as_bytes())
        .to_hex()
        .to_string()
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(nonce: u64) -> Transaction {
        Transaction::new(
            "syna1sender".to_string(),
            "syna1receiver".to_string(),
            1,
            nonce,
            vec![1, 2, 3],
            1,
            21_000,
            None,
            "fndsa".to_string(),
        )
    }

    #[test]
    fn dag_vertex_hash_is_deterministic_for_same_batch() {
        let transactions = vec![tx(1), tx(2)];
        let mut dag = DagState::default();
        let first = dag
            .create_proposal_vertex(&transactions, "synv1validator", 8)
            .expect("vertex should be created");
        let second = dag
            .create_proposal_vertex(&transactions, "synv1validator", 8)
            .expect("matching vertex should be returned");

        assert_eq!(first, second);
        assert_eq!(dag.vertices.len(), 1);
    }

    #[test]
    fn committed_block_marks_matching_proposed_vertex() {
        let transactions = vec![tx(7)];
        let previous = Block::new(0, vec![], String::new(), "genesis".to_string(), 0);
        let block = Block::new(
            1,
            transactions.clone(),
            previous.hash,
            "synv1validator".to_string(),
            1,
        );
        let mut dag = DagState::default();
        let proposed = dag
            .create_proposal_vertex(&transactions, "synv1validator", 1)
            .expect("proposal vertex should be created");
        let committed = dag.commit_block(&block);

        assert_eq!(committed, vec![proposed.clone()]);
        assert_eq!(
            dag.vertices.get(&proposed).map(|vertex| vertex.status),
            Some(DagVertexStatus::Committed)
        );
        assert_eq!(
            dag.vertices
                .get(&proposed)
                .and_then(|vertex| vertex.block_number),
            Some(1)
        );
    }
}
