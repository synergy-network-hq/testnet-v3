use serde::{Deserialize, Serialize};

use crate::block::{Block, BlockHeader};
use crate::consensus::dual_quorum::{QuorumCertificate, Vote};
use crate::synergy_types::AegisPqSignature;
use crate::transaction::Transaction;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Handshake {
        node_id: String,
        version: String,
        capabilities: Vec<String>,
        #[serde(default)]
        chain_id: Option<u64>,
        #[serde(default)]
        network_id: Option<u64>,
        #[serde(default)]
        network_id_text: Option<String>,
        #[serde(default)]
        genesis_hash: String,
        #[serde(default)]
        network_magic_bytes: String,
        #[serde(default)]
        protocol_version: Option<String>,
        #[serde(default)]
        consensus_version: Option<String>,
        #[serde(default)]
        native_caip2: Option<String>,
        #[serde(default)]
        reserved_eip155: Option<String>,
        #[serde(default)]
        public_address: Option<String>,
        #[serde(default)]
        validator_address: Option<String>,
        #[serde(default)]
        role: Option<String>,
        #[serde(default)]
        active_validator_set_hash: Option<String>,
        #[serde(default)]
        cluster_map_hash: Option<String>,
        #[serde(default)]
        protocol_config_hash: Option<String>,
        #[serde(default)]
        aegis_pqvm_version: Option<String>,
        #[serde(default)]
        aegis_pq_public_key_id: Option<String>,
        #[serde(default)]
        aegis_pq_public_key_algorithm: Option<String>,
        #[serde(default)]
        aegis_pq_public_key: Vec<u8>,
        #[serde(default)]
        aegis_pq_handshake_signature: Option<AegisPqSignature>,
    },
    Block {
        block_data: Block,
        #[serde(default)]
        quorum_certificate: Option<QuorumCertificate>,
    },
    VoteRequest {
        block_data: Block,
        epoch_number: u64,
        round_number: u64,
    },
    Vote {
        vote: Vote,
    },
    Transaction {
        transaction_data: Transaction,
    },
    GetBlocks {
        from_height: u64,
        count: u32,
    },
    Blocks {
        blocks: Vec<Block>,
        #[serde(default)]
        quorum_certificates: Vec<QuorumCertificate>,
    },
    GetPeers,
    Peers {
        peer_addresses: Vec<String>,
    },
    Ping,
    Pong,
    Error {
        message: String,
    },
    GetStatus,
    Status {
        block_height: u64,
        best_block_hash: String,
        genesis_hash: String,
        #[serde(default)]
        status_timestamp: Option<u64>,
        #[serde(default)]
        validator_address: Option<String>,
        #[serde(default)]
        source_session_id: Option<String>,
        #[serde(default)]
        active_validator_set_hash: Option<String>,
        #[serde(default)]
        quarantined: bool,
        #[serde(default)]
        consensus_duties_disabled: bool,
        #[serde(default)]
        recovery_state: Option<String>,
    },
    GetBlockHeaders {
        start_height: u64,
        count: u64,
    },
    BlockHeaders {
        headers: Vec<BlockHeader>,
    },
    GetBlockBodies {
        hashes: Vec<String>,
    },
    BlockBodies {
        blocks: Vec<Block>,
        #[serde(default)]
        quorum_certificates: Vec<QuorumCertificate>,
    },
}
