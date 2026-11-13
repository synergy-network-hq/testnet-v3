//! Canonical authenticated-handshake framing.
//!
//! This module owns the bytes covered by the Aegis PQ signature and the
//! accepted peer-key algorithms. Consensus-specific membership checks remain
//! in the PoSy adapter, after transport authentication succeeds.

use serde::Serialize;

use crate::crypto::pqc::PQCAlgorithm;
use crate::p2p::messages::NetworkMessage;

#[derive(Debug, Serialize, PartialEq, Eq)]
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

pub(super) fn signing_payload(message: &NetworkMessage) -> Result<Vec<u8>, String> {
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

pub(super) fn parse_pqc_algorithm(value: &str) -> Result<PQCAlgorithm, String> {
    match value.trim() {
        "fndsa" | "FN-DSA-1024" => Ok(PQCAlgorithm::FNDSA),
        "mldsa65" | "ML-DSA-65" => Ok(PQCAlgorithm::MLDSA65),
        "mldsa87" | "ML-DSA-87" => Ok(PQCAlgorithm::MLDSA87),
        other => Err(format!(
            "unsupported Aegis PQC peer key algorithm: {other}; use fndsa, mldsa65, or mldsa87"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_pqc_algorithm;
    use crate::crypto::pqc::PQCAlgorithm;

    #[test]
    fn accepts_only_supported_authenticated_peer_key_algorithms() {
        assert_eq!(
            parse_pqc_algorithm("mldsa65").unwrap(),
            PQCAlgorithm::MLDSA65
        );
        assert!(parse_pqc_algorithm("slhdsa").is_err());
    }
}
