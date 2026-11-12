//! Canonical signed registry format shared by runtime and offline issuer.
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use synergy_address_engine::{
    apqe::{HashAlgorithm, Primitives},
    canonical_json::to_canonical_json,
};

const REGISTRY_DOMAIN: &[u8] = b"SYNERGY/CANARY-TRANSPORT-REGISTRY/v1";
pub(crate) const REGISTRY_CONTEXT: &[u8] = b"SYNERGY.CANARY.TRANSPORT.REGISTRY.V1";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransportEntry {
    pub node_address: String,
    pub dial_address: SocketAddr,
    pub transport_key_id: String,
    pub transport_key_version: u64,
    pub transport_public_key: Vec<u8>,
    pub enrollment_sha256: String,
    pub revoked: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistryPayload {
    pub schema_version: u16,
    pub scope: String,
    pub chain_id: u64,
    pub network_id: String,
    pub protocol: String,
    pub genesis_hash: String,
    pub genesis_artifact_sha256: String,
    pub authority_binding_sha256: String,
    pub epoch: u64,
    pub generation: u64,
    pub valid_from_unix: u64,
    pub expires_at_unix: u64,
    pub validators: Vec<TransportEntry>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedRegistry {
    pub payload: RegistryPayload,
    pub signature: Vec<u8>,
}
pub(crate) fn signing_bytes(payload: &RegistryPayload) -> Result<Vec<u8>, String> {
    let canonical = to_canonical_json(&serde_json::to_value(payload).map_err(|e| e.to_string())?)?;
    let mut hash = Primitives
        .hash_stream(HashAlgorithm::Sha3512)
        .map_err(|e| e.to_string())?;
    hash.update(REGISTRY_DOMAIN);
    hash.update(&canonical);
    Ok(hash.finalize())
}
