//! Signed, Genesis-bound release barrier for Chain 1266.

use base64::{engine::general_purpose, Engine as _};
use pqsynq::Sign;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub const CHAIN1266_START_SIGNATURE_DOMAIN: &str = "SYNERGY_CHAIN1266_START_CONSENSUS_V1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Chain1266StartRequest {
    pub schema_version: u32,
    pub action: String,
    pub release_id: String,
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub genesis_hash: String,
    pub desired_state_sha256: String,
    pub activate_unix_ms: u64,
    pub signature_algorithm: String,
    pub signature_domain: String,
    pub authority_public_key_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedChain1266StartCommand {
    pub request: Chain1266StartRequest,
    pub signature_base64: String,
}

#[derive(Debug, Deserialize)]
struct DesiredStateStartView {
    release_id: String,
    chain: DesiredChainView,
    state: DesiredConsensusStateView,
    start_authority: StartAuthorityView,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredChainView {
    chain_id: u64,
    incarnation: u64,
    genesis_hash: String,
    validator_set_root: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredConsensusStateView {
    consensus_schema_version: u32,
    directory_namespace: String,
    mode: String,
    coordinator_id: String,
    producer_ids: Vec<String>,
    producer_turn_timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
struct StartAuthorityView {
    signature_algorithm: String,
    signature_domain: String,
    public_key_fingerprint: String,
    public_key_base64: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn verify_signed_start_command(
    command_path: &Path,
    desired_state_path: &Path,
    expected_desired_state_sha256: &str,
) -> Result<Chain1266StartRequest, String> {
    let desired_bytes = fs::read(desired_state_path)
        .map_err(|error| format!("read desired state for start barrier: {error}"))?;
    let actual_desired_sha256 = sha256_hex(&desired_bytes);
    if actual_desired_sha256 != expected_desired_state_sha256 {
        return Err("start barrier desired-state digest mismatch".to_string());
    }
    let desired: DesiredStateStartView = serde_json::from_slice(&desired_bytes)
        .map_err(|error| format!("parse desired state for start barrier: {error}"))?;
    if desired.chain.validator_set_root.is_empty() {
        return Err("start barrier desired state has an invalid validator authority".to_string());
    }
    if desired.state.consensus_schema_version
        != crate::synergy_types::TESTNET_V3_CONSENSUS_STATE_SCHEMA_VERSION
        || desired.state.directory_namespace != "chain-1266/incarnation-4"
    {
        return Err("start barrier desired state has an invalid P1 state namespace".to_string());
    }
    crate::desired_state::validate_chain1266_p1_consensus_binding(
        &desired.state.mode,
        &desired.state.coordinator_id,
        &desired.state.producer_ids,
        desired.state.producer_turn_timeout_ms,
    )
    .map_err(|error| format!("start barrier desired state: {error}"))?;
    let command: SignedChain1266StartCommand = serde_json::from_slice(
        &fs::read(command_path)
            .map_err(|error| format!("read signed consensus start command: {error}"))?,
    )
    .map_err(|error| format!("parse signed consensus start command: {error}"))?;
    let request = &command.request;
    if request.schema_version != 1
        || request.action != "START_CONSENSUS"
        || request.release_id != desired.release_id
        || request.chain_id != desired.chain.chain_id
        || request.chain_incarnation != desired.chain.incarnation
        || request.genesis_hash != desired.chain.genesis_hash
        || request.desired_state_sha256 != actual_desired_sha256
        || request.signature_algorithm != "ML-DSA-87"
        || request.signature_domain != CHAIN1266_START_SIGNATURE_DOMAIN
        || request.authority_public_key_fingerprint
            != desired.start_authority.public_key_fingerprint
        || desired.start_authority.signature_algorithm != "ML-DSA-87"
        || desired.start_authority.signature_domain != CHAIN1266_START_SIGNATURE_DOMAIN
    {
        return Err("signed consensus start command disagrees with desired state".to_string());
    }
    let public_key = general_purpose::STANDARD
        .decode(&desired.start_authority.public_key_base64)
        .map_err(|error| format!("decode consensus start public key: {error}"))?;
    if public_key.len() != 2_592
        || format!("sha256:{}", sha256_hex(&public_key))
            != desired.start_authority.public_key_fingerprint
    {
        return Err("consensus start public key is invalid".to_string());
    }
    let signature = general_purpose::STANDARD
        .decode(&command.signature_base64)
        .map_err(|error| format!("decode consensus start signature: {error}"))?;
    let canonical = serde_json::to_vec(request)
        .map_err(|error| format!("encode canonical consensus start request: {error}"))?;
    let verified = Sign::mldsa87()
        .verify_ctx(
            &canonical,
            &signature,
            &public_key,
            CHAIN1266_START_SIGNATURE_DOMAIN.as_bytes(),
        )
        .map_err(|error| format!("verify ML-DSA-87 consensus start command: {error}"))?;
    if !verified {
        return Err("ML-DSA-87 consensus start command verification failed".to_string());
    }
    Ok(command.request)
}
