//! Synergy Genesis Format (SGEN) v1.
//!
//! This is the one runtime Genesis artifact for a clean Testnet-v3 node.  The
//! outer file is deliberately not a generic serialization container:
//!
//! ```text
//! header = magic[4] "SGEN" || version:u16-le || encoding:u8 || algorithm:u8
//!        || payload_length:u32-le || payload_digest[32] || signature_count:u8
//! payload = fixed-order SGEN-v1 fields below
//! signatures = signature_count * (role:u8 || signature_length:u16-le || signature)
//! ```
//!
//! Integers are little-endian. Strings and byte arrays are prefixed by a
//! little-endian `u32` byte length. Collections are prefixed by a `u32` item
//! count. Strings are UTF-8. Authority signatures are ordered deployer,
//! governance, then validator-registry. The decoder accepts no unknown
//! versions, no oversized field, no duplicate role, and no trailing byte.
//!
//! SGEN v1 carries the legacy document only as canonical, internally decoded
//! source material while the runtime completes its typed migration. It is
//! never an operator-visible runtime input and its signed H0 operations are
//! removed from that document and carried by the dedicated `h0_operations`
//! collection below. Thus a node needs only `genesis.sgen`, not JSON or a
//! replay sidecar. The explicit fields are independently checked against the
//! reconstructed document so the binary payload, not JSON formatting, is the
//! canonical authority boundary.

use crate::genesis::recompute_testnet_v3_candidate_integrity;
use crate::genesis_deployment::GenesisReplayOperation;
use pqsynq::Sign;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub const SGEN_MAGIC: [u8; 4] = *b"SGEN";
pub const SGEN_VERSION: u16 = 1;
pub const SGEN_PAYLOAD_ENCODING_BORSH_LE: u8 = 1;
pub const SGEN_SIGNATURE_ALGORITHM_MLDSA87: u8 = 1;
pub const SGEN_PAYLOAD_HASH_DOMAIN: &[u8] = b"SYNERGY_SGEN_V1_PAYLOAD_HASH";
pub const SGEN_AUTHORITY_SIGNATURE_DOMAIN: &[u8] = b"SYNERGY_SGEN_V1_AUTHORITY_APPROVAL";

const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = 48 * 1024 * 1024;
const MAX_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;
const MAX_OPERATION_BYTES: usize = 2 * 1024 * 1024;
const MAX_STRING_BYTES: usize = 16 * 1024;
const MAX_SIGNATURE_BYTES: usize = 8 * 1024;
const H0_OPERATION_COUNT: usize = 36;
const DEPLOYMENT_COUNT: usize = 9;
const INITIALIZATION_COUNT: usize = 27;

const DEPLOYER_ROLE: &str = "SNRG-TESTNET-V3-GENESIS-DEPLOYER";
const GOVERNANCE_ROLE: &str = "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY";
const REGISTRY_ROLE: &str = "SNRG-TESTNET-V3-VALIDATOR-REGISTRY-AUTHORITY";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgenAuthoritySigner {
    pub role: String,
    pub identity_address: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgenAuthorityPublic {
    pub role: String,
    pub identity_address: String,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgenSignature {
    pub role: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgenHeader {
    pub payload_length: u32,
    pub payload_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SgenPayloadV1 {
    pub chain_id: u64,
    pub network_id: String,
    pub release_id: String,
    pub protocol_version: String,
    pub consensus_version: String,
    pub activation_timestamp: u64,
    pub target_block_time_ms: u64,
    pub parameter_root: String,
    pub membership_root: String,
    pub expected_execution_state_root: String,
    pub expected_aivm_state_root: String,
    pub expected_receipt_root: String,
    /// Canonical JSON source with `signed_replay_operations` removed. This is
    /// internal migration material, not a separately supplied runtime file.
    pub legacy_document: Vec<u8>,
    /// Exact canonical JSON encodings of the 36 already-signed SynQ envelopes.
    pub h0_operations: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct VerifiedSgen {
    pub header: SgenHeader,
    pub payload: SgenPayloadV1,
    pub signatures: Vec<SgenSignature>,
    pub genesis_hash: String,
    pub reconstructed_document: Value,
}

pub fn payload_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SGEN_PAYLOAD_HASH_DOMAIN);
    hasher.update(payload);
    hasher.finalize().into()
}

fn signature_message(digest: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SGEN_AUTHORITY_SIGNATURE_DOMAIN.len() + digest.len());
    message.extend_from_slice(SGEN_AUTHORITY_SIGNATURE_DOMAIN);
    message.extend_from_slice(digest);
    message
}

pub fn compile_sgen(payload: SgenPayloadV1, signers: &[SgenAuthoritySigner]) -> Result<Vec<u8>, String> {
    validate_payload_shape(&payload)?;
    let payload_bytes = encode_payload(&payload)?;
    let digest = payload_digest(&payload_bytes);
    let canonical = canonical_testnet_authorities()?;
    let mut signer_by_role = BTreeMap::new();
    for signer in signers {
        if signer_by_role.insert(signer.role.as_str(), signer).is_some() {
            return Err("SGEN authority signer roles must be unique".to_string());
        }
    }
    let message = signature_message(&digest);
    let mut signatures = Vec::with_capacity(3);
    for expected in canonical.values() {
        let signer = signer_by_role
            .get(expected.role.as_str())
            .ok_or_else(|| format!("SGEN ceremony is missing {}", expected.role))?;
        if signer.identity_address != expected.identity_address || signer.public_key != expected.public_key {
            return Err(format!("SGEN signer does not match frozen authority {}", expected.role));
        }
        let signature = Sign::mldsa87()
            .sign_ctx(&message, &signer.private_key, SGEN_AUTHORITY_SIGNATURE_DOMAIN)
            .map_err(|error| format!("SGEN {} signature failed: {error}", expected.role))?;
        if signature.len() > MAX_SIGNATURE_BYTES {
            return Err("SGEN ML-DSA-87 signature exceeds its bounded encoding".to_string());
        }
        signatures.push(SgenSignature { role: expected.role.clone(), signature });
    }
    encode_file(&payload_bytes, digest, &signatures)
}

pub fn verify_sgen_file(path: impl AsRef<Path>) -> Result<VerifiedSgen, String> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|error| format!("read SGEN {}: {error}", path.display()))?;
    verify_sgen_bytes(&bytes)
}

pub fn verify_sgen_bytes(bytes: &[u8]) -> Result<VerifiedSgen, String> {
    let authorities = canonical_testnet_authorities()?;
    verify_sgen_bytes_against(bytes, &authorities)
}

fn verify_sgen_bytes_against(
    bytes: &[u8],
    authorities: &BTreeMap<String, SgenAuthorityPublic>,
) -> Result<VerifiedSgen, String> {
    if bytes.len() > MAX_FILE_BYTES { return Err("SGEN exceeds the v1 file limit".to_string()); }
    let mut decoder = Decoder::new(bytes);
    if decoder.take_exact(4)? != SGEN_MAGIC { return Err("SGEN magic is invalid".to_string()); }
    if decoder.u16()? != SGEN_VERSION { return Err("SGEN format version is unsupported".to_string()); }
    if decoder.u8()? != SGEN_PAYLOAD_ENCODING_BORSH_LE { return Err("SGEN payload encoding is unsupported".to_string()); }
    if decoder.u8()? != SGEN_SIGNATURE_ALGORITHM_MLDSA87 { return Err("SGEN authority signature algorithm is unsupported".to_string()); }
    let length = decoder.u32()? as usize;
    if length == 0 || length > MAX_PAYLOAD_BYTES { return Err("SGEN payload length is invalid".to_string()); }
    let digest = decoder.array_32()?;
    let signature_count = decoder.u8()? as usize;
    if signature_count != 3 { return Err("SGEN v1 requires exactly three authority signatures".to_string()); }
    let payload_bytes = decoder.take_exact(length)?.to_vec();
    if payload_digest(&payload_bytes) != digest { return Err("SGEN payload digest does not match its canonical bytes".to_string()); }
    let payload = decode_payload(&payload_bytes)?;
    validate_payload_shape(&payload)?;
    let message = signature_message(&digest);
    let mut seen = BTreeSet::new();
    let mut signatures = Vec::with_capacity(3);
    for _ in 0..signature_count {
        let role = role_from_code(decoder.u8()?)?.to_string();
        if !seen.insert(role.clone()) { return Err("SGEN contains duplicate authority signatures".to_string()); }
        let signature = decoder.bytes_u16(MAX_SIGNATURE_BYTES)?;
        let authority = authorities.get(&role).ok_or_else(|| "SGEN signature has an unknown authority role".to_string())?;
        let valid = Sign::mldsa87()
            .verify_ctx(&message, &signature, &authority.public_key, SGEN_AUTHORITY_SIGNATURE_DOMAIN)
            .map_err(|error| format!("SGEN {role} signature is malformed: {error}"))?;
        if !valid { return Err(format!("SGEN {role} authority signature is invalid")); }
        signatures.push(SgenSignature { role, signature });
    }
    if !decoder.is_empty() { return Err("SGEN contains unexpected trailing data".to_string()); }
    let reconstructed_document = reconstruct_document(&payload)?;
    validate_document_binding(&payload, &reconstructed_document)?;
    Ok(VerifiedSgen { header: SgenHeader { payload_length: length as u32, payload_digest: digest }, payload, signatures, genesis_hash: hex::encode(digest), reconstructed_document })
}

pub fn payload_from_finalized_document(value: &Value) -> Result<SgenPayloadV1, String> {
    let deployment = value.get("genesis_deployment").and_then(Value::as_object)
        .ok_or_else(|| "SGEN requires finalized genesis_deployment".to_string())?;
    let operations = deployment.get("signed_replay_operations").and_then(Value::as_array)
        .ok_or_else(|| "SGEN requires embedded signed H0 operations".to_string())?;
    if operations.len() != H0_OPERATION_COUNT { return Err(format!("SGEN requires exactly {H0_OPERATION_COUNT} H0 operations")); }
    let mut operation_bytes = Vec::with_capacity(operations.len());
    for operation in operations {
        let parsed: GenesisReplayOperation = serde_json::from_value(operation.clone())
            .map_err(|error| format!("SGEN H0 operation is malformed: {error}"))?;
        let canonical = canonical_json(&serde_json::to_value(parsed).map_err(|error| format!("canonicalize SGEN H0 operation: {error}"))?);
        if canonical.len() > MAX_OPERATION_BYTES { return Err("SGEN H0 operation exceeds v1 size limit".to_string()); }
        operation_bytes.push(canonical.into_bytes());
    }
    let mut legacy = value.clone();
    let deployment = legacy.get_mut("genesis_deployment").and_then(Value::as_object_mut)
        .ok_or_else(|| "SGEN cannot remove missing signed H0 operation field".to_string())?;
    deployment.remove("signed_replay_operations");
    // These historical records are audit evidence, not inputs to H0. SGEN
    // carries the actual operations and receipts, so a clean node neither
    // restores a snapshot nor follows a reference to an evidence sidecar.
    for field in [
        "execution_state",
        "execution_status_sha256",
        "execution_state_snapshot_sha256",
        "execution_state_snapshot_canonical_sha256",
        "signed_replay_operations_sha256",
        "deployment_receipts_sha256",
        "initialization_receipts_sha256",
        "authority_record_sha256",
        "contract_derivation_record_sha256",
    ] { deployment.remove(field); }
    recompute_testnet_v3_candidate_integrity(&mut legacy)
        .map_err(|error| format!("recompute snapshot-free SGEN legacy bindings: {error}"))?;
    let legacy_document = canonical_json(&legacy).into_bytes();
    let payload = SgenPayloadV1 {
        chain_id: required_u64(value, "/network/chain_id")?,
        network_id: required_string(value, "/network/network_id")?,
        release_id: required_string(value, "/network/release_id")?,
        protocol_version: required_string(value, "/network/protocol_version")?,
        consensus_version: required_string(value, "/network/consensus_version")?,
        activation_timestamp: required_u64(value, "/header/timestamp")?,
        target_block_time_ms: required_u64(value, "/consensus/target_block_time_ms")?,
        parameter_root: required_string(value, "/integrity/consensus_parameter_root_sha3_512")?,
        membership_root: membership_root(value)?,
        expected_execution_state_root: required_string(value, "/genesis_deployment/post_deployment_execution_state_root")?,
        expected_aivm_state_root: required_string(value, "/genesis_deployment/post_deployment_aivm_state_root")?,
        expected_receipt_root: required_string(value, "/genesis_deployment/receipt_root")?,
        legacy_document,
        h0_operations: operation_bytes,
    };
    validate_payload_shape(&payload)?;
    Ok(payload)
}

fn encode_file(payload: &[u8], digest: [u8; 32], signatures: &[SgenSignature]) -> Result<Vec<u8>, String> {
    if payload.len() > MAX_PAYLOAD_BYTES || signatures.len() != 3 { return Err("invalid SGEN framing".to_string()); }
    let mut out = Vec::with_capacity(44 + payload.len() + signatures.iter().map(|entry| entry.signature.len() + 3).sum::<usize>());
    out.extend_from_slice(&SGEN_MAGIC);
    out.extend_from_slice(&SGEN_VERSION.to_le_bytes());
    out.push(SGEN_PAYLOAD_ENCODING_BORSH_LE);
    out.push(SGEN_SIGNATURE_ALGORITHM_MLDSA87);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&digest);
    out.push(signatures.len() as u8);
    out.extend_from_slice(payload);
    let mut expected = 1u8;
    for signature in signatures {
        let code = role_code(&signature.role)?;
        if code != expected { return Err("SGEN authority signatures are not in canonical order".to_string()); }
        expected += 1;
        if signature.signature.is_empty() || signature.signature.len() > MAX_SIGNATURE_BYTES { return Err("SGEN signature length is invalid".to_string()); }
        out.push(code);
        out.extend_from_slice(&(signature.signature.len() as u16).to_le_bytes());
        out.extend_from_slice(&signature.signature);
    }
    Ok(out)
}

fn encode_payload(payload: &SgenPayloadV1) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(&payload.chain_id.to_le_bytes());
    push_string(&mut out, &payload.network_id)?;
    push_string(&mut out, &payload.release_id)?;
    push_string(&mut out, &payload.protocol_version)?;
    push_string(&mut out, &payload.consensus_version)?;
    out.extend_from_slice(&payload.activation_timestamp.to_le_bytes());
    out.extend_from_slice(&payload.target_block_time_ms.to_le_bytes());
    push_string(&mut out, &payload.parameter_root)?;
    push_string(&mut out, &payload.membership_root)?;
    push_string(&mut out, &payload.expected_execution_state_root)?;
    push_string(&mut out, &payload.expected_aivm_state_root)?;
    push_string(&mut out, &payload.expected_receipt_root)?;
    push_bytes_u32(&mut out, &payload.legacy_document, MAX_DOCUMENT_BYTES)?;
    out.extend_from_slice(&(payload.h0_operations.len() as u32).to_le_bytes());
    for operation in &payload.h0_operations { push_bytes_u32(&mut out, operation, MAX_OPERATION_BYTES)?; }
    Ok(out)
}

fn decode_payload(bytes: &[u8]) -> Result<SgenPayloadV1, String> {
    let mut decoder = Decoder::new(bytes);
    let payload = SgenPayloadV1 {
        chain_id: decoder.u64()?,
        network_id: decoder.string(MAX_STRING_BYTES)?,
        release_id: decoder.string(MAX_STRING_BYTES)?,
        protocol_version: decoder.string(MAX_STRING_BYTES)?,
        consensus_version: decoder.string(MAX_STRING_BYTES)?,
        activation_timestamp: decoder.u64()?,
        target_block_time_ms: decoder.u64()?,
        parameter_root: decoder.string(MAX_STRING_BYTES)?,
        membership_root: decoder.string(MAX_STRING_BYTES)?,
        expected_execution_state_root: decoder.string(MAX_STRING_BYTES)?,
        expected_aivm_state_root: decoder.string(MAX_STRING_BYTES)?,
        expected_receipt_root: decoder.string(MAX_STRING_BYTES)?,
        legacy_document: decoder.bytes_u32(MAX_DOCUMENT_BYTES)?,
        h0_operations: {
            let count = decoder.u32()? as usize;
            if count != H0_OPERATION_COUNT { return Err("SGEN H0 operation count is invalid".to_string()); }
            let mut operations = Vec::with_capacity(count);
            for _ in 0..count { operations.push(decoder.bytes_u32(MAX_OPERATION_BYTES)?); }
            operations
        },
    };
    if !decoder.is_empty() { return Err("SGEN payload contains trailing data".to_string()); }
    Ok(payload)
}

fn reconstruct_document(payload: &SgenPayloadV1) -> Result<Value, String> {
    let mut document: Value = serde_json::from_slice(&payload.legacy_document)
        .map_err(|error| format!("SGEN internal document is invalid: {error}"))?;
    if canonical_json(&document).as_bytes() != payload.legacy_document.as_slice() { return Err("SGEN internal document is not canonical".to_string()); }
    let mut operations = Vec::with_capacity(H0_OPERATION_COUNT);
    for (index, bytes) in payload.h0_operations.iter().enumerate() {
        let value: Value = serde_json::from_slice(bytes).map_err(|error| format!("SGEN H0 operation {index} is invalid: {error}"))?;
        if canonical_json(&value).as_bytes() != bytes.as_slice() { return Err(format!("SGEN H0 operation {index} is not canonical")); }
        let operation: GenesisReplayOperation = serde_json::from_value(value.clone())
            .map_err(|error| format!("SGEN H0 operation {index} is malformed: {error}"))?;
        if operation.sequence != index as u64 { return Err("SGEN H0 operation sequence is non-canonical".to_string()); }
        operations.push(value);
    }
    let deployment = document.get_mut("genesis_deployment").and_then(Value::as_object_mut)
        .ok_or_else(|| "SGEN internal document lacks genesis_deployment".to_string())?;
    if deployment.contains_key("signed_replay_operations") { return Err("SGEN internal document duplicates H0 operations".to_string()); }
    deployment.insert("signed_replay_operations".to_string(), Value::Array(operations));
    Ok(document)
}

fn validate_payload_shape(payload: &SgenPayloadV1) -> Result<(), String> {
    if payload.chain_id != 1266 || payload.network_id != "testnet" || payload.release_id != "testnet-v3" { return Err("SGEN has the wrong Chain 1266 / testnet identity".to_string()); }
    if payload.protocol_version != "1.0.0" || payload.consensus_version != "posy/3.0" { return Err("SGEN has an unsupported protocol version".to_string()); }
    if !(100..=1100).contains(&payload.target_block_time_ms) { return Err("SGEN target block time is outside the allowed range".to_string()); }
    if payload.legacy_document.is_empty() || payload.legacy_document.len() > MAX_DOCUMENT_BYTES { return Err("SGEN internal document length is invalid".to_string()); }
    if payload.h0_operations.len() != H0_OPERATION_COUNT { return Err("SGEN must contain exactly 36 H0 operations".to_string()); }
    for value in [&payload.parameter_root, &payload.membership_root, &payload.expected_execution_state_root, &payload.expected_aivm_state_root, &payload.expected_receipt_root] {
        if !is_lower_hex(value, 64) { return Err("SGEN contains a non-canonical root".to_string()); }
    }
    Ok(())
}

fn validate_document_binding(payload: &SgenPayloadV1, document: &Value) -> Result<(), String> {
    if required_u64(document, "/network/chain_id")? != payload.chain_id
        || required_string(document, "/network/network_id")? != payload.network_id
        || required_string(document, "/network/release_id")? != payload.release_id
        || required_string(document, "/network/protocol_version")? != payload.protocol_version
        || required_string(document, "/network/consensus_version")? != payload.consensus_version
        || required_u64(document, "/header/timestamp")? != payload.activation_timestamp
        || required_u64(document, "/consensus/target_block_time_ms")? != payload.target_block_time_ms
        || required_string(document, "/integrity/consensus_parameter_root_sha3_512")? != payload.parameter_root
        || membership_root(document)? != payload.membership_root
        || required_string(document, "/genesis_deployment/post_deployment_execution_state_root")? != payload.expected_execution_state_root
        || required_string(document, "/genesis_deployment/post_deployment_aivm_state_root")? != payload.expected_aivm_state_root
        || required_string(document, "/genesis_deployment/receipt_root")? != payload.expected_receipt_root
    { return Err("SGEN typed payload fields disagree with its internal Genesis document".to_string()); }
    let validators = document.get("validators").and_then(Value::as_array).ok_or_else(|| "SGEN Genesis validators are missing".to_string())?;
    let mut identities = BTreeSet::new();
    for validator in validators {
        let identity = validator.get("validator_id").and_then(Value::as_str).ok_or_else(|| "SGEN validator identity is missing".to_string())?;
        if !identities.insert(identity) { return Err("SGEN contains duplicate validator identity".to_string()); }
    }
    if validators.is_empty() { return Err("SGEN validator set is empty".to_string()); }
    let operations = document.pointer("/genesis_deployment/signed_replay_operations").and_then(Value::as_array).ok_or_else(|| "SGEN H0 operations are missing".to_string())?;
    if operations.len() != H0_OPERATION_COUNT { return Err("SGEN H0 operation count is invalid".to_string()); }
    let deployment_count = operations.iter().filter(|entry| entry.get("kind").and_then(Value::as_str) == Some("Deploy")).count();
    let initialization_count = operations.iter().filter(|entry| entry.get("kind").and_then(Value::as_str) == Some("Call")).count();
    if deployment_count != DEPLOYMENT_COUNT || initialization_count != INITIALIZATION_COUNT { return Err("SGEN H0 operation semantics are invalid".to_string()); }
    Ok(())
}

fn canonical_testnet_authorities() -> Result<BTreeMap<String, SgenAuthorityPublic>, String> {
    let value: Value = serde_json::from_str(include_str!("../../launch/posy-v3-genesis-inputs/fresh-genesis-authority-freeze.json"))
        .map_err(|error| format!("parse built-in Testnet-v3 authority freeze: {error}"))?;
    let entries = value.get("authorities").and_then(Value::as_array).ok_or_else(|| "built-in authority freeze is malformed".to_string())?;
    let mut result = BTreeMap::new();
    for role in [DEPLOYER_ROLE, GOVERNANCE_ROLE, REGISTRY_ROLE] {
        let entry = entries.iter().find(|entry| entry.get("role_id").and_then(Value::as_str) == Some(role)).ok_or_else(|| "built-in authority role is missing".to_string())?;
        let identity_address = entry.get("identity_address").and_then(Value::as_str).ok_or_else(|| "built-in authority identity is missing".to_string())?.to_string();
        let public_key = entry.pointer("/authorization_public/public_key").and_then(Value::as_str).ok_or_else(|| "built-in authority public key is missing".to_string())?;
        let public_key = hex::decode(public_key).map_err(|_| "built-in authority public key is invalid".to_string())?;
        if public_key.len() != 2592 { return Err("built-in authority public key is not ML-DSA-87".to_string()); }
        result.insert(role.to_string(), SgenAuthorityPublic { role: role.to_string(), identity_address, public_key });
    }
    Ok(result)
}

fn role_code(role: &str) -> Result<u8, String> { match role { DEPLOYER_ROLE => Ok(1), GOVERNANCE_ROLE => Ok(2), REGISTRY_ROLE => Ok(3), _ => Err("unknown SGEN authority role".to_string()) } }
fn role_from_code(code: u8) -> Result<&'static str, String> { match code { 1 => Ok(DEPLOYER_ROLE), 2 => Ok(GOVERNANCE_ROLE), 3 => Ok(REGISTRY_ROLE), _ => Err("unknown SGEN authority role code".to_string()) } }
fn push_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> { push_bytes_u32(out, value.as_bytes(), MAX_STRING_BYTES) }
fn push_bytes_u32(out: &mut Vec<u8>, value: &[u8], max: usize) -> Result<(), String> { if value.len() > max { return Err("SGEN field exceeds its v1 bound".to_string()); } out.extend_from_slice(&(value.len() as u32).to_le_bytes()); out.extend_from_slice(value); Ok(()) }
fn required_u64(value: &Value, pointer: &str) -> Result<u64, String> { value.pointer(pointer).and_then(Value::as_u64).ok_or_else(|| format!("SGEN document is missing {pointer}")) }
fn required_string(value: &Value, pointer: &str) -> Result<String, String> { value.pointer(pointer).and_then(Value::as_str).map(str::to_string).ok_or_else(|| format!("SGEN document is missing {pointer}")) }
fn membership_root(value: &Value) -> Result<String, String> { value.pointer("/etdag_membership_anchor/membership_root_sha3_512").or_else(|| value.pointer("/etdag_membership_anchor/root")).or_else(|| value.pointer("/integrity/etdag_membership_root_sha3_512")).and_then(Value::as_str).map(str::to_string).ok_or_else(|| "SGEN document is missing the ETDAG membership root".to_string()) }
fn is_lower_hex(value: &str, length: usize) -> bool { value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) }

fn canonical_json(value: &Value) -> String { match value { Value::Null => "null".to_string(), Value::Bool(entry) => entry.to_string(), Value::Number(entry) => entry.to_string(), Value::String(entry) => serde_json::to_string(entry).expect("JSON string serialization"), Value::Array(entries) => format!("[{}]", entries.iter().map(canonical_json).collect::<Vec<_>>().join(",")), Value::Object(entries) => { let mut keys = entries.keys().collect::<Vec<_>>(); keys.sort(); format!("{{{}}}", keys.into_iter().map(|key| format!("{}:{}", serde_json::to_string(key).expect("JSON key serialization"), canonical_json(&entries[key]))).collect::<Vec<_>>().join(",")) } } }

struct Decoder<'a> { bytes: &'a [u8], cursor: usize }
impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, cursor: 0 } }
    fn is_empty(&self) -> bool { self.cursor == self.bytes.len() }
    fn take_exact(&mut self, length: usize) -> Result<&'a [u8], String> { let end = self.cursor.checked_add(length).ok_or_else(|| "SGEN length overflow".to_string())?; let result = self.bytes.get(self.cursor..end).ok_or_else(|| "SGEN is truncated".to_string())?; self.cursor = end; Ok(result) }
    fn u8(&mut self) -> Result<u8, String> { Ok(self.take_exact(1)?[0]) }
    fn u16(&mut self) -> Result<u16, String> { Ok(u16::from_le_bytes(self.take_exact(2)?.try_into().expect("length checked"))) }
    fn u32(&mut self) -> Result<u32, String> { Ok(u32::from_le_bytes(self.take_exact(4)?.try_into().expect("length checked"))) }
    fn u64(&mut self) -> Result<u64, String> { Ok(u64::from_le_bytes(self.take_exact(8)?.try_into().expect("length checked"))) }
    fn array_32(&mut self) -> Result<[u8; 32], String> { Ok(self.take_exact(32)?.try_into().expect("length checked")) }
    fn bytes_u16(&mut self, max: usize) -> Result<Vec<u8>, String> { let length = self.u16()? as usize; if length == 0 || length > max { return Err("SGEN u16 field length is invalid".to_string()); } Ok(self.take_exact(length)?.to_vec()) }
    fn bytes_u32(&mut self, max: usize) -> Result<Vec<u8>, String> { let length = self.u32()? as usize; if length > max { return Err("SGEN u32 field length is invalid".to_string()); } Ok(self.take_exact(length)?.to_vec()) }
    fn string(&mut self, max: usize) -> Result<String, String> { let bytes = self.bytes_u32(max)?; let value = String::from_utf8(bytes).map_err(|_| "SGEN string is not UTF-8".to_string())?; if value.is_empty() { return Err("SGEN string is empty".to_string()); } Ok(value) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_pqvm::pqc::signatures::mldsa::mldsa87;
    use pqrust_traits::sign::{PublicKey as _, SecretKey as _};

    fn payload() -> SgenPayloadV1 { SgenPayloadV1 { chain_id: 1266, network_id: "testnet".to_string(), release_id: "testnet-v3".to_string(), protocol_version: "1.0.0".to_string(), consensus_version: "posy/3.0".to_string(), activation_timestamp: 1, target_block_time_ms: 500, parameter_root: "11".repeat(32), membership_root: "22".repeat(32), expected_execution_state_root: "33".repeat(32), expected_aivm_state_root: "44".repeat(32), expected_receipt_root: "55".repeat(32), legacy_document: br#"{}"#.to_vec(), h0_operations: vec![b"{}".to_vec(); H0_OPERATION_COUNT] } }

    #[test]
    fn payload_encoding_is_deterministic() {
        assert_eq!(encode_payload(&payload()).unwrap(), encode_payload(&payload()).unwrap());
    }

    #[test]
    fn decoder_rejects_magic_version_length_and_trailing_bytes() {
        let raw = encode_payload(&payload()).unwrap();
        let digest = payload_digest(&raw);
        let signatures = vec![SgenSignature { role: DEPLOYER_ROLE.to_string(), signature: vec![1] }, SgenSignature { role: GOVERNANCE_ROLE.to_string(), signature: vec![1] }, SgenSignature { role: REGISTRY_ROLE.to_string(), signature: vec![1] }];
        let encoded = encode_file(&raw, digest, &signatures).unwrap();
        let mut wrong_magic = encoded.clone(); wrong_magic[0] = b'X'; assert!(verify_sgen_bytes(&wrong_magic).unwrap_err().contains("magic"));
        let mut wrong_version = encoded.clone(); wrong_version[4] = 2; assert!(verify_sgen_bytes(&wrong_version).unwrap_err().contains("version"));
        let mut truncated = encoded.clone(); truncated.pop(); assert!(verify_sgen_bytes(&truncated).is_err());
        let mut corrupted = encoded.clone(); corrupted[16] ^= 1; assert!(verify_sgen_bytes(&corrupted).unwrap_err().contains("digest"));
        let mut trailing = encoded; trailing.push(0); assert!(verify_sgen_bytes(&trailing).is_err());
    }

    #[test]
    fn payload_rejects_wrong_chain_and_operation_count() {
        let mut wrong_chain = payload(); wrong_chain.chain_id = 1; assert!(validate_payload_shape(&wrong_chain).is_err());
        let mut wrong_operations = payload(); wrong_operations.h0_operations.pop(); assert!(validate_payload_shape(&wrong_operations).is_err());
    }

    #[test]
    fn signatures_are_domain_bound_and_wrong_authorities_fail_closed() {
        let raw = encode_payload(&payload()).unwrap();
        let digest = payload_digest(&raw);
        let message = signature_message(&digest);
        let mut authorities = BTreeMap::new();
        let mut signatures = Vec::new();
        for role in [DEPLOYER_ROLE, GOVERNANCE_ROLE, REGISTRY_ROLE] {
            let (public, secret) = mldsa87::keypair();
            let public_key = public.as_bytes().to_vec();
            let signature = Sign::mldsa87().sign_ctx(&message, secret.as_bytes(), SGEN_AUTHORITY_SIGNATURE_DOMAIN).unwrap();
            authorities.insert(role.to_string(), SgenAuthorityPublic { role: role.to_string(), identity_address: format!("test-{role}"), public_key });
            signatures.push(SgenSignature { role: role.to_string(), signature });
        }
        let encoded = encode_file(&raw, digest, &signatures).unwrap();
        // All three real test-domain signatures verify before the deliberately
        // minimal test document is rejected by semantic validation.
        let semantic_error = verify_sgen_bytes_against(&encoded, &authorities).unwrap_err();
        assert!(semantic_error.contains("document") || semantic_error.contains("Genesis") || semantic_error.contains("operation"), "{semantic_error}");

        let mut tampered = encoded.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(verify_sgen_bytes_against(&tampered, &authorities).unwrap_err().contains("signature"));

        let (wrong_public, _) = mldsa87::keypair();
        authorities.get_mut(REGISTRY_ROLE).unwrap().public_key = wrong_public.as_bytes().to_vec();
        assert!(verify_sgen_bytes_against(&encoded, &authorities).unwrap_err().contains("signature"));
    }
}
