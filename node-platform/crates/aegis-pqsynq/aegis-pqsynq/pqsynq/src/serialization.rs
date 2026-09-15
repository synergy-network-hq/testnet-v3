//! Canonical binary serialization for SynQ signing payloads.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::{error::AegisSynQError, payload::SynQSigningPayload};

pub fn canonicalize_signing_payload(
    payload: &SynQSigningPayload,
) -> Result<Vec<u8>, AegisSynQError> {
    let network = payload.network_id.as_str().as_bytes();
    let signer = payload.signer_address.as_bytes();
    if network.len() > u16::MAX as usize || signer.len() > u16::MAX as usize {
        return Err(AegisSynQError::NonCanonicalPayload);
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"SQSP");
    push_u16(&mut out, 1);
    push_u16(&mut out, payload.domain_tag.code());
    push_u64(&mut out, payload.chain_id.0);
    push_u16(&mut out, network.len() as u16);
    out.extend_from_slice(network);
    push_u16(&mut out, payload.protocol_version);
    push_u16(&mut out, payload.algorithm_id.code());
    push_u16(&mut out, payload.signature_purpose.code());
    push_u64(&mut out, payload.nonce);
    push_u64(&mut out, payload.not_before_unix);
    push_u64(&mut out, payload.expiration_unix);
    push_u16(&mut out, signer.len() as u16);
    out.extend_from_slice(signer);
    out.extend_from_slice(&payload.payload_hash);
    Ok(out)
}

pub fn hash_signing_payload(payload: &SynQSigningPayload) -> Result<[u8; 32], AegisSynQError> {
    let canonical = canonicalize_signing_payload(payload)?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(finalize_hash(hasher))
}

pub fn hash_contract_deploy_body(
    bytecode_hash: &[u8; 32],
    manifest_hash: &[u8; 32],
    abi_hash: &[u8; 32],
    deployer: &[u8],
    constructor_args_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytecode_hash);
    hasher.update(manifest_hash);
    hasher.update(abi_hash);
    hasher.update(deployer);
    hasher.update(constructor_args_hash);
    finalize_hash(hasher)
}

pub fn hash_contract_call_body(
    contract_address: &[u8],
    method_selector: &[u8; 4],
    encoded_args_hash: &[u8; 32],
    caller: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(contract_address);
    hasher.update(method_selector);
    hasher.update(encoded_args_hash);
    hasher.update(caller);
    finalize_hash(hasher)
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn finalize_hash(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}
