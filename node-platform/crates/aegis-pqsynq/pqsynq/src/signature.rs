//! Signature verification dispatch for SynQ policy envelopes.

use crate::{
    algorithms::AlgorithmId,
    error::AegisSynQError,
    keys::{SynQPublicKey, SynQSignature},
    traits::DigitalSignature,
    Sign,
};

pub fn verify_signature(
    algorithm: AlgorithmId,
    message: &[u8],
    signature: &SynQSignature,
    public_key: &SynQPublicKey,
) -> Result<(), AegisSynQError> {
    // ML-DSA-87 is the governed account domain (transactions, deploys, calls);
    // ML-DSA-65 is the consensus domain. Only ML-DSA-65 was implemented here
    // until 2026-07-27, so every ML-DSA-87 envelope failed with
    // `UnsupportedAlgorithm` regardless of policy — the enum variant existed but
    // had no verification arm. Admissibility is decided by
    // `SynQSecurityPolicy`, not by which arms exist here, so both are
    // implemented and the policy does the gating.
    let valid = match algorithm {
        AlgorithmId::MlDsa87 => verify_with(Sign::mldsa87(), message, signature, public_key)?,
        AlgorithmId::MlDsa65 => verify_with(Sign::mldsa65(), message, signature, public_key)?,
        _ => return Err(AegisSynQError::UnsupportedAlgorithm),
    };

    if valid {
        Ok(())
    } else {
        Err(AegisSynQError::InvalidSignature)
    }
}

/// Size-checks the key and signature against the concrete signer, then verifies.
///
/// The length checks are what stop a short or oversized key from reaching the
/// backend, so they must run for every algorithm rather than only ML-DSA-65.
fn verify_with(
    signer: Sign,
    message: &[u8],
    signature: &SynQSignature,
    public_key: &SynQPublicKey,
) -> Result<bool, AegisSynQError> {
    if public_key.bytes.len() != signer.public_key_size() {
        return Err(AegisSynQError::MalformedPublicKey);
    }
    if signature.bytes.len() != signer.signature_size() {
        return Err(AegisSynQError::MalformedSignature);
    }
    signer
        .verify(message, &signature.bytes, &public_key.bytes)
        .map_err(|_| AegisSynQError::MalformedSignature)
}
