//! Strict canonicalization for `DesiredStateV2`.
//!
//! Signing an arbitrary supplied JSON document is unsafe: two textual encodings
//! of the same logical state would produce two different signatures, and a
//! verifier that signs "whatever bytes arrived" cannot detect that. So the
//! canonical form is defined by RECONSTRUCTION, not by the input text:
//!
//!   1. strictly parse the supplied bytes
//!   2. re-serialize from the parsed value
//!   3. require the supplied bytes to be byte-identical to the reconstruction
//!   4. only then verify the signature over the domain-separated canonical bytes
//!
//! `serde_json` emits struct fields in declaration order with no whitespace and
//! no map reordering ambiguity (DesiredStateV2 contains no maps), so the
//! reconstruction is deterministic. The golden-vector tests pin that property
//! so a future field reorder or serializer change fails loudly instead of
//! silently invalidating previously signed artifacts.

use crate::desired_state_v2::{
    canonical_signing_payload, DesiredStateV2, SignedDesiredStateV2,
    CHAIN1266_START_SIGNATURE_DOMAIN_V2, START_AUTHORIZATION_ALGORITHM,
};
use crate::synergy_types::Hash;

pub const CANONICAL_DIGEST_DOMAIN: &str = "SYNERGY_CHAIN1266_DESIRED_STATE_V2_CANONICAL";

/// Canonical bytes for a value already in memory.
pub fn canonical_bytes(state: &DesiredStateV2) -> Result<Vec<u8>, String> {
    serde_json::to_vec(state)
        .map_err(|error| format!("canonicalize desired state v2: {error}"))
}

/// Stable digest over the canonical bytes.
pub fn canonical_digest(state: &DesiredStateV2) -> Result<Hash, String> {
    Ok(Hash::from_domain_bytes(
        CANONICAL_DIGEST_DOMAIN,
        &canonical_bytes(state)?,
    ))
}

/// Strictly parses supplied bytes and REQUIRES them to already be canonical.
/// This is the only entry point that should ever touch on-disk or transmitted
/// desired-state documents.
pub fn parse_strict_canonical(supplied: &[u8]) -> Result<DesiredStateV2, String> {
    let parsed: DesiredStateV2 = serde_json::from_slice(supplied)
        .map_err(|error| format!("strict parse of desired state v2 failed: {error}"))?;
    let reconstructed = canonical_bytes(&parsed)?;
    if supplied != reconstructed.as_slice() {
        return Err(format!(
            "desired state v2 is not in canonical form: supplied {} bytes, canonical form is {} \
             bytes; re-serialize the document before signing or verifying",
            supplied.len(),
            reconstructed.len()
        ));
    }
    parsed.validate()?;
    Ok(parsed)
}

/// Everything a verifier must check before trusting an activation artifact.
pub fn verify_canonical_and_signature(
    supplied_desired_state_bytes: &[u8],
    signed: &SignedDesiredStateV2,
    verify_signature: impl FnOnce(&[u8], &[u8]) -> Result<bool, String>,
    signature_bytes: &[u8],
) -> Result<DesiredStateV2, String> {
    let canonical = parse_strict_canonical(supplied_desired_state_bytes)?;

    // The parsed document must be the same state the envelope claims.
    if canonical != signed.desired_state {
        return Err(
            "supplied desired-state document does not match the signed envelope".to_string(),
        );
    }
    if signed.signature_algorithm != START_AUTHORIZATION_ALGORITHM {
        return Err(format!(
            "start authorization must be {START_AUTHORIZATION_ALGORITHM}"
        ));
    }
    if signed.signature_domain != CHAIN1266_START_SIGNATURE_DOMAIN_V2 {
        return Err("start authorization domain is not the V2 domain".to_string());
    }

    let payload = canonical_signing_payload(&canonical)?;
    if !verify_signature(&payload, signature_bytes)? {
        return Err("ML-DSA-87 start authorization signature verification failed".to_string());
    }
    Ok(canonical)
}
