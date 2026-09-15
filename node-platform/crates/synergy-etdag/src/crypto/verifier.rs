use serde::Serialize;

use crate::{EtdagDigest, EtdagError};

/// Verification is supplied by the node cryptography owner. ETDAG never infers
/// validator authority from a transport peer or process role.
pub trait SignatureVerifier {
    fn verify(
        &self,
        validator_id: &str,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), EtdagError>;
}

pub fn canonical_signing_bytes(
    domain: &str,
    value: &impl Serialize,
) -> Result<Vec<u8>, EtdagError> {
    let payload = serde_json::to_vec(value)
        .map_err(|error| EtdagError::Corrupt(format!("canonical signing payload: {error}")))?;
    let digest = EtdagDigest::from_domain_bytes(domain, &payload);
    Ok(digest.0.into_bytes())
}
