use std::collections::BTreeSet;

use crate::SignedTransportLease;

pub trait LeaseSignatureVerifier {
    fn verify(
        &self,
        authority_id: &str,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String>;
}

pub fn verify_transport_lease(
    lease: &SignedTransportLease,
    now: u64,
    authorities: &BTreeSet<String>,
    verifier: &impl LeaseSignatureVerifier,
) -> Result<(), String> {
    lease
        .validate_shape(now)
        .map_err(|error| format!("invalid transport lease: {error:?}"))?;
    if !authorities.contains(&lease.authority_id) {
        return Err("untrusted transport lease authority".into());
    }
    verifier.verify(
        &lease.authority_id,
        &lease.key_id,
        &lease.unsigned_bytes(),
        &lease.signature,
    )
}
