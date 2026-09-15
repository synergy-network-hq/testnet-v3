use std::collections::BTreeSet;

use super::EnrollmentRequest;

pub trait EnrollmentSignatureVerifier {
    fn verify(
        &self,
        identity: &str,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String>;
}

pub fn verify_enrollment_proof(
    request: &EnrollmentRequest,
    now: u64,
    eligible_identities: &BTreeSet<String>,
    verifier: &impl EnrollmentSignatureVerifier,
) -> Result<(), String> {
    request.validate_shape(now)?;
    if !eligible_identities.contains(&request.identity) {
        return Err("identity is not eligible for VPN enrollment".into());
    }
    verifier.verify(
        &request.identity,
        &request.consensus_key_id,
        &request.unsigned_bytes(),
        &request.signature,
    )
}
