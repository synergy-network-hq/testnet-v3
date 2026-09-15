use super::AdmissionRequest;
use crate::{EtdagDigest, EtdagError};

/// Narrow verification boundary supplied by the canonical Aegis owner. The
/// implementation must bind the presented public key to `sender_wallet`
/// before accepting its signature; ETDAG never becomes a wallet-key engine.
pub trait AdmissionSignatureVerifier {
    fn verify_wallet_signature(
        &self,
        sender_wallet: &str,
        signature_algorithm: &str,
        signer_public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), EtdagError>;
}

pub fn verify_admission_request(
    request: &AdmissionRequest,
    expected_chain_id: u64,
    expected_network_id: &str,
    expected_context_root: &EtdagDigest,
    expected_target_height: u64,
    verifier: &impl AdmissionSignatureVerifier,
) -> Result<(), EtdagError> {
    request.validate_shape()?;
    if request.chain_id != expected_chain_id
        || request.network_id != expected_network_id
        || &request.context_root != expected_context_root
        || request.target_height != expected_target_height
    {
        return Err(EtdagError::ContextMismatch);
    }
    let message = request.signing_bytes()?;
    verifier.verify_wallet_signature(
        &request.sender_wallet,
        &request.signature_algorithm,
        &request.signer_public_key,
        &message,
        &request.signature,
    )
}
