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
    let valid = match algorithm {
        AlgorithmId::MlDsa65 => {
            let signer = Sign::mldsa65();
            if public_key.bytes.len() != signer.public_key_size() {
                return Err(AegisSynQError::MalformedPublicKey);
            }
            if signature.bytes.len() != signer.signature_size() {
                return Err(AegisSynQError::MalformedSignature);
            }
            signer
                .verify(message, &signature.bytes, &public_key.bytes)
                .map_err(|_| AegisSynQError::MalformedSignature)?
        }
        _ => return Err(AegisSynQError::UnsupportedAlgorithm),
    };

    if valid {
        Ok(())
    } else {
        Err(AegisSynQError::InvalidSignature)
    }
}
