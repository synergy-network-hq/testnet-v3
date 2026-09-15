use synergy_aegis::{AegisPolicy, PqvmVerifier, SignatureAlgorithm};

use crate::signing::{self, SignedGenesis};

pub fn verify_signed_genesis(
    signed: &SignedGenesis,
    trust_public_key: &[u8],
) -> Result<(), String> {
    let verifier = PqvmVerifier::new(AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: 16 * 1024 * 1024,
        maximum_signature_bytes: 16 * 1024,
    })
    .map_err(|error| error.to_string())?;
    signing::verify(signed, &verifier, trust_public_key)
}
