use synergy_aegis::{AegisPolicy, PqvmVerifier, SignatureAlgorithm};

use crate::sign::{self, SignedManifest};

pub fn verify_signed_manifest(
    signed: &SignedManifest,
    trust_public_key: &[u8],
) -> Result<(), String> {
    let verifier = PqvmVerifier::new(AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: crate::build::MAX_MANIFEST_BYTES as usize,
        maximum_signature_bytes: 64 * 1024,
    })
    .map_err(|error| error.to_string())?;
    sign::verify(signed, &verifier, trust_public_key)
}
