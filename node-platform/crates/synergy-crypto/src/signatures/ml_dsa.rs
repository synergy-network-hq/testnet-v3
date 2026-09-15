use synergy_aegis::{AegisVerifier, KeyId, SignatureAlgorithm, SigningContext};

use super::{AegisSignatureScheme, SignatureVerificationError};

pub fn verifier<'a, V: AegisVerifier>(
    provider: &'a V,
    context: SigningContext,
    key_id: KeyId,
) -> Result<AegisSignatureScheme<'a, V>, SignatureVerificationError> {
    AegisSignatureScheme::new(provider, context, SignatureAlgorithm::MlDsa65, key_id)
}
