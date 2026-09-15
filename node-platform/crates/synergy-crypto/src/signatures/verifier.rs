use synergy_aegis::{AegisVerifier, KeyId, Signature, SignatureAlgorithm, SigningContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureVerificationError {
    InvalidPublicKey,
    InvalidSignature,
    UnsupportedAlgorithm,
    Provider(String),
}

pub struct AegisSignatureScheme<'a, V: AegisVerifier> {
    provider: &'a V,
    context: SigningContext,
    algorithm: SignatureAlgorithm,
    key_id: KeyId,
}

impl<'a, V: AegisVerifier> AegisSignatureScheme<'a, V> {
    pub fn new(
        provider: &'a V,
        context: SigningContext,
        algorithm: SignatureAlgorithm,
        key_id: KeyId,
    ) -> Result<Self, SignatureVerificationError> {
        context
            .validate()
            .map_err(|_| SignatureVerificationError::Provider("invalid signing context".into()))?;
        Ok(Self {
            provider,
            context,
            algorithm,
            key_id,
        })
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<(), SignatureVerificationError> {
        self.provider
            .verify(
                &self.context,
                message,
                &Signature {
                    algorithm: self.algorithm,
                    key_id: self.key_id.clone(),
                    bytes: signature.to_vec(),
                },
                public_key,
            )
            .map_err(|error| SignatureVerificationError::Provider(error.to_string()))
    }
}
