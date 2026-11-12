//! Explicit APQE primitive boundary for existing protected-envelope formats.
//! Callers own nonce uniqueness and exact transcript framing.
use synergy_address_engine::apqe::{HashAlgorithm, Primitives, SecretBytes};

#[derive(Debug, Clone, Copy, Default)]
pub struct AegisProtectedPrimitives;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrimitiveError;

impl AegisProtectedPrimitives {
    pub fn random_bytes(&self, output: &mut [u8]) -> Result<(), PrimitiveError> {
        Primitives.random_bytes(output).map_err(|_| PrimitiveError)
    }
    pub fn encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, PrimitiveError> {
        Primitives
            .aead_encrypt(key, nonce, aad, plaintext)
            .map_err(|_| PrimitiveError)
    }
    pub fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<SecretBytes, PrimitiveError> {
        Primitives
            .aead_decrypt(key, nonce, aad, ciphertext)
            .map_err(|_| PrimitiveError)
    }
    /// Fixed legacy Kyber derivation output, without changing its caller's gate.
    pub fn shake256_32_segments(&self, segments: &[&[u8]]) -> [u8; 32] {
        let mut hash = Primitives
            .hash_stream(HashAlgorithm::Shake256 { output_bytes: 32 })
            .expect("fixed SHAKE256 output is supported");
        for segment in segments {
            hash.update(segment);
        }
        let digest = SecretBytes::from_bytes(hash.finalize());
        let mut output = [0; 32];
        output.copy_from_slice(digest.as_bytes());
        output
    }
}
