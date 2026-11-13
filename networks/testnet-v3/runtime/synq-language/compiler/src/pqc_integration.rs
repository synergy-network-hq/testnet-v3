//! Integration with aegis-pqsynq for PQC operations
//! This module provides helpers for generating PQC-related bytecode and runtime verification
//!
//! This is the core integration layer that connects SynQ smart contracts with post-quantum cryptography.

#[cfg(feature = "pqc-aegis")]
use pqsynq::{DigitalSignature, KeyEncapsulation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAlgorithm {
    Mldsa44,
    Mldsa65,
    Mldsa87,
    Fndsa512,
    Fndsa1024,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    Mlkem512,
    Mlkem768,
    Mlkem1024,
    Hqckem128,
    Hqckem192,
    Hqckem256,
}

#[cfg(feature = "pqc-aegis")]
pub type PqcError = pqsynq::PqcError;

#[cfg(not(feature = "pqc-aegis"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcError {
    message: String,
}

#[cfg(not(feature = "pqc-aegis"))]
impl PqcError {
    fn backend_unavailable() -> Self {
        Self {
            message: "aegis-pqsynq backend is unavailable; restore aegis-pqsynq/pqsynq and build with feature `pqc-aegis`".to_string(),
        }
    }
}

#[cfg(not(feature = "pqc-aegis"))]
impl std::fmt::Display for PqcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[cfg(not(feature = "pqc-aegis"))]
impl std::error::Error for PqcError {}

/// PQC operation helpers for code generation and runtime
pub struct PqcIntegration;

#[cfg(feature = "pqc-aegis")]
fn to_pqsynq_sign_algorithm(algorithm: SignAlgorithm) -> pqsynq::SignAlgorithm {
    match algorithm {
        SignAlgorithm::Mldsa44 => pqsynq::SignAlgorithm::Mldsa44,
        SignAlgorithm::Mldsa65 => pqsynq::SignAlgorithm::Mldsa65,
        SignAlgorithm::Mldsa87 => pqsynq::SignAlgorithm::Mldsa87,
        SignAlgorithm::Fndsa512 => pqsynq::SignAlgorithm::Fndsa512,
        SignAlgorithm::Fndsa1024 => pqsynq::SignAlgorithm::Fndsa1024,
    }
}

#[cfg(feature = "pqc-aegis")]
fn to_pqsynq_kem_algorithm(algorithm: KemAlgorithm) -> pqsynq::KemAlgorithm {
    match algorithm {
        KemAlgorithm::Mlkem512 => pqsynq::KemAlgorithm::Mlkem512,
        KemAlgorithm::Mlkem768 => pqsynq::KemAlgorithm::Mlkem768,
        KemAlgorithm::Mlkem1024 => pqsynq::KemAlgorithm::Mlkem1024,
        KemAlgorithm::Hqckem128 => pqsynq::KemAlgorithm::Hqckem128,
        KemAlgorithm::Hqckem192 => pqsynq::KemAlgorithm::Hqckem192,
        KemAlgorithm::Hqckem256 => pqsynq::KemAlgorithm::Hqckem256,
    }
}

impl PqcIntegration {
    fn normalize(name: &str) -> String {
        let mut normalized = String::with_capacity(name.len());
        for ch in name.chars() {
            if ch != '_' && ch != '-' {
                normalized.push(ch.to_ascii_lowercase());
            }
        }
        normalized
    }

    /// Generate bytecode for ML-DSA signature verification
    pub fn mldsa_verify_bytecode() -> Vec<u8> {
        vec![0x80] // MLDSAVerify opcode
    }

    /// Generate bytecode for FN-DSA signature verification
    pub fn fndsa_verify_bytecode() -> Vec<u8> {
        vec![0x82] // FNDSAVerify opcode
    }

    /// Generate bytecode for ML-KEM key exchange
    pub fn mlkem_key_exchange_bytecode() -> Vec<u8> {
        vec![0x81] // MLKEMKeyExchange opcode
    }

    /// Generate bytecode for HQC-KEM-128 key exchange
    pub fn hqckem128_key_exchange_bytecode() -> Vec<u8> {
        vec![0x84] // HQCKEM128KeyExchange opcode
    }

    /// Generate bytecode for HQC-KEM-192 key exchange
    pub fn hqckem192_key_exchange_bytecode() -> Vec<u8> {
        vec![0x85] // HQCKEM192KeyExchange opcode
    }

    /// Generate bytecode for HQC-KEM-256 key exchange
    pub fn hqckem256_key_exchange_bytecode() -> Vec<u8> {
        vec![0x86] // HQCKEM256KeyExchange opcode
    }

    /// Check if a function name is a PQC operation
    pub fn is_pqc_function(name: &str) -> bool {
        let normalized = Self::normalize(name);
        normalized.starts_with("verifymldsa")
            || normalized.starts_with("verifyfndsa")
            || normalized.starts_with("verifyslhdsa")
            || normalized.starts_with("mlkem")
            || normalized.starts_with("hqckem")
            || normalized.starts_with("mldsa")
            || normalized.starts_with("fndsa")
            || normalized.starts_with("slhdsa")
    }

    pub fn is_mldsa_verify_function(name: &str) -> bool {
        Self::normalize(name).starts_with("verifymldsa")
    }

    pub fn is_fndsa_verify_function(name: &str) -> bool {
        Self::normalize(name).starts_with("verifyfndsa")
    }

    pub fn is_slhdsa_verify_function(name: &str) -> bool {
        Self::normalize(name).starts_with("verifyslhdsa")
    }

    pub fn is_hqckem_family_function(name: &str) -> bool {
        Self::normalize(name).starts_with("hqckem")
    }

    pub fn is_mlkem_family_function(name: &str) -> bool {
        Self::normalize(name).starts_with("mlkem")
    }

    /// Get the algorithm variant from a function name
    pub fn get_sign_algorithm(name: &str) -> Option<SignAlgorithm> {
        let normalized = Self::normalize(name);
        if normalized.contains("mldsa44") {
            Some(SignAlgorithm::Mldsa44)
        } else if normalized.contains("mldsa65") {
            Some(SignAlgorithm::Mldsa65)
        } else if normalized.contains("mldsa87") {
            Some(SignAlgorithm::Mldsa87)
        } else if normalized.contains("fndsa512") {
            Some(SignAlgorithm::Fndsa512)
        } else if normalized.contains("fndsa1024") {
            Some(SignAlgorithm::Fndsa1024)
        } else {
            None
        }
    }

    /// Get the KEM algorithm variant from a function name
    pub fn get_kem_algorithm(name: &str) -> Option<KemAlgorithm> {
        let normalized = Self::normalize(name);
        if normalized.contains("mlkem512") {
            Some(KemAlgorithm::Mlkem512)
        } else if normalized.contains("mlkem768") {
            Some(KemAlgorithm::Mlkem768)
        } else if normalized.contains("mlkem1024") {
            Some(KemAlgorithm::Mlkem1024)
        } else if normalized.contains("hqckem128") {
            Some(KemAlgorithm::Hqckem128)
        } else if normalized.contains("hqckem192") {
            Some(KemAlgorithm::Hqckem192)
        } else if normalized.contains("hqckem256") {
            Some(KemAlgorithm::Hqckem256)
        } else {
            None
        }
    }
}

impl PqcIntegration {
    /// Verify an ML-DSA signature using pqsynq
    pub fn verify_mldsa_signature(
        algorithm: SignAlgorithm,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, PqcError> {
        #[cfg(not(feature = "pqc-aegis"))]
        {
            let _ = (algorithm, public_key, message, signature);
            return Err(PqcError::backend_unavailable());
        }

        #[cfg(feature = "pqc-aegis")]
        let signer = pqsynq::Sign::new(to_pqsynq_sign_algorithm(algorithm));

        #[cfg(feature = "pqc-aegis")]
        signer.verify(message, signature, public_key)
    }

    /// Verify an FN-DSA signature using pqsynq
    pub fn verify_fndsa_signature(
        algorithm: SignAlgorithm,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, PqcError> {
        #[cfg(not(feature = "pqc-aegis"))]
        {
            let _ = (algorithm, public_key, message, signature);
            return Err(PqcError::backend_unavailable());
        }

        #[cfg(feature = "pqc-aegis")]
        let signer = pqsynq::Sign::new(to_pqsynq_sign_algorithm(algorithm));

        #[cfg(feature = "pqc-aegis")]
        signer.verify(message, signature, public_key)
    }

    /// Perform ML-KEM key exchange using pqsynq
    pub fn mlkem_key_exchange(
        algorithm: KemAlgorithm,
        _public_key: &[u8],
        ciphertext: &[u8],
        secret_key: &[u8],
    ) -> Result<Vec<u8>, PqcError> {
        #[cfg(not(feature = "pqc-aegis"))]
        {
            let _ = (algorithm, ciphertext, secret_key);
            return Err(PqcError::backend_unavailable());
        }

        #[cfg(feature = "pqc-aegis")]
        let kem = {
            use pqsynq::Kem;
            Kem::new(to_pqsynq_kem_algorithm(algorithm))
        };

        #[cfg(feature = "pqc-aegis")]
        kem.decapsulate(ciphertext, secret_key)
    }

    /// Perform HQC-KEM key exchange using pqsynq
    pub fn hqckem_key_exchange(
        algorithm: KemAlgorithm,
        _public_key: &[u8],
        ciphertext: &[u8],
        secret_key: &[u8],
    ) -> Result<Vec<u8>, PqcError> {
        #[cfg(not(feature = "pqc-aegis"))]
        {
            let _ = (algorithm, ciphertext, secret_key);
            return Err(PqcError::backend_unavailable());
        }

        #[cfg(feature = "pqc-aegis")]
        let kem = {
            use pqsynq::Kem;
            Kem::new(to_pqsynq_kem_algorithm(algorithm))
        };

        #[cfg(feature = "pqc-aegis")]
        kem.decapsulate(ciphertext, secret_key)
    }

    /// Generate a key pair for signatures
    pub fn generate_signature_keypair(
        algorithm: SignAlgorithm,
    ) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        #[cfg(not(feature = "pqc-aegis"))]
        {
            let _ = algorithm;
            return Err(PqcError::backend_unavailable());
        }

        #[cfg(feature = "pqc-aegis")]
        let signer = pqsynq::Sign::new(to_pqsynq_sign_algorithm(algorithm));

        #[cfg(feature = "pqc-aegis")]
        signer.keygen()
    }

    /// Generate a key pair for KEM
    pub fn generate_kem_keypair(algorithm: KemAlgorithm) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        #[cfg(not(feature = "pqc-aegis"))]
        {
            let _ = algorithm;
            return Err(PqcError::backend_unavailable());
        }

        #[cfg(feature = "pqc-aegis")]
        let kem = {
            use pqsynq::Kem;
            Kem::new(to_pqsynq_kem_algorithm(algorithm))
        };

        #[cfg(feature = "pqc-aegis")]
        kem.keygen()
    }

    /// Encapsulate a shared secret (KEM)
    pub fn kem_encapsulate(
        algorithm: KemAlgorithm,
        public_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        #[cfg(not(feature = "pqc-aegis"))]
        {
            let _ = (algorithm, public_key);
            return Err(PqcError::backend_unavailable());
        }

        #[cfg(feature = "pqc-aegis")]
        let kem = {
            use pqsynq::Kem;
            Kem::new(to_pqsynq_kem_algorithm(algorithm))
        };

        #[cfg(feature = "pqc-aegis")]
        kem.encapsulate(public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::{KemAlgorithm, PqcIntegration};

    #[test]
    fn detects_hqckem_functions() {
        assert!(PqcIntegration::is_pqc_function(
            "hqckem_hqckem128_decapsulate"
        ));
        assert_eq!(
            PqcIntegration::get_kem_algorithm("hqckem_hqckem256_decapsulate"),
            Some(KemAlgorithm::Hqckem256)
        );
    }

    #[test]
    fn detects_camel_case_verify_aliases() {
        assert!(PqcIntegration::is_pqc_function("verifyMLDSASignature"));
        assert!(PqcIntegration::is_mldsa_verify_function(
            "verifyMLDSASignature"
        ));
        assert!(PqcIntegration::is_fndsa_verify_function(
            "verifyFNDSASignature"
        ));
    }

    #[cfg(feature = "pqc-aegis")]
    #[test]
    fn hqckem_roundtrip_via_integration_helper() {
        let (pk, sk) = PqcIntegration::generate_kem_keypair(KemAlgorithm::Hqckem128)
            .expect("keygen should work");
        let (ct, ss1) = PqcIntegration::kem_encapsulate(KemAlgorithm::Hqckem128, &pk)
            .expect("encapsulation should work");
        let ss2 = PqcIntegration::hqckem_key_exchange(KemAlgorithm::Hqckem128, &pk, &ct, &sk)
            .expect("decapsulation should work");
        assert_eq!(ss1, ss2);
    }
}
