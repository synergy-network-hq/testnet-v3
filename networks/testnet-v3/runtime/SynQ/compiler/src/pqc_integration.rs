use serde::{Deserialize, Serialize};
use synq_pqc_shims::dilithium;
use synq_pqc_shims::falcon;
use synq_pqc_shims::hqc::{decaps as hqc_decaps, encaps as hqc_encaps, keygen as hqc_keygen};
use synq_pqc_shims::kyber::{
    decaps as kyber_decaps, encaps as kyber_encaps, keygen as kyber_keygen,
};
use synq_pqc_shims::mceliece::{
    decaps as mceliece_decaps, encaps as mceliece_encaps, keygen as mceliece_keygen,
};
use synq_pqc_shims::sphincs;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PQCSecurityLevel {
    Basic,
    Enhanced,
    Maximum,
    Military,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCKeyPair {
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub security_level: PQCSecurityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCSignature {
    pub algorithm: String,
    pub signature: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub security_level: PQCSecurityLevel,
}

#[derive(Debug)]
pub struct PQCCompiler {
    security_level: PQCSecurityLevel,
}

impl PQCCompiler {
    pub fn new(security_level: PQCSecurityLevel) -> Self {
        PQCCompiler { security_level }
    }

    pub fn generate_keypair(&self, algorithm: &str) -> Result<PQCKeyPair, String> {
        let (pk, sk) = match algorithm.to_lowercase().as_str() {
            "kyber" | "kyber768" => match kyber_keygen() {
                Ok((pk, sk)) => (pk, sk),
                Err(e) => return Err(format!("Kyber key generation failed: {}", e)),
            },
            // Dilithium/Falcon/SPHINCS+/McEliece shims return the keypair
            // directly (they cannot fail at keygen time) rather than a Result.
            "dilithium" | "dilithium3" => dilithium::keygen(),
            "falcon" | "falcon512" => falcon::keygen(),
            "sphincs" | "sphincsplus" => sphincs::keygen(),
            "mceliece" | "classicmceliece" => mceliece_keygen(),
            "hqc" | "hqc128" => hqc_keygen(),
            _ => return Err(format!("Unsupported PQC algorithm: {}", algorithm)),
        };

        Ok(PQCKeyPair {
            algorithm: algorithm.to_string(),
            public_key: pk,
            private_key: sk,
            security_level: self.security_level.clone(),
        })
    }

    /// Signs a message with a REAL PQC signature — dispatches to the matching
    /// pqc-shims algorithm (Dilithium / Falcon / SPHINCS+) instead of the
    /// previous fake SHA3-hash-only placeholder.
    pub fn sign_message(
        &self,
        private_key: &[u8],
        message: &[u8],
        algorithm: &str,
    ) -> Result<PQCSignature, String> {
        let signature = self.create_signature(private_key, message, algorithm)?;

        Ok(PQCSignature {
            algorithm: algorithm.to_string(),
            signature,
            message_hash: self.hash_message(message),
            security_level: self.security_level.clone(),
        })
    }

    /// Verifies a REAL PQC signature — dispatches to the matching pqc-shims
    /// algorithm's verify() instead of the previous fake hash-equality check
    /// (which compared hash(message) to hash(signature) and could never
    /// meaningfully validate anything).
    pub fn verify_signature(
        &self,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
        algorithm: &str,
    ) -> Result<bool, String> {
        let result = match algorithm.to_lowercase().as_str() {
            "dilithium" | "dilithium3" => dilithium::verify(message, signature, public_key),
            "falcon" | "falcon512" => falcon::verify(message, signature, public_key),
            "sphincs" | "sphincsplus" => sphincs::verify(message, signature, public_key),
            _ => return Err(format!("Unsupported signature algorithm: {}", algorithm)),
        };
        Ok(result)
    }

    pub fn encapsulate_key(
        &self,
        public_key: &[u8],
        algorithm: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        match algorithm.to_lowercase().as_str() {
            "kyber" | "kyber768" => match kyber_encaps(public_key) {
                Ok((ct, ss)) => Ok((ct, ss)),
                Err(e) => Err(format!("Kyber encapsulation failed: {}", e)),
            },
            "mceliece" | "classicmceliece" => Ok(mceliece_encaps(public_key)),
            "hqc" | "hqc128" => Ok(hqc_encaps(public_key)),
            _ => Err(format!("Unsupported KEM algorithm: {}", algorithm)),
        }
    }

    pub fn decapsulate_key(
        &self,
        ciphertext: &[u8],
        private_key: &[u8],
        algorithm: &str,
    ) -> Result<Vec<u8>, String> {
        match algorithm.to_lowercase().as_str() {
            "kyber" | "kyber768" => match kyber_decaps(ciphertext, private_key) {
                Ok(ss) => Ok(ss),
                Err(e) => Err(format!("Kyber decapsulation failed: {}", e)),
            },
            "mceliece" | "classicmceliece" => Ok(mceliece_decaps(ciphertext, private_key)),
            "hqc" | "hqc128" => Ok(hqc_decaps(ciphertext, private_key)),
            _ => Err(format!("Unsupported KEM algorithm: {}", algorithm)),
        }
    }

    /// Dispatches to the real pqc-shims sign() for the given algorithm.
    fn create_signature(
        &self,
        private_key: &[u8],
        message: &[u8],
        algorithm: &str,
    ) -> Result<Vec<u8>, String> {
        match algorithm.to_lowercase().as_str() {
            "dilithium" | "dilithium3" => Ok(dilithium::sign(message, private_key)),
            "falcon" | "falcon512" => Ok(falcon::sign(message, private_key)),
            "sphincs" | "sphincsplus" => Ok(sphincs::sign(message, private_key)),
            _ => Err(format!("Unsupported signature algorithm: {}", algorithm)),
        }
    }

    fn hash_message(&self, message: &[u8]) -> Vec<u8> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    pub fn get_supported_algorithms(&self) -> Vec<String> {
        vec![
            "kyber".to_string(),
            "dilithium".to_string(),
            "falcon".to_string(),
            "sphincs".to_string(),
            "mceliece".to_string(),
            "hqc".to_string(),
        ]
    }

    pub fn get_security_level(&self) -> &PQCSecurityLevel {
        &self.security_level
    }
}

impl Default for PQCCompiler {
    fn default() -> Self {
        PQCCompiler::new(PQCSecurityLevel::Enhanced)
    }
}
