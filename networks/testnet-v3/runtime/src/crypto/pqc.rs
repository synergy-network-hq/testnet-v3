use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use aegis_pqvm::pqc::signatures::fndsa::fndsa1024;
use aegis_pqvm::pqc::signatures::mldsa::{mldsa65, mldsa87};
use pqcrypto_hqc::hqc256;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_sphincsplus::sphincsshake128fsimple;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PQCAlgorithm {
    MLKEM1024, // ML-KEM-1024 (Module-Lattice-based Key Encapsulation Mechanism)
    #[serde(alias = "ML-DSA-65", alias = "mldsa65", alias = "ml-dsa-65")]
    MLDSA65, // ML-DSA-65 (FIPS 204 security category 3)
    #[serde(alias = "ML-DSA-87", alias = "mldsa87", alias = "ml-dsa-87")]
    MLDSA87, // ML-DSA-87 (FIPS 204 security category 5)
    #[serde(alias = "FN-DSA", alias = "FN-DSA-1024", alias = "fn-dsa")]
    FNDSA, // FN-DSA-1024 (Fast Fourier lattice Digital Signature Algorithm)
    SLHDSA,    // SLH-DSA (Stateless Hash-based Digital Signature Algorithm)
    HQCKEM,    // HQC-KEM (Hamming Quasi-Cyclic Key Encapsulation Mechanism)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCPublicKey {
    pub algorithm: PQCAlgorithm,
    pub key_data: Vec<u8>,
    pub key_id: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCPrivateKey {
    pub algorithm: PQCAlgorithm,
    pub key_data: Vec<u8>,
    pub public_key_id: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCSignature {
    pub algorithm: PQCAlgorithm,
    pub signature_data: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub public_key_id: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCCiphertext {
    pub algorithm: PQCAlgorithm,
    pub ciphertext: Vec<u8>,
    pub encapsulated_key: Vec<u8>,
    pub public_key_id: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCSharedSecret {
    pub algorithm: PQCAlgorithm,
    pub secret: Vec<u8>,
    pub public_key_id: String,
    pub created_at: u64,
}

#[derive(Debug)]
pub struct PQCManager {
    keypairs: HashMap<String, (PQCPublicKey, PQCPrivateKey)>,
    signatures: HashMap<String, PQCSignature>,
    ciphertexts: HashMap<String, PQCCiphertext>,
    shared_secrets: HashMap<String, PQCSharedSecret>,
}

impl PQCManager {
    pub fn new() -> Self {
        Self {
            keypairs: HashMap::new(),
            signatures: HashMap::new(),
            ciphertexts: HashMap::new(),
            shared_secrets: HashMap::new(),
        }
    }

    pub fn generate_keypair(
        &mut self,
        algorithm: PQCAlgorithm,
    ) -> Result<(PQCPublicKey, PQCPrivateKey), String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let key_id = format!("{}_{}", algorithm_name(&algorithm), timestamp);

        match algorithm {
            PQCAlgorithm::MLKEM1024 => self.generate_mlkem_keypair(key_id, timestamp),
            PQCAlgorithm::MLDSA65 => self.generate_mldsa65_keypair(key_id, timestamp),
            PQCAlgorithm::MLDSA87 => self.generate_mldsa87_keypair(key_id, timestamp),
            PQCAlgorithm::FNDSA => self.generate_fndsa_keypair(key_id, timestamp),
            PQCAlgorithm::SLHDSA => self.generate_slhdsa_keypair(key_id, timestamp),
            PQCAlgorithm::HQCKEM => self.generate_hqckem_keypair(key_id, timestamp),
        }
    }

    fn generate_mldsa65_keypair(
        &mut self,
        key_id: String,
        timestamp: u64,
    ) -> Result<(PQCPublicKey, PQCPrivateKey), String> {
        let (pk, sk) = mldsa65::keypair();
        let public_key = PQCPublicKey {
            algorithm: PQCAlgorithm::MLDSA65,
            key_data: pk.as_bytes().to_vec(),
            key_id: key_id.clone(),
            created_at: timestamp,
        };
        let private_key = PQCPrivateKey {
            algorithm: PQCAlgorithm::MLDSA65,
            key_data: sk.as_bytes().to_vec(),
            public_key_id: key_id,
            created_at: timestamp,
        };
        Ok((public_key, private_key))
    }

    fn generate_mldsa87_keypair(
        &mut self,
        key_id: String,
        timestamp: u64,
    ) -> Result<(PQCPublicKey, PQCPrivateKey), String> {
        let (pk, sk) = mldsa87::keypair();

        let public_key = PQCPublicKey {
            algorithm: PQCAlgorithm::MLDSA87,
            key_data: pk.as_bytes().to_vec(),
            key_id: key_id.clone(),
            created_at: timestamp,
        };

        let private_key = PQCPrivateKey {
            algorithm: PQCAlgorithm::MLDSA87,
            key_data: sk.as_bytes().to_vec(),
            public_key_id: key_id.clone(),
            created_at: timestamp,
        };

        self.keypairs
            .insert(key_id.clone(), (public_key.clone(), private_key.clone()));
        Ok((public_key, private_key))
    }

    fn generate_mlkem_keypair(
        &mut self,
        key_id: String,
        timestamp: u64,
    ) -> Result<(PQCPublicKey, PQCPrivateKey), String> {
        let (pk, sk) = mlkem1024::keypair();

        let public_key = PQCPublicKey {
            algorithm: PQCAlgorithm::MLKEM1024,
            key_data: pk.as_bytes().to_vec(),
            key_id: key_id.clone(),
            created_at: timestamp,
        };

        let private_key = PQCPrivateKey {
            algorithm: PQCAlgorithm::MLKEM1024,
            key_data: sk.as_bytes().to_vec(),
            public_key_id: key_id.clone(),
            created_at: timestamp,
        };

        self.keypairs
            .insert(key_id.clone(), (public_key.clone(), private_key.clone()));
        Ok((public_key, private_key))
    }

    fn generate_fndsa_keypair(
        &mut self,
        key_id: String,
        timestamp: u64,
    ) -> Result<(PQCPublicKey, PQCPrivateKey), String> {
        let (pk, sk) = fndsa1024::keypair();

        let public_key = PQCPublicKey {
            algorithm: PQCAlgorithm::FNDSA,
            key_data: pk.as_bytes().to_vec(),
            key_id: key_id.clone(),
            created_at: timestamp,
        };

        let private_key = PQCPrivateKey {
            algorithm: PQCAlgorithm::FNDSA,
            key_data: sk.as_bytes().to_vec(),
            public_key_id: key_id.clone(),
            created_at: timestamp,
        };

        self.keypairs
            .insert(key_id.clone(), (public_key.clone(), private_key.clone()));
        Ok((public_key, private_key))
    }

    fn generate_slhdsa_keypair(
        &mut self,
        key_id: String,
        timestamp: u64,
    ) -> Result<(PQCPublicKey, PQCPrivateKey), String> {
        let (pk, sk) = sphincsshake128fsimple::keypair();

        let public_key = PQCPublicKey {
            algorithm: PQCAlgorithm::SLHDSA,
            key_data: pk.as_bytes().to_vec(),
            key_id: key_id.clone(),
            created_at: timestamp,
        };

        let private_key = PQCPrivateKey {
            algorithm: PQCAlgorithm::SLHDSA,
            key_data: sk.as_bytes().to_vec(),
            public_key_id: key_id.clone(),
            created_at: timestamp,
        };

        self.keypairs
            .insert(key_id.clone(), (public_key.clone(), private_key.clone()));
        Ok((public_key, private_key))
    }

    fn generate_hqckem_keypair(
        &mut self,
        key_id: String,
        timestamp: u64,
    ) -> Result<(PQCPublicKey, PQCPrivateKey), String> {
        let (pk, sk) = hqc256::keypair();

        let public_key = PQCPublicKey {
            algorithm: PQCAlgorithm::HQCKEM,
            key_data: pk.as_bytes().to_vec(),
            key_id: key_id.clone(),
            created_at: timestamp,
        };

        let private_key = PQCPrivateKey {
            algorithm: PQCAlgorithm::HQCKEM,
            key_data: sk.as_bytes().to_vec(),
            public_key_id: key_id.clone(),
            created_at: timestamp,
        };

        self.keypairs
            .insert(key_id.clone(), (public_key.clone(), private_key.clone()));
        Ok((public_key, private_key))
    }

    pub fn sign(
        &mut self,
        private_key: &PQCPrivateKey,
        message: &[u8],
    ) -> Result<PQCSignature, String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signature_data = match private_key.algorithm {
            PQCAlgorithm::MLDSA65 => {
                let sk = mldsa65::SecretKey::from_bytes(&private_key.key_data)
                    .map_err(|_| "Invalid ML-DSA-65 secret key bytes".to_string())?;
                mldsa65::detached_sign(message, &sk).as_bytes().to_vec()
            }
            PQCAlgorithm::MLDSA87 => {
                let sk = mldsa87::SecretKey::from_bytes(&private_key.key_data)
                    .map_err(|_| "Invalid ML-DSA-87 secret key bytes".to_string())?;
                let signature = mldsa87::detached_sign(message, &sk);
                signature.as_bytes().to_vec()
            }
            PQCAlgorithm::FNDSA => {
                let sk = fndsa1024::SecretKey::from_bytes(&private_key.key_data)
                    .map_err(|_| "Invalid FN-DSA secret key bytes".to_string())?;
                let signature = fndsa1024::detached_sign(message, &sk);
                signature.as_bytes().to_vec()
            }
            PQCAlgorithm::SLHDSA => {
                let sk = sphincsshake128fsimple::SecretKey::from_bytes(&private_key.key_data)
                    .map_err(|_| "Invalid SLH-DSA secret key bytes".to_string())?;
                let signature = sphincsshake128fsimple::detached_sign(message, &sk);
                signature.as_bytes().to_vec()
            }
            _ => return Err("Algorithm does not support signing".to_string()),
        };

        let signature = PQCSignature {
            algorithm: private_key.algorithm.clone(),
            signature_data,
            message_hash: message.to_vec(),
            public_key_id: private_key.public_key_id.clone(),
            created_at: timestamp,
        };

        let sig_id = format!("sig_{}", timestamp);
        self.signatures.insert(sig_id, signature.clone());
        Ok(signature)
    }

    pub fn verify(
        &self,
        public_key: &PQCPublicKey,
        signature: &PQCSignature,
        message: &[u8],
    ) -> Result<bool, String> {
        match public_key.algorithm {
            PQCAlgorithm::MLDSA65 => {
                let pk = mldsa65::PublicKey::from_bytes(&public_key.key_data)
                    .map_err(|_| "Invalid ML-DSA-65 public key bytes".to_string())?;
                let sig = mldsa65::DetachedSignature::from_bytes(&signature.signature_data)
                    .map_err(|_| "Invalid ML-DSA-65 signature bytes".to_string())?;
                mldsa65::verify_detached_signature(&sig, message, &pk)
                    .map(|_| true)
                    .map_err(|_| "ML-DSA-65 signature verification failed".to_string())
            }
            PQCAlgorithm::MLDSA87 => {
                let pk = mldsa87::PublicKey::from_bytes(&public_key.key_data)
                    .map_err(|_| "Invalid ML-DSA-87 public key bytes".to_string())?;
                let sig = mldsa87::DetachedSignature::from_bytes(&signature.signature_data)
                    .map_err(|_| "Invalid ML-DSA-87 signature bytes".to_string())?;
                mldsa87::verify_detached_signature(&sig, message, &pk)
                    .map(|_| true)
                    .map_err(|_| "ML-DSA-87 signature verification failed".to_string())
            }
            PQCAlgorithm::FNDSA => {
                let pk = fndsa1024::PublicKey::from_bytes(&public_key.key_data)
                    .map_err(|_| "Invalid FN-DSA public key bytes".to_string())?;
                let sig = fndsa1024::DetachedSignature::from_bytes(&signature.signature_data)
                    .map_err(|_| "Invalid FN-DSA signature bytes".to_string())?;
                fndsa1024::verify_detached_signature(&sig, message, &pk)
                    .map(|_| true)
                    .map_err(|_| "FN-DSA signature verification failed".to_string())
            }
            PQCAlgorithm::SLHDSA => {
                let pk = sphincsshake128fsimple::PublicKey::from_bytes(&public_key.key_data)
                    .map_err(|_| "Invalid SLH-DSA public key bytes".to_string())?;
                let sig = sphincsshake128fsimple::DetachedSignature::from_bytes(
                    &signature.signature_data,
                )
                .map_err(|_| "Invalid SLH-DSA signature bytes".to_string())?;
                sphincsshake128fsimple::verify_detached_signature(&sig, message, &pk)
                    .map(|_| true)
                    .map_err(|_| "SLH-DSA signature verification failed".to_string())
            }
            _ => Err("Algorithm does not support verification".to_string()),
        }
    }

    pub fn encapsulate(
        &mut self,
        public_key: &PQCPublicKey,
    ) -> Result<(PQCCiphertext, PQCSharedSecret), String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        match public_key.algorithm {
            PQCAlgorithm::MLKEM1024 => {
                let pk = mlkem1024::PublicKey::from_bytes(&public_key.key_data)
                    .map_err(|_| "Invalid ML-KEM-1024 public key bytes".to_string())?;
                let (shared_secret, ciphertext) = mlkem1024::encapsulate(&pk);

                let ciphertext_record = PQCCiphertext {
                    algorithm: PQCAlgorithm::MLKEM1024,
                    ciphertext: ciphertext.as_bytes().to_vec(),
                    encapsulated_key: shared_secret.as_bytes().to_vec(),
                    public_key_id: public_key.key_id.clone(),
                    created_at: timestamp,
                };

                let shared_secret_record = PQCSharedSecret {
                    algorithm: PQCAlgorithm::MLKEM1024,
                    secret: shared_secret.as_bytes().to_vec(),
                    public_key_id: public_key.key_id.clone(),
                    created_at: timestamp,
                };

                let ct_id = format!("ct_{}", timestamp);
                let ss_id = format!("ss_{}", timestamp);
                self.ciphertexts.insert(ct_id, ciphertext_record.clone());
                self.shared_secrets
                    .insert(ss_id, shared_secret_record.clone());

                Ok((ciphertext_record, shared_secret_record))
            }
            PQCAlgorithm::HQCKEM => {
                let pk = hqc256::PublicKey::from_bytes(&public_key.key_data)
                    .map_err(|_| "Invalid HQC-KEM public key bytes".to_string())?;
                let (shared_secret, ciphertext) = hqc256::encapsulate(&pk);

                let ciphertext_record = PQCCiphertext {
                    algorithm: PQCAlgorithm::HQCKEM,
                    ciphertext: ciphertext.as_bytes().to_vec(),
                    encapsulated_key: shared_secret.as_bytes().to_vec(),
                    public_key_id: public_key.key_id.clone(),
                    created_at: timestamp,
                };

                let shared_secret_record = PQCSharedSecret {
                    algorithm: PQCAlgorithm::HQCKEM,
                    secret: shared_secret.as_bytes().to_vec(),
                    public_key_id: public_key.key_id.clone(),
                    created_at: timestamp,
                };

                let ct_id = format!("ct_{}", timestamp);
                let ss_id = format!("ss_{}", timestamp);
                self.ciphertexts.insert(ct_id, ciphertext_record.clone());
                self.shared_secrets
                    .insert(ss_id, shared_secret_record.clone());

                Ok((ciphertext_record, shared_secret_record))
            }
            _ => Err("Algorithm does not support encapsulation".to_string()),
        }
    }

    pub fn decapsulate(
        &self,
        private_key: &PQCPrivateKey,
        ciphertext: &PQCCiphertext,
    ) -> Result<PQCSharedSecret, String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        match private_key.algorithm {
            PQCAlgorithm::MLKEM1024 => {
                let sk = mlkem1024::SecretKey::from_bytes(&private_key.key_data)
                    .map_err(|_| "Invalid ML-KEM-1024 secret key bytes".to_string())?;
                let ct = mlkem1024::Ciphertext::from_bytes(&ciphertext.ciphertext)
                    .map_err(|_| "Invalid ML-KEM-1024 ciphertext bytes".to_string())?;
                let shared_secret = mlkem1024::decapsulate(&ct, &sk);

                Ok(PQCSharedSecret {
                    algorithm: PQCAlgorithm::MLKEM1024,
                    secret: shared_secret.as_bytes().to_vec(),
                    public_key_id: private_key.public_key_id.clone(),
                    created_at: timestamp,
                })
            }
            PQCAlgorithm::HQCKEM => {
                let sk = hqc256::SecretKey::from_bytes(&private_key.key_data)
                    .map_err(|_| "Invalid HQC-KEM secret key bytes".to_string())?;
                let ct = hqc256::Ciphertext::from_bytes(&ciphertext.ciphertext)
                    .map_err(|_| "Invalid HQC-KEM ciphertext bytes".to_string())?;
                let shared_secret = hqc256::decapsulate(&ct, &sk);

                Ok(PQCSharedSecret {
                    algorithm: PQCAlgorithm::HQCKEM,
                    secret: shared_secret.as_bytes().to_vec(),
                    public_key_id: private_key.public_key_id.clone(),
                    created_at: timestamp,
                })
            }
            _ => Err("Algorithm does not support decapsulation".to_string()),
        }
    }

    /// Lookup a stored public key by ID and perform encapsulation with ML-KEM/HQC as appropriate.
    pub fn encapsulate_key(
        &mut self,
        public_key_id: &str,
    ) -> Result<(PQCCiphertext, PQCSharedSecret), String> {
        let public_key = self
            .keypairs
            .get(public_key_id)
            .map(|(pk, _)| pk.clone())
            .ok_or_else(|| format!("Public key {} not found", public_key_id))?;
        self.encapsulate(&public_key)
    }

    /// Lookup a stored private key by its public key ID and decapsulate a ciphertext.
    pub fn decapsulate_key(
        &self,
        public_key_id: &str,
        ciphertext: &PQCCiphertext,
    ) -> Result<PQCSharedSecret, String> {
        let private_key = self
            .keypairs
            .get(public_key_id)
            .map(|(_, sk)| sk.clone())
            .ok_or_else(|| format!("Private key for {} not found", public_key_id))?;
        self.decapsulate(&private_key, ciphertext)
    }

    /// Sign arbitrary message bytes using a stored private key ID.
    pub fn sign_message(
        &mut self,
        private_key_id: &str,
        message: &[u8],
    ) -> Result<PQCSignature, String> {
        let private_key = self
            .keypairs
            .get(private_key_id)
            .map(|(_, sk)| sk.clone())
            .ok_or_else(|| format!("Private key {} not found", private_key_id))?;
        self.sign(&private_key, message)
    }

    /// Enumerate supported algorithms for callers that iterate capabilities.
    pub fn get_supported_algorithms(&self) -> Vec<PQCAlgorithm> {
        vec![
            PQCAlgorithm::MLKEM1024,
            PQCAlgorithm::MLDSA65,
            PQCAlgorithm::MLDSA87,
            PQCAlgorithm::FNDSA,
            PQCAlgorithm::SLHDSA,
            PQCAlgorithm::HQCKEM,
        ]
    }

    pub fn get_keypair(&self, key_id: &str) -> Option<&(PQCPublicKey, PQCPrivateKey)> {
        self.keypairs.get(key_id)
    }

    pub fn get_signature(&self, sig_id: &str) -> Option<&PQCSignature> {
        self.signatures.get(sig_id)
    }

    pub fn get_ciphertext(&self, ct_id: &str) -> Option<&PQCCiphertext> {
        self.ciphertexts.get(ct_id)
    }

    pub fn get_shared_secret(&self, ss_id: &str) -> Option<&PQCSharedSecret> {
        self.shared_secrets.get(ss_id)
    }

    pub fn list_keypairs(&self) -> Vec<String> {
        self.keypairs.keys().cloned().collect()
    }

    pub fn list_signatures(&self) -> Vec<String> {
        self.signatures.keys().cloned().collect()
    }

    pub fn list_ciphertexts(&self) -> Vec<String> {
        self.ciphertexts.keys().cloned().collect()
    }

    pub fn list_shared_secrets(&self) -> Vec<String> {
        self.shared_secrets.keys().cloned().collect()
    }
}

fn algorithm_name(algorithm: &PQCAlgorithm) -> &'static str {
    match algorithm {
        PQCAlgorithm::MLKEM1024 => "mlkem1024",
        PQCAlgorithm::MLDSA65 => "mldsa65",
        PQCAlgorithm::MLDSA87 => "mldsa87",
        PQCAlgorithm::FNDSA => "fndsa",
        PQCAlgorithm::SLHDSA => "slhdsa",
        PQCAlgorithm::HQCKEM => "hqckem",
    }
}

impl Default for PQCManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem_keypair_generation() {
        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::MLKEM1024)
            .expect("ML-KEM-1024 key generation should succeed");
        assert_eq!(public_key.algorithm, PQCAlgorithm::MLKEM1024);
        assert_eq!(private_key.algorithm, PQCAlgorithm::MLKEM1024);
        assert_eq!(public_key.key_data.len(), mlkem1024::public_key_bytes());
        assert_eq!(private_key.key_data.len(), mlkem1024::secret_key_bytes());
    }

    #[test]
    fn supported_algorithms_include_fndsa_signing() {
        let manager = PQCManager::new();

        assert!(manager
            .get_supported_algorithms()
            .contains(&PQCAlgorithm::MLDSA65));
        assert!(manager
            .get_supported_algorithms()
            .contains(&PQCAlgorithm::MLDSA87));
        assert!(manager
            .get_supported_algorithms()
            .contains(&PQCAlgorithm::FNDSA));
    }

    #[test]
    fn test_mldsa87_sign_verify() {
        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::MLDSA87)
            .expect("ML-DSA-87 key generation should succeed");
        let message = b"ML-DSA-87 consensus integration test";
        let signature = manager
            .sign(&private_key, message)
            .expect("ML-DSA-87 signing should succeed");

        assert_eq!(public_key.key_data.len(), mldsa87::public_key_bytes());
        assert_eq!(private_key.key_data.len(), mldsa87::secret_key_bytes());
        assert_eq!(signature.signature_data.len(), mldsa87::signature_bytes());
        assert!(manager
            .verify(&public_key, &signature, message)
            .expect("ML-DSA-87 verification should return bool"));
    }

    #[test]
    fn test_mldsa65_sign_verify() {
        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::MLDSA65)
            .expect("ML-DSA-65 key generation should succeed");
        let message = b"ML-DSA-65 consensus integration test";
        let signature = manager
            .sign(&private_key, message)
            .expect("ML-DSA-65 signing should succeed");

        assert_eq!(public_key.key_data.len(), mldsa65::public_key_bytes());
        assert_eq!(private_key.key_data.len(), mldsa65::secret_key_bytes());
        assert_eq!(signature.signature_data.len(), mldsa65::signature_bytes());
        assert!(manager
            .verify(&public_key, &signature, message)
            .expect("ML-DSA-65 verification should return bool"));
    }

    #[test]
    fn test_fndsa_sign_verify() {
        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .expect("FN-DSA key generation should succeed");
        let message = b"FN-DSA integration test";
        let signature = manager
            .sign(&private_key, message)
            .expect("FN-DSA signing should succeed");

        let is_valid = manager
            .verify(&public_key, &signature, message)
            .expect("FN-DSA verification should return bool");
        assert!(is_valid, "FN-DSA signature should verify");
    }

    #[test]
    fn explicit_mldsa65_algorithm_label_deserializes_without_a_legacy_alias() {
        let algorithm: PQCAlgorithm =
            serde_json::from_str("\"ML-DSA-65\"").expect("ML-DSA-65 label should parse");
        assert_eq!(algorithm, PQCAlgorithm::MLDSA65);
        assert_eq!(
            serde_json::to_string(&algorithm).expect("algorithm should serialize"),
            "\"MLDSA65\""
        );

        let signature: PQCSignature = serde_json::from_value(serde_json::json!({
            "algorithm": "ML-DSA-65",
            "signature_data": [],
            "message_hash": [],
            "public_key_id": "legacy-qc-vote",
            "created_at": 0
        }))
        .expect("ML-DSA QC signature should parse");
        assert_eq!(signature.algorithm, PQCAlgorithm::MLDSA65);
    }

    #[test]
    fn test_fndsa_rejects_tampered_signature() {
        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .expect("FN-DSA key generation should succeed");
        let message = b"tamper-check";
        let mut signature = manager
            .sign(&private_key, message)
            .expect("FN-DSA signing should succeed");

        signature.signature_data[0] ^= 0x01;

        let verify_result = manager.verify(&public_key, &signature, message);
        assert!(verify_result.is_err() || !verify_result.unwrap_or(false));
    }

    #[test]
    fn test_mlkem_encapsulate_decapsulate_via_ids() {
        let mut manager = PQCManager::new();
        let (public_key, _) = manager
            .generate_keypair(PQCAlgorithm::MLKEM1024)
            .expect("ML-KEM-1024 key generation should succeed");

        let (ciphertext, shared_secret_enc) = manager
            .encapsulate_key(&public_key.key_id)
            .expect("Encapsulation should succeed");

        let shared_secret_dec = manager
            .decapsulate_key(&public_key.key_id, &ciphertext)
            .expect("Decapsulation should succeed");

        assert_eq!(shared_secret_enc.secret, shared_secret_dec.secret);
        assert_eq!(ciphertext.algorithm, PQCAlgorithm::MLKEM1024);
        assert_eq!(shared_secret_dec.algorithm, PQCAlgorithm::MLKEM1024);
    }
}
