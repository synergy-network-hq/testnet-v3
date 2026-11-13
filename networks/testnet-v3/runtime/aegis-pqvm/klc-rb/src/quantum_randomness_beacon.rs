//! Aegis PQC Core - Quantum Randomness Beacon
//! Patent Claim [1103], [1109]: Verifiable quantum randomness generation
//! 
//! This module implements deterministic yet unpredictable entropy generation
//! combining hardware sources, ML-KEM outputs, and cryptographic extractors.
//!
//! This module integrates with the actual PQC implementations in aegis_crypto_core.

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "mlkem")]
use crate::algorithms::mlkem::{mlkem768_keypair, mlkem768_encapsulate};

#[cfg(feature = "mldsa")]
use crate::algorithms::mldsa::{mldsa87_keygen, mldsa87_sign, mldsa87_verify};

/// Beacon output with cryptographic proof
#[derive(Debug, Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct BeaconOutput {
    pub epoch: u64,
    pub randomness: [u8; 32],
    pub proof: BeaconProof,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl BeaconOutput {
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    
    #[wasm_bindgen(getter)]
    pub fn randomness(&self) -> Vec<u8> {
        self.randomness.to_vec()
    }
    
    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> BeaconProof {
        self.proof.clone()
    }
}

/// Cryptographic proof for beacon auditability
#[derive(Debug, Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct BeaconProof {
    pub epoch: u64,
    pub timestamp: u64,
    pub policy_id: String,
    pub previous_hash: [u8; 32],
    pub mlkem_ciphertext: Vec<u8>,
    pub signature: Vec<u8>,  // ML-DSA signature
    pub commitment: [u8; 32], // Commitment to inputs
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl BeaconProof {
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    
    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    
    #[wasm_bindgen(getter)]
    pub fn policy_id(&self) -> String {
        self.policy_id.clone()
    }
    
    #[wasm_bindgen(getter)]
    pub fn previous_hash(&self) -> Vec<u8> {
        self.previous_hash.to_vec()
    }
    
    #[wasm_bindgen(getter)]
    pub fn mlkem_ciphertext(&self) -> Vec<u8> {
        self.mlkem_ciphertext.clone()
    }
    
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
    
    #[wasm_bindgen(getter)]
    pub fn commitment(&self) -> Vec<u8> {
        self.commitment.to_vec()
    }
}

/// Beacon verification result
#[derive(Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum VerificationResult {
    Valid,
    InvalidSignature,
    InvalidChaining,
    InvalidCommitment,
    EpochMismatch,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl VerificationResult {
    #[wasm_bindgen]
    pub fn is_valid(&self) -> bool {
        matches!(self, VerificationResult::Valid)
    }
    
    #[wasm_bindgen]
    pub fn as_string(&self) -> String {
        match self {
            VerificationResult::Valid => "Valid".to_string(),
            VerificationResult::InvalidSignature => "InvalidSignature".to_string(),
            VerificationResult::InvalidChaining => "InvalidChaining".to_string(),
            VerificationResult::InvalidCommitment => "InvalidCommitment".to_string(),
            VerificationResult::EpochMismatch => "EpochMismatch".to_string(),
        }
    }
}

/// Entropy source trait for pluggable entropy providers
pub trait EntropySource: Send + Sync {
    fn sample(&mut self, bytes: usize) -> Vec<u8>;
    fn source_name(&self) -> &str;
}

/// Hardware entropy source (TRNG, TPM, /dev/urandom)
pub struct HardwareEntropy;

impl EntropySource for HardwareEntropy {
    fn sample(&mut self, bytes: usize) -> Vec<u8> {
        let mut buffer = vec![0u8; bytes];
        use getrandom::getrandom;
        getrandom(&mut buffer).expect("OS CSPRNG unavailable: secure entropy required");
        buffer
    }

    fn source_name(&self) -> &str {
        "hardware_trng"
    }
}

/// ML-KEM-based entropy source
pub struct MLKEMEntropy {
    public_key: Vec<u8>,
}

impl MLKEMEntropy {
    pub fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }
}

impl EntropySource for MLKEMEntropy {
    fn sample(&mut self, bytes: usize) -> Vec<u8> {
        #[cfg(feature = "mlkem")]
        {
            // Use actual ML-KEM encapsulation
            use pqrust_mlkem::mlkem768::{PublicKey, encapsulate};
            use pqrust_traits::kem::{PublicKey as _, Ciphertext as _, SharedSecret as _};
            
            if let Ok(pk) = PublicKey::from_bytes(&self.public_key) {
                let (ct, ss) = encapsulate(&pk);
                // Combine ciphertext and shared secret for entropy
                let mut output = ct.as_bytes().to_vec();
                output.extend_from_slice(ss.as_bytes());
                output.truncate(bytes);
                output
            } else {
                // Invalid public key, use fallback
                let mut hasher = Shake256::default();
                hasher.update(&self.public_key);
                hasher.update(&current_timestamp().to_le_bytes());
                let mut reader = hasher.finalize_xof();
                let mut output = vec![0u8; bytes];
                reader.read(&mut output);
                output
            }
        }
        #[cfg(not(feature = "mlkem"))]
        {
            // Fallback when mlkem is not available
            let mut hasher = Shake256::default();
            hasher.update(&self.public_key);
            hasher.update(&current_timestamp().to_le_bytes());
            let mut reader = hasher.finalize_xof();
            let mut output = vec![0u8; bytes];
            reader.read(&mut output);
            output
        }
    }

    fn source_name(&self) -> &str {
        "mlkem768"
    }
}

/// Quantum Randomness Beacon
pub struct QuantumBeacon {
    epoch: u64,
    previous_output: [u8; 32],
    beacon_chain: Vec<BeaconOutput>,
    entropy_sources: Vec<Box<dyn EntropySource>>,
    signing_keypair: Option<(Vec<u8>, Vec<u8>)>, // (pk, sk) for ML-DSA signing
    policy_map: HashMap<String, BeaconPolicy>,
}

/// Policy for beacon generation
#[derive(Debug, Clone)]
pub struct BeaconPolicy {
    pub id: String,
    pub description: String,
    pub min_entropy_sources: usize,
    pub epoch_duration_seconds: u64,
    pub require_hardware_entropy: bool,
}

impl Default for BeaconPolicy {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            description: "Default beacon policy".to_string(),
            min_entropy_sources: 2,
            epoch_duration_seconds: 300, // 5 minutes
            require_hardware_entropy: true,
        }
    }
}

impl QuantumBeacon {
    /// Create new beacon with initial entropy
    pub fn new() -> Self {
        let mut beacon = Self {
            epoch: 0,
            previous_output: [0u8; 32],
            beacon_chain: Vec::new(),
            entropy_sources: Vec::new(),
            signing_keypair: None,
            policy_map: HashMap::new(),
        };

        // Generate signing keypair for ML-DSA
        #[cfg(feature = "mldsa")]
        {
            let keypair = mldsa87_keygen();
            beacon.signing_keypair = Some((
                keypair.public_key(),
                keypair.secret_key(),
            ));
        }

        // Add default entropy sources
        beacon.add_entropy_source(Box::new(HardwareEntropy));
        
        // Initialize with genesis output
        let genesis_hash = blake3::hash(b"AEGIS_QUANTUM_BEACON_GENESIS");
        beacon.previous_output.copy_from_slice(genesis_hash.as_bytes());

        // Add default policy
        beacon.register_policy(BeaconPolicy::default());

        beacon
    }

    /// Add entropy source to beacon
    pub fn add_entropy_source(&mut self, source: Box<dyn EntropySource>) {
        self.entropy_sources.push(source);
    }

    /// Register beacon generation policy
    pub fn register_policy(&mut self, policy: BeaconPolicy) {
        self.policy_map.insert(policy.id.clone(), policy);
    }

    /// Generate beacon for current epoch
    pub fn generate_beacon(&mut self, policy_id: &str) -> Result<BeaconOutput, String> {
        let policy = self.policy_map
            .get(policy_id)
            .ok_or_else(|| format!("Policy '{}' not found", policy_id))?
            .clone();

        // Validate entropy sources
        if self.entropy_sources.len() < policy.min_entropy_sources {
            return Err(format!(
                "Insufficient entropy sources: {} < {}",
                self.entropy_sources.len(),
                policy.min_entropy_sources
            ));
        }

        let timestamp = current_timestamp();

        // Step 1: Collect entropy from all sources
        let mut entropy_inputs = Vec::new();
        for source in &mut self.entropy_sources {
            let sample = source.sample(32);
            entropy_inputs.push((source.source_name().to_string(), sample));
        }

        // Step 2: Create commitment to inputs (for proof)
        let commitment = self.create_commitment(&entropy_inputs, timestamp, policy_id);

        // Step 3: Combine all entropy sources
        let mut combined_input = Vec::new();
        
        // Previous beacon output (chaining)
        combined_input.extend_from_slice(&self.previous_output);
        
        // Timestamp
        combined_input.extend_from_slice(&timestamp.to_le_bytes());
        
        // Policy identifier
        combined_input.extend_from_slice(policy_id.as_bytes());
        
        // Epoch number
        combined_input.extend_from_slice(&self.epoch.to_le_bytes());
        
        // All entropy samples
        for (source_name, sample) in &entropy_inputs {
            combined_input.extend_from_slice(source_name.as_bytes());
            combined_input.extend_from_slice(sample);
        }

        // Step 4: Extract randomness using SHAKE256
        let randomness = self.extract_randomness(&combined_input);

        // Step 5: Create ML-DSA signature for proof
        let signature = self.sign_beacon_output(&randomness, timestamp, policy_id)?;

        // Step 6: Store ML-KEM ciphertext for auditability
        let mlkem_ciphertext = entropy_inputs
            .iter()
            .find(|(name, _)| name.contains("mlkem"))
            .map(|(_, data)| data.clone())
            .unwrap_or_default();

        // Create proof
        let proof = BeaconProof {
            epoch: self.epoch,
            timestamp,
            policy_id: policy_id.to_string(),
            previous_hash: self.previous_output,
            mlkem_ciphertext,
            signature,
            commitment,
        };

        // Create output
        let output = BeaconOutput {
            epoch: self.epoch,
            randomness,
            proof,
        };

        // Update state
        self.previous_output = randomness;
        self.epoch += 1;
        self.beacon_chain.push(output.clone());

        Ok(output)
    }

    /// Verify beacon output
    pub fn verify_beacon(&self, output: &BeaconOutput) -> VerificationResult {
        // Check epoch sequence
        if output.epoch >= self.epoch {
            return VerificationResult::EpochMismatch;
        }

        // Verify signature
        if !self.verify_signature(
            &output.randomness,
            &output.proof.signature,
            output.proof.timestamp,
            &output.proof.policy_id,
        ) {
            return VerificationResult::InvalidSignature;
        }

        // Verify chaining
        if output.epoch > 0 {
            if let Some(previous) = self.beacon_chain.get(output.epoch as usize - 1) {
                if output.proof.previous_hash != previous.randomness {
                    return VerificationResult::InvalidChaining;
                }
            }
        }

        VerificationResult::Valid
    }

    /// Get beacon history
    pub fn get_beacon_history(&self) -> &[BeaconOutput] {
        &self.beacon_chain
    }

    /// Get current epoch
    pub fn current_epoch(&self) -> u64 {
        self.epoch
    }

    /// Get beacon output by epoch
    pub fn get_beacon_by_epoch(&self, epoch: u64) -> Option<&BeaconOutput> {
        self.beacon_chain.get(epoch as usize)
    }

    /// Get verification key for third-party verification
    pub fn get_verification_key(&self) -> Option<&[u8]> {
        self.signing_keypair.as_ref().map(|(pk, _)| pk.as_slice())
    }

    // Private helper methods

    fn create_commitment(
        &self,
        entropy_inputs: &[(String, Vec<u8>)],
        timestamp: u64,
        policy_id: &str,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(policy_id.as_bytes());
        
        for (source, data) in entropy_inputs {
            hasher.update(source.as_bytes());
            hasher.update(data);
        }
        
        let hash = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(hash.as_bytes());
        commitment
    }

    fn extract_randomness(&self, input: &[u8]) -> [u8; 32] {
        let mut hasher = Shake256::default();
        hasher.update(input);
        
        let mut reader = hasher.finalize_xof();
        let mut output = [0u8; 32];
        reader.read(&mut output);
        
        output
    }

    fn sign_beacon_output(
        &self,
        randomness: &[u8; 32],
        timestamp: u64,
        policy_id: &str,
    ) -> Result<Vec<u8>, String> {
        let message = Self::construct_signature_message(randomness, timestamp, policy_id);
        
        if let Some((_, ref sk)) = self.signing_keypair {
            #[cfg(feature = "mldsa")]
            {
                Ok(mldsa87_sign(sk, &message))
            }
            #[cfg(not(feature = "mldsa"))]
            {
                Err("mldsa feature not enabled".to_string())
            }
        } else {
            Err("Signing keypair not initialized".to_string())
        }
    }

    fn verify_signature(
        &self,
        randomness: &[u8; 32],
        signature: &[u8],
        timestamp: u64,
        policy_id: &str,
    ) -> bool {
        let message = Self::construct_signature_message(randomness, timestamp, policy_id);
        
        if let Some((ref pk, _)) = self.signing_keypair {
            #[cfg(feature = "mldsa")]
            {
                mldsa87_verify(pk, &message, signature)
            }
            #[cfg(not(feature = "mldsa"))]
            {
                false
            }
        } else {
            false
        }
    }

    fn construct_signature_message(
        randomness: &[u8; 32],
        timestamp: u64,
        policy_id: &str,
    ) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(b"AEGIS_BEACON_V1:");
        message.extend_from_slice(randomness);
        message.extend_from_slice(&timestamp.to_le_bytes());
        message.extend_from_slice(policy_id.as_bytes());
        message
    }
}

/// Verify beacon output without full state (third-party verification)
pub fn verify_beacon_standalone(
    output: &BeaconOutput,
    verification_key: &[u8],
    previous_randomness: Option<[u8; 32]>,
) -> VerificationResult {
    // Basic signature verification
    let message = QuantumBeacon::construct_signature_message(
        &output.randomness,
        output.proof.timestamp,
        &output.proof.policy_id,
    );

    #[cfg(feature = "mldsa")]
    let signature_valid = mldsa87_verify(verification_key, &message, &output.proof.signature);
    #[cfg(not(feature = "mldsa"))]
    let signature_valid = false;

    if !signature_valid {
        return VerificationResult::InvalidSignature;
    }

    // Check chaining if previous provided
    if let Some(prev) = previous_randomness {
        if output.proof.previous_hash != prev {
            return VerificationResult::InvalidChaining;
        }
    }

    VerificationResult::Valid
}

/// Verify beacon output without full state (JS-friendly WASM version)
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_beacon_standalone_js(
    output: &BeaconOutput,
    verification_key: &[u8],
    previous_randomness: Option<Vec<u8>>,
) -> VerificationResult {
    let prev_option = previous_randomness.and_then(|prev_vec| {
        if prev_vec.len() == 32 {
            let mut prev = [0u8; 32];
            prev.copy_from_slice(&prev_vec);
            Some(prev)
        } else {
            None
        }
    });
    
    verify_beacon_standalone(output, verification_key, prev_option)
}

// Make construct_signature_message public for standalone verification
impl QuantumBeacon {
    pub fn construct_signature_message(
        randomness: &[u8; 32],
        timestamp: u64,
        policy_id: &str,
    ) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(b"AEGIS_BEACON_V1:");
        message.extend_from_slice(randomness);
        message.extend_from_slice(&timestamp.to_le_bytes());
        message.extend_from_slice(policy_id.as_bytes());
        message
    }
}

// WASM bindings for QuantumBeacon
#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl QuantumBeacon {
    /// Create a new beacon instance (JS-friendly constructor)
    #[wasm_bindgen(constructor)]
    pub fn new_js() -> QuantumBeacon {
        Self::new()
    }
    
    /// Generate beacon for current epoch (JS-friendly)
    #[wasm_bindgen]
    pub fn generate(&mut self, policy_id: &str) -> Result<BeaconOutput, String> {
        self.generate_beacon(policy_id)
    }
    
    /// Verify beacon output (JS-friendly)
    #[wasm_bindgen]
    pub fn verify(&self, output: &BeaconOutput) -> VerificationResult {
        self.verify_beacon(output)
    }
    
    /// Get current epoch (JS-friendly)
    #[wasm_bindgen]
    pub fn epoch(&self) -> u64 {
        self.current_epoch()
    }
    
    /// Get verification key for third-party verification (JS-friendly)
    #[wasm_bindgen]
    pub fn verification_key(&self) -> Option<Vec<u8>> {
        self.get_verification_key().map(|k| k.to_vec())
    }
}

// Utility functions

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
