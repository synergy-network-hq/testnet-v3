//! Aegis PQC Core - Quantum Randomness Beacon
//! Patent Claim [1103], [1109]: Verifiable quantum randomness generation
//!
//! This module implements deterministic yet unpredictable entropy generation
//! combining hardware sources, ML-KEM outputs, and cryptographic extractors.
//!
//! This module integrates with the actual PQC implementations in aegis-pqvm.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tiny_keccak::{Hasher, Sha3, Shake, Xof};

#[cfg(feature = "mlkem")]
use crate::pqc::kem::mlkem::mlkem768::{
    encapsulate as mlkem768_encapsulate, PublicKey as MLKEM768PublicKey,
};

#[cfg(feature = "fndsa")]
use crate::pqc::signatures::fndsa::fndsa1024::{
    detached_sign as fndsa1024_detached_sign, keypair as fndsa1024_keypair,
    verify_detached_signature as fndsa1024_verify_detached_signature,
    DetachedSignature as FNDSA1024DetachedSignature, PublicKey as FNDSA1024PublicKey,
    SecretKey as FNDSA1024SecretKey,
};

/// Beacon output with cryptographic proof
#[derive(Debug, Clone)]
pub struct BeaconOutput {
    pub epoch: u64,
    pub randomness: [u8; 32],
    pub proof: BeaconProof,
}

/// Cryptographic proof for beacon auditability
#[derive(Debug, Clone)]
pub struct BeaconProof {
    pub epoch: u64,
    pub timestamp: u64,
    pub policy_id: String,
    pub previous_hash: [u8; 32],
    pub entropy_inputs: Vec<(String, Vec<u8>)>,
    pub entropy_sources_used: Vec<String>,
    pub hardware_entropy_sources_used: Vec<String>,
    pub mlkem_ciphertext: Vec<u8>,
    pub signature: Vec<u8>,   // FN-DSA signature
    pub commitment: [u8; 32], // Commitment to inputs
}

/// Beacon verification result
#[derive(Debug, PartialEq)]
pub enum VerificationResult {
    Valid,
    InvalidSignature,
    InvalidChaining,
    InvalidCommitment,
    PolicyViolation,
    EpochMismatch,
}

/// Entropy source trait for pluggable entropy providers
pub trait EntropySource: Send + Sync {
    fn sample(&mut self, bytes: usize) -> Result<Vec<u8>, String>;
    fn source_name(&self) -> &str;
}

struct RegisteredEntropySource {
    source: Box<dyn EntropySource>,
    hardware_attested: bool,
}

impl RegisteredEntropySource {
    fn new(source: Box<dyn EntropySource>, hardware_attested: bool) -> Self {
        Self {
            source,
            hardware_attested,
        }
    }
}

struct CommitmentContext<'a> {
    epoch: u64,
    randomness: &'a [u8; 32],
    timestamp: u64,
    policy_id: &'a str,
    previous_hash: &'a [u8; 32],
    entropy_inputs: &'a [(String, Vec<u8>)],
    hardware_entropy_sources_used: &'a [String],
    mlkem_ciphertext: &'a [u8],
}

/// Hardware entropy source (TRNG, TPM, /dev/urandom)
pub struct HardwareEntropy;

impl EntropySource for HardwareEntropy {
    fn sample(&mut self, bytes: usize) -> Result<Vec<u8>, String> {
        let mut buffer = vec![0u8; bytes];
        use getrandom::getrandom;
        getrandom(&mut buffer).map_err(|err| format!("OS CSPRNG unavailable: {err}"))?;
        Ok(buffer)
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
    fn sample(&mut self, bytes: usize) -> Result<Vec<u8>, String> {
        #[cfg(feature = "mlkem")]
        {
            // Use actual ML-KEM encapsulation
            use pqrust_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
            if let Ok(pk) = MLKEM768PublicKey::from_bytes(&self.public_key) {
                let (ss, ct) = mlkem768_encapsulate(&pk);
                // Combine ciphertext and shared secret for entropy
                let mut output = ct.as_bytes().to_vec();
                output.extend_from_slice(ss.as_bytes());
                if output.len() >= bytes {
                    output.truncate(bytes);
                    Ok(output)
                } else {
                    // Stretch strong seed material with SHAKE256 when caller asks for more bytes.
                    let mut hasher = Shake::v256();
                    hasher.update(&output);
                    let mut expanded = vec![0u8; bytes];
                    hasher.squeeze(&mut expanded);
                    Ok(expanded)
                }
            } else {
                // Invalid key material: use secure OS entropy fallback.
                let mut output = vec![0u8; bytes];
                use getrandom::getrandom;
                getrandom(&mut output).map_err(|err| {
                    format!(
                        "OS CSPRNG unavailable while recovering from ML-KEM entropy error: {err}"
                    )
                })?;
                Ok(output)
            }
        }
        #[cfg(not(feature = "mlkem"))]
        {
            // Feature-disabled fallback uses secure OS entropy.
            let mut output = vec![0u8; bytes];
            use getrandom::getrandom;
            getrandom(&mut output).map_err(|err| {
                format!("OS CSPRNG unavailable while ML-KEM feature is disabled: {err}")
            })?;
            Ok(output)
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
    entropy_sources: Vec<RegisteredEntropySource>,
    signing_keypair: Option<(Vec<u8>, Vec<u8>)>, // (pk, sk) for FN-DSA signing
    policy_map: HashMap<String, BeaconPolicy>,
    last_beacon_timestamp: Option<u64>,
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
            last_beacon_timestamp: None,
        };

        // Generate signing keypair for FN-DSA
        #[cfg(feature = "fndsa")]
        {
            use pqrust_traits::sign::{PublicKey as _, SecretKey as _};
            let (pk, sk) = fndsa1024_keypair();
            beacon.signing_keypair = Some((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()));
        }

        // Add default entropy sources
        beacon.add_hardware_entropy_source(Box::new(HardwareEntropy));

        // Initialize with genesis output
        let mut hasher = Sha3::v256();
        hasher.update(b"AEGIS_QUANTUM_BEACON_GENESIS");
        hasher.finalize(&mut beacon.previous_output);

        // Add default policy
        beacon.register_policy(BeaconPolicy::default());

        beacon
    }

    /// Add entropy source to beacon
    pub fn add_entropy_source(&mut self, source: Box<dyn EntropySource>) {
        self.entropy_sources
            .push(RegisteredEntropySource::new(source, false));
    }

    /// Add an entropy source that is explicitly attested as hardware-backed.
    pub fn add_hardware_entropy_source(&mut self, source: Box<dyn EntropySource>) {
        self.entropy_sources
            .push(RegisteredEntropySource::new(source, true));
    }

    /// Register beacon generation policy
    pub fn register_policy(&mut self, policy: BeaconPolicy) {
        self.policy_map.insert(policy.id.clone(), policy);
    }

    /// Generate beacon for current epoch
    pub fn generate_beacon(&mut self, policy_id: &str) -> Result<BeaconOutput, String> {
        let policy = self
            .policy_map
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
        if policy.require_hardware_entropy
            && !self
                .entropy_sources
                .iter()
                .any(|entry| entry.hardware_attested)
        {
            return Err(
                "Policy requires hardware entropy but no hardware entropy source is registered"
                    .to_string(),
            );
        }

        let timestamp = current_timestamp();
        if let Some(last_timestamp) = self.last_beacon_timestamp {
            let minimum_allowed = last_timestamp.saturating_add(policy.epoch_duration_seconds);
            if timestamp < minimum_allowed {
                return Err(format!(
                    "Epoch policy violation: current timestamp {timestamp} is earlier than minimum allowed {minimum_allowed}"
                ));
            }
        }

        // Step 1: Collect entropy from all sources
        let mut entropy_inputs = Vec::new();
        let mut hardware_entropy_sources_used = Vec::new();
        for entry in &mut self.entropy_sources {
            let source_name = entry.source.source_name().to_string();
            let sample = entry
                .source
                .sample(32)
                .map_err(|err| format!("Entropy source '{source_name}' failed: {err}"))?;
            if entry.hardware_attested {
                hardware_entropy_sources_used.push(source_name.clone());
            }
            entropy_inputs.push((source_name, sample));
        }

        // Step 3: Combine all entropy sources
        let combined_input = build_randomness_input(
            self.epoch,
            timestamp,
            policy_id,
            &self.previous_output,
            &entropy_inputs,
        );

        // Step 4: Extract randomness using SHAKE256
        let randomness = self.extract_randomness(&combined_input);

        // Step 5: Store source metadata and ML-KEM ciphertext for auditability
        let entropy_sources_used = entropy_inputs
            .iter()
            .map(|(source_name, _)| source_name.clone())
            .collect::<Vec<_>>();
        let mlkem_ciphertext = entropy_inputs
            .iter()
            .find(|(name, _)| name.contains("mlkem"))
            .map(|(_, data)| data.clone())
            .unwrap_or_default();

        // Step 6: Create commitment to proof-critical fields
        let commitment = QuantumBeacon::construct_commitment(&CommitmentContext {
            epoch: self.epoch,
            randomness: &randomness,
            timestamp,
            policy_id,
            previous_hash: &self.previous_output,
            entropy_inputs: &entropy_inputs,
            hardware_entropy_sources_used: &hardware_entropy_sources_used,
            mlkem_ciphertext: &mlkem_ciphertext,
        });

        // Step 7: Create FN-DSA signature for proof
        let signature = self.sign_beacon_output(&randomness, timestamp, policy_id)?;

        // Create proof
        let proof = BeaconProof {
            epoch: self.epoch,
            timestamp,
            policy_id: policy_id.to_string(),
            previous_hash: self.previous_output,
            entropy_inputs,
            entropy_sources_used,
            hardware_entropy_sources_used,
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
        self.last_beacon_timestamp = Some(timestamp);
        self.beacon_chain.push(output.clone());

        Ok(output)
    }

    /// Verify beacon output
    pub fn verify_beacon(&self, output: &BeaconOutput) -> VerificationResult {
        // Check epoch sequence
        if output.epoch >= self.epoch {
            return VerificationResult::EpochMismatch;
        }
        if output.proof.epoch != output.epoch {
            return VerificationResult::EpochMismatch;
        }
        let policy = match self.policy_map.get(&output.proof.policy_id) {
            Some(policy) => policy,
            None => return VerificationResult::PolicyViolation,
        };
        let derived_sources = output
            .proof
            .entropy_inputs
            .iter()
            .map(|(source_name, _)| source_name.clone())
            .collect::<Vec<_>>();
        if derived_sources != output.proof.entropy_sources_used {
            return VerificationResult::InvalidCommitment;
        }
        if derived_sources.len() < policy.min_entropy_sources {
            return VerificationResult::PolicyViolation;
        }
        if policy.require_hardware_entropy && output.proof.hardware_entropy_sources_used.is_empty()
        {
            return VerificationResult::PolicyViolation;
        }
        if output
            .proof
            .hardware_entropy_sources_used
            .iter()
            .any(|source_name| !derived_sources.iter().any(|derived| derived == source_name))
        {
            return VerificationResult::InvalidCommitment;
        }
        let derived_mlkem_ciphertext = output
            .proof
            .entropy_inputs
            .iter()
            .find(|(name, _)| name.contains("mlkem"))
            .map(|(_, data)| data.clone())
            .unwrap_or_default();
        if derived_mlkem_ciphertext != output.proof.mlkem_ciphertext {
            return VerificationResult::InvalidCommitment;
        }
        let expected_randomness = extract_randomness_bytes(&build_randomness_input(
            output.epoch,
            output.proof.timestamp,
            &output.proof.policy_id,
            &output.proof.previous_hash,
            &output.proof.entropy_inputs,
        ));
        if expected_randomness != output.randomness {
            return VerificationResult::InvalidCommitment;
        }

        let expected_commitment = QuantumBeacon::construct_commitment(&CommitmentContext {
            epoch: output.epoch,
            randomness: &output.randomness,
            timestamp: output.proof.timestamp,
            policy_id: &output.proof.policy_id,
            previous_hash: &output.proof.previous_hash,
            entropy_inputs: &output.proof.entropy_inputs,
            hardware_entropy_sources_used: &output.proof.hardware_entropy_sources_used,
            mlkem_ciphertext: &output.proof.mlkem_ciphertext,
        });
        if output.proof.commitment != expected_commitment {
            return VerificationResult::InvalidCommitment;
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
            let Some(previous) = self.beacon_chain.get(output.epoch as usize - 1) else {
                return VerificationResult::InvalidChaining;
            };
            if output.proof.previous_hash != previous.randomness {
                return VerificationResult::InvalidChaining;
            }

            let minimum_allowed = previous
                .proof
                .timestamp
                .saturating_add(policy.epoch_duration_seconds);
            if output.proof.timestamp < minimum_allowed {
                return VerificationResult::PolicyViolation;
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

    fn construct_commitment(ctx: &CommitmentContext<'_>) -> [u8; 32] {
        let mut hasher = Sha3::v256();
        hasher.update(b"AEGIS_BEACON_COMMITMENT_V1");
        hasher.update(&ctx.epoch.to_le_bytes());
        hasher.update(ctx.randomness);
        hasher.update(&ctx.timestamp.to_le_bytes());
        hash_len_prefixed(&mut hasher, ctx.policy_id.as_bytes());
        hasher.update(ctx.previous_hash);
        hasher.update(&(ctx.entropy_inputs.len() as u64).to_le_bytes());
        for (source, sample) in ctx.entropy_inputs {
            hash_len_prefixed(&mut hasher, source.as_bytes());
            hash_len_prefixed(&mut hasher, sample);
        }
        hasher.update(&(ctx.hardware_entropy_sources_used.len() as u64).to_le_bytes());
        for source in ctx.hardware_entropy_sources_used {
            hash_len_prefixed(&mut hasher, source.as_bytes());
        }
        hash_len_prefixed(&mut hasher, ctx.mlkem_ciphertext);

        let mut commitment = [0u8; 32];
        hasher.finalize(&mut commitment);
        commitment
    }

    fn extract_randomness(&self, input: &[u8]) -> [u8; 32] {
        extract_randomness_bytes(input)
    }

    fn sign_beacon_output(
        &self,
        randomness: &[u8; 32],
        timestamp: u64,
        policy_id: &str,
    ) -> Result<Vec<u8>, String> {
        let message = QuantumBeacon::construct_signature_message(randomness, timestamp, policy_id);

        if let Some((_, ref sk_bytes)) = self.signing_keypair {
            #[cfg(not(feature = "fndsa"))]
            let _ = (&message, sk_bytes);
            #[cfg(feature = "fndsa")]
            {
                use pqrust_traits::sign::{DetachedSignature as _, SecretKey as _};
                if let Ok(sk) = FNDSA1024SecretKey::from_bytes(sk_bytes) {
                    let signature = fndsa1024_detached_sign(&message, &sk);
                    Ok(signature.as_bytes().to_vec())
                } else {
                    Err("Invalid secret key".to_string())
                }
            }
            #[cfg(not(feature = "fndsa"))]
            {
                Err("FN-DSA feature not enabled".to_string())
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
        let message = QuantumBeacon::construct_signature_message(randomness, timestamp, policy_id);

        if let Some((ref pk_bytes, _)) = self.signing_keypair {
            #[cfg(not(feature = "fndsa"))]
            let _ = (&message, signature, pk_bytes);
            #[cfg(feature = "fndsa")]
            {
                use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};
                if let Ok(pk) = FNDSA1024PublicKey::from_bytes(pk_bytes) {
                    if let Ok(detached_sig) = FNDSA1024DetachedSignature::from_bytes(signature) {
                        fndsa1024_verify_detached_signature(&detached_sig, &message, &pk).is_ok()
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            #[cfg(not(feature = "fndsa"))]
            {
                false
            }
        } else {
            false
        }
    }

    /// Construct signature message for beacon output (public for standalone verification)
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

impl Default for QuantumBeacon {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify beacon output without full state (third-party verification)
pub fn verify_beacon_standalone(
    output: &BeaconOutput,
    verification_key: &[u8],
    previous_randomness: Option<[u8; 32]>,
) -> VerificationResult {
    if output.proof.epoch != output.epoch {
        return VerificationResult::EpochMismatch;
    }
    let derived_sources = output
        .proof
        .entropy_inputs
        .iter()
        .map(|(source_name, _)| source_name.clone())
        .collect::<Vec<_>>();
    if derived_sources != output.proof.entropy_sources_used {
        return VerificationResult::InvalidCommitment;
    }
    if output
        .proof
        .hardware_entropy_sources_used
        .iter()
        .any(|source_name| !derived_sources.iter().any(|derived| derived == source_name))
    {
        return VerificationResult::InvalidCommitment;
    }
    let derived_mlkem_ciphertext = output
        .proof
        .entropy_inputs
        .iter()
        .find(|(name, _)| name.contains("mlkem"))
        .map(|(_, data)| data.clone())
        .unwrap_or_default();
    if derived_mlkem_ciphertext != output.proof.mlkem_ciphertext {
        return VerificationResult::InvalidCommitment;
    }
    let expected_randomness = extract_randomness_bytes(&build_randomness_input(
        output.epoch,
        output.proof.timestamp,
        &output.proof.policy_id,
        &output.proof.previous_hash,
        &output.proof.entropy_inputs,
    ));
    if expected_randomness != output.randomness {
        return VerificationResult::InvalidCommitment;
    }
    let expected_commitment = QuantumBeacon::construct_commitment(&CommitmentContext {
        epoch: output.epoch,
        randomness: &output.randomness,
        timestamp: output.proof.timestamp,
        policy_id: &output.proof.policy_id,
        previous_hash: &output.proof.previous_hash,
        entropy_inputs: &output.proof.entropy_inputs,
        hardware_entropy_sources_used: &output.proof.hardware_entropy_sources_used,
        mlkem_ciphertext: &output.proof.mlkem_ciphertext,
    });
    if output.proof.commitment != expected_commitment {
        return VerificationResult::InvalidCommitment;
    }

    // Basic signature verification
    let message = QuantumBeacon::construct_signature_message(
        &output.randomness,
        output.proof.timestamp,
        &output.proof.policy_id,
    );
    #[cfg(not(feature = "fndsa"))]
    let _ = (verification_key, &message);

    #[cfg(feature = "fndsa")]
    let signature_valid = {
        use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};
        if let Ok(pk) = FNDSA1024PublicKey::from_bytes(verification_key) {
            if let Ok(detached_sig) =
                FNDSA1024DetachedSignature::from_bytes(&output.proof.signature)
            {
                fndsa1024_verify_detached_signature(&detached_sig, &message, &pk).is_ok()
            } else {
                false
            }
        } else {
            false
        }
    };
    #[cfg(not(feature = "fndsa"))]
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

// Utility functions

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn build_randomness_input(
    epoch: u64,
    timestamp: u64,
    policy_id: &str,
    previous_hash: &[u8; 32],
    entropy_inputs: &[(String, Vec<u8>)],
) -> Vec<u8> {
    let mut combined_input = Vec::new();
    combined_input.extend_from_slice(previous_hash);
    combined_input.extend_from_slice(&timestamp.to_le_bytes());
    combined_input.extend_from_slice(policy_id.as_bytes());
    combined_input.extend_from_slice(&epoch.to_le_bytes());
    for (source_name, sample) in entropy_inputs {
        combined_input.extend_from_slice(source_name.as_bytes());
        combined_input.extend_from_slice(sample);
    }
    combined_input
}

fn extract_randomness_bytes(input: &[u8]) -> [u8; 32] {
    let mut hasher = Shake::v256();
    hasher.update(input);

    let mut output = [0u8; 32];
    hasher.squeeze(&mut output);
    output
}

fn hash_len_prefixed(hasher: &mut Sha3, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}
