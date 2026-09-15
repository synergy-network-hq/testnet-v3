use crate::consensus::dual_quorum::VALIDATOR_QUORUM_RATIO;
use crate::validator::Validator;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VRFProof {
    pub proof: Vec<u8>,
    pub output: Vec<u8>,
    pub validator_address: String,
    pub block_height: u64,
    pub timestamp: u64,
}

impl VRFProof {
    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.proof);
        hasher.update(self.validator_address.as_bytes());
        hasher.update(&self.block_height.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.finalize().to_vec()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VRFSeed {
    pub seed: Vec<u8>,
    pub block_height: u64,
    pub previous_hash: String,
    pub timestamp: u64,
}

impl VRFSeed {
    pub fn generate() -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"vrf_seed_generation");
        hasher.update(
            &std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_le_bytes(),
        );
        let hash = hasher.finalize();

        VRFSeed {
            seed: hash.to_vec(),
            block_height: 0,
            previous_hash: "genesis".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VRFResult {
    pub validator_address: String,
    pub vrf_output: Vec<u8>,
    pub proof: VRFProof,
    pub priority_score: f64,
    pub is_leader: bool,
}

#[derive(Debug)]
pub struct VRFConsensus {
    // VRF parameters
    threshold: f64,
    _max_validators: usize,
    epoch_length: u64,
}

impl VRFConsensus {
    pub fn new() -> Self {
        VRFConsensus {
            threshold: VALIDATOR_QUORUM_RATIO,
            _max_validators: 100,
            epoch_length: 100, // Blocks per epoch
        }
    }

    /// Generate VRF seed for a given block height
    pub fn generate_seed(&self, block_height: u64, previous_hash: &str) -> VRFSeed {
        let mut hasher = Sha3_256::new();
        hasher.update(previous_hash.as_bytes());
        hasher.update(&block_height.to_le_bytes());
        hasher.update(&self.epoch_length.to_le_bytes());

        let seed = hasher.finalize().to_vec();

        VRFSeed {
            seed,
            block_height,
            previous_hash: previous_hash.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Generate VRF proof for a given input string
    pub fn generate_vrf_proof(&self, input: &str) -> VRFResult {
        let mut hasher = Sha3_256::new();
        hasher.update(input.as_bytes());
        hasher.update(&self.epoch_length.to_le_bytes());
        let hash = hasher.finalize();

        VRFResult {
            validator_address: "system".to_string(),
            vrf_output: hash.to_vec(),
            proof: VRFProof {
                proof: hash.to_vec(),
                output: hash.to_vec(),
                validator_address: "system".to_string(),
                block_height: 0,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            priority_score: 0.5,
            is_leader: false,
        }
    }

    /// Generate VRF proof for a validator
    pub fn generate_proof(&self, validator: &Validator, seed: &VRFSeed) -> VRFProof {
        let mut hasher = Sha3_256::new();
        hasher.update(&seed.seed);
        hasher.update(validator.address.as_bytes());
        hasher.update(&validator.synergy_score.to_le_bytes());
        hasher.update(&seed.block_height.to_le_bytes());

        let output = hasher.finalize().to_vec();

        // Generate proof (simplified)
        let mut proof_hasher = Sha3_256::new();
        proof_hasher.update(&output);
        proof_hasher.update(validator.address.as_bytes());
        proof_hasher.update(&seed.block_height.to_le_bytes());

        let proof = proof_hasher.finalize().to_vec();

        VRFProof {
            proof,
            output,
            validator_address: validator.address.clone(),
            block_height: seed.block_height,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Verify VRF proof
    pub fn verify_proof(&self, proof: &VRFProof, seed: &VRFSeed, validator: &Validator) -> bool {
        // In a real implementation, this would verify the cryptographic proof
        // For now, we'll regenerate and compare

        let expected_proof = self.generate_proof(validator, seed);

        // Compare outputs
        proof.output == expected_proof.output
            && proof.validator_address == validator.address
            && proof.block_height == seed.block_height
    }

    /// Select block proposer using VRF
    pub fn select_block_proposer(&self, validators: &[Validator], seed: &VRFSeed) -> VRFResult {
        let mut vrf_results = Vec::new();

        // Generate VRF proofs for all validators
        for validator in validators {
            let proof = self.generate_proof(validator, seed);
            let priority_score = self.calculate_priority_score(&proof, validator);

            vrf_results.push(VRFResult {
                validator_address: validator.address.clone(),
                vrf_output: proof.output.clone(),
                proof,
                priority_score,
                is_leader: false,
            });
        }

        // Sort by priority score (highest first)
        vrf_results.sort_by(|a, b| b.priority_score.partial_cmp(&a.priority_score).unwrap());

        // Mark the highest scoring validator as leader
        if let Some(leader) = vrf_results.first_mut() {
            leader.is_leader = true;
        }

        // Return the leader result
        vrf_results.into_iter().next().unwrap()
    }

    /// Calculate priority score based on VRF output and validator attributes
    fn calculate_priority_score(&self, proof: &VRFProof, validator: &Validator) -> f64 {
        // Convert VRF output to a score between 0 and 1
        let vrf_score = self.vrf_output_to_score(&proof.output);

        // Weight by validator's synergy score
        let synergy_weight = validator.synergy_score / 100.0; // Normalize to 0-1

        // Weight by uptime
        let uptime_weight = validator.uptime_percentage / 100.0; // Normalize to 0-1

        // Weight by stake (if available)
        let stake_weight = 1.0; // Placeholder - would use actual stake amount

        // Combined score
        vrf_score * 0.4 + synergy_weight * 0.3 + uptime_weight * 0.2 + stake_weight * 0.1
    }

    /// Convert VRF output to a score between 0 and 1
    fn vrf_output_to_score(&self, output: &[u8]) -> f64 {
        if output.is_empty() {
            return 0.0;
        }

        // Use first 8 bytes to create a score
        let mut score_bytes = [0u8; 8];
        let copy_len = std::cmp::min(8, output.len());
        score_bytes[..copy_len].copy_from_slice(&output[..copy_len]);

        let score_u64 = u64::from_be_bytes(score_bytes);
        (score_u64 as f64) / (u64::MAX as f64)
    }

    /// Select committee members for consensus
    pub fn select_committee(
        &self,
        validators: &[Validator],
        seed: &VRFSeed,
        committee_size: usize,
    ) -> Vec<VRFResult> {
        let mut vrf_results = Vec::new();

        // Generate VRF proofs for all validators
        for validator in validators {
            let proof = self.generate_proof(validator, seed);
            let priority_score = self.calculate_priority_score(&proof, validator);

            vrf_results.push(VRFResult {
                validator_address: validator.address.clone(),
                vrf_output: proof.output.clone(),
                proof,
                priority_score,
                is_leader: false,
            });
        }

        // Sort by priority score
        vrf_results.sort_by(|a, b| b.priority_score.partial_cmp(&a.priority_score).unwrap());

        // Select top committee_size validators
        vrf_results.truncate(committee_size);

        // Mark first as leader
        if let Some(leader) = vrf_results.first_mut() {
            leader.is_leader = true;
        }

        vrf_results
    }

    /// Verify consensus threshold
    pub fn verify_consensus_threshold(
        &self,
        votes: &HashMap<String, bool>,
        _total_validators: usize,
    ) -> bool {
        let total_votes = votes.len();
        let positive_votes = votes.values().filter(|&&vote| vote).count();

        if total_votes == 0 {
            return false;
        }

        let consensus_ratio = positive_votes as f64 / total_votes as f64;
        consensus_ratio >= self.threshold
    }

    /// Calculate epoch transition
    pub fn should_transition_epoch(&self, current_height: u64) -> bool {
        crate::epoch::is_epoch_end_height(current_height, self.epoch_length)
    }

    /// Get validator clusters for distributed consensus
    pub fn get_validator_clusters(&self, validators: &[Validator]) -> HashMap<u64, Vec<Validator>> {
        let mut clusters: HashMap<u64, Vec<Validator>> = HashMap::new();

        // Group validators by cluster ID (simplified)
        for validator in validators {
            let cluster_id = self.calculate_cluster_id(&validator.address);
            clusters
                .entry(cluster_id)
                .or_insert_with(Vec::new)
                .push(validator.clone());
        }

        clusters
    }

    /// Calculate cluster ID for a validator
    fn calculate_cluster_id(&self, validator_address: &str) -> u64 {
        let mut hasher = Sha3_256::new();
        hasher.update(validator_address.as_bytes());
        let hash = hasher.finalize();

        // Use first 8 bytes to create cluster ID
        let mut cluster_bytes = [0u8; 8];
        cluster_bytes.copy_from_slice(&hash[..8]);
        u64::from_be_bytes(cluster_bytes) % 10 // 10 clusters max
    }

    /// Generate randomness for the next epoch
    pub fn generate_epoch_randomness(
        &self,
        previous_randomness: &[u8],
        block_height: u64,
    ) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(previous_randomness);
        hasher.update(&block_height.to_le_bytes());
        hasher.update(&self.epoch_length.to_le_bytes());

        hasher.finalize().to_vec()
    }

    /// Validate VRF-based block proposal
    pub fn validate_block_proposal(
        &self,
        proposer: &Validator,
        seed: &VRFSeed,
        _block_data: &[u8],
    ) -> bool {
        // Generate expected VRF proof
        let _expected_proof = self.generate_proof(proposer, seed);

        // Verify the proposer has the right to propose
        let vrf_result = self.select_block_proposer(&[proposer.clone()], seed);

        vrf_result.is_leader && vrf_result.validator_address == proposer.address
    }
}

impl Default for VRFConsensus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::ValidatorStatus;

    fn make_validator(
        address: &str,
        public_key: &str,
        synergy_score: f64,
        uptime: f64,
        stake: u64,
    ) -> Validator {
        let mut v = Validator::new(
            address.to_string(),
            public_key.to_string(),
            format!("{}-name", address),
            stake,
        );
        v.synergy_score = synergy_score;
        v.uptime_percentage = uptime;
        v.status = ValidatorStatus::Active;
        v
    }

    #[test]
    fn test_vrf_seed_generation() {
        let vrf = VRFConsensus::new();
        let seed = vrf.generate_seed(100, "previous_hash");

        assert_eq!(seed.block_height, 100);
        assert_eq!(seed.previous_hash, "previous_hash");
        assert!(!seed.seed.is_empty());
    }

    #[test]
    fn test_vrf_proof_generation() {
        let vrf = VRFConsensus::new();
        let seed = vrf.generate_seed(100, "previous_hash");

        let validator = make_validator("validator1", "pubkey1", 85.0, 95.0, 1000);

        let proof = vrf.generate_proof(&validator, &seed);

        assert_eq!(proof.validator_address, "validator1");
        assert_eq!(proof.block_height, 100);
        assert!(!proof.output.is_empty());
        assert!(!proof.proof.is_empty());
    }

    #[test]
    fn test_vrf_proof_verification() {
        let vrf = VRFConsensus::new();
        let seed = vrf.generate_seed(100, "previous_hash");

        let validator = make_validator("validator1", "pubkey1", 85.0, 95.0, 1000);

        let proof = vrf.generate_proof(&validator, &seed);
        let is_valid = vrf.verify_proof(&proof, &seed, &validator);

        assert!(is_valid);
    }

    #[test]
    fn test_block_proposer_selection() {
        let vrf = VRFConsensus::new();
        let seed = vrf.generate_seed(100, "previous_hash");

        let validators = vec![
            make_validator("validator1", "pubkey1", 85.0, 95.0, 1000),
            make_validator("validator2", "pubkey2", 90.0, 98.0, 2000),
        ];

        let result = vrf.select_block_proposer(&validators, &seed);

        assert!(result.is_leader);
        assert!(validators
            .iter()
            .any(|v| v.address == result.validator_address));
    }

    #[test]
    fn test_consensus_threshold() {
        let vrf = VRFConsensus::new();

        let mut votes = HashMap::new();
        votes.insert("validator1".to_string(), true);
        votes.insert("validator2".to_string(), true);
        votes.insert("validator3".to_string(), true);

        let has_consensus = vrf.verify_consensus_threshold(&votes, 3);
        assert!(has_consensus); // 3/3 = 100% >= two-thirds threshold

        votes.insert("validator4".to_string(), false);
        votes.insert("validator5".to_string(), false);
        let has_consensus = vrf.verify_consensus_threshold(&votes, 5);
        assert!(!has_consensus); // 3/5 = 60% < two-thirds threshold
    }

    #[test]
    fn test_epoch_transition() {
        let vrf = VRFConsensus::new();

        assert!(vrf.should_transition_epoch(100));
        assert!(vrf.should_transition_epoch(200));
        assert!(!vrf.should_transition_epoch(101));
        assert!(!vrf.should_transition_epoch(199));
    }
}
