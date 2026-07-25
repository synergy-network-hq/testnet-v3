use crate::consensus::synergy_score::{EpochSnapshot, SynergyScoreCalculator, ValidatorMetrics};
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCSignature};
use crate::validator::{Validator, ValidatorManager};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProposalType {
    ParameterAdjustment,
    ProtocolUpgrade,
    EmergencyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub proposal_id: String,
    pub proposal_type: ProposalType,
    pub title: String,
    pub description: String,
    pub parameters: HashMap<String, String>,
    pub proposer: String,
    pub submitted_at: u64,
    pub discussion_end: u64,
    pub voting_end: u64,
    pub execution_timestamp: u64,
    pub status: ProposalStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalStatus {
    Discussion,
    Voting,
    Approved,
    Rejected,
    Executed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVote {
    pub proposal_id: String,
    pub validator_address: String,
    pub vote_type: VoteType,
    pub vote_weight: f64,
    pub signature: PQCSignature,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VoteType {
    Approve,
    Reject,
    Abstain,
}

#[derive(Debug)]
pub struct DAOGovernance {
    pub validator_manager: Arc<ValidatorManager>,
    pub synergy_calculator: Arc<SynergyScoreCalculator>,
    pub pqc_manager: Arc<Mutex<PQCManager>>,
    pub proposals: HashMap<String, GovernanceProposal>,
    pub votes: HashMap<String, Vec<ValidatorVote>>, // proposal_id -> votes
    pub total_governance_weight: f64,
    pub proposal_bond_requirement: f64,
    pub approval_thresholds: HashMap<ProposalType, f64>,
    pub discussion_period: u64,
    pub voting_period: u64,
    pub timelock_period: u64,
}

impl DAOGovernance {
    pub fn new(
        validator_manager: Arc<ValidatorManager>,
        synergy_calculator: Arc<SynergyScoreCalculator>,
        pqc_manager: Arc<Mutex<PQCManager>>,
    ) -> Self {
        let mut approval_thresholds = HashMap::new();
        approval_thresholds.insert(ProposalType::ParameterAdjustment, 0.50);
        approval_thresholds.insert(ProposalType::ProtocolUpgrade, 0.67);
        approval_thresholds.insert(ProposalType::EmergencyAction, 0.80);

        DAOGovernance {
            validator_manager,
            synergy_calculator,
            pqc_manager,
            proposals: HashMap::new(),
            votes: HashMap::new(),
            total_governance_weight: 1_000_000.0, // Precision units
            proposal_bond_requirement: 0.05,      // 5% of total synergy score
            approval_thresholds,
            discussion_period: 7 * 24 * 60 * 60, // 7 days in seconds
            voting_period: 3 * 24 * 60 * 60,     // 3 days in seconds
            timelock_period: 2 * 24 * 60 * 60,   // 2 days in seconds
        }
    }

    pub fn submit_proposal(
        &mut self,
        proposer: &str,
        proposal_type: ProposalType,
        title: String,
        description: String,
        parameters: HashMap<String, String>,
    ) -> Result<String, String> {
        // Check if proposer is an active validator
        let validator = self
            .validator_manager
            .get_validator(proposer)
            .ok_or("Proposer is not a registered validator".to_string())?;

        // Check proposal bond requirement
        let synergy_components = self.synergy_calculator.calculate_synergy_score(&validator);
        let bond_amount = synergy_components.normalized_score * self.proposal_bond_requirement;

        if bond_amount < 0.01 {
            return Err("Insufficient synergy score for proposal bond".to_string());
        }

        let proposal_id = format!(
            "prop_{}_{}",
            proposal_type_to_string(&proposal_type),
            Self::current_timestamp()
        );
        let current_time = Self::current_timestamp();

        let proposal = GovernanceProposal {
            proposal_id: proposal_id.clone(),
            proposal_type,
            title,
            description,
            parameters,
            proposer: proposer.to_string(),
            submitted_at: current_time,
            discussion_end: current_time + self.discussion_period,
            voting_end: current_time + self.discussion_period + self.voting_period,
            execution_timestamp: current_time
                + self.discussion_period
                + self.voting_period
                + self.timelock_period,
            status: ProposalStatus::Discussion,
        };

        self.proposals.insert(proposal_id.clone(), proposal);
        Ok(proposal_id)
    }

    pub fn cast_vote(
        &mut self,
        validator_address: &str,
        proposal_id: &str,
        vote_type: VoteType,
    ) -> Result<(), String> {
        // Check if proposal exists and is in voting period
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or("Proposal not found".to_string())?;

        if proposal.status != ProposalStatus::Voting {
            return Err("Proposal is not in voting period".to_string());
        }

        let current_time = Self::current_timestamp();
        if current_time < proposal.voting_end {
            return Err("Voting period has ended".to_string());
        }

        // Get validator and calculate vote weight
        let validator = self
            .validator_manager
            .get_validator(validator_address)
            .ok_or("Validator not found".to_string())?;

        let synergy_components = self.synergy_calculator.calculate_synergy_score(&validator);
        let vote_weight = synergy_components.normalized_score * self.total_governance_weight;

        // Create signature for the vote
        let message = format!(
            "{}:{}:{}",
            validator_address,
            proposal_id,
            vote_type_to_string(&vote_type)
        );
        let mut pqc_manager = self.pqc_manager.lock().unwrap();

        // Get validator's private key (in real implementation, this would be secure)
        let private_key = self.get_validator_private_key(validator_address)?;

        let signature = pqc_manager
            .sign(&private_key, message.as_bytes())
            .map_err(|e| format!("Failed to sign vote: {}", e))?;

        let vote = ValidatorVote {
            proposal_id: proposal_id.to_string(),
            validator_address: validator_address.to_string(),
            vote_type,
            vote_weight,
            signature,
            timestamp: current_time,
        };

        self.votes
            .entry(proposal_id.to_string())
            .or_insert_with(Vec::new)
            .push(vote);

        Ok(())
    }

    pub fn calculate_vote_results(
        &self,
        proposal_id: &str,
    ) -> Result<HashMap<VoteType, f64>, String> {
        let votes = self
            .votes
            .get(proposal_id)
            .ok_or("No votes found for proposal".to_string())?;

        let mut results = HashMap::new();
        results.insert(VoteType::Approve, 0.0);
        results.insert(VoteType::Reject, 0.0);
        results.insert(VoteType::Abstain, 0.0);

        for vote in votes {
            *results.get_mut(&vote.vote_type).unwrap() += vote.vote_weight;
        }

        Ok(results)
    }

    pub fn check_proposal_approval(&self, proposal_id: &str) -> Result<bool, String> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or("Proposal not found".to_string())?;

        let vote_results = self.calculate_vote_results(proposal_id)?;
        let approve_weight = vote_results.get(&VoteType::Approve).unwrap_or(&0.0);
        let total_weight = self.total_governance_weight;

        let threshold = self
            .approval_thresholds
            .get(&proposal.proposal_type)
            .ok_or("Unknown proposal type".to_string())?;

        // Check if approval weight meets threshold
        let approval_met = approve_weight / total_weight > *threshold;

        // Check quorum requirement (minimum participation)
        let quorum_met = self.check_quorum_requirement(proposal_id)?;

        Ok(approval_met && quorum_met)
    }

    fn check_quorum_requirement(&self, proposal_id: &str) -> Result<bool, String> {
        let votes = self
            .votes
            .get(proposal_id)
            .ok_or("No votes found for proposal".to_string())?;

        let total_vote_weight: f64 = votes.iter().map(|v| v.vote_weight).sum();
        let quorum_threshold = 0.40; // 40% of total governance weight

        Ok(total_vote_weight / self.total_governance_weight >= quorum_threshold)
    }

    pub fn execute_approved_proposal(&mut self, proposal_id: &str) -> Result<(), String> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or("Proposal not found".to_string())?;

        if proposal.status != ProposalStatus::Approved {
            return Err("Proposal is not approved".to_string());
        }

        let current_time = Self::current_timestamp();
        if current_time < proposal.execution_timestamp {
            return Err("Timelock period not yet completed".to_string());
        }

        // Execute the proposal based on type
        match proposal.proposal_type {
            ProposalType::ParameterAdjustment => {
                self.execute_parameter_adjustment(proposal)?;
            }
            ProposalType::ProtocolUpgrade => {
                self.execute_protocol_upgrade(proposal)?;
            }
            ProposalType::EmergencyAction => {
                self.execute_emergency_action(proposal)?;
            }
        }

        // Update proposal status
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            proposal.status = ProposalStatus::Executed;
        }

        Ok(())
    }

    fn execute_parameter_adjustment(&self, proposal: &GovernanceProposal) -> Result<(), String> {
        // Update consensus parameters based on proposal
        for (param_name, param_value) in &proposal.parameters {
            match param_name.as_str() {
                "epoch_length" => {
                    // Update epoch length in consensus configuration
                    println!("🔧 Updating epoch length to: {}", param_value);
                }
                "cluster_size" => {
                    // Update cluster size
                    println!("🔧 Updating cluster size to: {}", param_value);
                }
                "quorum_threshold" => {
                    // Update quorum thresholds
                    println!("🔧 Updating quorum threshold to: {}", param_value);
                }
                "stake_cap" => {
                    // Update stake cap
                    println!("🔧 Updating stake cap to: {}", param_value);
                }
                _ => {
                    println!("🔧 Updating parameter {} to: {}", param_name, param_value);
                }
            }
        }

        Ok(())
    }

    fn execute_protocol_upgrade(&self, proposal: &GovernanceProposal) -> Result<(), String> {
        // Execute protocol upgrade
        println!("🔧 Executing protocol upgrade: {}", proposal.title);

        // Update consensus rules, cryptographic algorithms, etc.
        for (param_name, param_value) in &proposal.parameters {
            match param_name.as_str() {
                "consensus_rules" => {
                    println!("🔧 Updating consensus rules to: {}", param_value);
                }
                "cryptographic_algorithm" => {
                    println!("🔧 Updating cryptographic algorithm to: {}", param_value);
                }
                "reward_distribution" => {
                    println!("🔧 Updating reward distribution to: {}", param_value);
                }
                _ => {
                    println!(
                        "🔧 Updating protocol parameter {} to: {}",
                        param_name, param_value
                    );
                }
            }
        }

        Ok(())
    }

    fn execute_emergency_action(&self, proposal: &GovernanceProposal) -> Result<(), String> {
        // Execute emergency action
        println!("⚠️ Executing emergency action: {}", proposal.title);

        for (param_name, param_value) in &proposal.parameters {
            match param_name.as_str() {
                "network_pause" => {
                    if param_value == "true" {
                        println!("⚠️ PAUSING NETWORK OPERATIONS");
                    } else {
                        println!("🔧 RESUMING NETWORK OPERATIONS");
                    }
                }
                "rollback_block" => {
                    println!("⚠️ ROLLING BACK TO BLOCK: {}", param_value);
                }
                "validator_ejection" => {
                    println!("⚠️ EJECTING VALIDATOR: {}", param_value);
                }
                _ => {
                    println!(
                        "⚠️ Executing emergency parameter {}: {}",
                        param_name, param_value
                    );
                }
            }
        }

        Ok(())
    }

    pub fn update_proposal_status(
        &mut self,
        proposal_id: &str,
        new_status: ProposalStatus,
    ) -> Result<(), String> {
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            proposal.status = new_status;
            Ok(())
        } else {
            Err("Proposal not found".to_string())
        }
    }

    pub fn transition_proposal_to_voting(&mut self, proposal_id: &str) -> Result<(), String> {
        let current_time = Self::current_timestamp();
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            if proposal.status == ProposalStatus::Discussion
                && current_time >= proposal.discussion_end
            {
                proposal.status = ProposalStatus::Voting;
                println!("🔧 Proposal {} transitioned to voting phase", proposal_id);
                Ok(())
            } else {
                Err("Proposal cannot be transitioned to voting".to_string())
            }
        } else {
            Err("Proposal not found".to_string())
        }
    }

    pub fn finalize_voting(&mut self, proposal_id: &str) -> Result<(), String> {
        let current_time = Self::current_timestamp();
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            if proposal.status == ProposalStatus::Voting && current_time >= proposal.voting_end {
                // Release the mutable borrow before checking approval
                let _ = proposal;

                let approved = self.check_proposal_approval(proposal_id)?;

                // Get mutable borrow again to update status
                if let Some(proposal_mut) = self.proposals.get_mut(proposal_id) {
                    if approved {
                        proposal_mut.status = ProposalStatus::Approved;
                        println!(
                            "🎉 Proposal {} approved and scheduled for execution",
                            proposal_id
                        );
                    } else {
                        proposal_mut.status = ProposalStatus::Rejected;
                        println!("❌ Proposal {} rejected", proposal_id);
                    }
                }
                Ok(())
            } else {
                Err("Proposal cannot be finalized".to_string())
            }
        } else {
            Err("Proposal not found".to_string())
        }
    }

    fn get_validator_private_key(
        &self,
        _validator_address: &str,
    ) -> Result<crate::crypto::pqc::PQCPrivateKey, String> {
        // In real implementation, this would retrieve the proper private key securely
        let mut pqc_manager = self.pqc_manager.lock().unwrap();

        // Generate a new key if needed (for demo purposes)
        let (_pub_key, priv_key) = pqc_manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .map_err(|e| format!("Failed to generate keypair: {}", e))?;

        Ok(priv_key)
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

fn proposal_type_to_string(proposal_type: &ProposalType) -> String {
    match proposal_type {
        ProposalType::ParameterAdjustment => "param".to_string(),
        ProposalType::ProtocolUpgrade => "proto".to_string(),
        ProposalType::EmergencyAction => "emerg".to_string(),
    }
}

fn vote_type_to_string(vote_type: &VoteType) -> String {
    match vote_type {
        VoteType::Approve => "approve".to_string(),
        VoteType::Reject => "reject".to_string(),
        VoteType::Abstain => "abstain".to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct SynergyOracle {
    pub validator_metrics: HashMap<String, ValidatorMetrics>,
    pub epoch_snapshots: HashMap<u64, EpochSnapshot>,
    pub synergy_calculator: Arc<SynergyScoreCalculator>,
    pub pqc_manager: Arc<Mutex<PQCManager>>,
}

impl SynergyOracle {
    pub fn new(
        synergy_calculator: Arc<SynergyScoreCalculator>,
        pqc_manager: Arc<Mutex<PQCManager>>,
    ) -> Self {
        SynergyOracle {
            validator_metrics: HashMap::new(),
            epoch_snapshots: HashMap::new(),
            synergy_calculator,
            pqc_manager,
        }
    }

    pub fn update_validator_metrics(&mut self, validator_address: &str, metrics: ValidatorMetrics) {
        self.validator_metrics
            .insert(validator_address.to_string(), metrics);
    }

    pub fn compute_epoch_snapshot(&mut self, epoch_number: u64) -> EpochSnapshot {
        let mut total_stake = 0;
        let mut individual_scores = HashMap::new();

        for (validator_address, metrics) in &self.validator_metrics {
            // Calculate synergy score for this validator
            let validator = self.get_validator_from_metrics(metrics);
            let components = self.synergy_calculator.calculate_synergy_score(&validator);

            individual_scores.insert(validator_address.clone(), components.normalized_score);
            total_stake += metrics.stake_amount;
        }

        let active_validator_count = individual_scores.len();

        // Create Merkle root for verification
        let merkle_root = self.compute_merkle_root(&individual_scores);

        EpochSnapshot {
            epoch_number,
            total_stake,
            active_validator_count,
            individual_synergy_scores: individual_scores,
            merkle_root,
            timestamp: Self::current_timestamp(),
        }
    }

    fn get_validator_from_metrics(&self, metrics: &ValidatorMetrics) -> Validator {
        // Create a validator object from metrics (simplified)
        Validator {
            address: "temp_address".to_string(),
            public_key: "temp_key".to_string(),
            name: "temp_validator".to_string(),
            stake_amount: metrics.stake_amount,
            synergy_score: 0.0,
            finalized_synergy_score_bps: 0,
            task_accuracy: 0.0,
            collaboration_score: 0.0,
            reputation_score: 0.0,
            slashing_penalty: metrics.slashing_penalty,
            uptime_percentage: 0.0,
            average_block_time: 0.0,
            total_blocks_produced: metrics.blocks_participated,
            missed_blocks: metrics.blocks_eligible - metrics.blocks_participated,
            double_signs: 0,
            consecutive_missed_votes: 0,
            missed_vote_window: 0,
            last_vote_timestamp: 0,
            equivocation_evidence_count: 0,
            last_active: metrics.last_update_block,
            registered_at: 0,
            min_stake_required: 0,
            cluster_id: None,
            cluster_address: None,
            cluster_assignment_epoch: None,
            cluster_assignment_seed: None,
            cluster_assignment_effective_height: None,
            status: crate::validator::ValidatorStatus::Active,
            version: "1.0".to_string(),
            website: None,
            description: None,
            email: None,
            total_transactions_validated: metrics.correct_votes,
            activation_tx_hash: None,
            shadow_started_at_height: None,
            activation_recorded_height: None,
            activation_effective_height: None,
        }
    }

    fn compute_merkle_root(&self, scores: &HashMap<String, f64>) -> String {
        // Simplified Merkle root computation
        let mut hasher = Sha3_512::new();

        let mut sorted_scores: Vec<_> = scores.iter().collect();
        sorted_scores.sort_by(|a, b| a.0.cmp(b.0));

        for (address, score) in sorted_scores {
            hasher.update(address.as_bytes());
            hasher.update(&score.to_be_bytes());
        }

        let hash = hasher.finalize();
        hex::encode(hash)
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}
