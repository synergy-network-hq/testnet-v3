use crate::consensus::synergy_score::SynergyScoreCalculator;
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCSignature};
use crate::validator::ValidatorManager;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRecord {
    pub validator_address: String,
    pub block_height: u64,
    pub voted_for_winner: bool,
    pub vote_timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CartelDetectionResult {
    pub validator_address: String,
    pub correlation_score: f64,
    pub timing_similarity: f64,
    pub cartel_size: usize,
    pub penalty_factor: f64,
    pub detected_at: u64,
}

#[derive(Debug, Clone)]
pub struct CartelDetectionEngine {
    pub validator_manager: Arc<ValidatorManager>,
    pub synergy_calculator: Arc<SynergyScoreCalculator>,
    pub vote_history: HashMap<u64, HashMap<String, VoteRecord>>, // epoch -> validator -> votes
    pub detection_results: HashMap<String, Vec<CartelDetectionResult>>, // validator -> detection history
    pub correlation_threshold: f64,
    pub timing_similarity_threshold: f64,
    pub cartel_size_threshold: usize,
    pub trailing_window_size: usize,
}

impl CartelDetectionEngine {
    pub fn new(
        validator_manager: Arc<ValidatorManager>,
        synergy_calculator: Arc<SynergyScoreCalculator>,
    ) -> Self {
        CartelDetectionEngine {
            validator_manager,
            synergy_calculator,
            vote_history: HashMap::new(),
            detection_results: HashMap::new(),
            correlation_threshold: 0.85,
            timing_similarity_threshold: 0.9,
            cartel_size_threshold: 10,
            trailing_window_size: 1000,
        }
    }

    pub fn record_vote(&mut self, epoch: u64, vote_record: VoteRecord) {
        self.vote_history
            .entry(epoch)
            .or_insert_with(HashMap::new)
            .insert(vote_record.validator_address.clone(), vote_record);
    }

    pub fn detect_cartels(&mut self, current_epoch: u64) -> HashMap<String, f64> {
        let mut cartel_penalties = HashMap::new();

        // Get all validators with vote history
        let validators = self.get_validators_with_vote_history(current_epoch);

        // Calculate pairwise correlations
        let correlation_matrix = self.calculate_pairwise_correlations(&validators, current_epoch);

        // Identify cartels based on correlation and timing
        for validator in &validators {
            let penalty =
                self.calculate_cartel_penalty(validator, &correlation_matrix, current_epoch);
            if penalty > 1.0 {
                cartel_penalties.insert(validator.clone(), penalty);

                // Record detection result
                let detection_result = CartelDetectionResult {
                    validator_address: validator.clone(),
                    correlation_score: self.get_average_correlation(validator, &correlation_matrix),
                    timing_similarity: self.get_average_timing_similarity(validator),
                    cartel_size: self.estimate_cartel_size(validator, &correlation_matrix),
                    penalty_factor: penalty,
                    detected_at: Self::current_timestamp(),
                };

                self.detection_results
                    .entry(validator.clone())
                    .or_insert_with(Vec::new)
                    .push(detection_result);
            }
        }

        cartel_penalties
    }

    fn get_validators_with_vote_history(&self, current_epoch: u64) -> Vec<String> {
        let mut validators = HashSet::new();

        // Look at recent epochs
        for epoch in (current_epoch.saturating_sub(3))..=current_epoch {
            if let Some(epoch_votes) = self.vote_history.get(&epoch) {
                for validator_address in epoch_votes.keys() {
                    validators.insert(validator_address.clone());
                }
            }
        }

        validators.into_iter().collect()
    }

    fn calculate_pairwise_correlations(
        &self,
        validators: &[String],
        current_epoch: u64,
    ) -> HashMap<(String, String), f64> {
        let mut correlation_matrix = HashMap::new();

        for i in 0..validators.len() {
            for j in i + 1..validators.len() {
                let v1 = &validators[i];
                let v2 = &validators[j];

                if let Some(correlation) = self.calculate_pearson_correlation(v1, v2, current_epoch)
                {
                    correlation_matrix.insert((v1.clone(), v2.clone()), correlation);
                    correlation_matrix.insert((v2.clone(), v1.clone()), correlation);
                }
            }
        }

        correlation_matrix
    }

    fn calculate_pearson_correlation(
        &self,
        validator1: &str,
        validator2: &str,
        current_epoch: u64,
    ) -> Option<f64> {
        let vote_vector1 = self.construct_vote_vector(validator1, current_epoch);
        let vote_vector2 = self.construct_vote_vector(validator2, current_epoch);

        if vote_vector1.is_empty() || vote_vector2.is_empty() {
            return None;
        }

        let n = vote_vector1.len().min(vote_vector2.len());
        if n < 100 {
            return None; // Not enough data points
        }

        let mut sum1 = 0.0;
        let mut sum2 = 0.0;
        let mut sum1_sq = 0.0;
        let mut sum2_sq = 0.0;
        let mut p_sum = 0.0;

        for i in 0..n {
            let x = if vote_vector1[i] { 1.0 } else { 0.0 };
            let y = if vote_vector2[i] { 1.0 } else { 0.0 };

            sum1 += x;
            sum2 += y;
            sum1_sq += x * x;
            sum2_sq += y * y;
            p_sum += x * y;
        }

        let num = p_sum - (sum1 * sum2 / n as f64);
        let den1 = (sum1_sq - (sum1 * sum1 / n as f64)).sqrt();
        let den2 = (sum2_sq - (sum2 * sum2 / n as f64)).sqrt();

        if den1 == 0.0 || den2 == 0.0 {
            Some(0.0)
        } else {
            Some(num / (den1 * den2))
        }
    }

    fn construct_vote_vector(&self, validator: &str, current_epoch: u64) -> Vec<bool> {
        let mut vote_vector = Vec::new();

        // Look at recent blocks
        for epoch in (current_epoch.saturating_sub(3))..=current_epoch {
            if let Some(epoch_votes) = self.vote_history.get(&epoch) {
                if epoch_votes.get(validator).is_some() {
                    // Add votes in chronological order
                    let mut votes: Vec<_> = epoch_votes
                        .values()
                        .filter(|v| v.validator_address == validator)
                        .collect();

                    votes.sort_by(|a, b| a.block_height.cmp(&b.block_height));

                    for vote in votes {
                        vote_vector.push(vote.voted_for_winner);
                    }
                }
            }
        }

        vote_vector
    }

    fn calculate_cartel_penalty(
        &self,
        validator: &str,
        correlation_matrix: &HashMap<(String, String), f64>,
        _current_epoch: u64,
    ) -> f64 {
        let mut total_correlation = 0.0;
        let mut cartel_size = 0;

        // Get all validators correlated with this one
        let correlated_validators: Vec<String> = correlation_matrix
            .iter()
            .filter(|(key, &corr)| {
                (key.0 == validator || key.1 == validator) && corr > self.correlation_threshold
            })
            .map(|(key, _)| {
                if key.0 == validator {
                    key.1.clone()
                } else {
                    key.0.clone()
                }
            })
            .collect();

        for correlated_validator in correlated_validators {
            if let Some(correlation) =
                correlation_matrix.get(&(validator.to_string(), correlated_validator.clone()))
            {
                let timing_similarity =
                    self.calculate_timing_similarity(validator, &correlated_validator);

                if timing_similarity > self.timing_similarity_threshold {
                    total_correlation += correlation;
                    cartel_size += 1;
                }
            }
        }

        if cartel_size >= self.cartel_size_threshold {
            let avg_correlation = total_correlation / cartel_size as f64;
            1.0 + avg_correlation * cartel_size as f64 * 0.1
        } else {
            1.0
        }
    }

    fn calculate_timing_similarity(&self, validator1: &str, validator2: &str) -> f64 {
        let timestamps1 = self.get_vote_timestamps(validator1);
        let timestamps2 = self.get_vote_timestamps(validator2);

        if timestamps1.is_empty() || timestamps2.is_empty() {
            return 0.0;
        }

        let median1 = self.calculate_median(&timestamps1);
        let median2 = self.calculate_median(&timestamps2);
        let block_time = 5.0; // average block time in seconds

        1.0 - (median1 as f64 - median2 as f64).abs() / block_time
    }

    fn get_vote_timestamps(&self, validator: &str) -> Vec<u64> {
        let mut timestamps = Vec::new();

        for epoch_votes in self.vote_history.values() {
            if let Some(validator_votes) = epoch_votes.get(validator) {
                timestamps.push(validator_votes.vote_timestamp);
            }
        }

        timestamps
    }

    fn get_average_correlation(
        &self,
        validator: &str,
        correlation_matrix: &HashMap<(String, String), f64>,
    ) -> f64 {
        let correlations: Vec<f64> = correlation_matrix
            .iter()
            .filter(|(key, _)| key.0 == validator || key.1 == validator)
            .map(|(_, &corr)| corr)
            .collect();

        if correlations.is_empty() {
            0.0
        } else {
            correlations.iter().sum::<f64>() / correlations.len() as f64
        }
    }

    fn get_average_timing_similarity(&self, validator: &str) -> f64 {
        let active_validators = self.validator_manager.get_active_validators();
        let mut total_similarity = 0.0;
        let mut count = 0;

        for other_validator in active_validators {
            if other_validator.address != validator {
                let similarity =
                    self.calculate_timing_similarity(validator, &other_validator.address);
                total_similarity += similarity;
                count += 1;
            }
        }

        if count == 0 {
            0.0
        } else {
            total_similarity / count as f64
        }
    }

    fn estimate_cartel_size(
        &self,
        validator: &str,
        correlation_matrix: &HashMap<(String, String), f64>,
    ) -> usize {
        let correlated_validators: Vec<String> = correlation_matrix
            .iter()
            .filter(|(key, &corr)| {
                (key.0 == validator || key.1 == validator) && corr > self.correlation_threshold
            })
            .map(|(key, _)| {
                if key.0 == validator {
                    key.1.clone()
                } else {
                    key.0.clone()
                }
            })
            .collect();

        correlated_validators.len() + 1 // +1 for the validator itself
    }

    fn calculate_median(&self, values: &[u64]) -> u64 {
        let mut sorted = values.to_vec();
        sorted.sort();
        let len = sorted.len();
        if len == 0 {
            0
        } else if len % 2 == 0 {
            (sorted[len / 2 - 1] + sorted[len / 2]) / 2
        } else {
            sorted[len / 2]
        }
    }

    pub fn apply_cartel_penalties(&self, penalties: &HashMap<String, f64>) {
        for (validator_address, penalty_factor) in penalties {
            if let Some(mut validator) = self.validator_manager.get_validator(validator_address) {
                // Apply cartelization penalty to synergy score
                let components = self.synergy_calculator.calculate_synergy_score(&validator);
                let new_normalized_score = components.normalized_score / penalty_factor;

                // Update validator's synergy score
                validator.synergy_score = new_normalized_score;

                // Apply slashing if severe cartel detected
                if *penalty_factor > 1.5 {
                    self.apply_slashing(validator_address, "cartel_participation");
                }

                println!(
                    "⚠️ Applied cartel penalty to {}: factor={:.2}, new_score={:.2}",
                    validator_address, penalty_factor, new_normalized_score
                );
            }
        }
    }

    fn apply_slashing(&self, validator_address: &str, reason: &str) {
        if let Some(mut validator) = self.validator_manager.get_validator(validator_address) {
            // Apply slashing based on severity
            let slashing_amount = match reason {
                "cartel_participation" => 0.15, // 15% for cartel participation
                "double_signing" => 0.10,       // 10% for double signing
                _ => 0.05,                      // 5% for other infractions
            };

            // Reduce stake
            let stake_reduction = (validator.stake_amount as f64 * slashing_amount) as u64;
            validator.stake_amount -= stake_reduction;

            // Reduce reputation
            validator.reputation_score *= 1.0 - slashing_amount;

            // Update synergy score
            validator.calculate_synergy_score();

            println!(
                "⚠️ Applied slashing to {}: reason={}, amount={} SNRG, new_stake={}",
                validator_address, reason, stake_reduction, validator.stake_amount
            );
        }
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[derive(Debug, Clone)]
pub struct WhistleblowerSystem {
    pub reports: HashMap<String, WhistleblowerReport>,
    pub rewards: HashMap<String, u64>,
    pub pqc_manager: Arc<Mutex<PQCManager>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhistleblowerReport {
    pub report_id: String,
    pub reporter: String,
    pub accused_validators: Vec<String>,
    pub evidence: Vec<u8>,
    pub evidence_signature: PQCSignature,
    pub submitted_at: u64,
    pub status: WhistleblowerStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WhistleblowerStatus {
    Submitted,
    UnderInvestigation,
    Confirmed,
    Rejected,
    Rewarded,
}

impl WhistleblowerSystem {
    pub fn new(pqc_manager: Arc<Mutex<PQCManager>>) -> Self {
        WhistleblowerSystem {
            reports: HashMap::new(),
            rewards: HashMap::new(),
            pqc_manager,
        }
    }

    pub fn submit_report(
        &mut self,
        reporter: &str,
        accused_validators: Vec<String>,
        evidence: Vec<u8>,
    ) -> Result<String, String> {
        let report_id = format!("whistle_{}_{}", reporter, Self::current_timestamp());
        let current_time = Self::current_timestamp();

        // Create signature for the evidence
        let mut pqc_manager = self.pqc_manager.lock().unwrap();
        let private_key = self.generate_whistleblower_key(reporter)?;

        let evidence_signature = pqc_manager
            .sign(&private_key, &evidence)
            .map_err(|e| format!("Failed to sign evidence: {}", e))?;

        let report = WhistleblowerReport {
            report_id: report_id.clone(),
            reporter: reporter.to_string(),
            accused_validators,
            evidence,
            evidence_signature,
            submitted_at: current_time,
            status: WhistleblowerStatus::Submitted,
        };

        self.reports.insert(report_id.clone(), report);
        Ok(report_id)
    }

    pub fn verify_report(&mut self, report_id: &str) -> Result<bool, String> {
        let report = self
            .reports
            .get(report_id)
            .ok_or("Report not found".to_string())?;

        // Verify the evidence signature
        let pqc_manager = self.pqc_manager.lock().unwrap();
        let public_key = self.get_whistleblower_public_key(&report.reporter)?;

        let verified = pqc_manager
            .verify(&public_key, &report.evidence_signature, &report.evidence)
            .map_err(|e| format!("Signature verification failed: {}", e))?;

        // Release the pqc_manager lock before calling self.calculate_reward
        drop(pqc_manager);

        if verified {
            {
                let mut report_mut = report.clone();
                report_mut.status = WhistleblowerStatus::Confirmed;
                self.reports.insert(report_id.to_string(), report_mut);
            }
            self.calculate_reward(report_id)?;
            Ok(true)
        } else {
            {
                let mut report_mut = report.clone();
                report_mut.status = WhistleblowerStatus::Rejected;
                self.reports.insert(report_id.to_string(), report_mut);
            }
            Ok(false)
        }
    }

    fn calculate_reward(&mut self, report_id: &str) -> Result<(), String> {
        let report = self
            .reports
            .get(report_id)
            .ok_or("Report not found".to_string())?;

        // Calculate reward based on number of accused validators
        let reward_amount = report.accused_validators.len() as u64 * 1000; // 1000 SNRG per validator

        self.rewards.insert(report_id.to_string(), reward_amount);
        Ok(())
    }

    pub fn pay_reward(&mut self, report_id: &str, recipient: &str) -> Result<(), String> {
        if let Some(reward_amount) = self.rewards.remove(report_id) {
            // In real implementation, this would transfer tokens
            println!(
                "💰 Paid whistleblower reward of {} SNRG to {}",
                reward_amount, recipient
            );
            Ok(())
        } else {
            Err("No reward found for this report".to_string())
        }
    }

    fn generate_whistleblower_key(
        &self,
        _reporter: &str,
    ) -> Result<crate::crypto::pqc::PQCPrivateKey, String> {
        let mut pqc_manager = self.pqc_manager.lock().unwrap();
        let (_pub_key, priv_key) = pqc_manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .map_err(|e| format!("Failed to generate keypair: {}", e))?;

        Ok(priv_key)
    }

    fn get_whistleblower_public_key(
        &self,
        _reporter: &str,
    ) -> Result<crate::crypto::pqc::PQCPublicKey, String> {
        let mut pqc_manager = self.pqc_manager.lock().unwrap();
        let (pub_key, _) = pqc_manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .map_err(|e| format!("Failed to generate keypair: {}", e))?;

        Ok(pub_key)
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}
