use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use crate::consensus::dual_quorum::{required_validator_quorum, VALIDATOR_QUORUM_RATIO};
use crate::consensus::consensus_algorithm::ProofOfSynergy;
use crate::validator::ValidatorManager;
use crate::block::BlockChain;
use super::model_registry::{AIModel, ModelRegistry};
use super::chat_interface::ChatInterface;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedAIComputation {
    pub computation_id: String,
    pub model_id: String,
    pub input_data: Vec<u8>,
    pub cluster_id: u64,
    pub participating_validators: Vec<String>,
    pub computation_status: ComputationStatus,
    pub created_at: u64,
    pub completed_at: Option<u64>,
    pub results: HashMap<String, Vec<u8>>, // validator_address -> partial_result
    pub final_result: Option<Vec<u8>>,
    pub consensus_threshold: f64,
    pub required_confirmations: u32,
    pub current_confirmations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComputationStatus {
    Pending,
    InProgress,
    Aggregating,
    Completed,
    Failed,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIComputationTask {
    pub task_id: String,
    pub computation_id: String,
    pub validator_address: String,
    pub cluster_id: u64,
    pub model_id: String,
    pub input_data: Vec<u8>,
    pub assigned_at: u64,
    pub completed_at: Option<u64>,
    pub partial_result: Option<Vec<u8>>,
    pub status: TaskStatus,
    pub reward_claimed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    Assigned,
    InProgress,
    Completed,
    Failed,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelShard {
    pub shard_id: String,
    pub model_id: String,
    pub cluster_id: u64,
    pub validator_addresses: Vec<String>,
    pub shard_data: Vec<u8>,
    pub shard_size: usize,
    pub total_shards: u32,
    pub created_at: u64,
    pub last_accessed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIRewardDistribution {
    pub computation_id: String,
    pub total_reward_pool: u64,
    pub validator_rewards: HashMap<String, u64>,
    pub distributed_at: u64,
    pub distribution_basis: RewardBasis,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RewardBasis {
    Participation,
    Accuracy,
    Speed,
    Combined,
}

#[derive(Debug)]
pub struct DistributedAIProtocol {
    computations: Arc<Mutex<HashMap<String, DistributedAIComputation>>>,
    tasks: Arc<Mutex<HashMap<String, AIComputationTask>>>,
    model_shards: Arc<Mutex<HashMap<String, ModelShard>>>,
    reward_distributions: Arc<Mutex<HashMap<String, AIRewardDistribution>>>,
    consensus_engine: Arc<ProofOfSynergy>,
    validator_manager: Arc<ValidatorManager>,
    model_registry: Arc<ModelRegistry>,
    chat_interface: Arc<ChatInterface>,
}

impl DistributedAIProtocol {
    pub fn new(
        consensus_engine: Arc<ProofOfSynergy>,
        validator_manager: Arc<ValidatorManager>,
        model_registry: Arc<ModelRegistry>,
        chat_interface: Arc<ChatInterface>,
    ) -> Self {
        DistributedAIProtocol {
            computations: Arc::new(Mutex::new(HashMap::new())),
            tasks: Arc::new(Mutex::new(HashMap::new())),
            model_shards: Arc::new(Mutex::new(HashMap::new())),
            reward_distributions: Arc::new(Mutex::new(HashMap::new())),
            consensus_engine,
            validator_manager,
            model_registry,
            chat_interface,
        }
    }

    pub fn initiate_distributed_computation(
        &self,
        model_id: String,
        input_data: Vec<u8>,
        cluster_id: Option<u64>,
    ) -> Result<String, String> {
        let computation_id = format!("ai_comp_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());

        // Get model information
        let model = match self.model_registry.get_model(&model_id) {
            Some(model) => model,
            None => return Err(format!("Model {} not found", model_id)),
        };

        // Determine cluster assignment
        let assigned_cluster_id = cluster_id.unwrap_or_else(|| {
            // Use synergy scoring to assign to optimal cluster
            self.select_optimal_cluster_for_ai(&model)
        });

        // Get validators in the assigned cluster
        let participating_validators = self.get_cluster_validators_for_ai(assigned_cluster_id)?;

        if participating_validators.is_empty() {
            return Err("No available validators in cluster for AI computation".to_string());
        }

        let computation = DistributedAIComputation {
            computation_id: computation_id.clone(),
            model_id: model_id.clone(),
            input_data,
            cluster_id: assigned_cluster_id,
            participating_validators: participating_validators.clone(),
            computation_status: ComputationStatus::Pending,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            completed_at: None,
            results: HashMap::new(),
            final_result: None,
            consensus_threshold: VALIDATOR_QUORUM_RATIO,
            required_confirmations: required_validator_quorum(participating_validators.len())
                as u32,
            current_confirmations: 0,
        };

        // Create tasks for each validator
        for validator_address in &participating_validators {
            let task_id = format!("{}_task_{}", computation_id, validator_address);
            let task = AIComputationTask {
                task_id: task_id.clone(),
                computation_id: computation_id.clone(),
                validator_address: validator_address.clone(),
                cluster_id: assigned_cluster_id,
                model_id: model_id.clone(),
                input_data: computation.input_data.clone(),
                assigned_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                completed_at: None,
                partial_result: None,
                status: TaskStatus::Assigned,
                reward_claimed: false,
            };

            if let Ok(mut tasks) = self.tasks.lock() {
                tasks.insert(task_id, task);
            }
        }

        // Store computation
        if let Ok(mut computations) = self.computations.lock() {
            computations.insert(computation_id.clone(), computation);
        }

        // Start the distributed computation
        self.start_distributed_computation(&computation_id)?;

        Ok(computation_id)
    }

    pub fn submit_partial_result(
        &self,
        task_id: &str,
        validator_address: &str,
        partial_result: Vec<u8>,
    ) -> Result<(), String> {
        // Verify validator is authorized for this task
        if let Ok(tasks) = self.tasks.lock() {
            if let Some(task) = tasks.get(task_id) {
                if task.validator_address != validator_address {
                    return Err("Unauthorized validator for this task".to_string());
                }

                if task.status != TaskStatus::Assigned && task.status != TaskStatus::InProgress {
                    return Err("Task is not in valid state for result submission".to_string());
                }
            } else {
                return Err("Task not found".to_string());
            }
        }

        // Update task status
        if let Ok(mut tasks) = self.tasks.lock() {
            if let Some(task) = tasks.get_mut(task_id) {
                task.status = TaskStatus::Completed;
                task.completed_at = Some(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs());
                task.partial_result = Some(partial_result.clone());
            }
        }

        // Update computation
        if let Ok(mut computations) = self.computations.lock() {
            if let Some(computation) = computations.get_mut(&task.computation_id) {
                computation.results.insert(validator_address.to_string(), partial_result);
                computation.current_confirmations += 1;

                // Check if we have enough confirmations
                if computation.current_confirmations >= computation.required_confirmations {
                    computation.computation_status = ComputationStatus::Aggregating;
                    self.aggregate_results(&computation.computation_id)?;
                }
            }
        }

        Ok(())
    }

    fn start_distributed_computation(&self, computation_id: &str) -> Result<(), String> {
        if let Ok(computations) = self.computations.lock() {
            if let Some(computation) = computations.get(computation_id) {
                // Notify validators in the cluster to start computation
                for validator_address in &computation.participating_validators {
                    let task_id = format!("{}_task_{}", computation_id, validator_address);

                    // In a real implementation, this would send network messages
                    // to validators to start their AI computation tasks
                    println!("🧠 Notifying validator {} to start AI computation task {}",
                             validator_address, task_id);

                    // Update task status to InProgress
                    if let Ok(mut tasks) = self.tasks.lock() {
                        if let Some(task) = tasks.get_mut(&task_id) {
                            task.status = TaskStatus::InProgress;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn aggregate_results(&self, computation_id: &str) -> Result<(), String> {
        if let Ok(computations) = self.computations.lock() {
            if let Some(computation) = computations.get(computation_id) {
                if computation.results.len() < computation.required_confirmations as usize {
                    return Err("Insufficient results for aggregation".to_string());
                }

                // Perform consensus aggregation of partial results
                let final_result = self.consensus_aggregate(&computation.results, computation.consensus_threshold)?;

                // Update computation status
                if let Ok(mut computations) = self.computations.lock() {
                    if let Some(comp) = computations.get_mut(computation_id) {
                        comp.computation_status = ComputationStatus::Completed;
                        comp.completed_at = Some(std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs());
                        comp.final_result = Some(final_result.clone());
                    }
                }

                // Distribute rewards to participating validators
                self.distribute_ai_rewards(computation_id, &computation.participating_validators)?;

                println!("✅ Distributed AI computation {} completed successfully", computation_id);
            }
        }

        Ok(())
    }

    fn consensus_aggregate(&self, results: &HashMap<String, Vec<u8>>, threshold: f64) -> Result<Vec<u8>, String> {
        // Simple majority voting for consensus
        // In a real implementation, this would use more sophisticated consensus algorithms

        if results.is_empty() {
            return Err("No results to aggregate".to_string());
        }

        // For now, return the most common result (simple majority)
        // In practice, this would involve cryptographic consensus
        let mut result_counts: HashMap<Vec<u8>, u32> = HashMap::new();

        for result in results.values() {
            *result_counts.entry(result.clone()).or_insert(0) += 1;
        }

        let total_validators = results.len() as u32;
        let required_votes = (total_validators as f64 * threshold).ceil() as u32;

        let mut final_result = None;
        let mut max_votes = 0;

        for (result, votes) in result_counts {
            if votes > max_votes && votes >= required_votes {
                max_votes = votes;
                final_result = Some(result);
            }
        }

        match final_result {
            Some(result) => Ok(result),
            None => Err("No consensus reached on AI computation result".to_string()),
        }
    }

    fn select_optimal_cluster_for_ai(&self, model: &AIModel) -> u64 {
        // Use synergy scoring to select the best cluster for AI computation
        // This integrates with the existing Proof of Synergy consensus

        let active_validators = self.validator_manager.get_active_validators();
        let clusters = self.consensus_engine.get_validator_clusters();

        // Find cluster with highest average synergy score for AI tasks
        let mut best_cluster_id = 0u64;
        let mut best_score = 0.0f64;

        for cluster in clusters.values() {
            let cluster_validators: Vec<_> = active_validators
                .iter()
                .filter(|v| cluster.validators.contains(&v.address))
                .collect();

            if !cluster_validators.is_empty() {
                let avg_synergy: f64 = cluster_validators
                    .iter()
                    .map(|v| v.synergy_score)
                    .sum::<f64>() / cluster_validators.len() as f64;

                if avg_synergy > best_score {
                    best_score = avg_synergy;
                    best_cluster_id = cluster.id;
                }
            }
        }

        best_cluster_id
    }

    fn get_cluster_validators_for_ai(&self, cluster_id: u64) -> Result<Vec<String>, String> {
        let active_validators = self.validator_manager.get_active_validators();
        let clusters = self.consensus_engine.get_validator_clusters();

        if let Some(cluster) = clusters.get(&cluster_id) {
            Ok(cluster.validators
                .iter()
                .filter(|addr| {
                    active_validators.iter().any(|v| v.address == **addr)
                })
                .cloned()
                .collect())
        } else {
            Err(format!("Cluster {} not found", cluster_id))
        }
    }

    fn distribute_ai_rewards(&self, computation_id: &str, validators: &[String]) -> Result<(), String> {
        let base_reward_per_validator = 1000u64; // Base reward in smallest token unit

        let total_reward_pool = base_reward_per_validator * validators.len() as u64;

        let mut validator_rewards = HashMap::new();
        for validator in validators {
            validator_rewards.insert(validator.clone(), base_reward_per_validator);
        }

        let reward_distribution = AIRewardDistribution {
            computation_id: computation_id.to_string(),
            total_reward_pool,
            validator_rewards,
            distributed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            distribution_basis: RewardBasis::Participation,
        };

        if let Ok(mut distributions) = self.reward_distributions.lock() {
            distributions.insert(computation_id.to_string(), reward_distribution);
        }

        // In a real implementation, this would trigger actual token transfers
        println!("💰 Distributed {} rewards to {} validators for AI computation {}",
                 total_reward_pool, validators.len(), computation_id);

        Ok(())
    }

    pub fn get_computation_status(&self, computation_id: &str) -> Option<ComputationStatus> {
        if let Ok(computations) = self.computations.lock() {
            computations.get(computation_id).map(|c| c.computation_status.clone())
        } else {
            None
        }
    }

    pub fn get_computation_result(&self, computation_id: &str) -> Option<Vec<u8>> {
        if let Ok(computations) = self.computations.lock() {
            computations.get(computation_id).and_then(|c| c.final_result.clone())
        } else {
            None
        }
    }

    pub fn get_pending_tasks_for_validator(&self, validator_address: &str) -> Vec<AIComputationTask> {
        if let Ok(tasks) = self.tasks.lock() {
            tasks
                .values()
                .filter(|task| {
                    task.validator_address == validator_address &&
                    (task.status == TaskStatus::Assigned || task.status == TaskStatus::InProgress)
                })
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_validator_ai_rewards(&self, validator_address: &str) -> u64 {
        if let Ok(distributions) = self.reward_distributions.lock() {
            distributions
                .values()
                .filter_map(|dist| dist.validator_rewards.get(validator_address))
                .sum()
        } else {
            0
        }
    }

    pub fn get_ai_network_stats(&self) -> HashMap<String, String> {
        let mut stats = HashMap::new();

        if let Ok(computations) = self.computations.lock() {
            let total_computations = computations.len();
            let completed_computations = computations.values()
                .filter(|c| c.computation_status == ComputationStatus::Completed)
                .count();
            let failed_computations = computations.values()
                .filter(|c| c.computation_status == ComputationStatus::Failed)
                .count();

            stats.insert("total_computations".to_string(), total_computations.to_string());
            stats.insert("completed_computations".to_string(), completed_computations.to_string());
            stats.insert("failed_computations".to_string(), failed_computations.to_string());
            stats.insert("success_rate".to_string(),
                        format!("{:.2}%",
                               if total_computations > 0 {
                                   (completed_computations as f64 / total_computations as f64) * 100.0
                               } else { 0.0 }));
        }

        if let Ok(tasks) = self.tasks.lock() {
            let total_tasks = tasks.len();
            let completed_tasks = tasks.values()
                .filter(|t| t.status == TaskStatus::Completed)
                .count();

            stats.insert("total_tasks".to_string(), total_tasks.to_string());
            stats.insert("completed_tasks".to_string(), completed_tasks.to_string());
        }

        if let Ok(distributions) = self.reward_distributions.lock() {
            let total_rewards: u64 = distributions.values()
                .map(|d| d.total_reward_pool)
                .sum();

            stats.insert("total_ai_rewards_distributed".to_string(), total_rewards.to_string());
        }

        stats
    }

    pub fn cleanup_expired_computations(&self, max_age_seconds: u64) -> usize {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut cleaned_count = 0;

        if let Ok(mut computations) = self.computations.lock() {
            let expired_ids: Vec<String> = computations
                .iter()
                .filter(|(_, comp)| {
                    current_time - comp.created_at > max_age_seconds &&
                    comp.computation_status != ComputationStatus::Completed
                })
                .map(|(id, _)| id.clone())
                .collect();

            for id in expired_ids {
                if let Some(computation) = computations.remove(&id) {
                    // Mark as failed/timeout
                    // In a real implementation, would handle cleanup and refunds
                    println!("🧹 Cleaned up expired AI computation: {}", id);
                    cleaned_count += 1;
                }
            }
        }

        cleaned_count
    }
}
