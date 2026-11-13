use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderNode {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub capabilities: Vec<String>,
    pub status: ProviderStatus,
    pub region: String,
    pub hardware_specs: HardwareSpecs,
    pub registered_at: u64,
    pub last_seen: u64,
    pub reputation_score: f64,
    pub total_tasks_completed: u64,
    pub average_response_time: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProviderStatus {
    Online,
    Offline,
    Busy,
    Maintenance,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSpecs {
    pub cpu_cores: u32,
    pub memory_gb: u32,
    pub gpu_memory_gb: Option<u32>,
    pub storage_gb: u32,
    pub network_bandwidth_mbps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRequest {
    pub task_id: String,
    pub model_id: String,
    pub input_data: Vec<u8>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub timeout_seconds: u64,
    pub priority: TaskPriority,
    pub requester: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskPriority {
    Low,
    Normal,
    High,
    Urgent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub success: bool,
    pub output_data: Vec<u8>,
    pub execution_time_ms: u64,
    pub tokens_used: Option<u32>,
    pub error_message: Option<String>,
    pub provider_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetrics {
    pub provider_id: String,
    pub uptime_percentage: f64,
    pub average_response_time_ms: f64,
    pub tasks_completed: u64,
    pub tasks_failed: u64,
    pub total_earnings: u64,
    pub reputation_score: f64,
}

#[derive(Debug)]
pub struct ProviderManager {
    providers: Arc<Mutex<HashMap<String, ProviderNode>>>,
    task_queue: Arc<Mutex<Vec<TaskRequest>>>,
    task_results: Arc<Mutex<HashMap<String, TaskResult>>>,
    provider_metrics: Arc<Mutex<HashMap<String, ProviderMetrics>>>,
}

impl ProviderManager {
    pub fn new() -> Self {
        ProviderManager {
            providers: Arc::new(Mutex::new(HashMap::new())),
            task_queue: Arc::new(Mutex::new(Vec::new())),
            task_results: Arc::new(Mutex::new(HashMap::new())),
            provider_metrics: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_provider(&self, provider: ProviderNode) -> Result<String, String> {
        if let Ok(mut providers) = self.providers.lock() {
            if providers.contains_key(&provider.id) {
                return Err(format!("Provider {} already registered", provider.id));
            }

            providers.insert(provider.id.clone(), provider);

            // Initialize metrics
            let metrics = ProviderMetrics {
                provider_id: provider.id.clone(),
                uptime_percentage: 100.0,
                average_response_time_ms: 0.0,
                tasks_completed: 0,
                tasks_failed: 0,
                total_earnings: 0,
                reputation_score: 100.0,
            };

            if let Ok(mut provider_metrics) = self.provider_metrics.lock() {
                provider_metrics.insert(provider.id.clone(), metrics);
            }

            Ok(provider.id)
        } else {
            Err("Failed to acquire providers lock".to_string())
        }
    }

    pub fn update_provider_status(&self, provider_id: &str, status: ProviderStatus) -> Result<(), String> {
        if let Ok(mut providers) = self.providers.lock() {
            if let Some(provider) = providers.get_mut(provider_id) {
                provider.status = status;
                provider.last_seen = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                return Ok(());
            }
        }

        Err(format!("Provider {} not found", provider_id))
    }

    pub fn get_available_providers(&self, capability: Option<&str>) -> Vec<ProviderNode> {
        if let Ok(providers) = self.providers.lock() {
            providers
                .values()
                .filter(|provider| {
                    provider.status == ProviderStatus::Online
                        && if let Some(cap) = capability {
                            provider.capabilities.contains(&cap.to_string())
                        } else {
                            true
                        }
                })
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_best_provider(&self, model_id: &str, priority: TaskPriority) -> Option<ProviderNode> {
        let available_providers = self.get_available_providers(Some(model_id));

        if available_providers.is_empty() {
            return None;
        }

        // Sort by reputation and response time
        let mut sorted_providers = available_providers;
        sorted_providers.sort_by(|a, b| {
            let a_score = a.reputation_score * (1000.0 / (a.average_response_time + 1.0));
            let b_score = b.reputation_score * (1000.0 / (b.average_response_time + 1.0));
            b_score.partial_cmp(&a_score).unwrap()
        });

        sorted_providers.into_iter().next()
    }

    pub fn submit_task(&self, task: TaskRequest) -> Result<String, String> {
        if let Ok(mut queue) = self.task_queue.lock() {
            queue.push(task);
            Ok("Task submitted successfully".to_string())
        } else {
            Err("Failed to acquire task queue lock".to_string())
        }
    }

    pub fn get_task_result(&self, task_id: &str) -> Option<TaskResult> {
        if let Ok(results) = self.task_results.lock() {
            results.get(task_id).cloned()
        } else {
            None
        }
    }

    pub fn record_task_completion(
        &self,
        task_id: &str,
        provider_id: &str,
        execution_time_ms: u64,
        tokens_used: Option<u32>,
        success: bool,
        error_message: Option<String>,
    ) -> Result<(), String> {
        let result = TaskResult {
            task_id: task_id.to_string(),
            success,
            output_data: vec![], // Would contain actual output
            execution_time_ms,
            tokens_used,
            error_message,
            provider_id: provider_id.to_string(),
        };

        if let Ok(mut results) = self.task_results.lock() {
            results.insert(task_id.to_string(), result);
        }

        // Update provider metrics
        if let Ok(mut metrics) = self.provider_metrics.lock() {
            if let Some(provider_metrics) = metrics.get_mut(provider_id) {
                if success {
                    provider_metrics.tasks_completed += 1;
                } else {
                    provider_metrics.tasks_failed += 1;
                }

                // Update average response time
                let total_tasks = provider_metrics.tasks_completed + provider_metrics.tasks_failed;
                if total_tasks > 0 {
                    let current_avg = provider_metrics.average_response_time_ms;
                    let new_avg = (current_avg * (total_tasks - 1) as f64 + execution_time_ms as f64) / total_tasks as f64;
                    provider_metrics.average_response_time_ms = new_avg;
                } else {
                    provider_metrics.average_response_time_ms = execution_time_ms as f64;
                }
            }
        }

        Ok(())
    }

    pub fn get_provider_metrics(&self, provider_id: &str) -> Option<ProviderMetrics> {
        if let Ok(metrics) = self.provider_metrics.lock() {
            metrics.get(provider_id).cloned()
        } else {
            None
        }
    }

    pub fn update_provider_reputation(&self, provider_id: &str, new_score: f64) -> Result<(), String> {
        if let Ok(mut metrics) = self.provider_metrics.lock() {
            if let Some(provider_metrics) = metrics.get_mut(provider_id) {
                provider_metrics.reputation_score = new_score;
                return Ok(());
            }
        }

        Err(format!("Provider {} not found", provider_id))
    }

    pub fn get_all_providers(&self) -> Vec<ProviderNode> {
        if let Ok(providers) = self.providers.lock() {
            providers.values().cloned().collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_provider(&self, provider_id: &str) -> Option<ProviderNode> {
        if let Ok(providers) = self.providers.lock() {
            providers.get(provider_id).cloned()
        } else {
            None
        }
    }

    pub fn remove_provider(&self, provider_id: &str) -> Result<(), String> {
        if let Ok(mut providers) = self.providers.lock() {
            if providers.remove(provider_id).is_some() {
                if let Ok(mut metrics) = self.provider_metrics.lock() {
                    metrics.remove(provider_id);
                }
                return Ok(());
            }
        }

        Err(format!("Provider {} not found", provider_id))
    }

    pub fn get_queue_size(&self) -> usize {
        if let Ok(queue) = self.task_queue.lock() {
            queue.len()
        } else {
            0
        }
    }

    pub fn get_pending_tasks(&self) -> Vec<TaskRequest> {
        if let Ok(queue) = self.task_queue.lock() {
            queue.clone()
        } else {
            Vec::new()
        }
    }

    pub fn process_task_queue(&self) -> Result<usize, String> {
        let mut processed = 0;

        if let Ok(mut queue) = self.task_queue.lock() {
            let mut tasks_to_process = Vec::new();

            // Get tasks sorted by priority
            queue.sort_by(|a, b| {
                let a_priority = match a.priority {
                    TaskPriority::Urgent => 4,
                    TaskPriority::High => 3,
                    TaskPriority::Normal => 2,
                    TaskPriority::Low => 1,
                };
                let b_priority = match b.priority {
                    TaskPriority::Urgent => 4,
                    TaskPriority::High => 3,
                    TaskPriority::Normal => 2,
                    TaskPriority::Low => 1,
                };
                b_priority.cmp(&a_priority)
            });

            // Process up to 10 tasks
            let batch_size = 10.min(queue.len());
            for task in queue.drain(..batch_size) {
                tasks_to_process.push(task);
            }

            processed = tasks_to_process.len();
        }

        Ok(processed)
    }

    pub fn get_network_stats(&self) -> HashMap<String, String> {
        let mut stats = HashMap::new();

        let providers = self.get_all_providers();
        let total_providers = providers.len();
        let online_providers = providers.iter().filter(|p| p.status == ProviderStatus::Online).count();

        stats.insert("total_providers".to_string(), total_providers.to_string());
        stats.insert("online_providers".to_string(), online_providers.to_string());
        stats.insert("queue_size".to_string(), self.get_queue_size().to_string());

        if let Ok(metrics) = self.provider_metrics.lock() {
            let total_tasks: u64 = metrics.values().map(|m| m.tasks_completed + m.tasks_failed).sum();
            let completed_tasks: u64 = metrics.values().map(|m| m.tasks_completed).sum();
            let average_uptime: f64 = if total_providers > 0 {
                metrics.values().map(|m| m.uptime_percentage).sum::<f64>() / total_providers as f64
            } else {
                0.0
            };

            stats.insert("total_tasks".to_string(), total_tasks.to_string());
            stats.insert("completed_tasks".to_string(), completed_tasks.to_string());
            stats.insert("average_uptime".to_string(), format!("{:.2}", average_uptime));
        }

        stats
    }

    pub fn initialize_builtin_providers(&self) -> Result<Vec<String>, String> {
        let mut registered_providers = Vec::new();

        // Register local GPT-OSS provider
        let local_provider = ProviderNode {
            id: "local_gpt_oss".to_string(),
            name: "Local GPT-OSS Provider".to_string(),
            endpoint: "http://localhost:8000".to_string(),
            capabilities: vec![
                "gpt-oss-20b".to_string(),
                "chat".to_string(),
                "text_generation".to_string(),
            ],
            status: ProviderStatus::Online,
            region: "local".to_string(),
            hardware_specs: HardwareSpecs {
                cpu_cores: 8,
                memory_gb: 16,
                gpu_memory_gb: Some(8),
                storage_gb: 100,
                network_bandwidth_mbps: 1000,
            },
            registered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            reputation_score: 100.0,
            total_tasks_completed: 0,
            average_response_time: 1000.0,
        };

        match self.register_provider(local_provider) {
            Ok(provider_id) => registered_providers.push(provider_id),
            Err(e) => return Err(format!("Failed to register local provider: {}", e)),
        }

        Ok(registered_providers)
    }
}
