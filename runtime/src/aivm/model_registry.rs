use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIModel {
    pub id: String,
    pub name: String,
    pub version: String,
    pub model_type: ModelType,
    pub capabilities: Vec<String>,
    pub parameters: HashMap<String, String>,
    pub registry_address: String,
    pub registered_at: u64,
    pub last_updated: u64,
    pub usage_count: u64,
    pub average_rating: f64,
    pub total_ratings: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ModelType {
    Chat,
    CodeGeneration,
    ImageGeneration,
    AudioProcessing,
    DataAnalysis,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelManifest {
    pub model_id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub model_type: ModelType,
    pub input_format: String,
    pub output_format: String,
    pub capabilities: Vec<String>,
    pub requirements: ModelRequirements,
    pub metadata: HashMap<String, String>,
    pub created_by: String,
    pub license: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRequirements {
    pub min_memory_gb: u32,
    pub min_gpu_memory_gb: Option<u32>,
    pub supported_frameworks: Vec<String>,
    pub dependencies: Vec<String>,
    pub max_input_tokens: Option<u32>,
    pub max_output_tokens: Option<u32>,
}

#[derive(Debug)]
pub struct ModelRegistry {
    models: Arc<Mutex<HashMap<String, AIModel>>>,
    manifests: Arc<Mutex<HashMap<String, ModelManifest>>>,
    model_usage: Arc<Mutex<HashMap<String, u64>>>,
}

impl ModelRegistry {
    pub fn new() -> Self {
        ModelRegistry {
            models: Arc::new(Mutex::new(HashMap::new())),
            manifests: Arc::new(Mutex::new(HashMap::new())),
            model_usage: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn register_model(&self, manifest: ModelManifest) -> Result<String, String> {
        let model_id = format!("{}_{}", manifest.name.to_lowercase(), manifest.version);

        // Create model entry
        let model = AIModel {
            id: model_id.clone(),
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            model_type: manifest.model_type.clone(),
            capabilities: manifest.capabilities.clone(),
            parameters: manifest.metadata.clone(),
            registry_address: "aivm_registry".to_string(), // Would be actual registry contract address
            registered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            usage_count: 0,
            average_rating: 0.0,
            total_ratings: 0,
        };

        // Store manifest and model
        if let Ok(mut manifests) = self.manifests.lock() {
            manifests.insert(model_id.clone(), manifest);
        } else {
            return Err("Failed to acquire manifests lock".to_string());
        }

        if let Ok(mut models) = self.models.lock() {
            models.insert(model_id.clone(), model);
            Ok(model_id)
        } else {
            Err("Failed to acquire models lock".to_string())
        }
    }

    pub fn get_model(&self, model_id: &str) -> Option<AIModel> {
        if let Ok(models) = self.models.lock() {
            models.get(model_id).cloned()
        } else {
            None
        }
    }

    pub fn get_manifest(&self, model_id: &str) -> Option<ModelManifest> {
        if let Ok(manifests) = self.manifests.lock() {
            manifests.get(model_id).cloned()
        } else {
            None
        }
    }

    pub fn get_models_by_type(&self, model_type: &ModelType) -> Vec<AIModel> {
        if let Ok(models) = self.models.lock() {
            models
                .values()
                .filter(|model| &model.model_type == model_type)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_models_by_capability(&self, capability: &str) -> Vec<AIModel> {
        if let Ok(models) = self.models.lock() {
            models
                .values()
                .filter(|model| model.capabilities.contains(&capability.to_string()))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn record_model_usage(&self, model_id: &str) -> Result<(), String> {
        if let Ok(mut models) = self.models.lock() {
            if let Some(model) = models.get_mut(model_id) {
                model.usage_count += 1;
                model.last_updated = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                return Ok(());
            }
        }

        if let Ok(mut usage) = self.model_usage.lock() {
            let count = usage.entry(model_id.to_string()).or_insert(0);
            *count += 1;
        }

        Err(format!("Model {} not found", model_id))
    }

    pub fn rate_model(&self, model_id: &str, rating: f64) -> Result<(), String> {
        if let Ok(mut models) = self.models.lock() {
            if let Some(model) = models.get_mut(model_id) {
                let current_total = model.average_rating * model.total_ratings as f64;
                model.total_ratings += 1;
                model.average_rating = (current_total + rating) / model.total_ratings as f64;
                return Ok(());
            }
        }

        Err(format!("Model {} not found", model_id))
    }

    pub fn get_all_models(&self) -> Vec<AIModel> {
        if let Ok(models) = self.models.lock() {
            models.values().cloned().collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_all_manifests(&self) -> Vec<ModelManifest> {
        if let Ok(manifests) = self.manifests.lock() {
            manifests.values().cloned().collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_top_models(&self, limit: usize) -> Vec<AIModel> {
        let mut models: Vec<AIModel> = self.get_all_models();
        models.sort_by(|a, b| {
            let a_score = a.average_rating * (1.0 + (a.usage_count as f64 * 0.01));
            let b_score = b.average_rating * (1.0 + (b.usage_count as f64 * 0.01));
            b_score.partial_cmp(&a_score).unwrap()
        });
        models.into_iter().take(limit).collect()
    }

    pub fn search_models(&self, query: &str) -> Vec<AIModel> {
        let query_lower = query.to_lowercase();
        if let Ok(models) = self.models.lock() {
            models
                .values()
                .filter(|model| {
                    model.name.to_lowercase().contains(&query_lower)
                        || model.id.to_lowercase().contains(&query_lower)
                        || model.capabilities.iter().any(|cap| cap.to_lowercase().contains(&query_lower))
                })
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn update_model(&self, model_id: &str, updates: HashMap<String, String>) -> Result<(), String> {
        if let Ok(mut models) = self.models.lock() {
            if let Some(model) = models.get_mut(model_id) {
                for (key, value) in updates {
                    match key.as_str() {
                        "name" => model.name = value,
                        "version" => model.version = value,
                        _ => {
                            model.parameters.insert(key, value);
                        }
                    }
                }
                model.last_updated = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                return Ok(());
            }
        }

        Err(format!("Model {} not found", model_id))
    }

    pub fn remove_model(&self, model_id: &str) -> Result<(), String> {
        if let Ok(mut models) = self.models.lock() {
            if models.remove(model_id).is_some() {
                if let Ok(mut manifests) = self.manifests.lock() {
                    manifests.remove(model_id);
                }
                return Ok(());
            }
        }

        Err(format!("Model {} not found", model_id))
    }

    pub fn get_registry_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("total_models".to_string(), self.get_all_models().len());
        stats.insert("total_manifests".to_string(), self.get_all_manifests().len());

        let models_by_type: HashMap<ModelType, usize> = self.get_all_models()
            .iter()
            .fold(HashMap::new(), |mut acc, model| {
                *acc.entry(model.model_type.clone()).or_insert(0) += 1;
                acc
            });

        for (model_type, count) in models_by_type {
            stats.insert(format!("{:?}", model_type).to_lowercase(), count);
        }

        stats
    }

    pub fn initialize_builtin_models(&self) -> Result<Vec<String>, String> {
        let mut registered_models = Vec::new();

        // Register GPT-OSS-20B model
        let gpt_oss_manifest = ModelManifest {
            model_id: "gpt-oss-20b".to_string(),
            name: "GPT-OSS-20B".to_string(),
            description: "Open-source GPT model for conversational AI".to_string(),
            version: "1.0.0".to_string(),
            model_type: ModelType::Chat,
            input_format: "text".to_string(),
            output_format: "text".to_string(),
            capabilities: vec![
                "conversation".to_string(),
                "code_generation".to_string(),
                "text_analysis".to_string(),
                "question_answering".to_string(),
            ],
            requirements: ModelRequirements {
                min_memory_gb: 8,
                min_gpu_memory_gb: Some(8),
                supported_frameworks: vec!["transformers".to_string()],
                dependencies: vec!["torch".to_string(), "transformers".to_string()],
                max_input_tokens: Some(4096),
                max_output_tokens: Some(2048),
            },
            metadata: HashMap::new(),
            created_by: "synergy_network".to_string(),
            license: "MIT".to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        match self.register_model(gpt_oss_manifest) {
            Ok(model_id) => registered_models.push(model_id),
            Err(e) => return Err(format!("Failed to register GPT-OSS model: {}", e)),
        }

        Ok(registered_models)
    }
}
