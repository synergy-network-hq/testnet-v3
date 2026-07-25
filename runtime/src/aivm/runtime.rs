use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use hex;
use crate::transaction::Transaction;
use crate::block::Block;
use super::distributed_ai::DistributedAIProtocol;
use super::model_registry::ModelRegistry;
use super::chat_interface::ChatInterface;
use super::wasm_vm::WASMVM;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIVMExecutionContext {
    pub transaction_hash: String,
    pub block_height: u64,
    pub timestamp: u64,
    pub sender: String,
    pub contract_address: Option<String>,
    pub input_data: Vec<u8>,
    pub gas_limit: u64,
    pub gas_price: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIVMExecutionResult {
    pub success: bool,
    pub output: Vec<u8>,
    pub gas_used: u64,
    pub logs: Vec<String>,
    pub return_value: Option<String>,
    pub error_message: Option<String>,
    pub ai_responses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIVMContract {
    pub address: String,
    pub bytecode: Vec<u8>,
    pub abi: String,
    pub creator: String,
    pub created_at: u64,
    pub contract_type: ContractType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContractType {
    Standard,
    AIEnhanced,
    CrossChain,
    Oracle,
}

#[derive(Debug)]
pub struct AIVMRuntime {
    contracts: Arc<Mutex<HashMap<String, AIVMContract>>>,
    execution_cache: Arc<Mutex<HashMap<String, AIVMExecutionResult>>>,
    model_registry: Arc<ModelRegistry>,
    chat_interface: Arc<ChatInterface>,
    pub distributed_ai: Arc<DistributedAIProtocol>,
    wasm_vm: Arc<Mutex<WASMVM>>,
    runtime: Runtime,
}

impl AIVMRuntime {
    pub fn new() -> Self {
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

        // Initialize distributed AI protocol
        let consensus_engine = Arc::new(crate::consensus::consensus_algorithm::ProofOfSynergy::new());
        let validator_manager = crate::validator::VALIDATOR_MANAGER.clone();
        let model_registry = Arc::new(ModelRegistry::new());
        let chat_interface = Arc::new(ChatInterface::new());

        let distributed_ai = Arc::new(DistributedAIProtocol::new(
            consensus_engine,
            validator_manager,
            model_registry.clone(),
            chat_interface.clone(),
        ));

        let wasm_vm = Arc::new(Mutex::new(WASMVM::new().expect("Failed to create WASM VM")));

        AIVMRuntime {
            contracts: Arc::new(Mutex::new(HashMap::new())),
            execution_cache: Arc::new(Mutex::new(HashMap::new())),
            model_registry,
            chat_interface,
            distributed_ai,
            wasm_vm,
            runtime,
        }
    }

    pub fn deploy_contract(
        &self,
        bytecode: Vec<u8>,
        abi: String,
        creator: String,
        contract_type: ContractType,
    ) -> Result<String, String> {
        let contract_address = self.generate_contract_address(&creator, &bytecode);

        let contract = AIVMContract {
            address: contract_address.clone(),
            bytecode,
            abi,
            creator,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            contract_type,
        };

        if let Ok(mut contracts) = self.contracts.lock() {
            contracts.insert(contract_address.clone(), contract);
            Ok(contract_address)
        } else {
            Err("Failed to acquire contracts lock".to_string())
        }
    }

    pub fn execute_contract(
        &self,
        contract_address: &str,
        context: AIVMExecutionContext,
    ) -> Result<AIVMExecutionResult, String> {
        // Check cache first
        let cache_key = format!("{}:{}", contract_address, context.transaction_hash);
        if let Ok(cache) = self.execution_cache.lock() {
            if let Some(cached_result) = cache.get(&cache_key) {
                return Ok(cached_result.clone());
            }
        }

        // Get contract
        let contract = {
            if let Ok(contracts) = self.contracts.lock() {
                match contracts.get(contract_address) {
                    Some(contract) => contract.clone(),
                    None => return Err(format!("Contract {} not found", contract_address)),
                }
            } else {
                return Err("Failed to acquire contracts lock".to_string());
            }
        };

        // Execute based on contract type
        let result = match contract.contract_type {
            ContractType::AIEnhanced => self.execute_ai_enhanced_contract(&contract, &context)?,
            ContractType::CrossChain => self.execute_cross_chain_contract(&contract, &context)?,
            ContractType::Oracle => self.execute_oracle_contract(&contract, &context)?,
            ContractType::Standard => self.execute_standard_contract(&contract, &context)?,
        };

        // Cache the result
        if let Ok(mut cache) = self.execution_cache.lock() {
            cache.insert(cache_key, result.clone());
        }

        Ok(result)
    }

    fn execute_standard_contract(
        &self,
        contract: &AIVMContract,
        context: &AIVMExecutionContext,
    ) -> Result<AIVMExecutionResult, String> {
        // Load WASM module if not already loaded
        let module_id = format!("contract_{}", contract.address);
        let instance_id = format!("instance_{}_{}", contract.address, context.transaction_hash);

        // Load and instantiate WASM module
        if let Ok(mut vm) = self.wasm_vm.lock() {
            // Load module if not already loaded
            if vm.get_module_count() == 0 || !vm.get_instance_count() > 0 {
                vm.load_module(&module_id, &contract.bytecode)?;
                vm.instantiate_module(&module_id, &instance_id)?;
            }

            // Execute the main function
            let result = vm.execute_function(
                &instance_id,
                "main",
                context.input_data.clone(),
                context.gas_limit,
            )?;

            Ok(AIVMExecutionResult {
                success: result.success,
                output: result.output,
                gas_used: result.gas_used,
                logs: result.logs,
                return_value: if result.success { Some("wasm_success".to_string()) } else { None },
                error_message: result.error_message,
                ai_responses: vec![],
            })
        } else {
            Err("Failed to acquire WASM VM lock".to_string())
        }
    }

    fn execute_ai_enhanced_contract(
        &self,
        contract: &AIVMContract,
        context: &AIVMExecutionContext,
    ) -> Result<AIVMExecutionResult, String> {
        // First execute the WASM contract to get AI parameters
        let wasm_result = self.execute_standard_contract(contract, context)?;
        
        if !wasm_result.success {
            return Ok(wasm_result);
        }

        // Extract AI model parameters from WASM output
        let ai_params = String::from_utf8_lossy(&wasm_result.output);
        let model_id = if ai_params.contains("model:") {
            ai_params.split("model:").nth(1)
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("distributed_ai_model")
                .to_string()
        } else {
            "distributed_ai_model".to_string()
        };

        // Use distributed AI computation with extracted parameters
        let input_data = context.input_data.clone();

        // Initiate distributed AI computation
        let computation_id = match self.distributed_ai.initiate_distributed_computation(
            model_id,
            input_data,
            None, // Let the system choose optimal cluster
        ) {
            Ok(id) => id,
            Err(e) => return Err(format!("Failed to initiate distributed AI computation: {}", e)),
        };

        // Wait for computation to complete with timeout
        let max_wait_iterations = 50; // Reduced timeout for better performance
        let mut iterations = 0;

        while iterations < max_wait_iterations {
            if let Some(status) = self.distributed_ai.get_computation_status(&computation_id) {
                match status {
                    super::distributed_ai::ComputationStatus::Completed => {
                        if let Some(result) = self.distributed_ai.get_computation_result(&computation_id) {
                            return Ok(AIVMExecutionResult {
                                success: true,
                                output: result,
                                gas_used: wasm_result.gas_used + 100000, // WASM + AI computation cost
                                logs: vec![
                                    "WASM contract executed successfully".to_string(),
                                    "Distributed AI computation completed".to_string(),
                                    format!("Computation ID: {}", computation_id),
                                ],
                                return_value: Some("ai_enhanced_success".to_string()),
                                error_message: None,
                                ai_responses: vec![format!("AI-enhanced contract executed via distributed computation (ID: {})", computation_id)],
                            });
                        }
                    },
                    super::distributed_ai::ComputationStatus::Failed => {
                        return Err("Distributed AI computation failed".to_string());
                    },
                    super::distributed_ai::ComputationStatus::Timeout => {
                        return Err("Distributed AI computation timed out".to_string());
                    },
                    _ => {
                        // Still in progress, continue waiting
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        iterations += 1;
                        continue;
                    }
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(50));
            iterations += 1;
        }

        Err("Distributed AI computation did not complete within timeout".to_string())
    }

    fn execute_cross_chain_contract(
        &self,
        contract: &AIVMContract,
        context: &AIVMExecutionContext,
    ) -> Result<AIVMExecutionResult, String> {
        // Execute WASM contract first
        let wasm_result = self.execute_standard_contract(contract, context)?;
        
        if !wasm_result.success {
            return Ok(wasm_result);
        }

        // Parse cross-chain parameters from WASM output
        let cross_chain_params = String::from_utf8_lossy(&wasm_result.output);
        let target_chain = if cross_chain_params.contains("chain:") {
            cross_chain_params.split("chain:").nth(1)
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("ethereum")
                .to_string()
        } else {
            "ethereum".to_string()
        };

        // Simulate cross-chain operation
        let cross_chain_result = self.simulate_cross_chain_operation(&target_chain, &context.input_data)?;

        Ok(AIVMExecutionResult {
            success: true,
            output: cross_chain_result,
            gas_used: wasm_result.gas_used + 75000, // WASM + cross-chain cost
            logs: vec![
                "WASM contract executed successfully".to_string(),
                format!("Cross-chain operation to {} initiated", target_chain),
                "Cross-chain contract executed".to_string(),
            ],
            return_value: Some("cross_chain_success".to_string()),
            error_message: None,
            ai_responses: vec![format!("Cross-chain operation completed to {}", target_chain)],
        })
    }

    fn simulate_cross_chain_operation(&self, target_chain: &str, input_data: &[u8]) -> Result<Vec<u8>, String> {
        // Simulate cross-chain operation result
        // In a real implementation, this would involve actual cross-chain communication
        let result = format!("cross_chain_result:{}:{}", target_chain, hex::encode(input_data));
        Ok(result.as_bytes().to_vec())
    }

    fn execute_oracle_contract(
        &self,
        contract: &AIVMContract,
        context: &AIVMExecutionContext,
    ) -> Result<AIVMExecutionResult, String> {
        // Execute WASM contract first
        let wasm_result = self.execute_standard_contract(contract, context)?;
        
        if !wasm_result.success {
            return Ok(wasm_result);
        }

        // Parse oracle parameters from WASM output
        let oracle_params = String::from_utf8_lossy(&wasm_result.output);
        let data_source = if oracle_params.contains("source:") {
            oracle_params.split("source:").nth(1)
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("price_feed")
                .to_string()
        } else {
            "price_feed".to_string()
        };

        // Fetch external data
        let external_data = self.fetch_external_data(&data_source)?;

        Ok(AIVMExecutionResult {
            success: true,
            output: external_data,
            gas_used: wasm_result.gas_used + 30000, // WASM + oracle cost
            logs: vec![
                "WASM contract executed successfully".to_string(),
                format!("Oracle data fetched from {}", data_source),
                "Oracle contract executed".to_string(),
            ],
            return_value: Some("oracle_success".to_string()),
            error_message: None,
            ai_responses: vec![format!("Oracle data retrieved from {}", data_source)],
        })
    }

    fn fetch_external_data(&self, data_source: &str) -> Result<Vec<u8>, String> {
        // Simulate external data fetching
        // In a real implementation, this would make actual HTTP requests to external APIs
        let mock_data = match data_source {
            "price_feed" => "{\"price\": 50000.0, \"timestamp\": 1234567890}",
            "weather" => "{\"temperature\": 25.0, \"humidity\": 60.0}",
            "news" => "{\"headline\": \"Synergy Network launches\", \"category\": \"crypto\"}",
            _ => "{\"data\": \"unknown_source\"}",
        };
        Ok(mock_data.as_bytes().to_vec())
    }

    pub fn get_contract(&self, address: &str) -> Option<AIVMContract> {
        if let Ok(contracts) = self.contracts.lock() {
            contracts.get(address).cloned()
        } else {
            None
        }
    }

    pub fn get_all_contracts(&self) -> Vec<AIVMContract> {
        if let Ok(contracts) = self.contracts.lock() {
            contracts.values().cloned().collect()
        } else {
            Vec::new()
        }
    }

    fn generate_contract_address(&self, creator: &str, bytecode: &[u8]) -> String {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(creator.as_bytes());
        hasher.update(bytecode);
        hasher.update(&std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_le_bytes());
        format!("aivm_{}", hex::encode(hasher.finalize())[..40].to_string())
    }

    pub fn process_transaction(&self, tx: &Transaction) -> Result<AIVMExecutionResult, String> {
        if let Some(contract_data) = &tx.data {
            if contract_data.starts_with("aivm_deploy:") {
                let deploy_data = contract_data.strip_prefix("aivm_deploy:").unwrap();
                let parts: Vec<&str> = deploy_data.split(':').collect();

                if parts.len() >= 3 {
                    let bytecode = hex::decode(parts[0]).map_err(|e| format!("Invalid bytecode: {}", e))?;
                    let abi = parts[1].to_string();
                    let contract_type = match parts[2] {
                        "ai" => ContractType::AIEnhanced,
                        "cross_chain" => ContractType::CrossChain,
                        "oracle" => ContractType::Oracle,
                        _ => ContractType::Standard,
                    };

                    return self.deploy_contract(bytecode, abi, tx.sender.clone(), contract_type)
                        .map(|addr| AIVMExecutionResult {
                            success: true,
                            output: addr.as_bytes().to_vec(),
                            gas_used: 100000,
                            logs: vec![format!("Contract deployed at {}", addr)],
                            return_value: Some(addr),
                            error_message: None,
                            ai_responses: vec![],
                        });
                }
            } else if contract_data.starts_with("aivm_execute:") {
                let execute_data = contract_data.strip_prefix("aivm_execute:").unwrap();
                let parts: Vec<&str> = execute_data.split(':').collect();

                if parts.len() >= 2 {
                    let contract_address = parts[0].to_string();
                    let input_data = hex::decode(parts[1]).unwrap_or_default();

                    let context = AIVMExecutionContext {
                        transaction_hash: tx.hash(),
                        block_height: 0, // Will be set when included in block
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        sender: tx.sender.clone(),
                        contract_address: Some(contract_address.clone()),
                        input_data,
                        gas_limit: tx.gas_limit,
                        gas_price: tx.gas_price,
                    };

                    return self.execute_contract(&contract_address, context);
                }
            }
        }

        Err("Not an AIVM transaction".to_string())
    }
}
