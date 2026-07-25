use crate::blockchain::RpcClient;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const MIN_VALIDATOR_CLUSTER_SIZE: usize = 5;
const TARGET_VALIDATOR_CLUSTER_SIZE: usize = 7;
const THIRD_VALIDATOR_CLUSTER_THRESHOLD: usize = 21;

fn estimated_validator_cluster_count(total_validators: usize) -> u64 {
    if total_validators == 0 {
        0
    } else if total_validators < MIN_VALIDATOR_CLUSTER_SIZE * 2 {
        1
    } else if total_validators < THIRD_VALIDATOR_CLUSTER_THRESHOLD {
        2
    } else {
        (total_validators / TARGET_VALIDATOR_CLUSTER_SIZE) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::estimated_validator_cluster_count;

    #[test]
    fn estimated_cluster_count_matches_protocol_boundaries() {
        for (validators, expected) in [
            (0, 0),
            (1, 1),
            (9, 1),
            (10, 2),
            (20, 2),
            (21, 3),
            (22, 3),
            (27, 3),
            (28, 4),
            (29, 4),
            (35, 5),
        ] {
            assert_eq!(
                estimated_validator_cluster_count(validators),
                expected,
                "validator count {validators}"
            );
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub current_block_height: u64,
    pub network_peers: u64,
    pub sync_percentage: f64,
    pub is_synced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: String,
    pub synergy_score: f64,
    pub blocks_produced: u64,
    pub uptime: f64,
    pub stake_amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    pub number: u64,
    pub hash: String,
    pub timestamp: u64,
    pub transaction_count: usize,
    pub validator: String, // Add validator field
    pub status: String,    // Add status field
}

pub struct BlockchainService {
    rpc_client: RpcClient,
}

impl BlockchainService {
    pub fn new(rpc_endpoint: String) -> Self {
        let rpc_client = RpcClient::new(rpc_endpoint);
        Self { rpc_client }
    }

    pub async fn get_network_status(&self) -> Result<NetworkStatus, String> {
        let current_block_height = self.rpc_client.get_block_number().await?;
        let peers = self.rpc_client.get_network_peers().await?;
        let network_peers = peers.len() as u64;
        let sync_status = self
            .rpc_client
            .call_method::<serde_json::Value>("synergy_getSyncStatus", serde_json::json!([]))
            .await
            .unwrap_or_default();
        let sync_percentage = sync_status
            .get("sync_percentage")
            .or_else(|| sync_status.get("syncPercentage"))
            .and_then(|value| value.as_f64())
            .unwrap_or(0.0);
        let is_synced = sync_status
            .get("syncing")
            .and_then(|value| value.as_bool())
            .map(|syncing| !syncing)
            .unwrap_or(false);

        Ok(NetworkStatus {
            current_block_height,
            network_peers,
            sync_percentage,
            is_synced,
        })
    }

    pub async fn get_validator_info(&self, address: &str) -> Result<ValidatorInfo, String> {
        let validator = self.rpc_client.get_validator_info(address).await?;
        let performance = self
            .rpc_client
            .call_method::<serde_json::Value>(
                "synergy_getValidatorPerformance",
                serde_json::json!([address]),
            )
            .await
            .unwrap_or_default();
        let synergy_score = validator
            .get("synergy_score")
            .or_else(|| validator.get("synergyScore"))
            .and_then(|value| value.as_f64())
            .or_else(|| performance.get("synergyScore").and_then(|value| value.as_f64()))
            .unwrap_or(0.0);

        Ok(ValidatorInfo {
            address: address.to_string(),
            synergy_score,
            blocks_produced: validator
                .get("total_blocks_produced")
                .or_else(|| validator.get("totalBlocksProduced"))
                .or_else(|| performance.get("totalBlocksProduced"))
                .and_then(|value| value.as_u64())
                .unwrap_or(0),
            uptime: validator
                .get("uptime_percentage")
                .or_else(|| validator.get("uptime"))
                .and_then(|value| value.as_f64())
                .unwrap_or(0.0),
            stake_amount: validator
                .get("stake_amount")
                .or_else(|| validator.get("stakeAmount"))
                .or_else(|| performance.get("effectiveBalance"))
                .and_then(|value| value.as_u64())
                .unwrap_or(0),
        })
    }

    pub async fn get_recent_blocks(&self, count: usize) -> Result<Vec<BlockInfo>, String> {
        let mut blocks = Vec::new();
        let current_height = self.rpc_client.get_block_number().await?;

        for i in 0..count {
            if current_height < i as u64 {
                break;
            }
            let block_number = current_height - i as u64;
            let block_data = self.rpc_client.get_block_by_number(block_number).await?;

            // Extract relevant information from the block data
            let hash = block_data
                .get("hash")
                .and_then(|h| h.as_str())
                .unwrap_or("")
                .to_string();

            let timestamp = block_data
                .get("timestamp")
                .and_then(|t| t.as_str())
                .and_then(|t| u64::from_str_radix(t.trim_start_matches("0x"), 16).ok())
                .unwrap_or_else(|| {
                    // If timestamp is not in hex, try parsing as decimal
                    block_data
                        .get("timestamp")
                        .and_then(|t| t.as_str())
                        .and_then(|t| t.parse::<u64>().ok())
                        .unwrap_or(0)
                });

            let transaction_count = block_data
                .get("transactions")
                .and_then(|t| t.as_array())
                .map(|t| t.len())
                .unwrap_or(0);

            // Extract validator information if available
            let validator = block_data
                .get("miner")
                .or_else(|| block_data.get("author"))
                .or_else(|| block_data.get("validator"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let status = block_data
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("validated")
                .to_string();

            blocks.push(BlockInfo {
                number: block_number,
                hash,
                timestamp,
                transaction_count,
                validator: validator.clone(),
                status: status.clone(),
            });
        }

        Ok(blocks)
    }

    pub async fn get_network_validators(&self) -> Result<(usize, usize), String> {
        let validators = self.rpc_client.get_validators().await?;
        // Return (active_validators, total_validators)
        Ok((validators.len(), validators.len()))
    }

    pub async fn get_cluster_info(&self) -> Result<(u64, u64), String> {
        let validators = self.rpc_client.get_validators().await?;
        let mut cluster_ids = HashSet::new();

        for validator in &validators {
            if let Some(cluster_id) = validator.get("cluster_id").and_then(|value| value.as_u64()) {
                cluster_ids.insert(cluster_id);
            }
        }

        let total_validators = validators.len();
        let estimated_clusters = if !cluster_ids.is_empty() {
            cluster_ids.len() as u64
        } else {
            estimated_validator_cluster_count(total_validators)
        };

        let total_stake = 5000000; // In a real implementation, this would come from blockchain data

        Ok((estimated_clusters, total_stake))
    }

    pub async fn get_bootstrap_nodes(&self) -> Result<Vec<String>, String> {
        // Get actual bootstrap nodes from the blockchain or configuration
        // For now, fetch from a network configuration endpoint
        let network_info = self.rpc_client.get_network_info().await?;

        match network_info.get("bootstrap_nodes") {
            Some(nodes) => {
                let mut result = Vec::new();
                if let Some(node_array) = nodes.as_array() {
                    for node in node_array {
                        if let Some(node_str) = node.as_str() {
                            result.push(node_str.to_string());
                        }
                    }
                }
                Ok(result)
            }
            None => {
                // Fallback to the published Testnet bootstrap set.
                Ok(vec![
                    "170.64.187.206:5620".to_string(),
                    "146.190.210.121:5620".to_string(),
                    "157.245.226.240:5620".to_string(),
                ])
            }
        }
    }

    pub async fn get_network_topology(&self) -> Result<String, String> {
        // Get actual network topology from the blockchain
        let network_info = self.rpc_client.get_network_info().await?;

        match network_info.get("topology") {
            Some(topology) => {
                if let Some(topology_str) = topology.as_str() {
                    Ok(topology_str.to_string())
                } else {
                    Ok("Mesh".to_string()) // Default fallback
                }
            }
            None => {
                Ok("Mesh".to_string()) // Default fallback
            }
        }
    }

    pub async fn get_validator_cluster_id(&self, address: &str) -> Result<Option<u64>, String> {
        self.rpc_client.get_validator_cluster_id(address).await
    }

    pub async fn get_synergy_score(&self, address: &str) -> Result<f64, String> {
        self.rpc_client.get_synergy_score(address).await
    }

    pub async fn get_all_validators(&self) -> Result<Vec<ValidatorInfo>, String> {
        let validator_values = self.rpc_client.get_validators().await?;

        let mut validators = Vec::new();

        for val in validator_values {
            if let Some(address) = val.get("address").and_then(|a| a.as_str()) {
                // Try to get the synergy score for each validator
                match self.rpc_client.get_synergy_score(address).await {
                    Ok(score) => {
                        validators.push(ValidatorInfo {
                            address: address.to_string(),
                            synergy_score: score,
                            blocks_produced: 0,
                            uptime: 100.0,
                            stake_amount: 0,
                        });
                    }
                    Err(_) => {
                        // If we can't get the synergy score, add with default value
                        validators.push(ValidatorInfo {
                            address: address.to_string(),
                            synergy_score: 0.0,
                            blocks_produced: 0,
                            uptime: 100.0,
                            stake_amount: 0,
                        });
                    }
                }
            }
        }

        Ok(validators)
    }
}
