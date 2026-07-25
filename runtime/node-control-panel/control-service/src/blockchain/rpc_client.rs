use reqwest;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RpcClient {
    client: reqwest::Client,
    endpoint: String,
}

#[derive(Debug, Deserialize)]
pub struct RpcResponse<T> {
    pub jsonrpc: String,
    pub id: u64,
    pub result: Option<T>,
    pub error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcClient {
    pub fn new(endpoint: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, endpoint }
    }

    pub async fn call_method<T>(&self, method: &str, params: Value) -> Result<T, String>
    where
        T: for<'de> Deserialize<'de>,
    {
        let request_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });

        let response = self
            .client
            .post(&self.endpoint)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| format!("Failed to send RPC request: {}", e))?;

        let response_text = response
            .text()
            .await
            .map_err(|e| format!("Failed to read RPC response: {}", e))?;

        let rpc_response: RpcResponse<T> = serde_json::from_str(&response_text)
            .map_err(|e| format!("Failed to parse RPC response: {}", e))?;

        match rpc_response.error {
            Some(error) => Err(format!("RPC error {}: {}", error.code, error.message)),
            None => rpc_response
                .result
                .ok_or_else(|| "RPC response has no result".to_string()),
        }
    }

    pub async fn get_block_number(&self) -> Result<u64, String> {
        let result: Value = self.call_method("synergy_blockNumber", json!([])).await?;
        parse_u64_value(&result).ok_or_else(|| "Failed to parse block number".to_string())
    }

    pub async fn get_network_peers(&self) -> Result<Vec<String>, String> {
        let result: Value = self.call_method("synergy_getPeerInfo", json!([])).await?;
        Ok(result
            .get("peers")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| item.as_str().map(str::to_string).unwrap_or_else(|| item.to_string()))
                    .collect()
            })
            .unwrap_or_default())
    }

    pub async fn get_synergy_score(&self, address: &str) -> Result<f64, String> {
        let result: Value = self
            .call_method("synergy_getSynergyScoreBreakdown", json!([address]))
            .await?;

        if let Some(score) = result.get("total_score").and_then(Value::as_f64).or_else(|| result.as_f64()) {
            Ok(score)
        } else {
            Err("Invalid synergy score format".to_string())
        }
    }

    pub async fn get_validator_info(&self, address: &str) -> Result<Value, String> {
        let result: Value = self
            .call_method("synergy_getValidator", json!([address]))
            .await?;
        Ok(result)
    }

    pub async fn get_validator_cluster_id(&self, address: &str) -> Result<Option<u64>, String> {
        let validator_info = self.get_validator_info(address).await?;
        Ok(validator_info.get("cluster_id").and_then(|id| id.as_u64()))
    }

    pub async fn get_block_by_number(&self, block_number: u64) -> Result<Value, String> {
        let result: Value = self
            .call_method("synergy_getBlockByNumber", json!([block_number]))
            .await?;
        Ok(result)
    }

    pub async fn get_validators(&self) -> Result<Vec<Value>, String> {
        let result: Vec<Value> = self.call_method("synergy_getValidators", json!([])).await?;
        Ok(result)
    }

    pub async fn get_node_info(&self, address: &str) -> Result<Value, String> {
        let mut result: Value = self.call_method("synergy_nodeInfo", json!([])).await?;
        if let Some(object) = result.as_object_mut() {
            object.insert("requested_address".to_string(), json!(address));
        }
        Ok(result)
    }

    pub async fn get_network_info(&self) -> Result<Value, String> {
        let result: Value = self
            .call_method("synergy_getNetworkStats", json!([]))
            .await?;
        Ok(result)
    }
}

fn parse_u64_value(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }
    value.as_str().and_then(|text| {
        if let Some(hex) = text.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).ok()
        } else {
            text.parse::<u64>().ok()
        }
    })
}
