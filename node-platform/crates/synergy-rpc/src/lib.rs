//! Bounded public JSON-RPC surface. Privileged node administration is excluded.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod auth;
pub mod health;
pub mod methods;
pub mod middleware;
pub mod provider;
pub mod rate_limit;
pub mod server;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl RpcRequest {
    pub fn validate(&self) -> Result<(), RpcError> {
        if self.jsonrpc != "2.0" || self.method.trim().is_empty() || self.method.len() > 256 {
            return Err(RpcError::invalid_request("invalid JSON-RPC request"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            code: -32600,
            message: message.into(),
        }
    }

    pub fn method_not_found() -> Self {
        Self {
            code: -32601,
            message: "method not found".into(),
        }
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: -32000,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl RpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(id: Value, error: RpcError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

pub trait RpcDispatcher: Send + Sync {
    fn dispatch(&self, method: &str, params: Value) -> Result<Value, RpcError>;
}
