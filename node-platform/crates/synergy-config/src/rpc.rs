use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcConfiguration {
    pub enabled: bool,
    pub listen_address: Option<SocketAddr>,
    pub max_request_bytes: usize,
    pub max_concurrent_requests: usize,
}

impl Default for RpcConfiguration {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: None,
            max_request_bytes: 1024 * 1024,
            max_concurrent_requests: 256,
        }
    }
}
