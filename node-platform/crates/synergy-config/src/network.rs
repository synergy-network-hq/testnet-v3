use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfiguration {
    pub listen_addresses: Vec<SocketAddr>,
    pub advertised_addresses: Vec<SocketAddr>,
    pub dial_timeout_ms: u64,
    pub idle_connection_timeout_ms: u64,
}

impl Default for NetworkConfiguration {
    fn default() -> Self {
        Self {
            listen_addresses: vec![SocketAddr::from(([127, 0, 0, 1], 5622))],
            advertised_addresses: Vec::new(),
            dial_timeout_ms: 5_000,
            idle_connection_timeout_ms: 60_000,
        }
    }
}
