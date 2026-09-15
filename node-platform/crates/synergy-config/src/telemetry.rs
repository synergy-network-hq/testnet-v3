use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Human,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfiguration {
    pub service_name: String,
    pub log_format: LogFormat,
    pub metrics_listen_address: Option<SocketAddr>,
    pub trace_sample_per_million: u32,
}

impl Default for TelemetryConfiguration {
    fn default() -> Self {
        Self {
            service_name: "synergy-node".into(),
            log_format: LogFormat::Json,
            metrics_listen_address: None,
            trace_sample_per_million: 10_000,
        }
    }
}
