use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnMode {
    Disabled,
    Preferred,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpnConfiguration {
    #[serde(default)]
    pub transport_context: Option<TransportContext>,
    pub mode: VpnMode,
    pub interface_name: Option<String>,
    pub signed_registry_path: Option<PathBuf>,
    #[serde(default)]
    pub attestation_public_key: Option<String>,
    #[serde(default)]
    pub provider_plan_sha256: Option<String>,
}

impl Default for VpnConfiguration {
    fn default() -> Self {
        Self {
            transport_context: None,
            mode: VpnMode::Disabled,
            interface_name: None,
            signed_registry_path: None,
            attestation_public_key: None,
            provider_plan_sha256: None,
        }
    }
}

/// Names bound by the signed transport snapshot and selected network configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportContext {
    pub network: String,
    pub registry_id: String,
    pub release_id: String,
    pub protocol_version: String,
}
