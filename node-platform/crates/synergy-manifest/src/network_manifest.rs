use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkManifest {
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub protocol_version: String,
    pub manifest_hash: String,
}
