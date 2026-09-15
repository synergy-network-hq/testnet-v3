//! Canonical configuration model for the new Synergy node platform.
//!
//! This crate intentionally does not accept legacy runtime configuration or
//! Genesis formats. It validates service settings and paths only; role
//! selection never grants validator authority.

mod consensus;
mod etdag;
mod loader;
mod network;
mod node;
mod p2p;
mod role;
mod rpc;
mod storage;
mod telemetry;
mod validation;
mod vpn;

pub use consensus::{ConsensusConfiguration, ConsensusMode};
pub use etdag::{EtdagConfiguration, GOVERNED_PROTECTED_LOOKAHEAD};
pub use loader::{decode, load, ConfigLoadError, MAX_CONFIGURATION_BYTES};
pub use network::NetworkConfiguration;
pub use node::{NodeConfiguration, CONFIG_SCHEMA_VERSION};
pub use p2p::P2pConfiguration;
pub use rpc::RpcConfiguration;
pub use storage::{StorageConfiguration, WalSyncPolicy};
pub use telemetry::{LogFormat, TelemetryConfiguration};
pub use validation::ConfigError;
pub use vpn::{VpnConfiguration, VpnMode};

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use synergy_protocol_types::NodeRole;

    use super::*;

    fn configuration(role: NodeRole) -> NodeConfiguration {
        NodeConfiguration {
            schema_version: CONFIG_SCHEMA_VERSION,
            node_name: "node-1".into(),
            role,
            chain_id: 1266,
            network_id: "testnet".into(),
            manifest_path: PathBuf::from("/etc/synergy/network-manifest.json"),
            public_identity_path: PathBuf::from("/etc/synergy/public-identity.json"),
            aegis_key_bindings_path: Some(PathBuf::from("/etc/synergy/aegis-bindings.json")),
            aegis_signing_key_path: Some(PathBuf::from("/etc/synergy/aegis-identity.key")),
            admin_socket_path: PathBuf::from("/run/synergy/admin.sock"),
            network: NetworkConfiguration::default(),
            p2p: P2pConfiguration::default(),
            consensus: ConsensusConfiguration::default(),
            etdag: EtdagConfiguration::default(),
            storage: StorageConfiguration {
                data_directory: PathBuf::from("/var/lib/synergy/node-1"),
                wal_sync: WalSyncPolicy::EveryCommit,
                max_open_files: 128,
                minimum_free_bytes: 2 * 1024 * 1024 * 1024,
                prune_finalized_history_after_blocks: None,
            },
            rpc: RpcConfiguration::default(),
            telemetry: TelemetryConfiguration::default(),
            vpn: VpnConfiguration::default(),
        }
    }

    #[test]
    fn validates_node_configuration() {
        assert!(configuration(NodeRole::ObserverLight).validate().is_ok());
        let mut invalid = configuration(NodeRole::ObserverLight);
        invalid.chain_id = 0;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn validator_role_does_not_grant_validator_authority() {
        assert!(!configuration(NodeRole::Validator).role_grants_validator_authority());
    }
}
