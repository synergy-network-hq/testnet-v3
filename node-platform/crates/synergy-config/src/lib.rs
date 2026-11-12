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
mod update;
mod validation;
mod vpn;

pub use consensus::{ConsensusConfiguration, ConsensusMode};
pub use etdag::{EtdagConfiguration, GOVERNED_PROTECTED_LOOKAHEAD};
pub use loader::{decode, load, ConfigLoadError, MAX_CONFIGURATION_BYTES};
pub use network::NetworkConfiguration;
pub use node::{
    ApqeProviderConfiguration, ApqeTransportConfiguration, ApqeTransportProfile, NodeConfiguration,
    CONFIG_SCHEMA_VERSION,
};
pub use p2p::P2pConfiguration;
pub use rpc::RpcConfiguration;
pub use storage::{default_world_memory_budget_bytes, StorageConfiguration, WalSyncPolicy};
pub use telemetry::{LogFormat, TelemetryConfiguration};
pub use update::{
    UpdateChannel, UpdateConfiguration, UpdateMode, DEFAULT_MAXIMUM_UPDATE_ARTIFACT_BYTES,
};
pub use validation::{is_disposable_formation_network, ConfigError, NativeTransportPolicyError};
pub use vpn::{TransportContext, VpnConfiguration, VpnMode};

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
            genesis_path: None,
            public_identity_path: PathBuf::from("/etc/synergy/public-identity.json"),
            aegis_key_bindings_path: Some(PathBuf::from("/etc/synergy/aegis-bindings.json")),
            aegis_signing_key_path: Some(PathBuf::from("/etc/synergy/aegis-identity.key")),
            aegis_provider: None,
            apqe_transport: None,
            admin_socket_path: PathBuf::from("/run/synergy/admin.sock"),
            network: NetworkConfiguration::default(),
            p2p: P2pConfiguration::default(),
            consensus: ConsensusConfiguration::default(),
            etdag: EtdagConfiguration::default(),
            storage: StorageConfiguration {
                data_directory: PathBuf::from("/var/lib/synergy/node-1"),
                wal_sync: WalSyncPolicy::EveryCommit,
                max_open_files: 128,
                world_memory_budget_bytes: default_world_memory_budget_bytes(),
                minimum_free_bytes: 2 * 1024 * 1024 * 1024,
                prune_finalized_history_after_blocks: None,
            },
            rpc: RpcConfiguration::default(),
            telemetry: TelemetryConfiguration::default(),
            update: UpdateConfiguration::default(),
            vpn: VpnConfiguration::default(),
        }
    }

    #[test]
    fn classical_overlays_and_unprotected_tcp_never_qualify_native_transport() {
        let mut config = configuration(NodeRole::ObserverLight);
        assert_eq!(
            config.require_native_post_quantum_transport(),
            Err(NativeTransportPolicyError::MissingPostQuantumAuthenticatedRecordLayer)
        );
        for mode in [VpnMode::Required, VpnMode::Preferred] {
            config.vpn.mode = mode;
            assert_eq!(
                config.require_native_post_quantum_transport(),
                Err(NativeTransportPolicyError::ClassicalOverlayForbidden)
            );
            assert_eq!(
                config.validate(),
                Err(ConfigError::NativeTransportNotQualified(
                    NativeTransportPolicyError::ClassicalOverlayForbidden
                ))
            );
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
    fn native_formation_namespace_still_requires_the_exact_apqe_trust_profile() {
        let mut cfg = configuration(NodeRole::Validator);
        cfg.chain_id = 999998;
        cfg.network_id = "nodenetwork-formation-disposable-20261112".into();
        cfg.aegis_key_bindings_path = None;
        cfg.aegis_signing_key_path = None;
        cfg.genesis_path = Some("/opt/Synergy/network/genesis.json".into());
        cfg.consensus.mode = ConsensusMode::ValidateAndVote;
        cfg.etdag.enabled = true;
        cfg.consensus.authority_binding = Some("/opt/Synergy/network/authority.json".into());
        cfg.consensus.authority_trust_key_path =
            Some("/opt/Synergy/network/authority-root.pub".into());
        cfg.aegis_provider = Some(ApqeProviderConfiguration {
            report_path: "/opt/Synergy/lib/apqe/build-report.json".into(),
            authenticated_report_sha256: "1".repeat(64),
        });
        cfg.apqe_transport = Some(ApqeTransportConfiguration {
            profile: ApqeTransportProfile::EngineeringCanaryPqVsessionV1,
            registry_path: "/opt/Synergy/network/transport-registry.json".into(),
            registry_trust_key_path: "/opt/Synergy/network/transport-root.pub".into(),
            registry_trust_key_sha256: "2".repeat(64),
            genesis_trust_key_sha256: "3".repeat(64),
            enrollment_path: "/opt/Synergy/keys/apqe/enrollment.json".into(),
            custody_path: "/opt/Synergy/keys/apqe/custody.json".into(),
            custody_unlock_path: "/opt/Synergy/keys/apqe/unlock".into(),
        });
        assert!(cfg.validate().is_ok(), "{:?}", cfg.validate());
        for other in [
            "mainnet",
            "nodenetwork-formation-disposable-",
            "nodenetwork-formation-disposable--bad",
        ] {
            let mut candidate = cfg.clone();
            candidate.network_id = other.into();
            assert!(candidate.validate().is_err(), "{other}");
        }
        for without in ["provider", "genesis", "authority", "root"] {
            let mut candidate = cfg.clone();
            match without {
                "provider" => candidate.aegis_provider = None,
                "genesis" => candidate.genesis_path = None,
                "authority" => candidate.consensus.authority_binding = None,
                "root" => candidate.consensus.authority_trust_key_path = None,
                _ => unreachable!(),
            }
            assert!(candidate.validate().is_err(), "{without}");
        }
    }

    #[test]
    fn enabled_etdag_lookahead_has_bounded_structural_validation() {
        let mut config = configuration(NodeRole::ObserverLight);
        config.etdag.enabled = true;
        assert_eq!(config.etdag.protected_lookahead, 5);
        for offset in [5, 6, 16] {
            config.etdag.protected_lookahead = offset;
            assert!(config.validate().is_ok(), "offset {offset}");
        }
        for offset in [0, 4, 17, u64::MAX] {
            config.etdag.protected_lookahead = offset;
            assert!(config.validate().is_err(), "offset {offset}");
        }
    }

    #[test]
    fn world_memory_budget_has_compatible_default_and_rejects_zero() {
        let mut config = configuration(NodeRole::ObserverLight);
        let mut json = serde_json::to_value(&config).unwrap();
        json["storage"]
            .as_object_mut()
            .unwrap()
            .remove("world_memory_budget_bytes");
        let decoded = decode("node.json", &serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(decoded.storage.world_memory_budget_bytes, 64 * 1024 * 1024);
        config.storage.world_memory_budget_bytes = 0;
        assert!(config.validate().is_err());
        config.storage.world_memory_budget_bytes = 256 * 1024 * 1024;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn update_authority_requires_complete_absolute_bindings() {
        let mut config = configuration(NodeRole::ObserverLight);
        config.update.enabled = true;
        assert!(config.validate().is_err());
        config.update.catalog_path = Some(PathBuf::from("/etc/synergy/releases.json"));
        config.update.release_signer_key_id = Some("release-root-1".into());
        config.update.release_signer_public_key_path =
            Some(PathBuf::from("/etc/synergy/release-root.pub"));
        config.update.staging_directory = Some(PathBuf::from("/var/lib/synergy/updates"));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validator_role_does_not_grant_validator_authority() {
        assert!(!configuration(NodeRole::Validator).role_grants_validator_authority());
    }

    #[test]
    fn ingress_kem_custody_path_is_optional_but_absolute_when_present() {
        let mut config = configuration(NodeRole::ObserverLight);
        let mut json = serde_json::to_value(&config).unwrap();
        json["etdag"]
            .as_object_mut()
            .unwrap()
            .remove("ingress_kem_secret_key_path");
        let decoded = decode("node.json", &serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(decoded.etdag.ingress_kem_secret_key_path, None);
        config.etdag.ingress_kem_secret_key_path = Some(PathBuf::from("keys/ingress.key"));
        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAbsolutePath(
                "etdag.ingress_kem_secret_key_path"
            ))
        );
        config.etdag.ingress_kem_secret_key_path =
            Some(PathBuf::from("/etc/synergy/keys/ingress.key"));
        assert!(config.validate().is_ok());
    }
}
