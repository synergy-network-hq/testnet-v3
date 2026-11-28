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

pub use consensus::{
    AutonomousEpochActivation, ConsensusConfiguration, ConsensusMode,
    ManagedWalletDispatchReleaseConfiguration,
};
pub use etdag::{EtdagConfiguration, GOVERNED_PROTECTED_LOOKAHEAD};
pub use loader::{decode, load, ConfigLoadError, MAX_CONFIGURATION_BYTES};
pub use network::NetworkConfiguration;
pub use node::{
    ApqeProviderConfiguration, ApqeTransportConfiguration, ApqeTransportProfile, NodeConfiguration,
    R1GenesisSelection, R1NicSelection, R1RuntimeConfiguration, R1RuntimeReadPolicy,
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
            r1_genesis: None,
            r1_runtime: None,
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

    fn formation_transport_configuration() -> NodeConfiguration {
        let mut cfg = configuration(NodeRole::Validator);
        cfg.chain_id = 999998;
        cfg.network_id = "nodenetwork-formation-disposable-20261112".into();
        cfg.aegis_key_bindings_path = None;
        cfg.aegis_signing_key_path = None;
        cfg.genesis_path = Some("/opt/synergy/network/genesis.json".into());
        cfg.consensus.mode = ConsensusMode::ValidateAndVote;
        cfg.etdag.enabled = true;
        cfg.consensus.authority_binding = Some("/opt/synergy/network/authority.json".into());
        cfg.consensus.authority_trust_key_path =
            Some("/opt/synergy/network/authority-root.pub".into());
        cfg.aegis_provider = Some(ApqeProviderConfiguration {
            report_path: "/opt/synergy/lib/apqe/build-report.json".into(),
            authenticated_report_sha256: "1".repeat(64),
        });
        cfg.apqe_transport = Some(ApqeTransportConfiguration {
            profile: ApqeTransportProfile::EngineeringCanaryPqVsessionV1,
            registry_path: "/opt/synergy/network/transport-registry.json".into(),
            registry_trust_key_path: "/opt/synergy/network/transport-root.pub".into(),
            registry_trust_key_sha256: "2".repeat(64),
            genesis_trust_key_sha256: "3".repeat(64),
            enrollment_path: "/opt/synergy/keys/apqe/enrollment.json".into(),
            custody_path: "/opt/synergy/keys/apqe/custody.json".into(),
            custody_unlock_path: "/opt/synergy/keys/apqe/unlock".into(),
        });
        cfg
    }

    #[test]
    fn native_formation_namespace_still_requires_the_exact_apqe_trust_profile() {
        let cfg = formation_transport_configuration();
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
    fn controlled_canary_namespace_preserves_chain_and_apqe_provenance_gates() {
        let mut cfg = formation_transport_configuration();
        cfg.chain_id = 99999;
        cfg.network_id = "synergy-posy-canary-20261117".into();
        assert!(cfg.validate().is_ok(), "{:?}", cfg.validate());
        for name in [
            "synergy-posy-canary-",
            "synergy-posy-canary--bad",
            "synergy-posy-canary-Mainnet",
            "synergy-posy-canary-bad_name",
            "synergy-posy-mainnet-20261117",
            "mainnet",
        ] {
            let mut candidate = cfg.clone();
            candidate.network_id = name.into();
            assert!(candidate.validate().is_err(), "{name}");
        }
        for chain in [0, 1266, 999998] {
            let mut candidate = cfg.clone();
            candidate.chain_id = chain;
            assert!(candidate.validate().is_err(), "chain {chain}");
        }
        for missing in [
            "provider",
            "genesis",
            "authority",
            "root",
            "report_pin",
            "transport_pin",
            "genesis_pin",
        ] {
            let mut candidate = cfg.clone();
            match missing {
                "provider" => candidate.aegis_provider = None,
                "genesis" => candidate.genesis_path = None,
                "authority" => candidate.consensus.authority_binding = None,
                "root" => candidate.consensus.authority_trust_key_path = None,
                "report_pin" => candidate
                    .aegis_provider
                    .as_mut()
                    .unwrap()
                    .authenticated_report_sha256
                    .clear(),
                "transport_pin" => candidate
                    .apqe_transport
                    .as_mut()
                    .unwrap()
                    .registry_trust_key_sha256
                    .clear(),
                "genesis_pin" => candidate
                    .apqe_transport
                    .as_mut()
                    .unwrap()
                    .genesis_trust_key_sha256
                    .clear(),
                _ => unreachable!(),
            }
            assert!(candidate.validate().is_err(), "{missing}");
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
    fn current_configuration() -> NodeConfiguration {
        let mut c = configuration(NodeRole::Validator);
        c.chain_id = u64::MAX - 1;
        c.network_id = "public-synthetic-current-r1".into();
        c.manifest_path = PathBuf::new();
        c.public_identity_path = PathBuf::new();
        c.aegis_key_bindings_path = None;
        c.aegis_signing_key_path = None;
        c.consensus = ConsensusConfiguration::default();
        c.consensus.mode = ConsensusMode::Observe;
        c.aegis_provider = Some(ApqeProviderConfiguration {
            report_path: "/managed/public-fixture/provider/report.json".into(),
            authenticated_report_sha256: "11".repeat(32),
        });
        c.admin_socket_path = "/managed/public-fixture/run/admin.sock".into();
        c.storage.data_directory = "/managed/public-fixture/state".into();
        c.storage.world_memory_budget_bytes = 64 * 1024 * 1024;
        c.r1_genesis = Some(R1GenesisSelection {
            managed_root: "/managed/public-fixture".into(),
            core_path: "public/core.bin".into(),
            approvals_path: "public/approvals.json".into(),
            pinned_bootstrap_input_path: "public/birth.json".into(),
            pinned_bootstrap_input_sha256: "12".repeat(32),
            profile_catalog_path: "public/catalog.bin".into(),
            profile_catalog_sha256: "13".repeat(32),
            expected_nic_hex: "14".repeat(64),
            expected_genesis_hex: "15".repeat(48),
        });
        c.r1_runtime = Some(R1RuntimeConfiguration {
            process_world_budget_bytes: 64 * 1024 * 1024,
            local_node_identity: format!("synv1.2.{}", "A".repeat(64)),
            transport_use_receipts: vec!["native/transport-use.json".into()],
            consensus_use_receipt: None,
            rpc_read_policy: None,
        });
        c
    }
    #[test]
    fn current_configuration_needs_no_legacy_dummy_files_and_grants_no_authority() {
        let c = current_configuration();
        assert!(c.validate().is_ok());
        let mut json = serde_json::to_value(&c).unwrap();
        json.as_object_mut().unwrap().remove("manifest_path");
        json.as_object_mut().unwrap().remove("public_identity_path");
        let decoded: NodeConfiguration = serde_json::from_value(json).unwrap();
        assert!(decoded.validate().is_ok());
        // Syntax is not transport/provider/startup qualification.
        assert!(decoded.require_native_post_quantum_transport().is_err());
        let mut legacy = configuration(NodeRole::ObserverLight);
        assert!(legacy.validate().is_ok());
        legacy.chain_id = 9969;
        assert!(legacy.validate().is_err());
    }
    #[test]
    fn current_configuration_rejects_legacy_mix_wrong_class_and_unconfined_receipts() {
        let c = current_configuration();
        let mut wrong = c.clone();
        wrong.manifest_path = "/legacy/manifest.json".into();
        assert!(wrong.validate().is_err());
        wrong = c.clone();
        wrong.consensus.authority_binding = Some("/legacy/authority.json".into());
        assert!(wrong.validate().is_err());
        wrong = c.clone();
        wrong.r1_runtime.as_mut().unwrap().local_node_identity =
            format!("synv5.2.{}", "A".repeat(64));
        assert!(wrong.validate().is_err());
        wrong = c.clone();
        wrong.r1_runtime.as_mut().unwrap().transport_use_receipts[0] = "../escape".into();
        assert!(wrong.validate().is_err());
        wrong = c.clone();
        wrong.storage.data_directory = "/unmanaged/state".into();
        assert!(wrong.validate().is_err());
        wrong = c.clone();
        wrong.r1_genesis.as_mut().unwrap().expected_nic_hex = "00".repeat(64);
        assert!(wrong.validate().is_err());
        wrong = c.clone();
        wrong.consensus.mode = ConsensusMode::ValidateAndVote;
        wrong.etdag.enabled = true;
        assert!(wrong.validate().is_err());
        wrong.r1_runtime.as_mut().unwrap().consensus_use_receipt =
            Some("native/transport-use.json".into());
        assert!(wrong.validate().is_err());
        wrong.r1_runtime.as_mut().unwrap().consensus_use_receipt =
            Some("native/consensus-use.json".into());
        assert!(wrong.validate().is_ok());
        wrong.role = NodeRole::Sentry;
        assert!(wrong.validate().is_err());
    }
    #[test]
    fn current_public_reads_require_explicit_quota_and_protected_process_headroom() {
        let mut c = current_configuration();
        c.rpc.enabled = true;
        c.rpc.listen_address = Some("127.0.0.1:19001".parse().unwrap());
        assert!(c.validate().is_err());
        c.r1_runtime.as_mut().unwrap().rpc_read_policy = Some(R1RuntimeReadPolicy {
            request_timeout_ms: 1000,
            maximum_hashes: 64,
            maximum_response_bytes: 1024,
            public_quota_bytes: 16 * 1024 * 1024,
            protected_world_headroom_bytes: 32 * 1024 * 1024,
        });
        assert!(c.validate().is_ok());
        c.r1_runtime
            .as_mut()
            .unwrap()
            .rpc_read_policy
            .as_mut()
            .unwrap()
            .maximum_response_bytes = 64 * 1024 * 1024;
        assert!(c.validate().is_err());
        c.r1_runtime
            .as_mut()
            .unwrap()
            .rpc_read_policy
            .as_mut()
            .unwrap()
            .maximum_response_bytes = 1024;
        c.r1_runtime.as_mut().unwrap().process_world_budget_bytes = 1;
        assert!(c.validate().is_err());
        c.r1_runtime.as_mut().unwrap().process_world_budget_bytes = 64 * 1024 * 1024;
        c.r1_runtime
            .as_mut()
            .unwrap()
            .rpc_read_policy
            .as_mut()
            .unwrap()
            .protected_world_headroom_bytes = 64 * 1024 * 1024;
        assert!(c.validate().is_err());
        c.r1_runtime
            .as_mut()
            .unwrap()
            .rpc_read_policy
            .as_mut()
            .unwrap()
            .protected_world_headroom_bytes = 0;
        assert!(c.validate().is_err());
    }
}
