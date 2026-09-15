#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeRole {
    Validator,
    Sentry,
    Archive,
    ConsensusAudit,
    CrossChain,
    Witness,
    Oracle,
    UmaCoordinator,
    SynqExecution,
    NetworkAnalytics,
    AegisCryptography,
    DataAvailability,
    AiCompute,
    AiCoordination,
    AiData,
    AiAssurance,
    RpcGateway,
    Indexer,
    ObserverLight,
    Bootseed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityPlane {
    ConsensusChainIntegrity,
    Interoperability,
    ExecutionDataCryptography,
    AiIntelligence,
    ServiceAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleProfile {
    pub role: NodeRole,
    pub role_id: &'static str,
    pub display_name: &'static str,
    pub compiled_profile: &'static str,
    pub authority_plane: AuthorityPlane,
    pub service_surface: &'static [&'static str],
    pub required_ports: &'static [&'static str],
}

const VALIDATOR_SERVICES: &[&str] = &[
    "p2p",
    "consensus",
    "etdag",
    "state",
    "aegis-verifier",
    "validator-vpn",
    "telemetry",
];
const SENTRY_SERVICES: &[&str] = &[
    "public-p2p",
    "validator-vpn",
    "authenticated-forwarder",
    "traffic-filter",
    "rate-limit",
    "telemetry",
];
const ARCHIVE_SERVICES: &[&str] = &["p2p", "state", "archive", "proof-builder", "snapshot"];
const CONSENSUS_AUDIT_SERVICES: &[&str] = &[
    "p2p",
    "consensus-audit",
    "qc-verifier",
    "state-diff",
    "alerting",
];
const CROSS_CHAIN_SERVICES: &[&str] = &[
    "p2p",
    "chain-sync",
    "sxcp-relay",
    "sxcp-verify",
    "finality-checker",
    "independence-guard",
    "receipt-issuer",
    "telemetry",
];
const WITNESS_SERVICES: &[&str] = &[
    "external-observer",
    "proof-capture",
    "witness-submit",
    "telemetry",
];
const ORACLE_SERVICES: &[&str] = &[
    "oracle-fetch",
    "source-auth",
    "quote-normalizer",
    "attestation-submit",
];
const UMA_COORDINATOR_SERVICES: &[&str] = &[
    "uma-registry-client",
    "identity-refresh-orchestration",
    "mapping-verifier",
    "audit-logging",
];
const SYNQ_EXECUTION_SERVICES: &[&str] = &[
    "synq-runtime",
    "trace",
    "determinism-check",
    "predeploy-sim",
];
const NETWORK_ANALYTICS_SERVICES: &[&str] =
    &["simulator", "risk-model", "anomaly-detector", "reporting"];
const AEGIS_CRYPTOGRAPHY_SERVICES: &[&str] = &[
    "aegis-verify",
    "kms-bridge",
    "key-lifecycle",
    "attestation-sign",
    "audit-log",
];
const DATA_AVAILABILITY_SERVICES: &[&str] = &[
    "da-store",
    "shard-serve",
    "proof-index",
    "availability-audit",
];
const AI_COMPUTE_SERVICES: &[&str] = &[
    "ai-inference",
    "ai-embeddings",
    "ai-training",
    "ai-agent-sandbox",
    "workload-receipts",
];
const AI_COORDINATION_SERVICES: &[&str] = &[
    "ai-routing",
    "gpu-scheduler",
    "quota-policy",
    "capacity-metering",
    "federated-coordination",
];
const AI_DATA_SERVICES: &[&str] = &[
    "model-repository",
    "dataset-provenance",
    "vector-memory",
    "retention",
    "deletion-receipts",
];
const AI_ASSURANCE_SERVICES: &[&str] = &[
    "receipt-verification",
    "replay",
    "evaluation",
    "reputation",
    "independence-guard",
];
const RPC_GATEWAY_SERVICES: &[&str] = &[
    "p2p",
    "rpc",
    "ws",
    "chain-sync",
    "state",
    "rate-limit",
    "authn/authz",
    "edge-cache",
];
const INDEXER_SERVICES: &[&str] = &[
    "p2p",
    "chain-sync",
    "state",
    "indexer-ingest",
    "query-api",
    "search",
    "explorer-backend",
];
const OBSERVER_LIGHT_SERVICES: &[&str] = &[
    "p2p",
    "chain-sync",
    "header-sync",
    "light-proof-check",
    "wallet-feed",
];
const BOOTSEED_SERVICES: &[&str] = &[
    "p2p",
    "authenticated-discovery",
    "peer-exchange",
    "telemetry",
];

const VALIDATOR_PORTS: &[&str] = &[
    "5622 plus slot p2p",
    "5640 plus slot localhost rpc",
    "5660 plus slot localhost ws",
    "6030 plus slot localhost metrics",
];
const SENTRY_PORTS: &[&str] = &[
    "5622 plus slot public p2p",
    "5623 plus slot validator-vpn p2p",
    "6030 plus slot localhost metrics",
];
const ARCHIVE_PORTS: &[&str] = &[
    "5622 plus slot p2p",
    "5640 plus slot localhost read rpc",
    "6030 plus slot localhost metrics",
];
const CROSS_CHAIN_PORTS: &[&str] = &[
    "5622 plus slot p2p",
    "3040 https sxcp api",
    "3041 wss sxcp stream",
    "6030 plus slot localhost metrics",
];
const BASIC_METRICS_PORTS: &[&str] = &["6030 plus slot localhost metrics"];
const RPC_GATEWAY_PORTS: &[&str] = &[
    "5622 plus slot p2p",
    "5640 plus slot core rpc upstream",
    "5660 plus slot core ws upstream",
    "5680 plus slot discovery",
    "8545 evm http",
    "8546 evm ws",
];
const INDEXER_PORTS: &[&str] = &[
    "5627 plus slot p2p",
    "5687 plus slot discovery",
    "3010 ingest",
    "3011 indexer api",
    "3020 explorer api",
    "5647 localhost rpc",
    "5667 localhost ws",
];
const OBSERVER_LIGHT_PORTS: &[&str] = &[
    "5622 plus slot private p2p",
    "implementation-specific readonly light api",
    "6030 plus slot localhost metrics",
];
const BOOTSEED_PORTS: &[&str] = &[
    "5622 plus slot p2p",
    "5680 plus slot discovery",
    "6030 plus slot localhost metrics",
];

const PROFILES: &[RoleProfile] = &[
    RoleProfile {
        role: NodeRole::Validator,
        role_id: "validator",
        display_name: "Validator Node",
        compiled_profile: "validator_node",
        authority_plane: AuthorityPlane::ConsensusChainIntegrity,
        service_surface: VALIDATOR_SERVICES,
        required_ports: VALIDATOR_PORTS,
    },
    RoleProfile {
        role: NodeRole::Sentry,
        role_id: "sentry",
        display_name: "Sentry Node",
        compiled_profile: "sentry_node",
        authority_plane: AuthorityPlane::ConsensusChainIntegrity,
        service_surface: SENTRY_SERVICES,
        required_ports: SENTRY_PORTS,
    },
    RoleProfile {
        role: NodeRole::Archive,
        role_id: "archive",
        display_name: "Archive Node",
        compiled_profile: "archive_node",
        authority_plane: AuthorityPlane::ConsensusChainIntegrity,
        service_surface: ARCHIVE_SERVICES,
        required_ports: ARCHIVE_PORTS,
    },
    RoleProfile {
        role: NodeRole::ConsensusAudit,
        role_id: "consensus_audit",
        display_name: "Consensus Audit Node",
        compiled_profile: "consensus_audit_node",
        authority_plane: AuthorityPlane::ConsensusChainIntegrity,
        service_surface: CONSENSUS_AUDIT_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::CrossChain,
        role_id: "cross_chain",
        display_name: "Cross-Chain Node",
        compiled_profile: "cross_chain_node",
        authority_plane: AuthorityPlane::Interoperability,
        service_surface: CROSS_CHAIN_SERVICES,
        required_ports: CROSS_CHAIN_PORTS,
    },
    RoleProfile {
        role: NodeRole::Witness,
        role_id: "witness",
        display_name: "Witness Node",
        compiled_profile: "witness_node",
        authority_plane: AuthorityPlane::Interoperability,
        service_surface: WITNESS_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::Oracle,
        role_id: "oracle",
        display_name: "Oracle Node",
        compiled_profile: "oracle_node",
        authority_plane: AuthorityPlane::Interoperability,
        service_surface: ORACLE_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::UmaCoordinator,
        role_id: "uma_coordinator",
        display_name: "UMA Coordinator Node",
        compiled_profile: "uma_coordinator_node",
        authority_plane: AuthorityPlane::Interoperability,
        service_surface: UMA_COORDINATOR_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::SynqExecution,
        role_id: "synq_execution",
        display_name: "SynQ Execution Node",
        compiled_profile: "synq_execution_node",
        authority_plane: AuthorityPlane::ExecutionDataCryptography,
        service_surface: SYNQ_EXECUTION_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::NetworkAnalytics,
        role_id: "network_analytics",
        display_name: "Network Analytics Node",
        compiled_profile: "network_analytics_node",
        authority_plane: AuthorityPlane::ExecutionDataCryptography,
        service_surface: NETWORK_ANALYTICS_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::AegisCryptography,
        role_id: "aegis_cryptography",
        display_name: "Aegis Cryptography Node",
        compiled_profile: "aegis_cryptography_node",
        authority_plane: AuthorityPlane::ExecutionDataCryptography,
        service_surface: AEGIS_CRYPTOGRAPHY_SERVICES,
        required_ports: &[
            "3050 aegis verify",
            "3051 private mtls kms",
            "6030 plus slot localhost metrics",
        ],
    },
    RoleProfile {
        role: NodeRole::DataAvailability,
        role_id: "data_availability",
        display_name: "Data Availability Node",
        compiled_profile: "data_availability_node",
        authority_plane: AuthorityPlane::ExecutionDataCryptography,
        service_surface: DATA_AVAILABILITY_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::AiCompute,
        role_id: "ai_compute",
        display_name: "AI Compute Node",
        compiled_profile: "ai_compute_node",
        authority_plane: AuthorityPlane::AiIntelligence,
        service_surface: AI_COMPUTE_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::AiCoordination,
        role_id: "ai_coordination",
        display_name: "AI Coordination Node",
        compiled_profile: "ai_coordination_node",
        authority_plane: AuthorityPlane::AiIntelligence,
        service_surface: AI_COORDINATION_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::AiData,
        role_id: "ai_data",
        display_name: "AI Data Node",
        compiled_profile: "ai_data_node",
        authority_plane: AuthorityPlane::AiIntelligence,
        service_surface: AI_DATA_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::AiAssurance,
        role_id: "ai_assurance",
        display_name: "AI Assurance Node",
        compiled_profile: "ai_assurance_node",
        authority_plane: AuthorityPlane::AiIntelligence,
        service_surface: AI_ASSURANCE_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::RpcGateway,
        role_id: "rpc_gateway",
        display_name: "RPC Gateway Node",
        compiled_profile: "rpc_gateway_node",
        authority_plane: AuthorityPlane::ServiceAccess,
        service_surface: RPC_GATEWAY_SERVICES,
        required_ports: RPC_GATEWAY_PORTS,
    },
    RoleProfile {
        role: NodeRole::Indexer,
        role_id: "indexer",
        display_name: "Indexer Node",
        compiled_profile: "indexer_node",
        authority_plane: AuthorityPlane::ServiceAccess,
        service_surface: INDEXER_SERVICES,
        required_ports: INDEXER_PORTS,
    },
    RoleProfile {
        role: NodeRole::ObserverLight,
        role_id: "observer_light",
        display_name: "Observer / Light Node",
        compiled_profile: "observer_light_node",
        authority_plane: AuthorityPlane::ServiceAccess,
        service_surface: OBSERVER_LIGHT_SERVICES,
        required_ports: OBSERVER_LIGHT_PORTS,
    },
    RoleProfile {
        role: NodeRole::Bootseed,
        role_id: "bootseed",
        display_name: "Bootseed Node",
        compiled_profile: "bootseed_node",
        authority_plane: AuthorityPlane::ServiceAccess,
        service_surface: BOOTSEED_SERVICES,
        required_ports: BOOTSEED_PORTS,
    },
];

impl NodeRole {
    pub fn from_role_id(value: &str) -> Option<Self> {
        match value.trim() {
            "validator" => Some(Self::Validator),
            "sentry" => Some(Self::Sentry),
            "archive" => Some(Self::Archive),
            "consensus_audit" => Some(Self::ConsensusAudit),
            "cross_chain" => Some(Self::CrossChain),
            "witness" => Some(Self::Witness),
            "oracle" => Some(Self::Oracle),
            "uma_coordinator" => Some(Self::UmaCoordinator),
            "synq_execution" => Some(Self::SynqExecution),
            "network_analytics" => Some(Self::NetworkAnalytics),
            "aegis_cryptography" => Some(Self::AegisCryptography),
            "data_availability" => Some(Self::DataAvailability),
            "ai_compute" => Some(Self::AiCompute),
            "ai_coordination" => Some(Self::AiCoordination),
            "ai_data" => Some(Self::AiData),
            "ai_assurance" => Some(Self::AiAssurance),
            "rpc_gateway" => Some(Self::RpcGateway),
            "indexer" => Some(Self::Indexer),
            "observer_light" => Some(Self::ObserverLight),
            "bootseed" => Some(Self::Bootseed),
            _ => None,
        }
    }

    pub fn profile(self) -> &'static RoleProfile {
        PROFILES
            .iter()
            .find(|profile| profile.role == self)
            .expect("every role must have a profile")
    }
}

pub fn all_role_profiles() -> &'static [RoleProfile] {
    PROFILES
}

pub fn profile_from_compiled_profile(value: &str) -> Option<&'static RoleProfile> {
    let normalized = value.trim();
    (!normalized.is_empty())
        .then(|| {
            PROFILES
                .iter()
                .find(|profile| profile.compiled_profile == normalized)
        })
        .flatten()
}

pub fn resolve_configured_role(
    role_id: &str,
    compiled_profile: &str,
) -> Result<Option<&'static RoleProfile>, String> {
    let role_id = role_id.trim();
    let compiled_profile = compiled_profile.trim();

    if role_id.is_empty() && compiled_profile.is_empty() {
        return Ok(None);
    }

    let role_profile = if role_id.is_empty() {
        None
    } else {
        let role = NodeRole::from_role_id(role_id)
            .ok_or_else(|| format!("Unknown role id '{role_id}' in configuration"))?;
        Some(role.profile())
    };

    let compiled_profile_match = if compiled_profile.is_empty() {
        None
    } else {
        Some(
            profile_from_compiled_profile(compiled_profile).ok_or_else(|| {
                format!("Unknown compiled profile '{compiled_profile}' in configuration")
            })?,
        )
    };

    if let (Some(role_profile), Some(compiled_profile_match)) =
        (role_profile, compiled_profile_match)
    {
        if role_profile.role != compiled_profile_match.role {
            return Err(format!(
                "Role '{}' does not match compiled profile '{}'",
                role_id, compiled_profile
            ));
        }
    }

    Ok(compiled_profile_match.or(role_profile))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_exactly_the_twenty_canonical_profiles() {
        assert_eq!(all_role_profiles().len(), 20);
        assert_eq!(
            all_role_profiles()
                .iter()
                .filter(|profile| profile.authority_plane == AuthorityPlane::ConsensusChainIntegrity)
                .count(),
            4
        );
        assert_eq!(
            all_role_profiles()
                .iter()
                .filter(|profile| profile.authority_plane == AuthorityPlane::Interoperability)
                .count(),
            4
        );
        assert_eq!(
            all_role_profiles()
                .iter()
                .filter(
                    |profile| profile.authority_plane == AuthorityPlane::ExecutionDataCryptography
                )
                .count(),
            4
        );
        assert_eq!(
            all_role_profiles()
                .iter()
                .filter(|profile| profile.authority_plane == AuthorityPlane::AiIntelligence)
                .count(),
            4
        );
        assert_eq!(
            all_role_profiles()
                .iter()
                .filter(|profile| profile.authority_plane == AuthorityPlane::ServiceAccess)
                .count(),
            4
        );
    }

    #[test]
    fn validator_is_the_only_consensus_signing_role() {
        assert!(NodeRole::Validator
            .profile()
            .service_surface
            .contains(&"consensus"));
        assert!(!NodeRole::Sentry
            .profile()
            .service_surface
            .contains(&"consensus"));
        assert!(!NodeRole::ConsensusAudit
            .profile()
            .service_surface
            .contains(&"consensus"));
        assert!(!NodeRole::Bootseed
            .profile()
            .service_surface
            .contains(&"consensus"));
    }

    #[test]
    fn cross_chain_role_exposes_separate_relay_verify_and_independence_capabilities() {
        let services = NodeRole::CrossChain.profile().service_surface;
        assert!(services.contains(&"sxcp-relay"));
        assert!(services.contains(&"sxcp-verify"));
        assert!(services.contains(&"independence-guard"));
    }

    #[test]
    fn legacy_role_ids_are_rejected() {
        for role_id in [
            "committee",
            "archive_validator",
            "audit_validator",
            "relayer",
            "cross_chain_verifier",
            "analytics_simulation",
            "indexer_explorer",
            "governance_auditor",
            "treasury_controller",
            "security_council",
            "ai_inference",
        ] {
            assert_eq!(NodeRole::from_role_id(role_id), None, "{role_id}");
        }
    }

    #[test]
    fn canonical_roles_resolve_to_matching_profiles() {
        for profile in all_role_profiles() {
            assert_eq!(
                resolve_configured_role(profile.role_id, profile.compiled_profile)
                    .expect("canonical role should resolve")
                    .expect("profile should be present")
                    .role,
                profile.role
            );
        }
    }

    #[test]
    fn service_roles_require_p2p_when_their_profiles_need_sync() {
        for role in [
            NodeRole::RpcGateway,
            NodeRole::Indexer,
            NodeRole::ObserverLight,
        ] {
            assert!(role.profile().service_surface.contains(&"p2p"));
        }
    }
}
