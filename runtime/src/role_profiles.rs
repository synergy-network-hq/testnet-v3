#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeRole {
    Validator,
    Committee,
    ArchiveValidator,
    AuditValidator,
    Relayer,
    Witness,
    Oracle,
    UmaCoordinator,
    CrossChainVerifier,
    SynqExecution,
    AnalyticsSimulation,
    AegisCryptography,
    DataAvailability,
    GovernanceAuditor,
    TreasuryController,
    SecurityCouncil,
    RpcGateway,
    IndexerExplorer,
    ObserverLight,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityPlane {
    Consensus,
    Interoperability,
    ExecutionDataCryptography,
    GovernanceSecurity,
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
    "mempool",
    "state",
    "aegis-verifier",
    "telemetry",
];
const COMMITTEE_SERVICES: &[&str] = &[
    "consensus",
    "committee-sync",
    "aegis-verifier",
    "epoch-rotation-listener",
];
const ARCHIVE_VALIDATOR_SERVICES: &[&str] = &["state", "archive", "proof-builder", "snapshot"];
const AUDIT_VALIDATOR_SERVICES: &[&str] =
    &["consensus-audit", "qc-verifier", "state-diff", "alerting"];
const RELAYER_SERVICES: &[&str] = &[
    "p2p",
    "chain-sync",
    "sxcp-relay",
    "light-client-adapters",
    "attestation-packager",
    "witness-registry-client",
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
const CROSS_CHAIN_VERIFIER_SERVICES: &[&str] = &[
    "proof-verifier",
    "finality-checker",
    "scope-binder",
    "receipt-issuer",
];
const SYNQ_EXECUTION_SERVICES: &[&str] = &[
    "synq-runtime",
    "trace",
    "determinism-check",
    "predeploy-sim",
];
const ANALYTICS_SIMULATION_SERVICES: &[&str] =
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
const GOVERNANCE_AUDITOR_SERVICES: &[&str] = &[
    "governance-audit",
    "vote-integrity",
    "scope-check",
    "reporting",
];
const TREASURY_CONTROLLER_SERVICES: &[&str] = &[
    "treasury-exec",
    "multisig-orchestrator",
    "disbursement-audit",
];
const SECURITY_COUNCIL_SERVICES: &[&str] = &[
    "emergency-scope",
    "aegis-emergency-auth",
    "incident-logging",
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
const INDEXER_EXPLORER_SERVICES: &[&str] = &[
    "p2p",
    "chain-sync",
    "state",
    "indexer-ingest",
    "query-api",
    "search",
    "explorer-ui-backend",
];
const OBSERVER_LIGHT_SERVICES: &[&str] = &[
    "p2p",
    "chain-sync",
    "header-sync",
    "light-proof-check",
    "wallet-feed",
];

const VALIDATOR_PORTS: &[&str] = &[
    "5622 plus slot p2p",
    "5640 plus slot localhost rpc",
    "5660 plus slot localhost ws",
    "6030 plus slot localhost metrics",
];
const COMMITTEE_PORTS: &[&str] = &["5622 plus slot p2p", "6030 plus slot localhost metrics"];
const ARCHIVE_VALIDATOR_PORTS: &[&str] = &[
    "5622 plus slot p2p",
    "5640 plus slot localhost read rpc",
    "6030 plus slot localhost metrics",
];
const AUDIT_VALIDATOR_PORTS: &[&str] = &["5622 plus slot p2p", "6030 plus slot localhost metrics"];
const RELAYER_PORTS: &[&str] = &[
    "5622 plus slot p2p",
    "5680 plus slot discovery",
    "3040 https sxcp api",
    "3041 wss sxcp stream",
    "6030 plus slot localhost metrics",
];
const BASIC_METRICS_PORTS: &[&str] = &["6030 plus slot localhost metrics"];
const CROSS_CHAIN_VERIFIER_PORTS: &[&str] =
    &["3030 https verify api", "6030 plus slot localhost metrics"];
const RPC_GATEWAY_PORTS: &[&str] = &[
    "5622 plus slot p2p",
    "5640 plus slot core rpc upstream",
    "5660 plus slot core ws upstream",
    "5680 plus slot discovery",
    "8545 evm http",
    "8546 evm ws",
];
const INDEXER_EXPLORER_PORTS: &[&str] = &[
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

const PROFILES: &[RoleProfile] = &[
    RoleProfile {
        role: NodeRole::Validator,
        role_id: "validator",
        display_name: "Validator Node",
        compiled_profile: "validator_node",
        authority_plane: AuthorityPlane::Consensus,
        service_surface: VALIDATOR_SERVICES,
        required_ports: VALIDATOR_PORTS,
    },
    RoleProfile {
        role: NodeRole::Committee,
        role_id: "committee",
        display_name: "Committee Node",
        compiled_profile: "committee_node",
        authority_plane: AuthorityPlane::Consensus,
        service_surface: COMMITTEE_SERVICES,
        required_ports: COMMITTEE_PORTS,
    },
    RoleProfile {
        role: NodeRole::ArchiveValidator,
        role_id: "archive_validator",
        display_name: "Archive Validator Node",
        compiled_profile: "archive_validator_node",
        authority_plane: AuthorityPlane::Consensus,
        service_surface: ARCHIVE_VALIDATOR_SERVICES,
        required_ports: ARCHIVE_VALIDATOR_PORTS,
    },
    RoleProfile {
        role: NodeRole::AuditValidator,
        role_id: "audit_validator",
        display_name: "Audit Validator Node",
        compiled_profile: "audit_validator_node",
        authority_plane: AuthorityPlane::Consensus,
        service_surface: AUDIT_VALIDATOR_SERVICES,
        required_ports: AUDIT_VALIDATOR_PORTS,
    },
    RoleProfile {
        role: NodeRole::Relayer,
        role_id: "relayer",
        display_name: "Relayer Node",
        compiled_profile: "relayer_node",
        authority_plane: AuthorityPlane::Interoperability,
        service_surface: RELAYER_SERVICES,
        required_ports: RELAYER_PORTS,
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
        role: NodeRole::CrossChainVerifier,
        role_id: "cross_chain_verifier",
        display_name: "Cross-Chain Verifier Node",
        compiled_profile: "cross_chain_verifier_node",
        authority_plane: AuthorityPlane::Interoperability,
        service_surface: CROSS_CHAIN_VERIFIER_SERVICES,
        required_ports: CROSS_CHAIN_VERIFIER_PORTS,
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
        role: NodeRole::AnalyticsSimulation,
        role_id: "analytics_simulation",
        display_name: "Analytics and Simulation Node",
        compiled_profile: "analytics_and_simulation_node",
        authority_plane: AuthorityPlane::ExecutionDataCryptography,
        service_surface: ANALYTICS_SIMULATION_SERVICES,
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
        display_name: "Data-Availability Node",
        compiled_profile: "data_availability_node",
        authority_plane: AuthorityPlane::ExecutionDataCryptography,
        service_surface: DATA_AVAILABILITY_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::GovernanceAuditor,
        role_id: "governance_auditor",
        display_name: "Governance Auditor Node",
        compiled_profile: "governance_auditor_node",
        authority_plane: AuthorityPlane::GovernanceSecurity,
        service_surface: GOVERNANCE_AUDITOR_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::TreasuryController,
        role_id: "treasury_controller",
        display_name: "Treasury Controller Node",
        compiled_profile: "treasury_controller_node",
        authority_plane: AuthorityPlane::GovernanceSecurity,
        service_surface: TREASURY_CONTROLLER_SERVICES,
        required_ports: BASIC_METRICS_PORTS,
    },
    RoleProfile {
        role: NodeRole::SecurityCouncil,
        role_id: "security_council",
        display_name: "Security Council Node",
        compiled_profile: "security_council_node",
        authority_plane: AuthorityPlane::GovernanceSecurity,
        service_surface: SECURITY_COUNCIL_SERVICES,
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
        role: NodeRole::IndexerExplorer,
        role_id: "indexer_explorer",
        display_name: "Indexer and Explorer Node",
        compiled_profile: "indexer_and_explorer_node",
        authority_plane: AuthorityPlane::ServiceAccess,
        service_surface: INDEXER_EXPLORER_SERVICES,
        required_ports: INDEXER_EXPLORER_PORTS,
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
];

impl NodeRole {
    pub fn from_role_id(value: &str) -> Option<Self> {
        match value.trim() {
            "validator" => Some(Self::Validator),
            "committee" => Some(Self::Committee),
            "archive_validator" => Some(Self::ArchiveValidator),
            "audit_validator" => Some(Self::AuditValidator),
            "relayer" => Some(Self::Relayer),
            "witness" => Some(Self::Witness),
            "oracle" => Some(Self::Oracle),
            "uma_coordinator" => Some(Self::UmaCoordinator),
            "cross_chain_verifier" => Some(Self::CrossChainVerifier),
            "synq_execution" | "compute" => Some(Self::SynqExecution),
            "analytics_simulation" | "ai_inference" => Some(Self::AnalyticsSimulation),
            "aegis_cryptography" | "pqc_crypto" => Some(Self::AegisCryptography),
            "data_availability" => Some(Self::DataAvailability),
            "governance_auditor" => Some(Self::GovernanceAuditor),
            "treasury_controller" => Some(Self::TreasuryController),
            "security_council" => Some(Self::SecurityCouncil),
            "rpc_gateway" => Some(Self::RpcGateway),
            "indexer_explorer" | "indexer" => Some(Self::IndexerExplorer),
            "observer_light" | "observer" => Some(Self::ObserverLight),
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

fn compiled_profile_aliases(profile: &'static RoleProfile) -> &'static [&'static str] {
    match profile.role {
        NodeRole::AnalyticsSimulation => &["analytics_simulation_node"],
        NodeRole::IndexerExplorer => &["indexer_explorer_node"],
        _ => &[],
    }
}

pub fn profile_from_compiled_profile(value: &str) -> Option<&'static RoleProfile> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return None;
    }

    PROFILES.iter().find(|profile| {
        profile.compiled_profile == normalized
            || compiled_profile_aliases(profile).contains(&normalized)
    })
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
    fn exposes_nineteen_profiles() {
        assert_eq!(all_role_profiles().len(), 19);
    }

    #[test]
    fn validator_profile_matches_spec_surface() {
        let profile = NodeRole::Validator.profile();
        assert_eq!(profile.compiled_profile, "validator_node");
        assert!(profile.service_surface.contains(&"consensus"));
        assert!(profile.service_surface.contains(&"aegis-verifier"));
    }

    #[test]
    fn aliases_map_to_canonical_roles() {
        assert_eq!(
            NodeRole::from_role_id("compute"),
            Some(NodeRole::SynqExecution)
        );
        assert_eq!(
            NodeRole::from_role_id("pqc_crypto"),
            Some(NodeRole::AegisCryptography)
        );
        assert_eq!(
            NodeRole::from_role_id("observer"),
            Some(NodeRole::ObserverLight)
        );
    }

    #[test]
    fn accepts_legacy_compiled_profile_aliases() {
        let profile = resolve_configured_role("ai_inference", "analytics_simulation_node")
            .expect("legacy alias should resolve")
            .expect("role profile should be present");
        assert_eq!(profile.role, NodeRole::AnalyticsSimulation);

        let profile = resolve_configured_role("indexer", "indexer_explorer_node")
            .expect("legacy alias should resolve")
            .expect("role profile should be present");
        assert_eq!(profile.role, NodeRole::IndexerExplorer);
    }

    #[test]
    fn rpc_gateway_profile_requires_p2p_surface() {
        let profile = NodeRole::RpcGateway.profile();
        assert!(profile.service_surface.contains(&"p2p"));
        assert!(profile
            .required_ports
            .iter()
            .any(|port| port.to_ascii_lowercase().contains("p2p")));
    }

    #[test]
    fn indexer_explorer_profile_requires_p2p_surface() {
        let profile = NodeRole::IndexerExplorer.profile();
        assert!(profile.service_surface.contains(&"p2p"));
        assert!(profile.service_surface.contains(&"chain-sync"));
        assert!(profile
            .required_ports
            .iter()
            .any(|port| port.to_ascii_lowercase().contains("p2p")));
    }

    #[test]
    fn observer_light_profile_requires_p2p_for_header_sync() {
        let profile = NodeRole::ObserverLight.profile();
        assert!(profile.service_surface.contains(&"p2p"));
        assert!(profile.service_surface.contains(&"chain-sync"));
        assert!(profile
            .required_ports
            .iter()
            .any(|port| port.to_ascii_lowercase().contains("p2p")));
    }
}
