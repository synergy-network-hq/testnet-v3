pub use synergy_protocol_types::NodeRole;

pub const fn role_id(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Validator => "validator",
        NodeRole::Sentry => "sentry",
        NodeRole::Archive => "archive",
        NodeRole::ConsensusAudit => "consensus-audit",
        NodeRole::CrossChain => "cross-chain",
        NodeRole::Witness => "witness",
        NodeRole::Oracle => "oracle",
        NodeRole::UmaCoordinator => "uma-coordinator",
        NodeRole::SynqExecution => "synq-execution",
        NodeRole::NetworkAnalytics => "network-analytics",
        NodeRole::AegisCryptography => "aegis-cryptography",
        NodeRole::DataAvailability => "data-availability",
        NodeRole::AiCompute => "ai-compute",
        NodeRole::AiCoordination => "ai-coordination",
        NodeRole::AiData => "ai-data",
        NodeRole::AiAssurance => "ai-assurance",
        NodeRole::RpcGateway => "rpc-gateway",
        NodeRole::Indexer => "indexer",
        NodeRole::ObserverLight => "observer-light",
        NodeRole::Bootseed => "bootseed",
    }
}
