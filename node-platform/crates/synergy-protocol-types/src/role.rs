//! Canonical Synergy node-role taxonomy.
//! A role selects a trust/resource boundary; it never grants consensus authority.

use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
impl NodeRole {
    pub const ALL: [Self; 20] = [
        Self::Validator,
        Self::Sentry,
        Self::Archive,
        Self::ConsensusAudit,
        Self::CrossChain,
        Self::Witness,
        Self::Oracle,
        Self::UmaCoordinator,
        Self::SynqExecution,
        Self::NetworkAnalytics,
        Self::AegisCryptography,
        Self::DataAvailability,
        Self::AiCompute,
        Self::AiCoordination,
        Self::AiData,
        Self::AiAssurance,
        Self::RpcGateway,
        Self::Indexer,
        Self::ObserverLight,
        Self::Bootseed,
    ];
    pub const fn hosts_posy_signing_component(self) -> bool {
        matches!(self, Self::Validator)
    }
    pub const fn may_determine_finality(self) -> bool {
        false
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn taxonomy_has_exactly_twenty_roles_and_no_legacy_committee() {
        assert_eq!(NodeRole::ALL.len(), 20);
        assert!(!NodeRole::ALL
            .iter()
            .any(|role| format!("{role:?}") == "Committee"));
    }
    #[test]
    fn role_only_hosts_components_not_validator_authority() {
        assert!(NodeRole::Validator.hosts_posy_signing_component());
        assert!(!NodeRole::Sentry.hosts_posy_signing_component());
        assert!(!NodeRole::Validator.may_determine_finality());
    }
}
