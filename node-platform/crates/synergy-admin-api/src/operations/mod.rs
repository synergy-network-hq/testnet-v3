mod ai;
mod config;
mod cross_chain;
mod etdag;
mod identity;
mod lifecycle;
mod naming;
mod ownership;
mod peers;
mod posy;
mod rewards;
mod sentry;
mod storage;
mod sync;
mod telemetry;
mod upgrade;
mod validator;
mod vpn;

use serde::{Deserialize, Serialize};

pub use ai::AiOperation;
pub use config::ConfigOperation;
pub use cross_chain::CrossChainOperation;
pub use etdag::EtdagOperation;
pub use identity::IdentityOperation;
pub use lifecycle::{LifecycleAction, LifecycleOperation};
pub use naming::NamingOperation;
pub use ownership::OwnershipOperation;
pub use peers::PeerOperation;
pub use posy::PosyOperation;
pub use rewards::RewardOperation;
pub use sentry::SentryOperation;
pub use storage::StorageOperation;
pub use sync::SyncOperation;
pub use telemetry::TelemetryOperation;
pub use upgrade::UpgradeOperation;
pub use validator::ValidatorOperation;
pub use vpn::VpnOperation;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "subsystem", content = "operation", rename_all = "snake_case")]
pub enum AdminOperation {
    Read(synergy_node_core::ManagementOperation),
    Lifecycle(LifecycleOperation),
    Config(ConfigOperation),
    Identity(IdentityOperation),
    Peers(PeerOperation),
    Sync(SyncOperation),
    Validator(ValidatorOperation),
    Vpn(VpnOperation),
    Sentry(SentryOperation),
    Posy(PosyOperation),
    Etdag(EtdagOperation),
    Storage(StorageOperation),
    Telemetry(TelemetryOperation),
    Upgrade(UpgradeOperation),
    CrossChain(CrossChainOperation),
    Ai(AiOperation),
    Ownership(OwnershipOperation),
    Naming(NamingOperation),
    Rewards(RewardOperation),
}

impl AdminOperation {
    pub fn is_mutating(&self) -> bool {
        !matches!(
            self,
            Self::Read(_) | Self::Telemetry(TelemetryOperation::Snapshot)
        ) && !matches!(self, Self::Validator(operation) if !operation.is_mutating())
            && !matches!(self, Self::Ownership(operation) if !operation.is_mutating())
            && !matches!(self, Self::Naming(operation) if !operation.is_mutating())
            && !matches!(self, Self::Rewards(operation) if !operation.is_mutating())
    }

    pub const fn required_permission(&self) -> crate::authorization::AdminPermission {
        use crate::authorization::AdminPermission;
        match self {
            Self::Read(_) | Self::Telemetry(TelemetryOperation::Snapshot) => AdminPermission::Read,
            Self::Lifecycle(_) => AdminPermission::Lifecycle,
            Self::Config(_) => AdminPermission::Configuration,
            Self::Identity(_) => AdminPermission::Identity,
            Self::Peers(_) => AdminPermission::Peers,
            Self::Sync(_) => AdminPermission::Consensus,
            Self::Validator(_) => AdminPermission::Validator,
            Self::Vpn(_) => AdminPermission::Vpn,
            Self::Sentry(_) => AdminPermission::Peers,
            Self::Posy(_) => AdminPermission::Consensus,
            Self::Etdag(_) => AdminPermission::Etdag,
            Self::Storage(_) => AdminPermission::Storage,
            Self::Telemetry(_) => AdminPermission::Read,
            Self::Upgrade(_) => AdminPermission::Upgrade,
            Self::CrossChain(_) | Self::Ai(_) => AdminPermission::Configuration,
            Self::Ownership(_) | Self::Naming(_) | Self::Rewards(_) => AdminPermission::Read,
        }
    }

    pub fn validate(&self) -> Result<(), crate::AdminError> {
        match self {
            Self::Read(_) | Self::Telemetry(TelemetryOperation::Snapshot) => Ok(()),
            Self::Lifecycle(operation) => operation.validate(),
            Self::Config(operation) => operation.validate(),
            Self::Identity(operation) => operation.validate(),
            Self::Peers(operation) => operation.validate(),
            Self::Sync(operation) => operation.validate(),
            Self::Validator(operation) => operation.validate(),
            Self::Vpn(operation) => operation.validate(),
            Self::Sentry(operation) => operation.validate(),
            Self::Posy(operation) => operation.validate(),
            Self::Etdag(operation) => operation.validate(),
            Self::Storage(operation) => operation.validate(),
            Self::Telemetry(operation) => operation.validate(),
            Self::Upgrade(operation) => operation.validate(),
            Self::CrossChain(operation) => operation.validate(),
            Self::Ai(operation) => operation.validate(),
            Self::Ownership(operation) => operation.validate(),
            Self::Naming(operation) => operation.validate(),
            Self::Rewards(operation) => operation.validate(),
        }
    }
}
