use serde::{Deserialize, Serialize};
use synergy_protocol_types::NodeAddress;

use crate::{validate_wallet, OwnershipError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeOwnershipBinding {
    pub record_version: u32,
    pub node_address: NodeAddress,
    pub owner_wallet: String,
    pub sequence: u64,
    pub effective_height: u64,
}

impl NodeOwnershipBinding {
    pub(crate) fn validate(&self) -> Result<(), OwnershipError> {
        if self.record_version != 1 || self.sequence == 0 {
            return Err(OwnershipError::CorruptState);
        }
        validate_wallet(&self.owner_wallet)
    }
}

/// Read-only ownership boundary consumed by naming and rewards.
pub trait NodeOwnerResolver {
    fn current_owner(&self, node_address: &NodeAddress) -> Result<Option<String>, String>;

    fn is_current_owner(&self, node_address: &NodeAddress, wallet: &str) -> Result<bool, String> {
        Ok(self
            .current_owner(node_address)?
            .is_some_and(|owner| owner == wallet))
    }
}

impl NodeOwnerResolver for crate::OwnershipRegistrySnapshot {
    fn current_owner(&self, node_address: &NodeAddress) -> Result<Option<String>, String> {
        Ok(crate::OwnershipRegistrySnapshot::current_owner(self, node_address).map(str::to_owned))
    }
}
