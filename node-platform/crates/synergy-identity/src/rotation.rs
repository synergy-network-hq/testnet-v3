use serde::{Deserialize, Serialize};

use crate::{IdentityError, NodeAddress, PublicNodeIdentity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRotation {
    #[serde(alias = "node_id")]
    pub node_address: NodeAddress,
    pub current_fingerprint: String,
    pub next_fingerprint: String,
    pub activation_epoch: u64,
    pub authorization_root: String,
}

impl IdentityRotation {
    pub fn validate(
        &self,
        current: &PublicNodeIdentity,
        next: &PublicNodeIdentity,
    ) -> Result<(), IdentityError> {
        let current = current.clone().validate()?;
        let next = next.clone().validate()?;
        if self.node_address != current.node_address
            || self.node_address != next.node_address
            || self.current_fingerprint != current.public_key_fingerprint
            || self.next_fingerprint != next.public_key_fingerprint
            || self.current_fingerprint == self.next_fingerprint
            || self.activation_epoch == 0
            || self.authorization_root.trim().is_empty()
        {
            return Err(IdentityError::InvalidRotation);
        }
        Ok(())
    }
}
