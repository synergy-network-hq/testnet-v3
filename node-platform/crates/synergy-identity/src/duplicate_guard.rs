use std::collections::BTreeMap;

use crate::{IdentityError, NodeAddress, PublicNodeIdentity};

#[derive(Debug, Clone, Default)]
pub struct DuplicateIdentityGuard {
    fingerprints: BTreeMap<NodeAddress, String>,
}

impl DuplicateIdentityGuard {
    pub fn admit(&mut self, identity: &PublicNodeIdentity) -> Result<(), IdentityError> {
        let identity = identity.clone().validate()?;
        if let Some(existing) = self.fingerprints.get(&identity.node_address) {
            if existing != &identity.public_key_fingerprint {
                return Err(IdentityError::ConflictingIdentity);
            }
            return Ok(());
        }
        if self
            .fingerprints
            .values()
            .any(|fingerprint| fingerprint == &identity.public_key_fingerprint)
        {
            return Err(IdentityError::DuplicateKeyBinding);
        }
        self.fingerprints
            .insert(identity.node_address, identity.public_key_fingerprint);
        Ok(())
    }
}
