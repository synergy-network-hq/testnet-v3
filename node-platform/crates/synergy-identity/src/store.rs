use crate::{IdentityError, NodeAddress, PublicNodeIdentity};

pub trait IdentityStore: Send + Sync {
    fn load(&self, node_address: &NodeAddress)
        -> Result<Option<PublicNodeIdentity>, IdentityError>;
    fn install_if_absent(&self, identity: &PublicNodeIdentity) -> Result<(), IdentityError>;
    fn rotate(
        &self,
        current: &PublicNodeIdentity,
        next: &PublicNodeIdentity,
        authorization_root: &str,
    ) -> Result<(), IdentityError>;
}
