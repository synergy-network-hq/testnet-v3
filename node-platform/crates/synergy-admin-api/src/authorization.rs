use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdminPermission {
    Read,
    Lifecycle,
    Configuration,
    Identity,
    Peers,
    Validator,
    Vpn,
    Consensus,
    Etdag,
    Storage,
    Upgrade,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationContext {
    pub principal: String,
    pub permissions: BTreeSet<AdminPermission>,
}

impl AuthorizationContext {
    pub fn require(&self, permission: AdminPermission) -> Result<(), crate::AdminError> {
        if self.principal.trim().is_empty() || !self.permissions.contains(&permission) {
            return Err(crate::AdminError {
                code: "forbidden".into(),
                message: "Admin API operation is not authorized".into(),
                retryable: false,
            });
        }
        Ok(())
    }
}
