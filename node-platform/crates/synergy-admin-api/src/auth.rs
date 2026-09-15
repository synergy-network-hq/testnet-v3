#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCallerIdentity {
    pub principal: String,
    pub user_id: u32,
    pub group_id: u32,
    pub process_id: Option<u32>,
}

pub trait AdminAuthenticator: Send + Sync {
    fn authenticate(&self, caller: &LocalCallerIdentity) -> Result<(), crate::AdminError>;
}

#[derive(Debug, Clone, Copy)]
pub struct OwnerOnlyAuthenticator {
    pub owner_user_id: u32,
}

impl AdminAuthenticator for OwnerOnlyAuthenticator {
    fn authenticate(&self, caller: &LocalCallerIdentity) -> Result<(), crate::AdminError> {
        if caller.principal.trim().is_empty() || caller.user_id != self.owner_user_id {
            return Err(crate::AdminError::invalid_request(
                "local Admin API caller is not the configured node owner",
            ));
        }
        Ok(())
    }
}
