use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub identity: String,
    pub effective_generation: u64,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct RevocationSet {
    revoked: BTreeMap<String, Revocation>,
}

impl RevocationSet {
    pub fn insert(&mut self, revocation: Revocation) -> Result<(), crate::RegistryError> {
        if revocation.identity.trim().is_empty()
            || revocation.effective_generation == 0
            || revocation.reason.trim().is_empty()
        {
            return Err(crate::RegistryError::DuplicateIdentity(
                "invalid transport revocation".into(),
            ));
        }
        if let Some(existing) = self.revoked.get(&revocation.identity) {
            if existing != &revocation {
                return Err(crate::RegistryError::DuplicateIdentity(
                    "conflicting transport revocation".into(),
                ));
            }
            return Ok(());
        }
        self.revoked.insert(revocation.identity.clone(), revocation);
        Ok(())
    }

    pub fn is_revoked(&self, identity: &str, generation: u64) -> bool {
        self.revoked
            .get(identity)
            .is_some_and(|revocation| generation >= revocation.effective_generation)
    }
}
