#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportLease {
    pub lease_id: String,
    pub identity: String,
    pub generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl TransportLease {
    pub fn validate(&self, now: u64) -> Result<(), crate::RegistryError> {
        if self.lease_id.trim().is_empty()
            || self.identity.trim().is_empty()
            || self.generation == 0
            || self.issued_at > now
            || self.expires_at <= now
            || self.expires_at <= self.issued_at
        {
            return Err(crate::RegistryError::DuplicateIdentity(
                "invalid transport lease".into(),
            ));
        }
        Ok(())
    }

    pub const fn grants_consensus_authority(&self) -> bool {
        false
    }
}
