#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRevocation {
    pub identity: String,
    pub authorization_id: String,
    pub effective_at: u64,
    pub reason: String,
}

impl EnrollmentRevocation {
    pub fn validate(&self) -> Result<(), String> {
        if self.identity.trim().is_empty()
            || self.authorization_id.trim().is_empty()
            || self.effective_at == 0
            || self.reason.trim().is_empty()
            || self.reason.len() > 512
        {
            return Err("invalid enrollment revocation".into());
        }
        Ok(())
    }
}
