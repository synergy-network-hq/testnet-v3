use crate::OverlayScope;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentAuthorization {
    pub authorization_id: String,
    pub identity: String,
    pub scope: OverlayScope,
    pub approved_at: u64,
    pub expires_at: u64,
    pub approved_by: String,
}

impl EnrollmentAuthorization {
    pub fn validate(&self, now: u64) -> Result<(), String> {
        if self.authorization_id.trim().is_empty()
            || self.identity.trim().is_empty()
            || self.approved_by.trim().is_empty()
            || self.approved_at > now
            || self.expires_at <= now
        {
            return Err("invalid enrollment authorization".into());
        }
        Ok(())
    }

    pub const fn grants_consensus_authority(&self) -> bool {
        false
    }
}
