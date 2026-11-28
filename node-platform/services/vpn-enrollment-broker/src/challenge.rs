use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentChallenge {
    pub id: String,
    pub nonce: Vec<u8>,
    pub expires_at: u64,
    pub used: bool,
}
impl EnrollmentChallenge {
    /// Checks challenge eligibility without consuming it before proof verification.
    pub fn validate(&self, now: u64) -> Result<(), String> {
        if self.used || self.expires_at <= now || self.nonce.len() < 32 {
            return Err("invalid, expired, or replayed enrollment challenge".into());
        }
        Ok(())
    }

    pub fn consume(&mut self, now: u64) -> Result<(), String> {
        self.validate(now)?;
        self.used = true;
        Ok(())
    }
}
