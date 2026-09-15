#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentChallenge {
    pub challenge_id: String,
    pub nonce: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

impl EnrollmentChallenge {
    pub fn validate(&self, now: u64) -> Result<(), String> {
        if self.challenge_id.trim().is_empty()
            || self.nonce.iter().all(|byte| *byte == 0)
            || self.issued_at > now
            || self.expires_at <= now
            || self.expires_at <= self.issued_at
        {
            return Err("invalid or expired enrollment challenge".into());
        }
        Ok(())
    }
}
