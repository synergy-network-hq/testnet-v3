#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentResumeRequest {
    pub identity: String,
    pub prior_authorization_id: String,
    pub prior_lease_id: String,
    pub challenge_nonce: [u8; 32],
    pub signature: Vec<u8>,
}

impl EnrollmentResumeRequest {
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.identity.trim().is_empty()
            || self.prior_authorization_id.trim().is_empty()
            || self.prior_lease_id.trim().is_empty()
            || self.challenge_nonce.iter().all(|byte| *byte == 0)
            || self.signature.is_empty()
        {
            return Err("invalid enrollment resume request".into());
        }
        Ok(())
    }
}
