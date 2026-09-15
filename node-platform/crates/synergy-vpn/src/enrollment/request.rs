use crate::OverlayScope;

use super::EnrollmentChallenge;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRequest {
    pub request_version: u32,
    pub identity: String,
    pub scope: OverlayScope,
    pub consensus_key_id: String,
    pub challenge: EnrollmentChallenge,
    pub signature: Vec<u8>,
}

impl EnrollmentRequest {
    pub fn validate_shape(&self, now: u64) -> Result<(), String> {
        self.challenge.validate(now)?;
        if self.request_version != 1
            || crate::normalize_validator_address(&self.identity).is_none()
            || self.consensus_key_id.trim().is_empty()
            || self.signature.is_empty()
        {
            return Err("invalid enrollment request".into());
        }
        Ok(())
    }

    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let scope = match self.scope {
            OverlayScope::Validator => "validator",
            OverlayScope::Sentry => "sentry",
        };
        let nonce = self
            .challenge
            .nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!(
            "SYNERGY_VPN_ENROLLMENT_REQUEST_V1\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            self.identity,
            scope,
            self.consensus_key_id,
            self.challenge.challenge_id,
            nonce,
            self.challenge.issued_at,
            self.challenge.expires_at,
        )
        .into_bytes()
    }
}
