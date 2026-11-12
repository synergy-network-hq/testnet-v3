use crate::{authorization::EnrollmentAuthorization, challenge::EnrollmentChallenge};
pub trait ChainAuthorityVerifier: Send + Sync {
    fn verify_finalized_authorization(
        &self,
        authorization: &EnrollmentAuthorization,
        challenge: &EnrollmentChallenge,
        proof: &[u8],
    ) -> Result<(), String>;
}
