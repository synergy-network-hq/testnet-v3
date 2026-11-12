use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentAuthorization {
    pub id: String,
    pub node_address: String,
    pub role: String,
    pub expires_at: u64,
    pub revoked: bool,
}
impl EnrollmentAuthorization {
    pub fn validate(&self, now: u64) -> Result<(), String> {
        if self.id.is_empty()
            || self.node_address.is_empty()
            || self.expires_at <= now
            || self.revoked
        {
            Err("enrollment authorization is unavailable".into())
        } else {
            Ok(())
        }
    }
}
