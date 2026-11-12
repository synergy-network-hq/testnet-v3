use crate::one_time_key::OneTimeEnrollmentKey;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetbirdEnrollment {
    pub peer_id: String,
    pub overlay_address: String,
}
pub trait NetbirdProvider: Send + Sync {
    fn enroll(&self, key: OneTimeEnrollmentKey) -> Result<NetbirdEnrollment, String>;
    fn revoke(&self, peer_id: &str) -> Result<(), String>;
}
