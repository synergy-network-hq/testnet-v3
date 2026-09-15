use crate::SignedTransportLease;

#[derive(Clone, PartialEq, Eq)]
pub struct EnrollmentResponse {
    pub authorization_id: String,
    pub peer_id: String,
    pub setup_credential: Vec<u8>,
    pub lease: SignedTransportLease,
}

impl std::fmt::Debug for EnrollmentResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnrollmentResponse")
            .field("authorization_id", &self.authorization_id)
            .field("peer_id", &self.peer_id)
            .field("setup_credential", &"[REDACTED]")
            .field("lease", &self.lease)
            .finish()
    }
}

impl EnrollmentResponse {
    pub fn validate_shape(&self, now: u64) -> Result<(), String> {
        if self.authorization_id.trim().is_empty()
            || self.peer_id.trim().is_empty()
            || self.setup_credential.is_empty()
            || self.setup_credential.len() > 4096
            || self.lease.identity != self.peer_id
        {
            return Err("invalid enrollment response".into());
        }
        self.lease
            .validate_shape(now)
            .map_err(|error| format!("invalid response lease: {error:?}"))
    }
}
