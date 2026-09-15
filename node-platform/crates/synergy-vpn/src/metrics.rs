#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VpnMetrics {
    pub connected: bool,
    pub connected_peers: usize,
    pub reconnects: u64,
    pub enrollment_failures: u64,
    pub lease_verification_failures: u64,
    pub revocations: u64,
}

impl VpnMetrics {
    pub fn record_reconnect(&mut self) {
        self.reconnects = self.reconnects.saturating_add(1);
    }

    pub fn record_enrollment_failure(&mut self) {
        self.enrollment_failures = self.enrollment_failures.saturating_add(1);
    }

    pub fn record_lease_failure(&mut self) {
        self.lease_verification_failures = self.lease_verification_failures.saturating_add(1);
    }

    pub fn record_revocation(&mut self) {
        self.revocations = self.revocations.saturating_add(1);
    }
}
