#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerHealthState {
    Healthy,
    Degraded,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerHealth {
    pub last_seen_at: u64,
    pub consecutive_failures: u32,
}

impl PeerHealth {
    pub fn state(self, now: u64, degraded_after: u64, stale_after: u64) -> PeerHealthState {
        let age = now.saturating_sub(self.last_seen_at);
        if age >= stale_after {
            PeerHealthState::Stale
        } else if age >= degraded_after || self.consecutive_failures > 0 {
            PeerHealthState::Degraded
        } else {
            PeerHealthState::Healthy
        }
    }
}
