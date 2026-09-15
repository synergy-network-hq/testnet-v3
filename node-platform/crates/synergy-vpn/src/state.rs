#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnState {
    Disabled,
    Disconnected,
    Connecting,
    Connected,
    Degraded,
    Revoked,
    Failed,
}

impl VpnState {
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Disabled | Self::Connected)
    }
}
