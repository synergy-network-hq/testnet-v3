use crate::{NetbirdStatus, VpnState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnReadiness {
    Ready,
    Pending(String),
    Blocked(String),
}

pub fn evaluate_readiness(
    required: bool,
    state: VpnState,
    status: Option<&NetbirdStatus>,
) -> VpnReadiness {
    if !required {
        return VpnReadiness::Ready;
    }
    match (state, status) {
        (VpnState::Connected, Some(status)) if status.connected && status.overlay_ip.is_some() => {
            VpnReadiness::Ready
        }
        (VpnState::Connecting | VpnState::Disconnected, _) => {
            VpnReadiness::Pending("VPN transport is not connected".into())
        }
        (VpnState::Revoked, _) => VpnReadiness::Blocked("VPN enrollment is revoked".into()),
        (VpnState::Failed, _) => VpnReadiness::Blocked("VPN daemon failed".into()),
        _ => VpnReadiness::Pending("VPN evidence is incomplete".into()),
    }
}
