use serde::{Deserialize, Serialize};

use crate::DiagnosticCheck;

/// Role-scoped overlay readiness; route presence never grants validator authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnReadiness {
    pub required_for_role: bool,
    pub enrolled: bool,
    pub lease_valid: bool,
    pub identity_route_bound: bool,
}

impl VpnReadiness {
    pub fn check(self) -> DiagnosticCheck {
        if !self.required_for_role {
            return DiagnosticCheck::passed(
                "vpn.not_required",
                "vpn",
                "the selected role requires no validator or sentry overlay",
            );
        }
        if self.enrolled && self.lease_valid && self.identity_route_bound {
            DiagnosticCheck::passed(
                "vpn.identity_route",
                "vpn",
                "role-scoped identity-bound overlay route is ready",
            )
        } else {
            DiagnosticCheck::failed(
                "vpn.identity_route",
                "vpn",
                "role-scoped identity-bound overlay route is not ready",
                "restore enrollment, lease validity, and identity-to-route binding",
            )
        }
    }
}
