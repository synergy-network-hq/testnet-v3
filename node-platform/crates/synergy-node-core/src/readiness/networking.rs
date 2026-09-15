use serde::{Deserialize, Serialize};

use crate::DiagnosticCheck;

/// Authenticated transport evidence; peerability never grants protocol authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkReadiness {
    pub listener_bound: bool,
    pub authenticated_compatible_peers: usize,
    pub required_peers: usize,
    pub router_accepting: bool,
}

impl NetworkReadiness {
    pub fn check(self) -> DiagnosticCheck {
        if self.listener_bound
            && self.router_accepting
            && self.authenticated_compatible_peers >= self.required_peers
        {
            DiagnosticCheck::passed(
                "network.authenticated_mesh",
                "network",
                "authenticated compatible peer requirement is satisfied",
            )
        } else {
            DiagnosticCheck::failed(
                "network.authenticated_mesh",
                "network",
                "authenticated compatible peer requirement is not satisfied",
                "restore the listener, bounded router, and authenticated peer sessions",
            )
        }
    }
}
