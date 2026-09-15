use crate::OverlayScope;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayAssignment {
    pub identity: String,
    pub scope: OverlayScope,
    pub dial_address: String,
}

impl OverlayAssignment {
    pub fn validate(&self) -> Result<(), crate::VpnRouteError> {
        crate::VpnRoutePolicy::new(self.scope)
            .validate(&self.identity, &self.dial_address)
            .map(|_| ())
    }

    pub const fn grants_consensus_authority(&self) -> bool {
        false
    }
}
