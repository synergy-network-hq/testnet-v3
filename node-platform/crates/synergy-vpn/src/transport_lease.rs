use crate::OverlayScope;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransportLease {
    pub lease_version: u32,
    pub lease_id: String,
    pub identity: String,
    pub scope: OverlayScope,
    pub dial_address: String,
    pub generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub authority_id: String,
    pub key_id: String,
    pub signature: Vec<u8>,
}

impl SignedTransportLease {
    pub fn validate_shape(&self, now: u64) -> Result<(), crate::VpnRouteError> {
        if self.lease_version != 1
            || self.lease_id.trim().is_empty()
            || self.generation == 0
            || self.issued_at > now
            || self.expires_at <= now
            || self.expires_at <= self.issued_at
            || self.authority_id.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.signature.is_empty()
        {
            return Err(crate::VpnRouteError::InvalidRoute);
        }
        crate::VpnRoutePolicy::new(self.scope)
            .validate(&self.identity, &self.dial_address)
            .map(|_| ())
    }

    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let scope = match self.scope {
            OverlayScope::Validator => "validator",
            OverlayScope::Sentry => "sentry",
        };
        format!(
            "SYNERGY_VPN_TRANSPORT_LEASE_V1\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            self.lease_id,
            self.identity,
            scope,
            self.dial_address,
            self.generation,
            self.issued_at,
            self.expires_at,
            self.authority_id,
            self.key_id,
        )
        .into_bytes()
    }

    pub const fn grants_consensus_authority(&self) -> bool {
        false
    }
}
