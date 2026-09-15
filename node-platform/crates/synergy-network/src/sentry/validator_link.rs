use synergy_protocol_types::AuthenticatedPeer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorLink {
    pub validator_id: String,
    pub sentry_id: String,
    pub overlay_address: String,
    pub peer: AuthenticatedPeer,
    pub healthy: bool,
}

impl ValidatorLink {
    pub fn validate(&self) -> Result<(), String> {
        if self.validator_id.trim().is_empty()
            || self.sentry_id.trim().is_empty()
            || self.peer.node_address.as_str() != self.validator_id
        {
            return Err("invalid sentry validator link identity".into());
        }
        let address = crate::transport::parse_dial_address(&self.overlay_address)
            .ok_or_else(|| "invalid validator overlay address".to_string())?;
        if address != self.overlay_address.trim() {
            return Err("validator link address is not canonical".into());
        }
        Ok(())
    }

    pub const fn grants_consensus_authority(&self) -> bool {
        false
    }
}
