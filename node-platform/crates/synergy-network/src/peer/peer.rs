#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDescriptor {
    pub peer_id: String,
    pub dial_addresses: Vec<String>,
    pub capabilities: Vec<String>,
}

impl PeerDescriptor {
    pub fn validate(&self) -> Result<(), super::ConnectionLimitError> {
        if self.peer_id.trim().is_empty() || self.dial_addresses.is_empty() {
            return Err(super::ConnectionLimitError::InvalidConfiguration);
        }
        for address in &self.dial_addresses {
            crate::transport::parse_dial_address(address)
                .ok_or(super::ConnectionLimitError::InvalidConfiguration)?;
        }
        Ok(())
    }
}
