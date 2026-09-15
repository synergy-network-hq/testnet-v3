#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLimits {
    pub max_connections: usize,
    pub max_inbound_connections: usize,
    pub max_outbound_connections: usize,
    pub max_frame_bytes: usize,
}

impl TransportLimits {
    pub fn validate(self) -> Result<Self, super::TransportError> {
        if self.max_connections == 0
            || self.max_inbound_connections == 0
            || self.max_outbound_connections == 0
            || self.max_frame_bytes == 0
            || self.max_inbound_connections > self.max_connections
            || self.max_outbound_connections > self.max_connections
        {
            return Err(super::TransportError::InvalidConfiguration(
                "invalid connection or frame limits".into(),
            ));
        }
        Ok(self)
    }
}
