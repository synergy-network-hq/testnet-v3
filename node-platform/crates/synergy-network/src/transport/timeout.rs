use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportTimeouts {
    pub connect: Duration,
    pub handshake: Duration,
    pub read: Duration,
    pub write: Duration,
}

impl TransportTimeouts {
    pub fn validate(self) -> Result<Self, super::TransportError> {
        if self.connect.is_zero()
            || self.handshake.is_zero()
            || self.read.is_zero()
            || self.write.is_zero()
        {
            return Err(super::TransportError::InvalidConfiguration(
                "transport timeouts must be nonzero".into(),
            ));
        }
        Ok(self)
    }
}
