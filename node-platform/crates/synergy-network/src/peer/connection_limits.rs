use super::PeerDirection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLimits {
    pub total: usize,
    pub inbound: usize,
    pub outbound: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionLimitError {
    InvalidConfiguration,
    TotalCapacity,
    DirectionCapacity(PeerDirection),
}

impl ConnectionLimits {
    pub fn validate(self) -> Result<Self, ConnectionLimitError> {
        if self.total == 0
            || self.inbound == 0
            || self.outbound == 0
            || self.inbound > self.total
            || self.outbound > self.total
        {
            return Err(ConnectionLimitError::InvalidConfiguration);
        }
        Ok(self)
    }

    pub fn permit(
        self,
        total: usize,
        inbound: usize,
        outbound: usize,
        direction: PeerDirection,
    ) -> Result<(), ConnectionLimitError> {
        self.validate()?;
        if total >= self.total {
            return Err(ConnectionLimitError::TotalCapacity);
        }
        match direction {
            PeerDirection::Inbound if inbound >= self.inbound => {
                Err(ConnectionLimitError::DirectionCapacity(direction))
            }
            PeerDirection::Outbound if outbound >= self.outbound => {
                Err(ConnectionLimitError::DirectionCapacity(direction))
            }
            _ => Ok(()),
        }
    }
}
