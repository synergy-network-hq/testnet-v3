#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub fn new(major: u16, minor: u16) -> Result<Self, super::ProtocolRegistryError> {
        if major == 0 {
            return Err(super::ProtocolRegistryError::InvalidVersion);
        }
        Ok(Self { major, minor })
    }

    pub const fn is_compatible_with(self, remote: Self) -> bool {
        self.major == remote.major && remote.minor <= self.minor
    }
}
