//! Human-facing software release identity.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ReleaseVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ReleaseVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn parse(value: &str) -> Result<Self, ReleaseVersionError> {
        let mut parts = value.split('.');
        let major = parse_part(parts.next())?;
        let minor = parse_part(parts.next())?;
        let patch = parse_part(parts.next())?;
        if parts.next().is_some() {
            return Err(ReleaseVersionError::InvalidFormat);
        }
        Ok(Self::new(major, minor, patch))
    }
}

impl std::fmt::Display for ReleaseVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn parse_part(value: Option<&str>) -> Result<u16, ReleaseVersionError> {
    let value = value.ok_or(ReleaseVersionError::InvalidFormat)?;
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(ReleaseVersionError::InvalidFormat);
    }
    value
        .parse::<u16>()
        .map_err(|_| ReleaseVersionError::InvalidFormat)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseVersionError {
    InvalidFormat,
}

impl std::fmt::Display for ReleaseVersionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("release version must be canonical major.minor.patch")
    }
}

impl std::error::Error for ReleaseVersionError {}
