use std::collections::BTreeSet;

use super::DiscoveryRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryVerificationError {
    InvalidIdentity,
    InvalidLifetime,
    NoAddresses,
    DuplicateAddress,
    InvalidAddress,
}

pub fn verify_discovery_record(
    record: &DiscoveryRecord,
    now: u64,
) -> Result<(), DiscoveryVerificationError> {
    if record.peer_id.trim().is_empty() {
        return Err(DiscoveryVerificationError::InvalidIdentity);
    }
    if record.observed_at > now
        || record.expires_at <= now
        || record.expires_at <= record.observed_at
    {
        return Err(DiscoveryVerificationError::InvalidLifetime);
    }
    if record.dial_addresses.is_empty() {
        return Err(DiscoveryVerificationError::NoAddresses);
    }
    let mut addresses = BTreeSet::new();
    for address in &record.dial_addresses {
        if !addresses.insert(address.as_str()) {
            return Err(DiscoveryVerificationError::DuplicateAddress);
        }
        crate::transport::parse_dial_address(address)
            .ok_or(DiscoveryVerificationError::InvalidAddress)?;
    }
    Ok(())
}
