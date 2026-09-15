#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvertisedNodeRole {
    Validator,
    Sentry,
    Bootseed,
    Rpc,
    DataAvailability,
    Archive,
    Observer,
}

impl AdvertisedNodeRole {
    /// A role is transport metadata only and never proves membership or
    /// consensus authority.
    pub const fn grants_consensus_authority(&self) -> bool {
        false
    }
}
