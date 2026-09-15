use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedSet {
    addresses: Vec<String>,
}

impl SeedSet {
    pub fn new(addresses: Vec<String>) -> Result<Self, String> {
        if addresses.is_empty() {
            return Err("seed set must not be empty".into());
        }
        let mut normalized = BTreeSet::new();
        for address in addresses {
            normalized.insert(
                crate::transport::parse_dial_address(&address)
                    .ok_or_else(|| "invalid seed dial address".to_string())?,
            );
        }
        Ok(Self {
            addresses: normalized.into_iter().collect(),
        })
    }

    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }
}
