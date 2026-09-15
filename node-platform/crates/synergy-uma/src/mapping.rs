use serde::{Deserialize, Serialize};

use crate::UmaAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressNamespace {
    Synergy,
    Bitcoin,
    Ethereum,
    Solana,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressMapping {
    pub uma: UmaAddress,
    pub namespace: AddressNamespace,
    pub destination: String,
    pub revision: u64,
    pub authorization_root: String,
}

impl AddressMapping {
    pub fn validate(&self) -> Result<(), String> {
        if self.destination.trim().is_empty()
            || self.destination.len() > 256
            || self.authorization_root.trim().is_empty()
        {
            return Err("invalid UMA mapping".into());
        }
        Ok(())
    }
}
