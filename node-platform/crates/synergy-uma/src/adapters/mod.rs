mod bitcoin;
mod ethereum;
mod solana;

pub use bitcoin::validate_bitcoin_destination;
pub use ethereum::validate_ethereum_destination;
pub use solana::validate_solana_destination;

use crate::{AddressMapping, AddressNamespace};

pub fn validate_destination(mapping: &AddressMapping) -> Result<(), String> {
    match mapping.namespace {
        AddressNamespace::Bitcoin => validate_bitcoin_destination(&mapping.destination),
        AddressNamespace::Ethereum => validate_ethereum_destination(&mapping.destination),
        AddressNamespace::Solana => validate_solana_destination(&mapping.destination),
        AddressNamespace::Synergy => {
            if mapping.destination.starts_with("syn1") {
                Ok(())
            } else {
                Err("invalid Synergy destination".into())
            }
        }
    }
}
