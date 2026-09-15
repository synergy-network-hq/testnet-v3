use synergy_uma::{AddressNamespace, UmaAddress, UmaRegistry};

use crate::ExternalChain;

pub fn resolve_uma_destination(
    registry: &UmaRegistry,
    address: &UmaAddress,
    destination_chain: ExternalChain,
) -> Result<String, String> {
    let namespace = match destination_chain {
        ExternalChain::Bitcoin => AddressNamespace::Bitcoin,
        ExternalChain::Ethereum => AddressNamespace::Ethereum,
        ExternalChain::Solana => AddressNamespace::Solana,
    };
    let mapping = registry
        .resolve(address, namespace)
        .ok_or_else(|| "UMA destination mapping is unavailable".to_string())?;
    synergy_uma::adapters::validate_destination(mapping)?;
    Ok(mapping.destination.clone())
}
