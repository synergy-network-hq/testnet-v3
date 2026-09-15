pub trait DiscoveryTransportRegistry {
    fn dial_address_for(&self, peer_id: &str) -> Result<Option<String>, String>;
    fn generation(&self) -> u64;

    fn grants_consensus_authority(&self) -> bool {
        false
    }
}
