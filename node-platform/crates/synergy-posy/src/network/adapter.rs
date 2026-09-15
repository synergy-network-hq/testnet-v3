use crate::{
    ConsensusSignatureVerifier, PosyInboundDecoder, PosyOutbound, PosyResult, SimplifiedPosyDriver,
};

pub struct PosyNetworkAdapter<D, V> {
    driver: D,
    verifier: V,
}

impl<D, V> PosyNetworkAdapter<D, V>
where
    D: PosyInboundDecoder,
    V: ConsensusSignatureVerifier,
{
    pub fn new(driver: D, verifier: V) -> Self {
        Self { driver, verifier }
    }

    pub fn receive(
        &mut self,
        envelope: &crate::PosyEnvelope,
        posy: &mut SimplifiedPosyDriver,
    ) -> PosyResult<Vec<crate::ConsensusTransition>> {
        crate::require_authenticated_posy_peer(envelope)?;
        let event = self.driver.decode(envelope)?;
        posy.handle(event, &self.verifier)
    }

    pub fn decoder(&self) -> &D {
        &self.driver
    }
}

pub fn send_posy_event(
    outbound: &mut impl PosyOutbound,
    event: &crate::ConsensusEvent,
) -> PosyResult<()> {
    outbound.broadcast(event)
}
