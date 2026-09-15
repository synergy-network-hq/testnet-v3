use crate::{ConsensusEvent, PosyEnvelope, PosyError, PosyResult};

pub trait PosyInboundDecoder {
    fn decode(&self, envelope: &PosyEnvelope) -> PosyResult<ConsensusEvent>;
}

pub fn require_authenticated_posy_peer(envelope: &PosyEnvelope) -> PosyResult<()> {
    envelope
        .authenticated_peer()
        .map(|_| ())
        .map_err(PosyError::Invalid)
}
