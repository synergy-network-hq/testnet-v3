use crate::{ConsensusEvent, PosyResult};

pub trait PosyOutbound {
    fn unicast(&mut self, peer_id: &str, event: &ConsensusEvent) -> PosyResult<()>;
    fn broadcast(&mut self, event: &ConsensusEvent) -> PosyResult<()>;
}
