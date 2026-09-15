use crate::protocol::InboundFrame;
use synergy_protocol_types::ProtocolKind;

pub trait ProtocolFrameHandler {
    fn protocol(&self) -> ProtocolKind;
    fn handle_frame(&mut self, frame: InboundFrame) -> Result<(), String>;

    fn may_determine_finality(&self) -> bool {
        false
    }
}
