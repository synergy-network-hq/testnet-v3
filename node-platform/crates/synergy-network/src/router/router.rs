use super::{BoundedPeerRouter, ProtocolFrameHandler};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    WrongProtocol,
    Handler(String),
}

pub fn dispatch_next(
    router: &mut BoundedPeerRouter,
    handler: &mut impl ProtocolFrameHandler,
) -> Result<bool, DispatchError> {
    let Some(frame) = router.try_next() else {
        return Ok(false);
    };
    if frame.protocol != handler.protocol() {
        return Err(DispatchError::WrongProtocol);
    }
    handler
        .handle_frame(frame)
        .map_err(DispatchError::Handler)?;
    Ok(true)
}
