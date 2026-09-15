pub fn node_event(
    sequence: u64,
    state: String,
    ready: bool,
) -> Result<crate::WsEvent, crate::WsError> {
    if state.trim().is_empty() {
        return Err(crate::WsError::InvalidEvent);
    }
    Ok(crate::WsEvent {
        sequence,
        topic: crate::WsTopic::Node,
        payload: serde_json::json!({"state": state, "ready": ready}),
    })
}
