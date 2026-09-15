pub fn block_event(
    sequence: u64,
    height: u64,
    block_hash: String,
) -> Result<crate::WsEvent, crate::WsError> {
    if height == 0 || block_hash.trim().is_empty() {
        return Err(crate::WsError::InvalidEvent);
    }
    Ok(crate::WsEvent {
        sequence,
        topic: crate::WsTopic::Blocks,
        payload: serde_json::json!({"height": height, "block_hash": block_hash}),
    })
}
