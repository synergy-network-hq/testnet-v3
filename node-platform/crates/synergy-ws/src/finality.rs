pub fn finality_event(
    sequence: u64,
    height: u64,
    finality_reference: String,
) -> Result<crate::WsEvent, crate::WsError> {
    if height == 0 || finality_reference.trim().is_empty() {
        return Err(crate::WsError::InvalidEvent);
    }
    Ok(crate::WsEvent {
        sequence,
        topic: crate::WsTopic::Finality,
        payload: serde_json::json!({"height": height, "finality_reference": finality_reference}),
    })
}
