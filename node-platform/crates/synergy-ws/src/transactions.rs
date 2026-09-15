pub fn transaction_event(
    sequence: u64,
    transaction_id: String,
    status: String,
) -> Result<crate::WsEvent, crate::WsError> {
    if transaction_id.trim().is_empty() || status.trim().is_empty() {
        return Err(crate::WsError::InvalidEvent);
    }
    Ok(crate::WsEvent {
        sequence,
        topic: crate::WsTopic::Transactions,
        payload: serde_json::json!({"transaction_id": transaction_id, "status": status}),
    })
}
