use super::PeerDirection;

pub fn preferred_direction(
    local_peer_id: &str,
    remote_peer_id: &str,
) -> Result<PeerDirection, super::ConnectionLimitError> {
    if local_peer_id.trim().is_empty()
        || remote_peer_id.trim().is_empty()
        || local_peer_id == remote_peer_id
    {
        return Err(super::ConnectionLimitError::InvalidConfiguration);
    }
    Ok(if local_peer_id < remote_peer_id {
        PeerDirection::Outbound
    } else {
        PeerDirection::Inbound
    })
}
