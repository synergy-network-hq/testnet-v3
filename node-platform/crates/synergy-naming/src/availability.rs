use crate::{NamingError, NamingRegistrySnapshot, NodeId};

/// Returns true only when the canonical NodeID has no current registration.
pub fn is_available(snapshot: &NamingRegistrySnapshot, node_id: &NodeId) -> bool {
    snapshot.record(node_id).is_none()
}

/// Fails closed when a NodeID is already registered.
///
/// # Errors
/// Returns NamingError::DuplicateNodeId for an occupied name.
pub fn ensure_available(
    snapshot: &NamingRegistrySnapshot,
    node_id: &NodeId,
) -> Result<(), NamingError> {
    if is_available(snapshot, node_id) {
        Ok(())
    } else {
        Err(NamingError::DuplicateNodeId)
    }
}
