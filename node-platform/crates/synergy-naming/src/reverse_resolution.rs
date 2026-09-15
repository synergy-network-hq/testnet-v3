use synergy_protocol_types::NodeAddress;

use crate::{NamingRegistrySnapshot, NodeId};

/// Returns the current display NodeID for a canonical NodeAddress.
pub fn reverse_resolve(
    snapshot: &NamingRegistrySnapshot,
    node_address: &NodeAddress,
) -> Option<NodeId> {
    snapshot.node_id(node_address).cloned()
}
