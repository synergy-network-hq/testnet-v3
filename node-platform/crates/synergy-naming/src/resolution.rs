use synergy_protocol_types::NodeAddress;

use crate::{NamingRegistrySnapshot, NodeId};

/// Resolves a display NodeID to its canonical protocol NodeAddress.
pub fn resolve(snapshot: &NamingRegistrySnapshot, node_id: &NodeId) -> Option<NodeAddress> {
    snapshot
        .record(node_id)
        .map(|record| record.node_address.clone())
}
