use crate::virtual_network::VirtualNetwork;
pub fn apply(network: &mut VirtualNetwork, edges: &[(&str, &str, u64)]) {
    for (a, b, ms) in edges {
        network.set_latency(a, b, *ms);
    }
}
