use crate::virtual_network::VirtualNetwork;
pub fn split(network: &mut VirtualNetwork, left: &[&str], right: &[&str]) {
    for a in left {
        for b in right {
            network.block(a, b);
            network.block(b, a);
        }
    }
}
pub fn heal(network: &mut VirtualNetwork) {
    network.heal();
}
