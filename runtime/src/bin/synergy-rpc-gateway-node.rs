use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-rpc-gateway-node",
        Some(NodeRole::RpcGateway.profile()),
    );
}
