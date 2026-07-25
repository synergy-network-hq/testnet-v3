use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-relayer-node",
        Some(NodeRole::Relayer.profile()),
    );
}
