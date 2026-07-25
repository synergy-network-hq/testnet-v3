use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-committee-node",
        Some(NodeRole::Committee.profile()),
    );
}
