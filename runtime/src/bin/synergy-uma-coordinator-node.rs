use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-uma-coordinator-node",
        Some(NodeRole::UmaCoordinator.profile()),
    );
}
