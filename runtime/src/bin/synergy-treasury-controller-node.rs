use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-treasury-controller-node",
        Some(NodeRole::TreasuryController.profile()),
    );
}
