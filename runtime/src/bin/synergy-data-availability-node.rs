use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-data-availability-node",
        Some(NodeRole::DataAvailability.profile()),
    );
}
