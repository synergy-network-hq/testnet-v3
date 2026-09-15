use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-observer-light-node",
        Some(NodeRole::ObserverLight.profile()),
    );
}
