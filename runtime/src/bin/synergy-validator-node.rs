use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-validator-node",
        Some(NodeRole::Validator.profile()),
    );
}
