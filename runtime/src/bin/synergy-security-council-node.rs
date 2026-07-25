use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-security-council-node",
        Some(NodeRole::SecurityCouncil.profile()),
    );
}
