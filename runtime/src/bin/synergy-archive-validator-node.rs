use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-archive-validator-node",
        Some(NodeRole::ArchiveValidator.profile()),
    );
}
