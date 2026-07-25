use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-audit-validator-node",
        Some(NodeRole::AuditValidator.profile()),
    );
}
