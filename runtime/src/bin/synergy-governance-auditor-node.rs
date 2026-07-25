use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-governance-auditor-node",
        Some(NodeRole::GovernanceAuditor.profile()),
    );
}
