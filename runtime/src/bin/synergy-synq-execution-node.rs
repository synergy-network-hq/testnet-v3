use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-synq-execution-node",
        Some(NodeRole::SynqExecution.profile()),
    );
}
