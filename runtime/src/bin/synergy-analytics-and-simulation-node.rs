use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-analytics-and-simulation-node",
        Some(NodeRole::AnalyticsSimulation.profile()),
    );
}
