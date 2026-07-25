use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-indexer-and-explorer-node",
        Some(NodeRole::IndexerExplorer.profile()),
    );
}
