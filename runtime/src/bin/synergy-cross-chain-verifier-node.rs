use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-cross-chain-verifier-node",
        Some(NodeRole::CrossChainVerifier.profile()),
    );
}
