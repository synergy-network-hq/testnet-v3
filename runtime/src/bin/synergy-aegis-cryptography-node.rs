use synergy_testnet::role_profiles::NodeRole;

fn main() {
    synergy_testnet::role_runtime::run(
        "synergy-aegis-cryptography-node",
        Some(NodeRole::AegisCryptography.profile()),
    );
}
