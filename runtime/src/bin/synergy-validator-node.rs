use synergy_testnet::role_profiles::NodeRole;

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.as_slice() == ["release-binding"] {
        print!(
            "{}",
            include_str!("../../../launch/TESTNET_V3_RUNTIME_BINDING.json")
        );
        return;
    }
    synergy_testnet::role_runtime::run(
        "synergy-validator-node",
        Some(NodeRole::Validator.profile()),
    );
}
